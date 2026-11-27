"""The guardrail layer: every tool call the agent makes goes through here.

The guard doesn't trust the model. It assumes the agent may have been
hijacked by text in a web page or file, and checks each action against what
the *user* asked for and a fixed policy:

  budget       at most N tool calls per task (stops runaway loops)
  paths        no absolute paths or "..", protected files only if the user named them
  fetch        https only, allowlisted domains, no IPs or localhost (SSRF),
               no secrets in the URL (exfiltration through a query string)
  email        recipient must be a contact or named by the user; no secrets in
               the message, even base64, hex, URL-encoded, spaced out or reversed
  delete       only files the user named, and only after a human confirms
  answer       secrets are redacted from the final answer

Every decision is written to an audit log, with secrets redacted.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from posixpath import normpath
from urllib.parse import unquote, urlsplit

from .sandbox import UNTRUSTED_OUTPUT, Sandbox


class Blocked(Exception):
    def __init__(self, rule: str, reason: str):
        super().__init__(f"[{rule}] {reason}")
        self.rule = rule
        self.reason = reason


@dataclass
class Policy:
    allowed_domains: set[str] = field(default_factory=set)
    contacts: set[str] = field(default_factory=set)
    secrets: list[str] = field(default_factory=list)
    protected_paths: tuple[str, ...] = (".env", "secrets/", ".ssh/")
    max_tool_calls: int = 20
    # Asked before any delete. The default answer is no.
    confirm: Callable[[str], bool] = field(default=lambda action: False)


@dataclass
class Decision:
    tool: str
    args: dict
    allowed: bool
    rule: str = ""
    reason: str = ""


_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_PATH = re.compile(r"[\w.~/-]+")  # sentence-ending dots are stripped below
_B64 = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){6,}\b")


def _squash(text: str) -> str:
    """Lowercase letters and digits only, so 'F A K E-c a n' matches 'FAKE-can'."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _decodings(text: str) -> list[str]:
    """The text plus every way an agent might disguise data inside it."""
    found = [text, unquote(text), text[::-1]]
    for token in _B64.findall(text):
        padded = token + "=" * (-len(token) % 4)
        for decode in (base64.b64decode, base64.urlsafe_b64decode):
            with suppress(binascii.Error, ValueError):
                found.append(decode(padded).decode("utf-8", "ignore"))
    for token in _HEX.findall(text):
        found.append(bytes.fromhex(token).decode("utf-8", "ignore"))
    return found


def leaks(text: str, secrets: list[str]) -> bool:
    """True if any secret appears in the text, plainly or disguised."""
    squashed = [_squash(d) for d in _decodings(text)]
    return any(_squash(secret) in s for secret in secrets if len(secret) >= 8 for s in squashed)


def redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        text = text.replace(secret, "[REDACTED]")
    return text


class Guard:
    """Wraps a Sandbox. Agents call guard.call(tool, **args), never the sandbox."""

    def __init__(self, sandbox: Sandbox, policy: Policy, user_request: str):
        self.sandbox = sandbox
        self.policy = policy
        self.user_request = user_request
        # Whole addresses and paths the user wrote. Exact matches only:
        # "s@company.example" is inside "boss@company.example" but isn't it.
        self.user_emails = {e.lower() for e in _EMAIL.findall(user_request)}
        self.user_paths = {
            normpath(p.rstrip(".")) for p in _PATH.findall(user_request) if p.rstrip(".")
        }
        self.audit: list[Decision] = []
        self.untrusted_seen: list[str] = []  # text from pages and files
        self.calls = 0

    # ------------------------------------------------------------ public

    def call(self, tool: str, **args):
        try:
            self.calls += 1
            if self.calls > self.policy.max_tool_calls:
                raise Blocked("budget", f"more than {self.policy.max_tool_calls} tool calls")
            check = getattr(self, f"_check_{tool}", None)
            if check is None:
                raise Blocked("unknown-tool", f"no such tool {tool!r}")
            check(**args)
        except Blocked as blocked:
            self._log(tool, args, False, blocked.rule, blocked.reason)
            raise
        except TypeError as error:  # wrong arguments from the model
            self._log(tool, args, False, "bad-arguments", str(error))
            raise Blocked("bad-arguments", str(error)) from error
        self._log(tool, args, True)
        result = getattr(self.sandbox, tool)(**args)
        if tool in UNTRUSTED_OUTPUT:
            self.untrusted_seen.append(str(result))
        return result

    def final_answer(self, text: str) -> str:
        if leaks(text, self.policy.secrets):
            self._log("final_answer", {}, True, "redacted", "secret removed from the answer")
        return redact(text, self.policy.secrets)

    @property
    def blocked(self) -> list[Decision]:
        return [d for d in self.audit if not d.allowed]

    # ------------------------------------------------------------ checks

    def _check_list_files(self) -> None:
        pass

    def _check_read_file(self, path: str) -> None:
        clean = self._clean_path(path)
        if self._is_protected(clean) and clean not in self.user_paths:
            raise Blocked("protected-path", f"{clean} is protected and the user didn't ask for it")

    def _check_fetch(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise Blocked("fetch-scheme", f"only https is allowed, not {parts.scheme or 'none'}")
        host = (parts.hostname or "").lower()
        try:
            ipaddress.ip_address(host)
            raise Blocked("ssrf", f"{host} is an IP address")
        except ValueError:
            pass
        if host == "localhost" or host.endswith((".localhost", ".internal")):
            raise Blocked("ssrf", f"{host} is an internal host")
        if not any(host == d or host.endswith("." + d) for d in self.policy.allowed_domains):
            raise Blocked("fetch-domain", f"{host} isn't an allowed domain")
        if leaks(url, self.policy.secrets):
            raise Blocked("exfiltration", "the URL contains a secret")

    def _check_send_email(self, to: str, subject: str, body: str) -> None:
        to = to.strip().lower()
        if not _EMAIL.fullmatch(to):
            raise Blocked("email-recipient", f"{to!r} isn't one email address")
        if to not in self.policy.contacts and to not in self.user_emails:
            from_untrusted = any(to in text.lower() for text in self.untrusted_seen)
            reason = (
                f"{to} came from a page or file, not from the user"
                if from_untrusted
                else f"{to} isn't a contact and the user didn't name them"
            )
            raise Blocked("email-recipient", reason)
        if leaks(subject + "\n" + body, self.policy.secrets):
            raise Blocked("exfiltration", "the email contains a secret")

    def _check_delete_file(self, path: str) -> None:
        clean = self._clean_path(path)
        if clean not in self.user_paths:
            raise Blocked("delete-scope", f"the user didn't ask to delete {clean}")
        if not self.policy.confirm(f"delete {clean}"):
            raise Blocked("needs-confirmation", f"deleting {clean} wasn't confirmed")

    # ------------------------------------------------------------ helpers

    def _clean_path(self, path: str) -> str:
        if path.startswith(("/", "~")) or "\\" in path or "\x00" in path:
            raise Blocked("path", f"{path!r} must be a plain relative path")
        clean = normpath(path)
        if clean == ".." or clean.startswith("../"):
            raise Blocked("path", f"{path!r} leaves the workspace")
        return clean

    def _is_protected(self, path: str) -> bool:
        """'.env' matches that file anywhere; 'secrets/' matches that folder anywhere."""
        wrapped = f"/{path}/"
        return any(
            f"/{p}" in wrapped if p.endswith("/") else wrapped.endswith(f"/{p}/")
            for p in self.policy.protected_paths
        )

    def _log(self, tool: str, args: dict, allowed: bool, rule: str = "", reason: str = "") -> None:
        safe_args = {k: redact(str(v), self.policy.secrets) for k, v in args.items()}
        self.audit.append(
            Decision(tool, safe_args, allowed, rule, redact(reason, self.policy.secrets))
        )
