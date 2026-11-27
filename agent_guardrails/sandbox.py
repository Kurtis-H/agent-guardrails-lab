"""A fake world for the agent: files, web pages and an outbox, all in memory.

Nothing here touches the real filesystem or network, so attacks can be run
safely and every side effect can be inspected afterwards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from posixpath import normpath


@dataclass
class Email:
    to: str
    subject: str
    body: str


@dataclass
class Sandbox:
    files: dict[str, str] = field(default_factory=dict)
    pages: dict[str, str] = field(default_factory=dict)
    outbox: list[Email] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    fetched: list[str] = field(default_factory=list)

    # ------------------------------------------------------------ the tools

    # Paths resolve like a real filesystem would: "notes/../.env" is ".env".
    def read_file(self, path: str) -> str:
        path = normpath(path)
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def list_files(self) -> list[str]:
        return sorted(self.files)

    def fetch(self, url: str) -> str:
        self.fetched.append(url)
        return self.pages.get(url, "404 not found")

    def send_email(self, to: str, subject: str, body: str) -> str:
        self.outbox.append(Email(to, subject, body))
        return f"sent to {to}"

    def delete_file(self, path: str) -> str:
        path = normpath(path)
        if path not in self.files:
            raise FileNotFoundError(path)
        del self.files[path]
        self.deleted.append(path)
        return f"deleted {path}"


TOOL_NAMES = ("read_file", "list_files", "fetch", "send_email", "delete_file")

# Tools whose output can carry an attacker's text into the agent's context.
UNTRUSTED_OUTPUT = {"read_file", "fetch"}
