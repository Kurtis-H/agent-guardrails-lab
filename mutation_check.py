"""Mutation check: weaken one guard rule at a time; the tests must catch each.

    python mutation_check.py

Green tests only matter if they'd go red when a protection breaks. Each
mutant below is a realistic mistake: a check deleted, loosened or inverted.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent

MUTANTS = {
    "budget never trips": ("if self.calls > self.policy.max_tool_calls:", "if False:"),
    "http allowed": ('if parts.scheme != "https":', "if False:"),
    "IP addresses allowed": ("ipaddress.ip_address(host)\n", "ipaddress.ip_address('x')\n"),
    "internal hosts allowed": (
        'if host == "localhost" or host.endswith((".localhost", ".internal")):',
        "if False:",
    ),
    "lookalike domains allowed": ('host.endswith("." + d)', "host.endswith(d)"),
    "secrets allowed in URLs": ("if leaks(url, self.policy.secrets):", "if False:"),
    "any recipient allowed": (
        "if to not in self.policy.contacts and to not in self.user_emails:",
        "if False:",
    ),
    "recipient matched by substring": (
        "to not in self.user_emails:",
        "to not in self.user_request.lower():",
    ),
    "secrets allowed in email": (
        'if leaks(subject + "\\n" + body, self.policy.secrets):',
        "if leaks(body, []):",
    ),
    "no base64 decoding": ("for token in _B64.findall(text):", "for token in []:"),
    "no hex decoding": ("for token in _HEX.findall(text):", "for token in []:"),
    "reversed text not checked": ("text[::-1]]", "]"),
    "deletes need no confirmation": (
        'if not self.policy.confirm(f"delete {clean}"):',
        "if False:",
    ),
    "delete scope unchecked": ("if clean not in self.user_paths:", "if False:"),
    "'..' allowed": ('if clean == ".." or clean.startswith("../"):', "if False:"),
    "absolute paths allowed": ('if path.startswith(("/", "~"))', 'if path.startswith(("~",))'),
    "protected files readable": (
        "if self._is_protected(clean) and clean not in self.user_paths:",
        "if False:",
    ),
    "answer not redacted": ("return redact(text, self.policy.secrets)\n", "return text\n"),
    "audit shows secrets": (
        "safe_args = {k: redact(str(v), self.policy.secrets)",
        "safe_args = {k: str(v)",
    ),
}


def main() -> int:
    source = (ROOT / "agent_guardrails" / "guard.py").read_text()
    survived = []
    for name, (old, new) in MUTANTS.items():
        assert source.count(old) == 1, f"{name}: pattern must match exactly once"
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(ROOT / "agent_guardrails", Path(tmp, "agent_guardrails"))
            shutil.copytree(ROOT / "tests", Path(tmp, "tests"))
            Path(tmp, "agent_guardrails", "guard.py").write_text(source.replace(old, new))
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "tests"],
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        killed = result.returncode != 0
        print(f"{'killed  ' if killed else 'SURVIVED'} {name}")
        if not killed:
            survived.append(name)
    print(f"{len(MUTANTS) - len(survived)}/{len(MUTANTS)} killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
