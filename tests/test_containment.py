"""The lab must never touch the real machine. This test reads the source and
fails if any module could run commands, open sockets, or write or delete files.

The one allowed network use is llm_agent.py's urllib call to Ollama, which is
locked to localhost (see test_llm_agent.py).
"""

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).parent.parent / "agent_guardrails"
MODULES = sorted(PACKAGE.glob("*.py"))

FORBIDDEN_IMPORTS = {
    "os", "subprocess", "socket", "shutil", "pathlib", "tempfile", "ctypes",
    "multiprocessing", "http", "ftplib", "smtplib", "telnetlib", "pty", "requests",
    "httpx", "aiohttp", "asyncio", "pickle", "marshal", "importlib",
}  # fmt: skip
NETWORK = {"urllib.request", "urllib"}  # "import urllib" could reach urllib.request
ALLOWED = {"llm_agent.py": {"urllib.request"}}  # to localhost Ollama only
FORBIDDEN_CALLS = {"open", "eval", "exec", "compile", "__import__", "input"}


def imports(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            yield node.module


@pytest.mark.parametrize("module", MODULES, ids=lambda p: p.name)
def test_no_imports_that_reach_the_real_system(module):
    tree = ast.parse(module.read_text())
    used = set(imports(tree))
    assert not {name.split(".")[0] for name in used} & FORBIDDEN_IMPORTS
    network = used & NETWORK
    assert network <= ALLOWED.get(module.name, set()), f"{module.name} imports {network}"


@pytest.mark.parametrize("module", MODULES, ids=lambda p: p.name)
def test_no_calls_that_run_code_or_open_files(module):
    tree = ast.parse(module.read_text())
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & FORBIDDEN_CALLS


def test_urllib_is_only_used_for_the_local_ollama_request():
    tree = ast.parse((PACKAGE / "llm_agent.py").read_text())
    attrs = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and getattr(node.value.value, "id", "") == "urllib"
    }
    assert attrs <= {"build_opener", "ProxyHandler", "Request"}, attrs


def test_the_check_would_catch_a_violation():
    """Guard against a containment test that can't fail."""
    bad = ast.parse("import subprocess\nfrom os import remove\nopen('x', 'w')\n")
    assert {n.split(".")[0] for n in imports(bad)} & FORBIDDEN_IMPORTS == {"subprocess", "os"}


def test_attack_targets_use_reserved_domains_only():
    """Every address in the scenarios is .example (RFC 2606): it can't exist."""
    import re

    text = (PACKAGE / "scenarios.py").read_text()
    hosts = set(re.findall(r"[\w.-]+@([\w.-]+)", text)) | set(
        re.findall(r"https?://([\w.-]+)", text)
    )
    hosts -= {
        "169.254.169.254",
        "localhost",
        "metadata.google.internal",
    }  # never reached: blocked or fake
    assert hosts and all(h.endswith((".example", "example.com")) for h in hosts), hosts
