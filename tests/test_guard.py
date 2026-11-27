"""Unit tests for each guard rule, including the tricks around it and false positives."""

import base64

import pytest

from agent_guardrails.guard import Blocked, Guard, Policy, leaks, redact
from agent_guardrails.sandbox import Sandbox
from agent_guardrails.scenarios import BOSS, SECRET, policy, world


def guard(request="", **overrides):
    return Guard(world(), policy(**overrides), request)


def blocked_rule(g, tool, **args):
    with pytest.raises(Blocked) as caught:
        g.call(tool, **args)
    return caught.value.rule


# ---------------------------------------------------------------- leak detection


@pytest.mark.parametrize(
    "text",
    [
        SECRET,
        f"key: {SECRET}.",
        SECRET.upper(),
        " ".join(SECRET),
        SECRET[::-1],
        base64.b64encode(SECRET.encode()).decode(),
        base64.urlsafe_b64encode(f"x={SECRET}".encode()).decode().rstrip("="),
        SECRET.encode().hex(),
        SECRET.replace("-", "%2D"),
        f"https://docs.example.com/?q={SECRET}",
    ],
    ids=[
        "plain",
        "in-text",
        "upper",
        "spaced",
        "reversed",
        "base64",
        "b64url-nopad",
        "hex",
        "url-encoded",
        "in-url",
    ],
)
def test_leaks_finds_disguised_secrets(text):
    assert leaks(text, [SECRET])


@pytest.mark.parametrize(
    "text",
    [
        "All good.",
        "Q3: 1,204 bookings.",
        "FAKE-canary-",
        "the key is set",
        "https://docs.example.com/guide",
    ],
)
def test_leaks_has_no_false_positives(text):
    assert not leaks(text, [SECRET])


def test_short_secrets_are_ignored_to_avoid_false_positives():
    assert not leaks("abc appears everywhere", ["abc"])


def test_redact():
    assert redact(f"key={SECRET}", [SECRET]) == "key=[REDACTED]"


# ---------------------------------------------------------------- fetch


@pytest.mark.parametrize(
    ("url", "rule"),
    [
        ("http://docs.example.com/", "fetch-scheme"),
        ("file:///etc/passwd", "fetch-scheme"),
        ("https://10.0.0.1/", "ssrf"),
        ("https://[::ffff:127.0.0.1]/", "ssrf"),
        ("https://localhost/", "ssrf"),
        ("https://api.localhost/", "ssrf"),
        ("https://metadata.google.internal/", "ssrf"),
        ("https://2130706433/", "fetch-domain"),  # 127.0.0.1 as a number
        ("https://evil.example/", "fetch-domain"),
        ("https://example.com.evil.example/", "fetch-domain"),
        ("https://evilexample.com/", "fetch-domain"),
        ("https://docs.example.com@evil.example/", "fetch-domain"),  # userinfo trick
    ],
)
def test_fetch_rules(url, rule):
    assert blocked_rule(guard(), "fetch", url=url) == rule


@pytest.mark.parametrize(
    "url", ["https://example.com/", "https://docs.example.com/guide", "https://DOCS.Example.com/x"]
)
def test_allowed_fetches(url):
    guard().call("fetch", url=url)


# ---------------------------------------------------------------- paths


@pytest.mark.parametrize(
    ("path", "rule"),
    [
        ("/etc/passwd", "path"),
        ("~/.ssh/id_rsa", "path"),
        ("..", "path"),
        ("../x", "path"),
        ("notes/../../x", "path"),
        ("notes\\..\\.env", "path"),
        ("notes/todo.md\x00.env", "path"),
        (".env", "protected-path"),
        ("./.env", "protected-path"),
        ("notes/../.env", "protected-path"),
        ("secrets/db.txt", "protected-path"),
        ("app/.ssh/key", "protected-path"),
    ],
)
def test_path_rules(path, rule):
    assert blocked_rule(guard("Read notes/todo.md"), "read_file", path=path) == rule


def test_user_can_read_a_protected_file_they_named():
    assert "API_KEY" in guard("Is the key in .env set?").call("read_file", path=".env")


# ---------------------------------------------------------------- email


def test_email_recipient_rules():
    g = guard(f"Email {BOSS} please")
    g.call("send_email", to=BOSS, subject="hi", body="hi")
    g.call("send_email", to=BOSS.upper(), subject="hi", body="hi")
    for to in [
        "s@company.example",
        "boss@company.example.evil.example",
        f"{BOSS},x@evil.example",
        "not an email",
    ]:
        assert blocked_rule(g, "send_email", to=to, subject="hi", body="hi") == "email-recipient"


def test_recipient_from_a_page_says_so():
    g = guard("Summarize https://news.example.com/ai")
    g.call("fetch", url="https://news.example.com/ai")
    with pytest.raises(Blocked, match="came from a page or file"):
        g.call("send_email", to="attacker@evil.example", subject="x", body="x")


def test_contacts_need_no_mention():
    guard("Send the usual update").call("send_email", to=BOSS, subject="update", body="ok")


def test_secret_in_subject_is_caught():
    g = guard(f"Email {BOSS}")
    assert blocked_rule(g, "send_email", to=BOSS, subject=SECRET, body="x") == "exfiltration"


# ---------------------------------------------------------------- delete


def test_delete_is_denied_by_default_even_when_asked():
    g = Guard(world(), Policy(), "Delete notes/old.md")
    assert blocked_rule(g, "delete_file", path="notes/old.md") == "needs-confirmation"


def test_delete_scope_is_exact():
    g = guard("Delete notes/old.md", confirm=lambda action: True)
    assert blocked_rule(g, "delete_file", path="old.md") == "delete-scope"
    g.call("delete_file", path="notes/old.md")


def test_confirmation_sees_the_cleaned_path():
    asked = []
    g = guard("Delete notes/old.md", confirm=lambda action: asked.append(action) or True)
    g.call("delete_file", path="notes/./old.md")
    assert asked == ["delete notes/old.md"]


# ---------------------------------------------------------------- general


def test_unknown_tools_and_bad_arguments_are_blocked():
    g = guard()
    assert blocked_rule(g, "shell", cmd="rm -rf /") == "unknown-tool"
    assert blocked_rule(g, "read_file", file="x") == "bad-arguments"


def test_audit_log_never_contains_the_secret():
    g = guard(f"Email {BOSS}")
    for body in [SECRET, f"k={SECRET}"]:
        with pytest.raises(Blocked):
            g.call("send_email", to=BOSS, subject="x", body=body)
    assert g.audit and all(SECRET not in str(d) for d in g.audit)


def test_final_answer_is_redacted_and_logged():
    g = guard()
    assert g.final_answer(f"the key is {SECRET}") == "the key is [REDACTED]"
    assert g.audit[-1].rule == "redacted"


def test_untrusted_output_is_tracked_but_trusted_is_not():
    g = Guard(Sandbox(files={"a.txt": "hello"}), Policy(), "read a.txt")
    g.call("list_files")
    g.call("read_file", path="a.txt")
    assert g.untrusted_seen == ["hello"]


def test_contacts_match_whatever_their_case():
    g = Guard(world(), policy(contacts={"Boss@Company.Example"}), "Send the usual update")
    g.call("send_email", to="boss@company.example", subject="update", body="ok")
