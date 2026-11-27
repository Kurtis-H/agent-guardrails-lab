"""Every scenario, run by the worst-case agent that obeys every injection."""

import pytest

from agent_guardrails.agents import ScriptedAgent, Step
from agent_guardrails.guard import Blocked, Guard
from agent_guardrails.report import run, scripted_table
from agent_guardrails.scenarios import SCENARIOS, world

ids = [s.name for s in SCENARIOS]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=ids)
def test_attack_works_without_the_guard(scenario):
    """If the attack failed with no guard, the guarded result would prove nothing."""
    assert run(scenario, guarded=False).attacked


@pytest.mark.parametrize("scenario", SCENARIOS, ids=ids)
def test_guard_blocks_the_attack(scenario):
    assert not run(scenario, guarded=True).attacked


@pytest.mark.parametrize("scenario", SCENARIOS, ids=ids)
def test_users_task_still_gets_done(scenario):
    """A guard that blocks everything is useless. The real task must still work."""
    outcome = run(scenario, guarded=True)
    assert outcome.task_done


def _attempts():
    for s in SCENARIOS:
        if s.name.startswith("hijacked agent loops"):
            continue  # each call is fine on its own; the budget stops the loop
        for i, step in enumerate(s.attack):
            gap = i in s.known_gaps
            yield pytest.param(
                s, step, gap, id=f"{s.name} #{i + 1} {step.tool}{' (gap)' if gap else ''}"
            )


@pytest.mark.parametrize(("scenario", "step", "known_gap"), list(_attempts()))
def test_every_single_attempt_is_blocked(scenario, step, known_gap):
    """Not just "the attack failed overall": each attempt on its own is refused.
    A known gap must stay allowed, so fixing it shows up here and gets documented."""
    guard = Guard(world(), scenario.make_policy(), scenario.user_request)
    ScriptedAgent(scenario.task).run(guard)  # the agent has done the real task first
    if known_gap:
        guard.call(step.tool, **step.args)
        return
    with pytest.raises(Blocked):
        guard.call(step.tool, **step.args)


def test_the_loop_is_cut_off_at_the_budget():
    scenario = next(s for s in SCENARIOS if s.name.startswith("hijacked agent loops"))
    sandbox = world()
    guard = Guard(sandbox, scenario.make_policy(), scenario.user_request)
    ScriptedAgent(scenario.task + scenario.attack).run(guard)
    assert len(sandbox.fetched) == 20
    assert guard.blocked[0].rule == "budget"


def test_a_delete_the_user_asked_for_still_needs_confirmation():
    scenario = next(s for s in SCENARIOS if s.name.startswith("user asked to delete"))
    sandbox = world()
    guard = Guard(sandbox, scenario.make_policy().__class__(), scenario.user_request)
    with pytest.raises(Blocked, match="wasn't confirmed"):
        guard.call("delete_file", path="notes/old.md")
    assert sandbox.deleted == []


def test_report_table_is_all_green():
    table, ok = scripted_table()
    assert ok, table
    assert "GOT THROUGH" not in table and "FAILS" not in table


def test_scripted_agent_keeps_going_after_a_refusal():
    guard = Guard(world(), SCENARIOS[0].make_policy(), SCENARIOS[0].user_request)
    result = ScriptedAgent([Step("read_file", {"path": ".env"}), Step("list_files")]).run(guard)
    assert len(result.refused) == 1 and len(result.observations) == 1
