"""Agents and the two ways of running them: with the guard, or straight at the tools.

ScriptedAgent is the worst case: it does the user's task AND everything an
attacker's injected text told it to. If the guardrails hold against an agent
that obeys every injection, they hold no matter how the model behaves.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .guard import Blocked, Guard
from .sandbox import Sandbox


class Unguarded:
    """Same interface as Guard, but calls the tools directly. The baseline."""

    def __init__(self, sandbox: Sandbox):
        self.sandbox = sandbox
        self.blocked: list = []

    def call(self, tool: str, **args):
        return getattr(self.sandbox, tool)(**args)

    def final_answer(self, text: str) -> str:
        return text


@dataclass
class Step:
    tool: str
    args: dict = field(default_factory=dict)


@dataclass
class RunResult:
    answer: str
    observations: list[str] = field(default_factory=list)  # tool results the agent saw
    refused: list[str] = field(default_factory=list)  # why each blocked call was blocked


@dataclass
class ScriptedAgent:
    """Runs fixed steps. A refused or failed step doesn't stop it: a hijacked
    agent keeps trying, so the guard must stop every attempt, not just the first."""

    steps: list[Step]
    answer: str = "Done."

    def run(self, tools: Guard | Unguarded) -> RunResult:
        result = RunResult(answer="")
        for step in self.steps:
            try:
                result.observations.append(str(tools.call(step.tool, **step.args)))
            except Blocked as blocked:
                result.refused.append(str(blocked))
            except (FileNotFoundError, KeyError) as error:
                result.observations.append(f"error: {error!r}")
        result.answer = tools.final_answer(self.answer)
        return result
