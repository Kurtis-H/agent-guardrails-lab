"""Run every scenario with and without the guard, and print a Markdown table.

    python -m agent_guardrails.report                        # worst-case scripted agent
    python -m agent_guardrails.report --model llama3.1:8b    # a real local model (Ollama)

The scripted run needs nothing installed. The model run needs Ollama on this
machine; the tools are still the fake sandbox.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

from .agents import ScriptedAgent, Unguarded
from .guard import Guard
from .llm_agent import LLMAgent, OllamaClient
from .scenarios import SCENARIOS, Scenario, world


@dataclass
class Outcome:
    attacked: bool
    task_done: bool
    rules: list[str]


def run(scenario: Scenario, guarded: bool, agent=None) -> Outcome:
    sandbox = world()
    tools = (
        Guard(sandbox, scenario.make_policy(), scenario.user_request)
        if guarded
        else Unguarded(sandbox)
    )
    agent = agent or ScriptedAgent(scenario.task + scenario.attack, scenario.answer)
    result = agent.run(tools)
    rules = sorted({d.rule for d in getattr(tools, "audit", []) if d.rule})
    return Outcome(scenario.attacked(sandbox, result), scenario.task_done(sandbox, result), rules)


def scripted_table() -> tuple[str, bool]:
    rows = [
        "| Scenario | OWASP LLM risk | Attack without guard | With guard "
        "| Task still done | Rules that fired |",
        "|---|---|---|---|---|---|",
    ]
    ok = True
    for s in SCENARIOS:
        bare, guarded = run(s, guarded=False), run(s, guarded=True)
        good = bare.attacked and not guarded.attacked and guarded.task_done
        ok &= good
        rows.append(
            f"| {s.name} | {s.owasp} | {'succeeds' if bare.attacked else 'FAILS (bad scenario)'} "
            f"| {'blocked' if not guarded.attacked else 'GOT THROUGH'} "
            f"| {'yes' if guarded.task_done else 'NO'} | {', '.join(guarded.rules) or '-'} |"
        )
    return "\n".join(rows), ok


def model_table(model: str, runs: int, base_url: str) -> str:
    client = OllamaClient(base_url)
    rows = [
        f"Model: `{model}`, {runs} run(s) per scenario. "
        "Attack rate = runs where the attacker got what they wanted.",
        "",
        "| Scenario | Attack rate, no guard | Attack rate, guard | Task done, guard |",
        "|---|---|---|---|",
    ]
    for s in SCENARIOS:
        counts = {"bare": 0, "guard": 0, "done": 0}
        for _ in range(runs):
            agent = LLMAgent(client, model, s.user_request)
            bare = run(s, guarded=False, agent=agent)
            guarded = run(s, guarded=True, agent=agent)
            counts["bare"] += bare.attacked
            counts["guard"] += guarded.attacked
            counts["done"] += guarded.task_done
        rows.append(
            f"| {s.name} | {counts['bare']}/{runs} | {counts['guard']}/{runs} "
            f"| {counts['done']}/{runs} |"
        )
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", help="an Ollama model name, e.g. llama3.1:8b")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--ollama", default="http://localhost:11434")
    args = parser.parse_args(argv)
    if args.model:
        print(model_table(args.model, args.runs, args.ollama))
        return 0
    table, ok = scripted_table()
    print(table)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
