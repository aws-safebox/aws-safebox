from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Iterable

from safebox.policy import Rule, decide, normalize_command


@dataclass(frozen=True)
class ExecutionResult:
    allowed: bool
    executed: bool
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    rule: str | None = None
    reason: str = ""


def execute(
    command: str,
    rules: Iterable[Rule] | None = None,
) -> ExecutionResult:
    decision = decide(command, rules=rules)

    if not decision.allowed:
        return ExecutionResult(
            allowed=False,
            executed=False,
            rule=decision.rule,
            reason=decision.reason,
        )

    tokens = normalize_command(command)

    if not tokens:
        return ExecutionResult(
            allowed=False,
            executed=False,
            rule="invalid_command",
            reason="Command could not be parsed safely.",
        )

    try:
        completed = subprocess.run(
            tokens,
            shell=False,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return ExecutionResult(
            allowed=True,
            executed=False,
            stderr=str(exc),
            reason="Command could not be executed.",
        )

    return ExecutionResult(
        allowed=True,
        executed=True,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        reason="Command allowed and executed.",
    )