from __future__ import annotations

import shlex
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    action: str
    severity: str
    command: tuple[str, ...]
    requires_any: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule: str | None = None
    severity: str | None = None


DEFAULT_POLICY_FILE = Path(__file__).with_name("policies.toml")


def load_rules(policy_file: Path = DEFAULT_POLICY_FILE) -> tuple[Rule, ...]:
    with policy_file.open("rb") as file:
        data = tomllib.load(file)

    rules = []

    for raw_rule in data.get("rules", []):
        rules.append(
            Rule(
                id=raw_rule["id"],
                description=raw_rule["description"],
                action=raw_rule["action"],
                severity=raw_rule["severity"],
                command=tuple(raw_rule["command"]),
                requires_any=tuple(raw_rule.get("requires_any", [])),
            )
        )

    return tuple(rules)


def tokenize(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return []


def decide(
    command: str,
    rules: Iterable[Rule] | None = None,
) -> Decision:
    tokens = tokenize(command)

    if not tokens:
        return Decision(
            allowed=False,
            reason="Command could not be parsed safely.",
            rule="invalid_command",
            severity="critical",
        )

    if rules is None:
        rules = load_rules()

    for rule in rules:
        if rule.action != "block":
            continue

        if _matches_command(tokens, rule):
            return Decision(
                allowed=False,
                reason=f"Blocked by policy rule: {rule.id}",
                rule=rule.id,
                severity=rule.severity,
            )

    return Decision(
        allowed=True,
        reason="No current deny rule matched.",
    )


def _matches_command(tokens: list[str], rule: Rule) -> bool:
    pattern = rule.command

    if len(tokens) < len(pattern):
        return False

    # Terraform supports options such as:
    # terraform -chdir=infra destroy
    if pattern[0] == "terraform" and tokens[0] == "terraform":
        index = 1

        while index < len(tokens) and tokens[index].startswith("-"):
            index += 1

        if tokens[index : index + len(pattern) - 1] != list(pattern[1:]):
            return False

    elif tokens[: len(pattern)] != list(pattern):
        return False

    if rule.requires_any:
        return any(option in tokens for option in rule.requires_any)

    return True
