from __future__ import annotations

import os
import re
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

SHELL_WRAPPERS = {"bash", "sh", "zsh"}

ENV_ASSIGNMENT_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*=.*$"
)


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

def contains_unsupported_shell_construct(command: str) -> bool:
    """
    Detect shell constructs that SafeBox intentionally does not
    attempt to interpret.

    SafeBox fails closed when these constructs are present outside
    quoted strings.

    Unsupported:
        |
        &
        $(
        backticks

    Supported compound operators:
        &&
        ||
        ;
    """
    in_single_quote = False
    in_double_quote = False
    index = 0

    while index < len(command):
        char = command[index]

        if char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            index += 1
            continue

        if char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            index += 1
            continue

        if not in_single_quote and not in_double_quote:
            # Command substitution.
            if command[index : index + 2] == "$(":
                return True

            if char == "`":
                return True

            # && is supported.
            if command[index : index + 2] == "&&":
                index += 2
                continue

            # || is supported.
            if command[index : index + 2] == "||":
                index += 2
                continue

            # Single pipe/background operators are unsupported.
            if char in ("|", "&"):
                return True

        index += 1

    return False

def split_command_segments(command: str) -> list[str]:
    """
    Split a command on supported shell control operators while
    respecting quoted strings.

    Supported separators:
        &&
        ||
        ;

    This is intentionally not a complete shell parser.
    """
    segments: list[str] = []
    current: list[str] = []

    in_single_quote = False
    in_double_quote = False
    index = 0

    while index < len(command):
        char = command[index]

        if char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            current.append(char)
            index += 1
            continue

        if char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            current.append(char)
            index += 1
            continue

        if not in_single_quote and not in_double_quote:
            if command[index : index + 2] in ("&&", "||"):
                segment = "".join(current).strip()

                if segment:
                    segments.append(segment)

                current = []
                index += 2
                continue

            if char == ";":
                segment = "".join(current).strip()

                if segment:
                    segments.append(segment)

                current = []
                index += 1
                continue

        current.append(char)
        index += 1

    segment = "".join(current).strip()

    if segment:
        segments.append(segment)

    return segments

def normalize_command(command: str) -> list[str]:
    tokens = tokenize(command)

    if not tokens:
        return []

    return _normalize_tokens(tokens)


def _normalize_tokens(tokens: list[str]) -> list[str]:
    tokens = list(tokens)

    if not tokens:
        return []

    # Remove leading environment assignments:
    # AWS_PROFILE=prod terraform destroy
    while tokens and _is_env_assignment(tokens[0]):
        tokens.pop(0)

    if not tokens:
        return []

    # Normalize the executable name so paths such as
    # /usr/local/bin/terraform become terraform.
    tokens[0] = os.path.basename(tokens[0])

    # Remove sudo wrapper.
    if tokens[0] == "sudo":
        tokens = tokens[1:]

        if not tokens:
            return []

        # Support environment assignments after sudo:
        # sudo AWS_PROFILE=prod terraform destroy
        while tokens and _is_env_assignment(tokens[0]):
            tokens.pop(0)

        if not tokens:
            return []

        tokens[0] = os.path.basename(tokens[0])

    # Remove env wrapper and its variable assignments:
    # env AWS_PROFILE=prod terraform destroy
    if tokens and tokens[0] == "env":
        tokens = tokens[1:]

        while tokens and _is_env_assignment(tokens[0]):
            tokens.pop(0)

        if not tokens:
            return []

        tokens[0] = os.path.basename(tokens[0])

    # Handle shell wrappers:
    # bash -c "terraform destroy"
    # sh -c "aws ec2 terminate-instances ..."
    if (
        len(tokens) >= 3
        and tokens[0] in SHELL_WRAPPERS
        and tokens[1] == "-c"
    ):
        inner_command = tokens[2]

        # A shell invoked with -c receives an entirely new shell
        # program. SafeBox currently supports simple nested commands,
        # but fails closed when that nested program contains compound
        # or unsupported shell syntax.
        if contains_unsupported_shell_construct(inner_command):
            return ["__SAFEBOX_UNSUPPORTED_SHELL__"]

        inner_segments = split_command_segments(inner_command)

        if len(inner_segments) != 1:
            return ["__SAFEBOX_UNSUPPORTED_SHELL__"]

        inner_tokens = tokenize(inner_command)

        if not inner_tokens:
            return []

        return _normalize_tokens(inner_tokens)
    
    return tokens


def _is_env_assignment(token: str) -> bool:
    return ENV_ASSIGNMENT_RE.match(token) is not None


def decide(
    command: str,
    rules: Iterable[Rule] | None = None,
) -> Decision:
    if contains_unsupported_shell_construct(command):
        return Decision(
            allowed=False,
            reason="Unsupported shell construct requires explicit review.",
            rule="unsupported_shell",
            severity="high",
        )
    if rules is None:
        rules = load_rules()

    # Materialize once because callers may supply a generator.
    rules = tuple(rules)

    segments = split_command_segments(command)

    if not segments:
        return Decision(
            allowed=False,
            reason="Command could not be parsed safely.",
            rule="invalid_command",
            severity="critical",
        )

    for segment in segments:
        tokens = normalize_command(segment)

        if tokens == ["__SAFEBOX_UNSUPPORTED_SHELL__"]:
            return Decision(
                allowed=False,
                reason="Unsupported nested shell construct requires explicit review.",
                rule="unsupported_shell",
                severity="high",
            )        

        if not tokens:
            return Decision(
                allowed=False,
                reason="Command could not be parsed safely.",
                rule="invalid_command",
                severity="critical",
            )

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
