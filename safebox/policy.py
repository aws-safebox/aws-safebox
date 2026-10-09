from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule: str | None = None


DEFAULT_DENIED_PATTERNS = (
    ("terraform_destroy", ("terraform", "destroy")),
    ("kubectl_delete", ("kubectl", "delete")),
    ("aws_ec2_terminate", ("aws", "ec2", "terminate-instances")),
    ("aws_rds_delete", ("aws", "rds", "delete-db-instance")),
    ("aws_s3_recursive_delete", ("aws", "s3", "rm")),
    (
        "aws_cloudformation_delete_stack",
        ("aws", "cloudformation", "delete-stack"),
    ),
)


def tokenize(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return []


def decide(
    command: str,
    denied_patterns: Iterable[tuple[str, tuple[str, ...]]] = DEFAULT_DENIED_PATTERNS,
) -> Decision:
    tokens = tokenize(command)

    if not tokens:
        return Decision(
            allowed=False,
            reason="Command could not be parsed safely.",
            rule="invalid_command",
        )

    for rule_name, pattern in denied_patterns:
        if _matches_command(tokens, pattern):
            return Decision(
                allowed=False,
                reason=f"Blocked by policy rule: {rule_name}",
                rule=rule_name,
            )

    return Decision(
        allowed=True,
        reason="No current deny rule matched.",
    )


def _matches_command(tokens: list[str], pattern: tuple[str, ...]) -> bool:
    if len(tokens) < len(pattern):
        return False

    if tokens[: len(pattern)] == list(pattern):
        # Special case for S3 recursive deletion:
        # "aws s3 rm" is not inherently destructive enough to block
        # every invocation. Require --recursive somewhere in the command.
        if pattern == ("aws", "s3", "rm"):
            return "--recursive" in tokens or "-r" in tokens

        return True

    # Terraform supports options such as:
    # terraform -chdir=infra destroy
    if pattern[0] == "terraform" and tokens[0] == "terraform":
        index = 1

        while index < len(tokens) and tokens[index].startswith("-"):
            index += 1

        return tokens[index : index + len(pattern) - 1] == list(pattern[1:])
    
    return False