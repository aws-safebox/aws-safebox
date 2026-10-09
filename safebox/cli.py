from __future__ import annotations

import argparse
import sys
from pathlib import Path

from safebox.executor import execute
from safebox.policy import decide, load_rules


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="safebox",
        description="Safety guardrails for AI-assisted infrastructure work.",
    )

    subparsers = parser.add_subparsers(
        dest="action",
        required=True,
    )

    check_parser = subparsers.add_parser(
        "check",
        help="Check whether a command is allowed.",
    )

    check_parser.add_argument(
        "command",
        help="Command to evaluate, enclosed in quotes.",
    )

    check_parser.add_argument(
        "--policy",
        type=Path,
        help="Path to a custom SafeBox TOML policy file.",
    )

    run_parser = subparsers.add_parser(
        "run",
        help="Check a command and execute it only if allowed.",
    )

    run_parser.add_argument(
        "command",
        help="Command to evaluate and execute, enclosed in quotes.",
    )

    run_parser.add_argument(
        "--policy",
        type=Path,
        help="Path to a custom SafeBox TOML policy file.",
    )

    args = parser.parse_args()

    rules = load_rules(args.policy) if args.policy else None

    if args.action == "check":
        result = decide(
            args.command,
            rules=rules,
        )

        if result.allowed:
            print(f"ALLOW: {result.reason}")
            return 0

        print(f"BLOCK: {result.reason}")
        return 1

    if args.action == "run":
        result = execute(
            args.command,
            rules=rules,
        )

        if not result.allowed:
            print(f"BLOCK: {result.reason}")
            return 1

        if not result.executed:
            if result.stderr:
                print(result.stderr, file=sys.stderr)

            return 126

        if result.stdout:
            print(result.stdout, end="")

        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)

        return result.returncode if result.returncode is not None else 0

    return 2


if __name__ == "__main__":
    sys.exit(main())