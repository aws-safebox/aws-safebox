from __future__ import annotations

import argparse
import sys
from pathlib import Path

from safebox.policy import decide, load_rules


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="safebox",
        description="Check a command against AWS SafeBox safety rules.",
    )

    subparsers = parser.add_subparsers(dest="action", required=True)

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

    args = parser.parse_args()

    if args.action == "check":
        rules = load_rules(args.policy) if args.policy else None
        result = decide(args.command, rules=rules)

        if result.allowed:
            print(f"ALLOW: {result.reason}")
            return 0

        print(f"BLOCK: {result.reason}")
        return 1

    return 2


if __name__ == "__main__":
    sys.exit(main())

