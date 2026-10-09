from __future__ import annotations

import argparse
import sys

from safebox.policy import decide


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

    args = parser.parse_args()

    if args.action == "check":
        result = decide(args.command)

        if result.allowed:
            print(f"ALLOW: {result.reason}")
            return 0

        print(f"BLOCK: {result.reason}")
        return 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
