from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

from safebox.executor import execute
from safebox.policy import decide, load_rules
from safebox.proxy import DEFAULT_PROXY_DIR, setup_proxies


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

    setup_parser = subparsers.add_parser(
        "setup",
        help="Create SafeBox executable proxies.",
    )

    setup_parser.add_argument(
        "--proxy-dir",
        type=Path,
        default=DEFAULT_PROXY_DIR,
        help=(
            "Directory where SafeBox proxies are created. "
            "Default: ~/.safebox/bin"
        ),
    )

    args = parser.parse_args()

    if args.action == "setup":
        result = setup_proxies(
            proxy_dir=args.proxy_dir,
        )

        print("SafeBox proxies created:")
        for proxy in result.proxies:
            print(f"  {proxy}")

        quoted_proxy_dir = shlex.quote(str(result.proxy_dir))

        print()
        print("Add the SafeBox proxy directory to the front of PATH:")
        print()
        print(f'export PATH={quoted_proxy_dir}:"$PATH"')
        print()
        print(
            "SafeBox does not modify your shell configuration automatically."
        )

        return 0

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
