"""``agw`` entry point. Subcommands are modules registered here (C2 adds login, init,
doctor and uninstall the same way)."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from agw_cli import UNAVAILABLE, __version__
from agw_cli.commands import doctor, hook, init, login, session, status, uninstall

# C2 added login/logout, init, doctor and uninstall.
COMMANDS = (hook, status, session, login, init, doctor, uninstall)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agw", description="AgentGuard coding-agent CLI")
    parser.add_argument("--version", action="version", version=f"agw {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for module in COMMANDS:
        module.register(sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:
        sys.stderr.write(f"{UNAVAILABLE} (internal error: {type(exc).__name__})\n")
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
