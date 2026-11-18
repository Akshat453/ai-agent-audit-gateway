"""``agw status``: configuration (key redacted) and the gateway's view of this device."""

from __future__ import annotations

import argparse
import json
import sys

from agw_cli import UNAVAILABLE, __version__
from agw_cli.client import GatewayClient, GatewayRefused, GatewayUnavailable
from agw_cli.config import ConfigError, load


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("status", help="show configuration and gateway status")
    p.set_defaults(func=main)


def main(args: argparse.Namespace) -> int:
    report: dict[str, object] = {"cli_version": __version__}
    try:
        cfg = load()
    except ConfigError as exc:
        report["config"] = {"error": str(exc)}
        print(json.dumps(report, indent=2))
        return 1
    report["config"] = cfg.redacted()
    try:
        report["gateway"] = GatewayClient(cfg).status()
    except GatewayRefused as exc:
        report["gateway"] = {"error": exc.code}
        print(json.dumps(report, indent=2))
        return 1
    except GatewayUnavailable as exc:
        report["gateway"] = {"error": f"{UNAVAILABLE} ({exc})"}
        print(json.dumps(report, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    sys.stdout.flush()
    return 0
