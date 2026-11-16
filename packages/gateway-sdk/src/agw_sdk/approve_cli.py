"""``agw-approve``: minimal approver CLI for testing and the demo (Phase 5; no dashboard yet).

    agw-approve list [--state PENDING]
    agw-approve show <approval_id>
    agw-approve approve <approval_id> --reason "..." [--yes]
    agw-approve reject  <approval_id> --reason "..." [--yes]

Identity: a HUMAN session (``Authorization: Session``), never an agent key. Credentials come
from ``AGW_APPROVER_TENANT`` / ``AGW_APPROVER_USER`` and ``AGW_APPROVER_PASSWORD`` (or a
password prompt). The session token is used for one invocation, never printed or stored, and
revoked on exit.

``approve``/``reject`` fetch the approval, SHOW the exact tool, args, target and risk reasons,
and then echo back the ``action_digest`` and ``nonce`` that were displayed: the gateway rejects
the decision if the action changed in between.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from typing import Any

import httpx


class CliError(Exception):
    pass


def _check(resp: httpx.Response) -> Any:
    if resp.status_code >= 400:
        try:
            err = resp.json().get("error", {})
        except ValueError:
            err = {}
        raise CliError(f"{resp.status_code} {err.get('code', '?')}: {err.get('message', '')}")
    return resp.json() if resp.content else None


def _login(http: httpx.Client) -> str:
    tenant = os.environ.get("AGW_APPROVER_TENANT", "demo")
    user = os.environ.get("AGW_APPROVER_USER") or input("approver username: ")
    password = os.environ.get("AGW_APPROVER_PASSWORD") or getpass.getpass("password: ")
    data = _check(
        http.post("/v1/auth/login", json={"tenant": tenant, "username": user, "password": password})
    )
    return str(data["session_token"])


def _summary(a: dict[str, Any]) -> str:
    act = a["action"]
    risk = act["risk"]
    lines = [
        f"approval  {a['approval_id']}  state={a['state']}  "
        f"approvals={len([d for d in a['decisions'] if d['decision'] == 'APPROVED'])}"
        f"/{a['required_approvals']}  expires={a['expires_at']}",
        f"agent     {act['agent']['name']} ({act['agent']['id']})",
        f"tool      {act['tool']['id']}@{act['tool']['version']}  env={act['environment']}",
        f"risk      {risk['level']} (score {risk['score']})  rules={','.join(risk['rules'])}",
        f"reasons   {', '.join(risk['reasons'])}",
        f"policy    {act['policy']['id']} v{act['policy']['version']} "
        f"-> {act['policy']['effect']} ({','.join(act['policy']['rules'])})",
        "target    " + act["target_rendered"].replace("\n", "\n          "),
        "args      " + act["args_rendered"].replace("\n", "\n          "),
        f"digest    {a['action_digest']}",
    ]
    return "\n".join(lines)


ClientFactory = Callable[..., AbstractContextManager[httpx.Client]]


def run(argv: Sequence[str] | None = None, client_factory: ClientFactory = httpx.Client) -> int:
    ap = argparse.ArgumentParser(prog="agw-approve")
    ap.add_argument("--url", default=os.environ.get("AGW_GATEWAY_URL", "http://127.0.0.1:8080"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list")
    ls.add_argument("--state", default="PENDING")
    sh = sub.add_parser("show")
    sh.add_argument("approval_id")
    for name in ("approve", "reject"):
        p = sub.add_parser(name)
        p.add_argument("approval_id")
        p.add_argument("--reason", default="")
        p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    args = ap.parse_args(argv)

    with client_factory(base_url=args.url.rstrip("/"), timeout=15.0) as http:
        token = _login(http)
        http.headers["Authorization"] = f"Session {token}"
        try:
            if args.cmd == "list":
                data = _check(http.get("/v1/approvals", params={"state": args.state}))
                for a in data["approvals"]:
                    print(
                        f"{a['approval_id']}  {a['state']:<8} {a['risk_level']:<8} "
                        f"{a['tool']['id']}@{a['tool']['version']}  expires {a['expires_at']}"
                    )
                return 0
            shown = _check(http.get(f"/v1/approvals/{args.approval_id}"))
            print(_summary(shown))
            if args.cmd == "show":
                return 0
            decision = "APPROVE" if args.cmd == "approve" else "REJECT"
            if not args.yes:
                answer = input(f"{decision} exactly this action? [y/N] ")
                if answer.strip().lower() != "y":
                    print("aborted", file=sys.stderr)
                    return 1
            result = _check(
                http.post(
                    f"/v1/approvals/{args.approval_id}/decision",
                    json={
                        "decision": decision,
                        "reason": args.reason,
                        "action_digest": shown["action_digest"],
                        "nonce": shown["nonce"],
                    },
                )
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        finally:
            http.post("/v1/auth/logout")


def main() -> None:
    try:
        raise SystemExit(run())
    except CliError as exc:
        print(f"agw-approve: {exc}", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
