"""Seed a fresh tenant for the dashboard e2e tests (Phase 9). Talks to a RUNNING gateway over
HTTP as real agents, and uses the operator (migrator) only to create identities and to move
one approval's clock into the past. Writes e2e/.fixture.json (test-only random password).

    uv run python apps/dashboard/e2e/seed.py --gateway http://127.0.0.1:28080
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from sqlalchemy import text

from agw_gateway.admin import (
    create_device_key,
    create_key,
    ensure_agent,
    ensure_human,
    ensure_tenant,
)
from agw_gateway.db import create_db_engine

HERE = Path(__file__).resolve().parent
XSS_SUBJECT = '<img src=x onerror="window.__xss=1">'
XSS_BODY = (
    '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>\n'
    + "long body line. " * 400
)
ALL = (
    "tools:public_doc_search", "tools:create_ticket", "tools:delete_record", "tools:send_email",
    "tools:export_customer_data", "tools:update_iam_role",
)  # fmt: skip


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--gateway", required=True)
    args = p.parse_args()
    gw = args.gateway.rstrip("/")
    for _ in range(120):
        try:
            if httpx.get(f"{gw}/v1/ready", timeout=2).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    mig = create_db_engine(os.environ["AGW_MIGRATOR_DATABASE_URL"], pool_size=1)
    tenant = f"e2e-{secrets.token_hex(4)}"
    password = secrets.token_urlsafe(18)
    ensure_tenant(mig, tenant, "dashboard e2e")
    humans = {
        "alice": ["approver"], "carol": ["approver"], "audrey": ["auditor"], "adam": ["admin"],
    }  # fmt: skip
    for name, roles in humans.items():
        ensure_human(mig, tenant, name, password, roles)
    ensure_agent(mig, tenant, "e2e-agent", ALL)
    ensure_agent(mig, tenant, "e2e-iam", ("tools:update_iam_role", "iam:admin"))
    worker_id = ensure_agent(mig, tenant, "e2e-worker", ALL)
    agent = create_key(mig, tenant, "e2e-agent", timedelta(hours=2))
    iam = create_key(mig, tenant, "e2e-iam", timedelta(hours=2))
    worker = create_key(mig, tenant, "e2e-worker", timedelta(hours=2))

    def act(
        token: str, tool: str, a: dict[str, object], run: str, **extra: object
    ) -> dict[str, object]:
        r = httpx.post(
            f"{gw}/v1/actions",
            json={"run_id": run, "tool": tool, "environment": "dev", "args": a, **extra},
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": str(uuid.uuid4())},
            timeout=15,
        )
        r.raise_for_status()
        return dict(r.json())

    run = str(uuid.uuid4())
    act(agent, "public_doc_search", {"query": "gateway"}, run)
    act(agent, "create_ticket", {"title": "e2e ticket", "body": "x"}, run)
    act(agent, "delete_record", {"record_id": str(uuid.uuid4())}, run)
    ext = ["partner@external.example"]
    approve = act(agent, "send_email", {"to": ext, "subject": "approve me"}, run)
    reject = act(agent, "send_email", {"to": ext, "subject": "reject me"}, run)
    expired = act(agent, "send_email", {"to": ext, "subject": "too late"}, run)
    xss = act(agent, "send_email", {"to": ext, "subject": XSS_SUBJECT, "body": XSS_BODY}, run)
    auditor_view = act(agent, "send_email", {"to": ext, "subject": "auditor looks"}, run)
    csrf_target = act(agent, "send_email", {"to": ext, "subject": "csrf target"}, run)
    keyboard = act(agent, "send_email", {"to": ext, "subject": "keyboard only"}, run)  # 9.5
    critical = act(
        iam, "update_iam_role", {"principal": "svc-e2e", "role": "editor", "grant": True}, run
    )
    # A delegation (planner = e2e-agent -> worker) so runs show a delegation tree.
    planner_run = str(uuid.uuid4())
    d = httpx.post(
        f"{gw}/v1/delegations",
        json={"child_agent_id": worker_id, "scopes": ["tools:create_ticket"],
              "tools": ["create_ticket"], "max_risk_level": "HIGH",
              "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(), "max_uses": 2,
              "purpose": "e2e",
              "run_id": planner_run},
        headers={"Authorization": f"Bearer {agent}"}, timeout=15,
    )  # fmt: skip
    child_run = str(uuid.uuid4())
    if d.status_code == 201:
        act(worker, "create_ticket", {"title": "delegated"}, child_run,
            delegation={"token": d.json()["token"]})  # fmt: skip
    with mig.begin() as conn:
        conn.execute(
            text(
                "UPDATE approvals SET requested_at = now() - interval '20 minutes', "
                "expires_at = now() - interval '1 second' WHERE approval_id = :a"
            ),
            {"a": expired["approval"]["approval_id"]},  # type: ignore[index]
        )
    # C2: a connector (admin + step-up over HTTP, like the console), a registered repository with
    # a pending loosening proposal (from an enrolled device), and a pending device-enrollment code.
    login = httpx.post(f"{gw}/v1/auth/login", json={"tenant": tenant, "username": "adam",
                                                     "password": password}, timeout=15)  # fmt: skip
    login.raise_for_status()
    admin = {"Authorization": f"Session {login.json()['session_token']}"}
    httpx.post(f"{gw}/v1/auth/step-up", json={"password": password}, headers=admin,
               timeout=15).raise_for_status()  # fmt: skip
    conn = httpx.post(
        f"{gw}/v1/connectors",
        json={"type_id": "slack", "slug": "seedslack", "name": "Seed Slack", "config": {},
              "credentials": {"webhook_url": "https://hooks.slack.com/services/T111/B111/SEEDSEEDSEED"}},
        headers=admin, timeout=15,
    )  # fmt: skip
    conn.raise_for_status()
    device = create_device_key(mig, tenant, "adam", "seedlaptop")
    repo = httpx.post(
        f"{gw}/v1/coding/repos",
        json={"remote_url": "https://github.com/acme/seed-repo.git",
              "agents": {"claude_code": {"tier": "enforced"}},
              "agentguard_yaml": "version: 1\ndeny_paths: [\"secrets/**\"]\n"
                                 "allow_commands: [\"make demo\"]\n"},
        headers={"Authorization": f"Bearer {device}"}, timeout=15,
    )  # fmt: skip
    repo.raise_for_status()
    dev = httpx.post(f"{gw}/v1/device/authorize",
                     json={"tenant": tenant, "agent_kind": "claude_code", "label": "e2e-laptop"},
                     timeout=15)  # fmt: skip
    dev.raise_for_status()
    fixture = {
        "tenant": tenant,
        "password": password,
        "approve": approve["approval"]["approval_id"],  # type: ignore[index]
        "reject": reject["approval"]["approval_id"],  # type: ignore[index]
        "expired": expired["approval"]["approval_id"],  # type: ignore[index]
        "xss": xss["approval"]["approval_id"],  # type: ignore[index]
        "auditor_view": auditor_view["approval"]["approval_id"],  # type: ignore[index]
        "csrf_target": csrf_target["approval"]["approval_id"],  # type: ignore[index]
        "critical": critical["approval"]["approval_id"],  # type: ignore[index]
        "keyboard": keyboard["approval"]["approval_id"],  # type: ignore[index]
        "keyboard_action": keyboard["action_id"],
        "run": run,
        "child_run": child_run,
        "planner_run": planner_run,
        "xss_subject": XSS_SUBJECT,
        "connector": conn.json()["connector_id"],
        "proposal": repo.json()["proposal_id"],
        "user_code": dev.json()["user_code"],
    }
    (HERE / ".fixture.json").write_text(json.dumps(fixture, indent=1))
    print(f"seeded tenant {tenant}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
