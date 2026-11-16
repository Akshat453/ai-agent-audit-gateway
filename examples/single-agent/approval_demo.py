"""Phase 5 demo: action-bound human approval (ADR-0027).

1. The agent asks to send an email to an EXTERNAL recipient -> risk HIGH -> PENDING_APPROVAL.
2. A human approver (alice) approves it with the ``agw-approve`` CLI, which shows the exact
   tool, args, target and risk reasons and echoes the digest + nonce it displayed.
3. The agent long-polls its action -> COMPLETED (the mock email tool ran exactly once).
4. The agent asks again with an ALTERED recipient. That is a new action with a new digest and
   needs a new approval. Re-using the first approval fails every way the demo tries it
   (stale echo -> 409, consumed approval -> 409, agent key on the decision endpoint -> 403).
   alice rejects the new request -> DENIED; the email tool never ran for it.

Env: AGW_GATEWAY_URL, AGW_AGENT_TOKEN, AGW_APPROVER_TENANT/USER/PASSWORD (demo human).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import httpx

from agw_sdk import Client

EXTERNAL = "partner@example.org"
ALTERED = "attacker@evil.example"


def cli(*args: str) -> str:
    """Run the approver CLI exactly as a human would (separate process, own session)."""
    out = subprocess.run(  # noqa: S603 - fixed argv, our own module
        [sys.executable, "-m", "agw_sdk.approve_cli", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout


def human_session(url: str) -> httpx.Client:
    http = httpx.Client(base_url=url, timeout=15.0)
    r = http.post(
        "/v1/auth/login",
        json={
            "tenant": os.environ["AGW_APPROVER_TENANT"],
            "username": os.environ["AGW_APPROVER_USER"],
            "password": os.environ["AGW_APPROVER_PASSWORD"],
        },
    )
    r.raise_for_status()
    http.headers["Authorization"] = f"Session {r.json()['session_token']}"
    return http


def show_timeline(client: Client, run_id: str) -> None:
    for ev in client.timeline(run_id):
        what = ev.get("decision") or ev.get("status") or ""
        extra = ""
        if "approval" in ev:
            ap = ev["approval"]
            extra = " ".join(f"{k}={v}" for k, v in ap.items() if k != "id")
        if ev.get("code"):
            extra += f" code={ev['code']}"
        epoch = ev["epoch"]
        sealed = f"epoch {epoch['epoch_no']} {epoch['seal_reason']}" if epoch else "pending"
        print(f"    {ev['seq']:<5} {ev['type']:<20} {what:<17} {sealed:<22} {extra}")


def main() -> int:
    url = os.environ.get("AGW_GATEWAY_URL", "http://127.0.0.1:8080")
    sandbox = Path(os.environ.get("AGW_DEMO_SANDBOX_DIR", "./.sandbox"))
    failures = 0
    with Client(url, os.environ["AGW_AGENT_TOKEN"]) as agent:
        # ------------------------------------------------------------ 1. request
        run1 = str(uuid.uuid4())
        sub = agent.submit_action(
            run_id=run1,
            tool="send_email",
            args={"to": [EXTERNAL], "subject": "Q4 figures", "body": "see attached summary"},
        )
        approval_id = sub.body["approval"]["approval_id"]
        print(f"\nPhase 5 approval run {run1}")
        print(
            f"  agent: send_email to {EXTERNAL}: status={sub.status} "
            f"risk={sub.body['decision']['risk_level']} approval={approval_id}"
        )
        failures += sub.status != "PENDING_APPROVAL"

        # ------------------------------------------------------------ 2. human approves
        print("  approver (agw-approve approve --yes):")
        out = cli("approve", approval_id, "--reason", "partner expects the Q4 summary", "--yes")
        print("    " + out.strip().replace("\n", "\n    "))

        # ------------------------------------------------------------ 3. agent sees it run
        final = agent.wait_for_final(sub.action_id, timeout=30)
        print(f"  agent: long-poll -> status={final['status']} result={final['result']}")
        failures += final["status"] != "COMPLETED"
        show_timeline(agent, run1)

        # ------------------------------------------------------------ 4. altered recipient
        run2 = str(uuid.uuid4())
        sub2 = agent.submit_action(
            run_id=run2,
            tool="send_email",
            args={"to": [ALTERED], "subject": "Q4 figures", "body": "see attached summary"},
        )
        approval2 = sub2.body["approval"]["approval_id"]
        print(f"\n  agent: same email, recipient altered to {ALTERED}: status={sub2.status}")
        print(f"         -> new action, new digest, NEW approval {approval2} required")
        failures += sub2.status != "PENDING_APPROVAL"

        attempts: list[tuple[str, int, str]] = []
        human = human_session(url)
        try:
            first = human.get(f"/v1/approvals/{approval_id}").json()
            second = human.get(f"/v1/approvals/{approval2}").json()
            print(
                f"         digests differ: {first['action_digest'][:16]}.. vs "
                f"{second['action_digest'][:16]}.."
            )
            stale = human.post(
                f"/v1/approvals/{approval2}/decision",
                json={
                    "decision": "APPROVE",
                    "action_digest": first["action_digest"],
                    "nonce": first["nonce"],
                },
            )
            attempts.append(
                (
                    "approve new request echoing the FIRST approval",
                    stale.status_code,
                    stale.json()["error"]["code"],
                )
            )
            reuse = human.post(
                f"/v1/approvals/{approval_id}/decision",
                json={
                    "decision": "APPROVE",
                    "action_digest": first["action_digest"],
                    "nonce": first["nonce"],
                },
            )
            attempts.append(
                (
                    "re-use the consumed first approval",
                    reuse.status_code,
                    reuse.json()["error"]["code"],
                )
            )
        finally:
            human.post("/v1/auth/logout")
            human.close()
        agent_try = httpx.post(
            f"{url}/v1/approvals/{approval2}/decision",
            json={
                "decision": "APPROVE",
                "action_digest": second["action_digest"],
                "nonce": second["nonce"],
            },
            headers={"Authorization": f"Bearer {os.environ['AGW_AGENT_TOKEN']}"},
        )
        attempts.append(
            (
                "agent approves its own request",
                agent_try.status_code,
                agent_try.json()["error"]["code"],
            )
        )
        for label, status, code in attempts:
            print(f"    attempt: {label:<48} -> {status} {code}")
            failures += status < 400

        print("  approver (agw-approve reject --yes):")
        out = cli("reject", approval2, "--reason", "unknown external recipient", "--yes")
        print("    " + out.strip().replace("\n", "\n    "))
        final2 = agent.wait_for_final(sub2.action_id, timeout=30)
        print(f"  agent: altered request -> status={final2['status']}")
        failures += final2["status"] != "DENIED"
        show_timeline(agent, run2)

    sent = (
        [
            json.loads(line)["action_id"]
            for line in (sandbox / "send_email.jsonl").read_text().splitlines()
        ]
        if (sandbox / "send_email.jsonl").exists()
        else []
    )
    ran_first, ran_second = sent.count(sub.action_id), sent.count(sub2.action_id)
    print(
        f"  email tool invocations: approved request={ran_first} (expected 1), "
        f"altered request={ran_second} (expected 0)"
    )
    failures += ran_first != 1 or ran_second != 0
    print("PHASE 5 DEMO OK" if failures == 0 else f"PHASE 5 DEMO FAILED ({failures})")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
