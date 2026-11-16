"""Phase 6 demo: CRITICAL pre-action anchoring on the local chain (ADR-0009, ADR-0028).

1. demo-iam-admin asks to change an IAM role in dev -> CRITICAL (the policy's one exception):
   REQUIRE_APPROVAL by two distinct approvers (four-eyes).
2. alice and bob approve with ``agw-approve``. The action is AUTHORIZED, but its dispatch job
   WAITS: ACTION_AUTHORIZED is sealed into its own one-event epoch, anchored on-chain, and only
   when that anchor is final does the job become dispatchable.
3. The agent long-polls until COMPLETED; ACTION_DISPATCHED carries dispatch.anchor.
4. Saves the ACTION_AUTHORIZED evidence bundle once its epoch's anchor is final, for the
   offline check after the gateway and worker are stopped (fetch_bundle.py waits for the rest).

The pre-action anchor proves the authorization was publicly committed BEFORE the side effect.
It does not prove the result; ACTION_COMPLETED is anchored later like any other event.

Env: AGW_GATEWAY_URL, AGW_IAM_AGENT_TOKEN, AGW_APPROVER_* (demo humans share one password).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from agw_sdk import Client


def approve(approval_id: str, who: str) -> None:
    env = {**os.environ, "AGW_APPROVER_USER": who}
    argv = [sys.executable, "-m", "agw_sdk.approve_cli", "approve", approval_id]
    argv += ["--reason", "SOD review done", "--yes"]
    subprocess.run(argv, check=True, capture_output=True, text=True, env=env)  # noqa: S603


def wait_anchor_final(fetch: Any, what: str, timeout: float = 120.0) -> dict[str, Any]:
    """Poll a bundle / epoch view until its (untrusted, informational) anchor claim is final."""
    deadline = time.monotonic() + timeout
    while True:
        doc = fetch()
        anchor = (doc or {}).get("anchor") or {}
        if anchor.get("status") == "FINALIZED":
            return dict(doc)
        if time.monotonic() > deadline:
            raise SystemExit(f"{what}: anchor not FINALIZED within {timeout:.0f} s: {anchor}")
        time.sleep(0.5)


def main() -> int:
    out = Path(sys.argv[1])
    url = os.environ["AGW_GATEWAY_URL"]
    failures = 0
    with Client(url, os.environ["AGW_IAM_AGENT_TOKEN"]) as agent:
        run = str(uuid.uuid4())
        sub = agent.submit_action(
            run_id=run,
            tool="update_iam_role",
            args={"principal": "svc-reporting", "role": "viewer"},
        )
        ap = sub.body["approval"]
        print(f"\nPhase 6 pre-action anchoring run {run}")
        print(
            f"  agent: update_iam_role (dev): status={sub.status} "
            f"risk={sub.body['decision']['risk_level']} "
            f"approvals required={ap['required_approvals']}"
        )
        failures += sub.status != "PENDING_APPROVAL"
        for who in ("alice", "bob"):
            approve(ap["approval_id"], who)
        t0 = time.monotonic()
        status = agent.get_action(sub.action_id)["status"]
        print(f"  alice + bob approved -> status={status}: dispatch waits for the anchor")
        failures += status != "AUTHORIZED"
        final = agent.wait_for_final(sub.action_id, timeout=120)
        print(
            f"  agent: long-poll -> status={final['status']} after {time.monotonic() - t0:.1f} s "
            "(seal own epoch -> anchor -> finality -> release -> dispatch)"
        )
        failures += final["status"] != "COMPLETED"
        authorized = agent.events(action_id=sub.action_id, event_type="ACTION_AUTHORIZED")[0]
        dispatched = agent.events(action_id=sub.action_id, event_type="ACTION_DISPATCHED")[0]
        ref = dispatched["header"]["dispatch"].get("anchor") or {}
        print(
            f"  ACTION_AUTHORIZED seq {authorized['seq']} -> anchored epoch {ref.get('epoch')} "
            f"in block {ref.get('block')} ({ref.get('fin')}) BEFORE ACTION_DISPATCHED "
            f"seq {dispatched['seq']}"
        )
        failures += not ref
        bundle = wait_anchor_final(
            lambda: agent.proof(authorized["event_id"]), "ACTION_AUTHORIZED epoch"
        )
        epoch = bundle["epoch"]
        print(
            f"  its epoch {epoch['epoch_no']}: seq {epoch['first_seq']}..{epoch['last_seq']} "
            f"(tree size {epoch['tree_size']}, {epoch['seal_reason']})"
        )
        failures += epoch["tree_size"] != 1
        (out / "bundle-critical.json").write_text(json.dumps(bundle, indent=1))
    print("PHASE 6 DEMO OK" if failures == 0 else f"PHASE 6 DEMO FAILED ({failures})")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
