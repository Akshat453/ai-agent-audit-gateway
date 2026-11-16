"""Phase 7 demo: selective disclosure to an external auditor (ADR-0029 §6).

1. The agent opens a ticket whose body is CONFIDENTIAL (stored encrypted, never in a header).
2. Its ACTION_REQUESTED and ACTION_COMPLETED events are sealed and anchored (final).
3. audrey (auditor) registers the X25519 public key she generated in HER OWN venv.
4. adam (admin) grants exactly those two events to audrey: DISCLOSURE_GRANTED evidence.
5. audrey exports: per event, header + proof + epoch chain + anchor claim + the ciphertext and
   its DEK sealed to her key (HPKE). DISCLOSURE_ACCESSED evidence. An event outside the grant
   is refused (403) and that attempt is evidence too.
6. Bundles are written to OUT/auditor/; the auditor verifies them later, offline, with only the
   bundles, her private key and the pinned trust roots (run_demo.sh).

Env: AGW_GATEWAY_URL, AGW_AGENT_TOKEN, AGW_APPROVER_TENANT, AGW_APPROVER_PASSWORD (shared demo
humans), AUDITOR_PUBLIC_KEY (hex).
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx

from agw_sdk import Client

sys.path.insert(0, str(Path(__file__).resolve().parent))
from anchor_demo import wait_anchor_final


def session(url: str, user: str) -> httpx.Client:
    http = httpx.Client(base_url=url, timeout=15.0)
    r = http.post(
        "/v1/auth/login",
        json={
            "tenant": os.environ["AGW_APPROVER_TENANT"],
            "username": user,
            "password": os.environ["AGW_APPROVER_PASSWORD"],
        },
    )
    r.raise_for_status()
    http.headers["Authorization"] = f"Session {r.json()['session_token']}"
    return http


def main() -> int:
    out = Path(sys.argv[1]) / "auditor"
    out.mkdir(parents=True, exist_ok=True)
    url = os.environ["AGW_GATEWAY_URL"]
    failures = 0
    with Client(url, os.environ["AGW_AGENT_TOKEN"]) as agent:
        sub = agent.submit_action(
            run_id=str(uuid.uuid4()),
            tool="create_ticket",
            args={
                "title": "Refund request",
                "body": "Customer Jane Roe, card ending 4242, disputes order 991",
                "priority": "high",
            },
        )
        final = agent.wait_for_final(sub.action_id, timeout=30)
        print(f"\nPhase 7 selective disclosure (action {sub.action_id}: {final['status']})")
        events = {
            e["type"]: e
            for e in agent.events(action_id=sub.action_id)
            if e["type"] in ("ACTION_REQUESTED", "ACTION_COMPLETED", "ACTION_DISPATCHED")
        }
        granted = [events["ACTION_REQUESTED"], events["ACTION_COMPLETED"]]
        header_text = json.dumps([e["header"] for e in granted])
        print(f"  confidential body in any header? {'4242' in header_text} (expected False)")
        failures += "4242" in header_text
        for e in granted:
            wait_anchor_final(lambda e=e: agent.proof(e["event_id"]), e["type"])
        print("  ACTION_REQUESTED + ACTION_COMPLETED sealed and anchored (final)")

    audrey, adam = session(url, "audrey"), session(url, "adam")
    try:
        key = audrey.post("/v1/auditor-keys", json={"public_key": os.environ["AUDITOR_PUBLIC_KEY"]})
        key.raise_for_status()
        me = audrey.get("/v1/auth/me").json()
        grant = adam.post(
            "/v1/disclosures",
            json={
                "auditor_id": me["human_id"],
                "auditor_key_id": key.json()["key_id"],
                "event_ids": [e["event_id"] for e in granted],
                "purpose": "chargeback investigation #991",
                "expires_in_seconds": 3600,
            },
        )
        grant.raise_for_status()
        gid = grant.json()["grant_id"]
        print(f"  adam granted 2 events to audrey (grant {gid}, key {key.json()['key_id'][:12]}..)")
        exp = audrey.post(f"/v1/disclosures/{gid}/export")
        exp.raise_for_status()
        doc: dict[str, Any] = exp.json()
        for i, b in enumerate(doc["bundles"]):
            (out / f"bundle-{i}.json").write_text(json.dumps(b, indent=1))
        print(
            f"  audrey exported {len(doc['bundles'])} bundles (mode {doc['delivery']}): "
            "ciphertext + DEK sealed to her key, no plaintext"
        )
        failures += any("payload" in b["disclosure"] for b in doc["bundles"])
        other = events["ACTION_DISPATCHED"]["event_id"]
        denied = audrey.post(f"/v1/disclosures/{gid}/export", json={"event_ids": [other]})
        print(
            f"  attempt: export an event outside the grant -> {denied.status_code} "
            f"{denied.json()['error']['code']}"
        )
        failures += denied.status_code != 403
    finally:
        for h in (audrey, adam):
            h.post("/v1/auth/logout")
            h.close()
    with Client(url, os.environ["AGW_AGENT_TOKEN"]) as agent:
        seen = agent.events(event_type="DISCLOSURE_ACCESSED")
    # Agents only see their own events: disclosure activity is invisible to them by design.
    print(f"  the agent sees {len(seen)} disclosure events (expected 0: not its business)")
    failures += len(seen) != 0
    print("PHASE 7 DISCLOSURE OK" if failures == 0 else f"PHASE 7 DISCLOSURE FAILED ({failures})")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
