"""Demo step: perform one HIGH action (sealed within a worker tick, ADR-0026), wait until its
evidence is sealed into an epoch, then save the evidence bundle and the latest epoch root to
OUT_DIR.

The epoch root saved here comes from the gateway itself, so it is only a STAND-IN for an
external trust root. Phase 6: with anchoring configured, this step also waits until the epochs
are anchored at finality; the offline check then uses the chain with pinned trust roots.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

from agw_sdk import Client

sys.path.insert(0, str(Path(__file__).resolve().parent))
from anchor_demo import wait_anchor_final


def main() -> int:
    out = Path(sys.argv[1])
    with Client(os.environ["AGW_GATEWAY_URL"], os.environ["AGW_AGENT_TOKEN"]) as c:
        sub = c.submit_action(
            run_id=str(uuid.uuid4()),
            tool="export_customer_data",
            args={"destination": "s3://exports.corp.example/b", "limit": 3, "fields": ["id"]},
        )
        c.wait_for_terminal(sub.action_id)  # PENDING_APPROVAL (HIGH)
        events = c.events(action_id=sub.action_id, event_type="POLICY_EVALUATED")
        event_id = events[0]["event_id"]
        deadline = time.monotonic() + 30
        bundle = None
        while bundle is None and time.monotonic() < deadline:
            bundle = c.proof(event_id)
            if bundle is None:
                time.sleep(0.5)
        if bundle is None:
            print("event was not sealed within 30 s (is the worker running?)", file=sys.stderr)
            return 1
        latest = c.epoch("latest")
        if os.environ.get("AGW_ANCHOR_RPC_URL"):
            # Phase 6: wait until the event's epoch and the latest sealed epoch are anchored at
            # the configured finality, so the offline check (gateway stopped) has a final anchor.
            bundle = wait_anchor_final(lambda: c.proof(event_id), "bundle epoch")
            latest = wait_anchor_final(lambda: c.epoch("latest"), "latest epoch")
            print(
                f"anchored: epoch {latest['epoch_no']} in block "
                f"{latest['anchor']['block_number']} (status {latest['anchor']['status']})"
            )
    (out / "bundle.json").write_text(json.dumps(bundle, indent=1))
    (out / "trusted_root.txt").write_text(latest["epoch_root"])
    print(
        f"bundle for event seq {bundle['event']['seq']} in epoch {bundle['proof']['epoch_no']}; "
        f"latest epoch {latest['epoch_no']} root {latest['epoch_root'][:16]}..."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
