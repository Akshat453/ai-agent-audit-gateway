"""Phase 3 demo step: perform one action, wait until its evidence is sealed into an epoch,
then save the evidence bundle and the latest epoch root to OUT_DIR.

The epoch root saved here comes from the gateway itself, so it is only a STAND-IN for an
external trust root (Phase 6 replaces it with an on-chain anchor).
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

from agw_sdk import Client


def main() -> int:
    out = Path(sys.argv[1])
    with Client(os.environ["AGW_GATEWAY_URL"], os.environ["AGW_AGENT_TOKEN"]) as c:
        sub = c.submit_action(
            run_id=str(uuid.uuid4()), tool="public_doc_search", args={"query": "ticket"}
        )
        c.wait_for_terminal(sub.action_id)
        events = c.events(action_id=sub.action_id, event_type="ACTION_COMPLETED")
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
    (out / "bundle.json").write_text(json.dumps(bundle, indent=1))
    (out / "trusted_root.txt").write_text(latest["epoch_root"])
    print(
        f"bundle for event seq {bundle['event']['seq']} in epoch {bundle['proof']['epoch_no']}; "
        f"latest epoch {latest['epoch_no']} root {latest['epoch_root'][:16]}..."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
