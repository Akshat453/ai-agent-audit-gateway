"""RQ5 victim process: submits one action (or seals) and DIES (os._exit, no cleanup, no
exception handlers, no finally blocks) when it reaches the armed lifecycle point.

    python -m experiments.rq5_faults.victim '<json spec>'
Exit 137 = died at the point; 0 = the point was never reached (reported as such).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from experiments.rq5_faults.kit import ADAPTER_TIMEOUT, LEASE, logged_spies  # sets sys.path


def main() -> int:
    spec = json.loads(sys.argv[1])
    from fastapi.testclient import TestClient
    from tests.conftest import PgUrls

    from agw_gateway.api.app import create_app
    from agw_worker.sealing import Sealer
    from agw_worker.sealing.policy import SealPolicy
    from experiments.lib.stack import gateway

    point = spec["point"]
    with gateway(PgUrls(**spec["urls"]), ablation=None, tenant=(spec["tenant"], spec["token"]),
                 spies=logged_spies(Path(spec["log"])), lease_seconds=LEASE,
                 adapter_timeout_seconds=ADAPTER_TIMEOUT) as gw:  # fmt: skip

        def die(p: str) -> None:
            if p == point:
                os._exit(137)  # the process is gone: like SIGKILL at this exact step

        gw.state.crash.hit = die
        with TestClient(create_app(gw.state, sync_registry=False)) as c:
            r = c.post("/v1/actions", json={"run_id": spec["run_id"], "tool": spec["tool"],
                       "environment": "dev", "args": spec["args"]},
                       headers={"Authorization": f"Bearer {gw.token}",
                                "Idempotency-Key": spec["run_id"]})  # fmt: skip
            assert r.status_code == 201, r.text
            while gw.state.executor.run_once():
                pass
            Sealer(engine=gw.engine, writer=gw.state.writer, crash=gw.state.crash,
                   policy=SealPolicy.fixed(100, 0.0)).drain()  # fmt: skip
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
