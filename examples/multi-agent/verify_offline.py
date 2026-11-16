"""Phase 8 acceptance, offline half: EVERY event of the multi-agent runs (planner run, worker
run, the DELEGATION_CREATED and every child action's lifecycle) is exported as an evidence
bundle by the OPERATOR (gateway and worker already stopped), then checked by ``agw-verify``
against the pinned trust roots and the chain - nothing from the live gateway is trusted.

    python verify_offline.py OUT_DIR PINNED_TRUST_JSON
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from collections import Counter
from pathlib import Path

from sqlalchemy import select

from agw_gateway.db import create_db_engine
from agw_gateway.db import tables as t
from agw_gateway.evidence.bundle import build_bundle


def main() -> int:
    out, trust = Path(sys.argv[1]), sys.argv[2]
    bundles = out / "multi-agent-bundles"
    bundles.mkdir(exist_ok=True)
    engine = create_db_engine(os.environ["AGW_MIGRATOR_DATABASE_URL"], pool_size=1)
    runs = [json.loads(p.read_text()) for p in sorted(out.glob("multi-agent-*.json"))]
    run_ids = [uuid.UUID(r[k]) for r in runs for k in ("planner_run", "worker_run")]
    with engine.connect() as conn:
        rows = conn.execute(
            select(t.evidence_events.c.event_id, t.evidence_events.c.event_type,
                   t.evidence_events.c.seq, t.evidence_events.c.tenant_id)
            .where(t.evidence_events.c.run_id.in_(run_ids))
            .order_by(t.evidence_events.c.seq)
        ).all()  # fmt: skip
        paths = []
        for r in rows:
            p = bundles / f"{r.seq:06d}-{r.event_type}.json"
            p.write_text(json.dumps(build_bundle(conn, r.event_id, tenant_id=r.tenant_id)))
            paths.append((r, p))
    results: Counter[str] = Counter()
    failed = 0
    verify = Path(sys.executable).parent / "agw-verify"
    for r, p in paths:
        proc = subprocess.run(  # noqa: S603 - our own CLI, fixed argv
            [str(verify), "event", "--bundle", str(p), "--trust-config", trust, "--json"],
            capture_output=True, text=True, check=False,
        )  # fmt: skip
        report = json.loads(proc.stdout) if proc.stdout.strip().startswith("{") else {}
        results[f"{r.event_type}:{report.get('result')}"] += 1
        if proc.returncode != 0:
            failed += 1
            print(f"  FAIL seq {r.seq} {r.event_type}: {report.get('reason')}")
    types = Counter(r.event_type for r, _ in paths)
    print(f"  exported {len(paths)} bundles from {len(runs)} multi-agent runs: {dict(types)}")
    print(f"  agw-verify (on-chain anchors, pinned trust): {dict(sorted(results.items()))}")
    ok = failed == 0 and len(paths) > 0 and types["DELEGATION_CREATED"] == len(runs)
    print(f"MULTI-AGENT OFFLINE VERIFICATION {'OK' if ok else 'FAILED'} "
          f"({len(paths) - failed}/{len(paths)} VERIFIED)")  # fmt: skip
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
