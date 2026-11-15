"""Phase 2 local micro-benchmark (LOCAL, UNVALIDATED - not a performance claim).

Measures, against the compose Postgres (AGW_DATABASE_URL / AGW_MIGRATOR_DATABASE_URL):

1. CPU: building + validating + canonically encoding + hashing one header and one payload
   (the work Phase 2 adds per event), P50/P95 in microseconds.
2. DB: one EvidenceWriter.append of a single event with payload, in its own transaction
   (chain-head lock + inserts + head update + commit), P50/P95 in milliseconds, versus a
   baseline transaction that inserts the same JSONB row shape without CBOR, hashing, payload
   or chain head (approximates the Phase 1 write path).
3. Contention: events/s with 8 threads writing to ONE tenant (single writer per tenant) vs
   8 threads writing to 8 tenants.

    uv run python experiments/benchmarks/phase2_event_latency.py [--n 2000]
"""

from __future__ import annotations

import argparse
import os
import statistics
import threading
import time
import uuid

from sqlalchemy import text

from agw_gateway.admin import ensure_tenant
from agw_gateway.crypto.canonical import encode, event_hash, payload_digest
from agw_gateway.db import create_db_engine
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.ids import uuid7
from agw_schemas.events import HEADER_MODELS, Payload


def pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def sample_event() -> NewEvent:
    return NewEvent(
        type="ACTION_DISPATCHED",
        actor_kind="gateway",
        actor_id="agw-gateway",
        action_id=uuid7(),
        run_id=uuid7(),
        fields={
            "tool": {"id": "create_ticket", "ver": "1.0.0"},
            "dispatch": {"attempt": 1, "worker": "bench", "cg": "bench/1"},
            "args": bytes(32),
            "obs": time.time_ns() // 1000,
        },
        payload={
            "execution": {"params": {"title": "t" * 40, "body": "b" * 200, "priority": "low"}}
        },
    )


def cpu_bench(n: int) -> list[float]:
    times = []
    for _ in range(n):
        ev = sample_event()
        t0 = time.perf_counter_ns()
        pl = encode(
            Payload(salt=os.urandom(32), event=uuid7().bytes, **dict(ev.payload or {})).to_record()
        )
        header = {
            "tenant": "bench",
            "seq": 1,
            "prev": bytes(32),
            "id": uuid7().bytes,
            "type": ev.type,
            "ts": 1,
            "class": "A2S",
            "actor": {"kind": "gateway", "id": "agw-gateway"},
            "action": uuid7().bytes,
            **dict(ev.fields),
            "payload": {"digest": payload_digest(pl), "len": len(pl), "ref": "inline"},
        }
        event_hash(encode(HEADER_MODELS[ev.type].model_validate(header).to_record()))
        times.append((time.perf_counter_ns() - t0) / 1000)
    return times


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    args = ap.parse_args()
    app = create_db_engine(os.environ["AGW_DATABASE_URL"], pool_size=12)
    mig = create_db_engine(os.environ["AGW_MIGRATOR_DATABASE_URL"], pool_size=2)
    run = uuid.uuid4().hex[:8]
    tenants = [f"bench-{run}-{i}" for i in range(9)]
    for tnt in tenants:
        ensure_tenant(mig, tnt, "benchmark")
    with mig.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS bench_baseline (id uuid PRIMARY KEY, tenant_id text, body jsonb)"
            )
        )
        conn.execute(text("GRANT INSERT ON bench_baseline TO agw_app"))
    writer = EvidenceWriter()

    cpu = cpu_bench(args.n)
    print(
        f"[local, unvalidated] CPU canonicalize+hash per event: P50 {statistics.median(cpu):.1f} us, P95 {pct(cpu, 95):.1f} us (n={args.n})"
    )

    def timed_append(tnt: str) -> float:
        t0 = time.perf_counter()
        with app.begin() as conn:
            writer.append(conn, tnt, [sample_event()])
        return (time.perf_counter() - t0) * 1000

    def timed_baseline(tnt: str) -> float:
        t0 = time.perf_counter()
        with app.begin() as conn:
            conn.execute(
                text("INSERT INTO bench_baseline VALUES (:i, :t, CAST(:b AS jsonb))"),
                {
                    "i": uuid.uuid4(),
                    "t": tnt,
                    "b": '{"type":"ACTION_DISPATCHED","tool":{"id":"create_ticket"}}',
                },
            )
        return (time.perf_counter() - t0) * 1000

    for _ in range(50):  # warm-up
        timed_append(tenants[0])
        timed_baseline(tenants[0])
    p2 = [timed_append(tenants[0]) for _ in range(args.n)]
    base = [timed_baseline(tenants[0]) for _ in range(args.n)]
    print(
        f"[local, unvalidated] Phase 2 append tx: P50 {statistics.median(p2):.2f} ms, P95 {pct(p2, 95):.2f} ms"
    )
    print(
        f"[local, unvalidated] baseline JSONB tx: P50 {statistics.median(base):.2f} ms, P95 {pct(base, 95):.2f} ms"
    )
    print(
        f"[local, unvalidated] added per event:   P50 {statistics.median(p2) - statistics.median(base):+.2f} ms, P95 {pct(p2, 95) - pct(base, 95):+.2f} ms"
    )

    def throughput(targets: list[str], per_thread: int) -> float:
        def work(tnt: str) -> None:
            for _ in range(per_thread):
                with app.begin() as conn:
                    writer.append(conn, tnt, [sample_event()])

        threads = [threading.Thread(target=work, args=(tnt,)) for tnt in targets]
        t0 = time.perf_counter()
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        return len(targets) * per_thread / (time.perf_counter() - t0)

    per = max(50, args.n // 8)
    one = throughput([tenants[1]] * 8, per)
    many = throughput(tenants[1:9], per)
    print(
        f"[local, unvalidated] 8 threads -> 1 tenant:  {one:,.0f} events/s (single writer per tenant)"
    )
    print(f"[local, unvalidated] 8 threads -> 8 tenants: {many:,.0f} events/s")
    with mig.begin() as conn:
        conn.execute(text("DROP TABLE bench_baseline"))


if __name__ == "__main__":
    main()
