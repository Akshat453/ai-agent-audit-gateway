"""Operator CLI. Runs as the migrator role (agw_app has no write access to identity tables).

    python -m agw_gateway.admin seed-demo
    python -m agw_gateway.admin create-agent-key --tenant demo --agent demo-agent
    python -m agw_gateway.admin revoke-key --key-id <16 hex>

``create-agent-key`` prints the token exactly once on stdout; only its digest is stored.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from sqlalchemy import Engine, func, select, update
from sqlalchemy.dialects.postgresql import insert

from agw_gateway.auth.tokens import issue_token
from agw_gateway.config import load_settings
from agw_gateway.db import create_db_engine
from agw_gateway.db import tables as t
from agw_gateway.evidence.export import export_chain
from agw_gateway.ids import uuid7

DEMO_TENANT = "demo"
DEMO_AGENTS: dict[str, tuple[str, ...]] = {
    # Has the delete scope on purpose: the DENY must come from policy, not a missing scope.
    "demo-agent": ("tools:public_doc_search", "tools:create_ticket", "tools:delete_record"),
    "demo-readonly": ("tools:public_doc_search",),
}
DEMO_RECORDS = ("alpha record", "beta record", "gamma record")


def ensure_tenant(engine: Engine, tenant_id: str, display_name: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            insert(t.tenants)
            .values(tenant_id=tenant_id, display_name=display_name)
            .on_conflict_do_nothing()
        )
        # Every tenant owns exactly one hash chain (ADR-0008); genesis head: seq -1, ZERO32.
        conn.execute(insert(t.chain_heads).values(tenant_id=tenant_id).on_conflict_do_nothing())


def ensure_agent(
    engine: Engine, tenant_id: str, name: str, scopes: Sequence[str], status: str = "active"
) -> str:
    with engine.begin() as conn:
        conn.execute(
            insert(t.agents)
            .values(
                agent_id=uuid7(), tenant_id=tenant_id, name=name, scopes=list(scopes), status=status
            )
            .on_conflict_do_nothing(index_elements=["tenant_id", "name"])
        )
        agent_id = conn.execute(
            select(t.agents.c.agent_id).where(
                t.agents.c.tenant_id == tenant_id, t.agents.c.name == name
            )
        ).scalar_one()
    return str(agent_id)


def create_key(
    engine: Engine, tenant_id: str, agent_name: str, expires_in: timedelta | None = None
) -> str:
    issued = issue_token()
    with engine.begin() as conn:
        agent_id = conn.execute(
            select(t.agents.c.agent_id).where(
                t.agents.c.tenant_id == tenant_id, t.agents.c.name == agent_name
            )
        ).scalar_one_or_none()
        if agent_id is None:
            raise SystemExit(f"unknown agent {tenant_id}/{agent_name}")
        conn.execute(
            insert(t.agent_credentials).values(
                credential_id=uuid7(),
                agent_id=agent_id,
                key_id=issued.key_id,
                key_digest=issued.digest,
                expires_at=(datetime.now(UTC) + expires_in) if expires_in else None,
            )
        )
    return issued.token


def revoke_key(engine: Engine, key_id: str) -> bool:
    with engine.begin() as conn:
        n = conn.execute(
            update(t.agent_credentials)
            .where(
                t.agent_credentials.c.key_id == key_id, t.agent_credentials.c.revoked_at.is_(None)
            )
            .values(revoked_at=func.now())
        ).rowcount
    return bool(n)


def seed_demo(engine: Engine) -> None:
    ensure_tenant(engine, DEMO_TENANT, "Demo tenant")
    for name, scopes in DEMO_AGENTS.items():
        ensure_agent(engine, DEMO_TENANT, name, scopes)
    with engine.begin() as conn:
        if conn.execute(select(func.count()).select_from(t.demo_records)).scalar_one() == 0:
            conn.execute(
                insert(t.demo_records),
                [{"record_id": uuid7(), "content": c} for c in DEMO_RECORDS],
            )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agw_gateway.admin")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed-demo", help="create demo tenant, agents and demo.records rows")
    ck = sub.add_parser("create-agent-key", help="issue an API key (printed once)")
    ck.add_argument("--tenant", required=True)
    ck.add_argument("--agent", required=True)
    ck.add_argument("--expires-days", type=int, default=None)
    rk = sub.add_parser("revoke-key")
    rk.add_argument("--key-id", required=True)
    ex = sub.add_parser(
        "export-chain", help="write export.jsonl for agw-verify (PLAINTEXT payloads)"
    )
    ex.add_argument("--tenant", required=True)
    ex.add_argument("--out", required=True)
    ex.add_argument("--from-seq", type=int, default=0)
    ex.add_argument("--to-seq", type=int, default=None)
    ex.add_argument("--no-payloads", action="store_true")
    hd = sub.add_parser("chain-head", help="print '<seq> <hash hex>' of a tenant's chain head")
    hd.add_argument("--tenant", required=True)
    args = parser.parse_args(argv)

    settings = load_settings()
    if settings.migrator_database_url is None:
        print("AGW_MIGRATOR_DATABASE_URL (missing)", file=sys.stderr)
        return 2
    engine = create_db_engine(settings.migrator_database_url.get_secret_value(), pool_size=1)
    try:
        if args.cmd == "seed-demo":
            seed_demo(engine)
            print("seeded tenant 'demo' with agents: " + ", ".join(DEMO_AGENTS))
        elif args.cmd == "create-agent-key":
            expires = timedelta(days=args.expires_days) if args.expires_days else None
            print(create_key(engine, args.tenant, args.agent, expires))
        elif args.cmd == "chain-head":
            with engine.connect() as conn:
                head = conn.execute(
                    select(t.chain_heads.c.last_seq, t.chain_heads.c.last_hash).where(
                        t.chain_heads.c.tenant_id == args.tenant
                    )
                ).one()
            print(f"{head.last_seq} {bytes(head.last_hash).hex()}")
        elif args.cmd == "export-chain":
            with open(args.out, "w", encoding="utf-8") as fh:
                n = export_chain(
                    engine,
                    args.tenant,
                    fh,
                    from_seq=args.from_seq,
                    to_seq=args.to_seq,
                    include_payloads=not args.no_payloads,
                )
            print(f"exported {n} events to {args.out}", file=sys.stderr)
        else:
            print("revoked" if revoke_key(engine, args.key_id) else "not found")
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
