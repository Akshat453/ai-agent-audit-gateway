"""Operator CLI. Runs as the migrator role (agw_app has no write access to identity tables).

    python -m agw_gateway.admin seed-demo
    python -m agw_gateway.admin create-agent-key --tenant demo --agent demo-agent
    python -m agw_gateway.admin revoke-key --key-id <16 hex>
    python -m agw_gateway.admin create-human --tenant demo --username alice --roles approver
    python -m agw_gateway.admin gen-signing-key --out secrets/approval-signing.key
    python -m agw_gateway.admin gen-delegation-key --out secrets/delegation-signing.key
    python -m agw_gateway.admin create-agent-key --tenant demo --agent w --audience URI
    python -m agw_gateway.admin create-integration-client --tenant demo --name mcp --audience URI

``create-agent-key`` prints the token exactly once on stdout; only its digest is stored.
``create-human`` reads the password from ``AGW_NEW_HUMAN_PASSWORD`` or prompts for it; it is
never a command-line argument (shell history, process list) and never printed.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import Engine, func, select, text, update
from sqlalchemy.dialects.postgresql import insert

from agw_gateway.api.app import load_blob_store, load_key_provider
from agw_gateway.approvals.signing import generate_key_file
from agw_gateway.auth.exchange import new_integration_token
from agw_gateway.auth.tokens import issue_token
from agw_gateway.config import Settings, load_settings
from agw_gateway.db import create_db_engine
from agw_gateway.db import tables as t
from agw_gateway.delegation.service import generate_delegation_key_file
from agw_gateway.evidence import EvidenceWriter
from agw_gateway.evidence.bundle import build_bundle, export_epochs
from agw_gateway.evidence.export import export_chain
from agw_gateway.evidence.payloads import EncryptedPayloadStore
from agw_gateway.humans import ROLES, hash_password
from agw_gateway.ids import uuid7
from agw_gateway.keys import KeyUnavailable, LocalKeyProvider
from agw_gateway.keys.provider import inside_git_checkout
from agw_gateway.privacy.cipher import EnvelopeCipher
from agw_gateway.privacy.migrate import migrate_plaintext
from agw_gateway.privacy.retention import LegalHold, RetentionJob
from agw_gateway.privacy.rotation import remaining, rewrap_all
from agw_gateway.tools.demo import demo_tool_specs
from agw_gateway.tools.registry import ToolRegistry

DEMO_TENANT = "demo"
DEMO_AGENTS: dict[str, tuple[str, ...]] = {
    # Has the delete and IAM scopes on purpose: the DENY must come from policy and risk, not
    # from a missing scope. It does NOT hold iam:admin, so no CRITICAL exception applies.
    "demo-agent": (
        "tools:public_doc_search",
        "tools:create_ticket",
        "tools:delete_record",
        "tools:send_email",
        "tools:export_customer_data",
        "tools:update_iam_role",
    ),
    "demo-readonly": ("tools:public_doc_search",),
    # Phase 6 demo: holds iam:admin, so update_iam_role in dev is the CRITICAL exception
    # (REQUIRE_APPROVAL by two approvers, then pre-action anchoring before dispatch).
    "demo-iam-admin": ("tools:update_iam_role", "iam:admin"),
    # Phase 8 (ADR-0030) multi-agent demo: the planner delegates "create ticket + email
    # summary" to the worker. Both hold the scopes (a delegation can only NARROW); the worker
    # acts only under the planner's token, which limits tools, risk, uses and time.
    "demo-planner": (
        "tools:public_doc_search",
        "tools:create_ticket",
        "tools:send_email_smtp",
        "tools:public_api_get",
    ),
    "demo-worker": (
        "tools:public_doc_search",
        "tools:create_ticket",
        "tools:send_email_smtp",
        "tools:public_api_get",
        "tools:delete_record",
    ),
}
DEMO_RECORDS = ("alpha record", "beta record", "gamma record")
# Demo humans (Phase 5). Created by seed-demo only when AGW_DEMO_APPROVER_PASSWORD is set.
DEMO_HUMANS: dict[str, tuple[str, ...]] = {
    "alice": ("approver",),
    "bob": ("approver",),
    "audrey": ("auditor",),
    "adam": ("admin",),  # Phase 7: grants disclosures (never to himself)
}


def ensure_tenant(engine: Engine, tenant_id: str, display_name: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            insert(t.tenants)
            .values(tenant_id=tenant_id, display_name=display_name)
            .on_conflict_do_nothing()
        )
        # Every tenant owns exactly one hash chain (ADR-0008); genesis head: seq -1, ZERO32.
        conn.execute(insert(t.chain_heads).values(tenant_id=tenant_id).on_conflict_do_nothing())
        conn.execute(insert(t.epoch_heads).values(tenant_id=tenant_id).on_conflict_do_nothing())


def ensure_agent(
    engine: Engine,
    tenant_id: str,
    name: str,
    scopes: Sequence[str],
    status: str = "active",
    trust_tier: str | None = "standard",
) -> str:
    with engine.begin() as conn:
        conn.execute(
            insert(t.agents)
            .values(
                agent_id=uuid7(),
                tenant_id=tenant_id,
                name=name,
                scopes=list(scopes),
                status=status,
                trust_tier=trust_tier,
            )
            .on_conflict_do_nothing(index_elements=["tenant_id", "name"])
        )
        agent_id = conn.execute(
            select(t.agents.c.agent_id).where(
                t.agents.c.tenant_id == tenant_id, t.agents.c.name == name
            )
        ).scalar_one()
    return str(agent_id)


def ensure_human(
    engine: Engine, tenant_id: str, username: str, password: str, roles: Sequence[str]
) -> str:
    """Create a human (or reset its password/roles). Humans are NOT agents: separate table,
    separate credential type (ADR-0027)."""
    bad = set(roles) - ROLES
    if bad or not roles:
        raise SystemExit(f"roles must be a non-empty subset of {sorted(ROLES)}")
    password_hash = hash_password(password)
    with engine.begin() as conn:
        conn.execute(
            insert(t.humans)
            .values(
                human_id=uuid7(),
                tenant_id=tenant_id,
                username=username,
                password_hash=password_hash,
                roles=list(roles),
                status="active",
            )
            .on_conflict_do_update(
                index_elements=["tenant_id", "username"],
                set_={"password_hash": password_hash, "roles": list(roles), "status": "active"},
            )
        )
        human_id = conn.execute(
            select(t.humans.c.human_id).where(
                t.humans.c.tenant_id == tenant_id, t.humans.c.username == username
            )
        ).scalar_one()
    return str(human_id)


def create_key(
    engine: Engine,
    tenant_id: str,
    agent_name: str,
    expires_in: timedelta | None = None,
    audience: str | None = None,
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
        values: dict[str, Any] = {
            "credential_id": uuid7(),
            "agent_id": agent_id,
            "key_id": issued.key_id,
            "key_digest": issued.digest,
            "expires_at": (datetime.now(UTC) + expires_in) if expires_in else None,
        }
        if audience is not None:  # Phase 8: bound to one resource (an MCP adapter)
            values["audience"] = audience
        conn.execute(insert(t.agent_credentials).values(**values))
    return issued.token


def create_integration_client(engine: Engine, tenant_id: str, name: str, audience: str) -> str:
    """Register (or re-key) a confidential integration client; prints its token once."""
    key_id, token, digest = new_integration_token()
    with engine.begin() as conn:
        conn.execute(
            insert(t.integration_clients)
            .values(
                client_id=uuid7(),
                tenant_id=tenant_id,
                name=name,
                audience=audience,
                key_id=key_id,
                key_digest=digest,
                status="active",
            )
            .on_conflict_do_update(
                index_elements=["tenant_id", "name"],
                set_={"audience": audience, "key_id": key_id, "key_digest": digest},
            )
        )
    return token


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
        with engine.begin() as conn:  # re-seeding refreshes scopes/tier of the DEMO agents only
            conn.execute(
                update(t.agents)
                .where(t.agents.c.tenant_id == DEMO_TENANT, t.agents.c.name == name)
                .values(scopes=list(scopes), trust_tier="standard")
            )
    approver_password = os.environ.get("AGW_DEMO_APPROVER_PASSWORD")
    if approver_password:
        for username, roles in DEMO_HUMANS.items():
            ensure_human(engine, DEMO_TENANT, username, approver_password, roles)
    with engine.begin() as conn:
        if conn.execute(select(func.count()).select_from(t.demo_records)).scalar_one() == 0:
            conn.execute(
                insert(t.demo_records),
                [{"record_id": uuid7(), "content": c} for c in DEMO_RECORDS],
            )


def _operator_store(settings: Settings) -> Any:
    """Operator exports decrypt payloads: they need the KEK (Phase 7)."""

    provider = load_key_provider(settings)
    if provider is None:
        raise SystemExit("KEK unavailable: use --no-payloads, or configure AGW_KEK_DIR")
    return EncryptedPayloadStore(
        provider, load_blob_store(settings), settings.payload_blob_threshold_bytes
    )


PHASE7_COMMANDS = frozenset(
    {
        "migrate-payloads",
        "rewrap-keys",
        "erase-payload",
        "set-retention",
        "legal-hold",
        "release-hold",
        "retention-sweep",
    }
)


def phase7_command(args: argparse.Namespace, settings: Settings, engine: Engine) -> int:

    if args.cmd == "set-retention":
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO retention_policies (policy_id, tenant_id, tool_id, classification,"
                    " retain_days) VALUES (:p, :t, :tool, :c, :d) ON CONFLICT (policy_id) DO "
                    "UPDATE SET tenant_id = :t, tool_id = :tool, classification = :c, "
                    "retain_days = :d"
                ),
                {"p": args.policy_id, "t": args.tenant, "tool": args.tool,
                 "c": args.classification, "d": args.days},
            )  # fmt: skip
        print(f"retention policy {args.policy_id}: {args.days} days")
        return 0
    if args.cmd == "legal-hold":
        hold = uuid7()
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO legal_holds (hold_id, tenant_id, scope, scope_id, reason, "
                    "created_by) VALUES (:h, :t, :s, :i, :r, 'admin-cli')"
                ),
                {"h": hold, "t": args.tenant, "s": args.scope, "i": args.id, "r": args.reason},
            )
        print(hold)
        return 0
    if args.cmd == "release-hold":
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE legal_holds SET released_at = now() WHERE hold_id = :h"),
                {"h": args.hold_id},
            )
        return 0
    provider = load_key_provider(settings)
    if provider is None:
        print("KEK unavailable (AGW_KEK_DIR / vault settings)", file=sys.stderr)
        return 2
    store = EncryptedPayloadStore(
        provider, load_blob_store(settings), settings.payload_blob_threshold_bytes
    )
    if args.cmd == "migrate-payloads":
        rep = migrate_plaintext(engine, store, EnvelopeCipher(provider), batch=args.batch)
        print(json.dumps(rep.__dict__ | {"remaining_blocked": rep.remaining_blocked}))
        return 0 if not rep.mismatched else 3
    if args.cmd == "rewrap-keys":
        n = rewrap_all(engine, provider)
        print(json.dumps({"rewrapped": n, "remaining": remaining(engine, provider)}))
        return 0
    job = RetentionJob(
        engine=engine,
        store=store,
        writer=EvidenceWriter(store),
        registry=ToolRegistry(demo_tool_specs()),
        blobs=store.blobs,
    )
    if args.cmd == "retention-sweep":
        print(json.dumps({"deleted": job.run_once(), "orphans_removed": job.collect_orphans()}))
        return 0
    try:
        ok = job.erase(args.tenant, UUID(args.event_id), "ERASURE_REQUEST",
                       actor_kind="system", actor_id="agw-admin")  # fmt: skip
    except LegalHold:
        print("refused: payload is under legal hold", file=sys.stderr)
        return 4
    print("erased" if ok else "nothing to erase")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agw_gateway.admin")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed-demo", help="create demo tenant, agents and demo.records rows")
    ck = sub.add_parser("create-agent-key", help="issue an API key (printed once)")
    ck.add_argument("--tenant", required=True)
    ck.add_argument("--agent", required=True)
    ck.add_argument("--expires-days", type=int, default=None)
    ck.add_argument("--audience", default=None, help="bind the key to one resource (MCP URI)")
    ic = sub.add_parser("create-integration-client", help="MCP adapter credential (printed once)")
    ic.add_argument("--tenant", required=True)
    ic.add_argument("--name", required=True)
    ic.add_argument("--audience", required=True, help="the adapter's canonical URI")
    ai = sub.add_parser("agent-id", help="print an agent's id (not a secret)")
    ai.add_argument("--tenant", required=True)
    ai.add_argument("--agent", required=True)
    gd = sub.add_parser("gen-delegation-key", help="write a dev Ed25519 delegation-signing key")
    gd.add_argument("--out", required=True)
    gd.add_argument("--if-missing", action="store_true")
    ch = sub.add_parser("create-human", help="create/reset an approver/auditor/admin (no agent)")
    ch.add_argument("--tenant", required=True)
    ch.add_argument("--username", required=True)
    ch.add_argument("--roles", required=True, help="comma-separated: approver,auditor,admin")
    gk = sub.add_parser("gen-signing-key", help="write a new dev Ed25519 decision-signing key")
    gk.add_argument("--out", required=True)
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
    ee = sub.add_parser("export-epochs", help="write epochs.jsonl for agw-verify epochs")
    ee.add_argument("--tenant", required=True)
    ee.add_argument("--out", required=True)
    eb = sub.add_parser("export-bundle", help="write an evidence bundle for one event")
    eb.add_argument("--event-id", required=True)
    eb.add_argument("--out", required=True)
    eb.add_argument("--include-payload", action="store_true", help="PLAINTEXT payload (sensitive)")
    # ---- Phase 7 (ADR-0029): keys, re-encryption, rotation, retention, erasure
    gkek = sub.add_parser("gen-kek", help="write the next local KEK version (0600, outside git)")
    gkek.add_argument("--dir", help="default: $AGW_KEK_DIR")
    gkek.add_argument("--kek-id", help="default: $AGW_KEK_ID or 'dev'")
    gkek.add_argument("--if-missing", action="store_true", help="no-op if a version exists")
    mp = sub.add_parser("migrate-payloads", help="re-encrypt Phase 2-6 plaintext (resumable)")
    mp.add_argument("--batch", type=int, default=200)
    sub.add_parser("rewrap-keys", help="re-wrap DEKs under the active KEK version")
    er = sub.add_parser("erase-payload", help="crypto-erase one payload (PAYLOAD_DELETED)")
    er.add_argument("--tenant", required=True)
    er.add_argument("--event-id", required=True)
    rp = sub.add_parser("set-retention", help="create/replace a retention policy")
    rp.add_argument("--policy-id", required=True)
    rp.add_argument("--tenant", default="*")
    rp.add_argument("--tool", default="*")
    rp.add_argument("--classification", default="*")
    rp.add_argument("--days", type=int, required=True)
    lh = sub.add_parser("legal-hold", help="place a legal hold (blocks retention/erasure)")
    lh.add_argument("--tenant", required=True)
    lh.add_argument("--scope", choices=["tenant", "run", "action", "event"], required=True)
    lh.add_argument("--id", default=None)
    lh.add_argument("--reason", required=True)
    rl = sub.add_parser("release-hold")
    rl.add_argument("--hold-id", required=True)
    sub.add_parser("retention-sweep", help="run the retention job once")
    args = parser.parse_args(argv)
    if args.cmd == "gen-kek":  # no database needed; never prints key material
        raw_dir = args.dir or os.environ.get("AGW_KEK_DIR")
        if not raw_dir:
            print("--dir or AGW_KEK_DIR is required", file=sys.stderr)
            return 2
        directory = Path(raw_dir).expanduser()
        kek_id = args.kek_id or os.environ.get("AGW_KEK_ID") or "dev"
        if inside_git_checkout(directory.resolve()):
            print("refusing: the KEK directory is inside a git checkout", file=sys.stderr)
            return 1
        if args.if_missing and directory.is_dir() and any(directory.glob(f"{kek_id}.v*.key")):
            print(f"KEK {kek_id} already present in {directory}", file=sys.stderr)
            return 0
        version = LocalKeyProvider.generate(directory, kek_id)
        try:
            LocalKeyProvider.from_dir(directory, kek_id)
        except KeyUnavailable as exc:
            print(f"refusing: {exc}", file=sys.stderr)
            return 1
        print(f"wrote KEK {kek_id} v{version} to {directory} (mode 0600)", file=sys.stderr)
        return 0
    if args.cmd == "gen-signing-key":  # no database needed
        try:
            key_id = generate_key_file(Path(args.out))
        except FileExistsError:
            print(f"{args.out} exists; refusing to overwrite", file=sys.stderr)
            return 1
        print(f"wrote approval signing key {key_id} to {args.out} (mode 0600)", file=sys.stderr)
        return 0

    if args.cmd == "gen-delegation-key":  # no database needed
        if args.if_missing and Path(args.out).exists():
            return 0
        try:
            kid = generate_delegation_key_file(Path(args.out))
        except FileExistsError:
            print(f"{args.out} exists; refusing to overwrite", file=sys.stderr)
            return 1
        print(f"wrote delegation signing key {kid} to {args.out} (mode 0600)", file=sys.stderr)
        return 0

    settings = load_settings()
    if settings.migrator_database_url is None:
        print("AGW_MIGRATOR_DATABASE_URL (missing)", file=sys.stderr)
        return 2
    engine = create_db_engine(settings.migrator_database_url.get_secret_value(), pool_size=1)
    try:
        if args.cmd == "seed-demo":
            seed_demo(engine)
            print("seeded tenant 'demo' with agents: " + ", ".join(DEMO_AGENTS))
            if os.environ.get("AGW_DEMO_APPROVER_PASSWORD"):
                print("seeded demo humans: " + ", ".join(DEMO_HUMANS))
        elif args.cmd == "create-human":
            password = os.environ.get("AGW_NEW_HUMAN_PASSWORD") or getpass.getpass("password: ")
            human_id = ensure_human(
                engine, args.tenant, args.username, password, args.roles.split(",")
            )
            print(f"human {args.tenant}/{args.username} = {human_id}")
        elif args.cmd == "create-agent-key":
            expires = timedelta(days=args.expires_days) if args.expires_days else None
            print(create_key(engine, args.tenant, args.agent, expires, args.audience))
        elif args.cmd == "agent-id":
            with engine.connect() as conn:
                print(
                    conn.execute(
                        select(t.agents.c.agent_id).where(
                            t.agents.c.tenant_id == args.tenant, t.agents.c.name == args.agent
                        )
                    ).scalar_one()
                )
        elif args.cmd == "create-integration-client":
            print(create_integration_client(engine, args.tenant, args.name, args.audience))
        elif args.cmd == "chain-head":
            with engine.connect() as conn:
                head = conn.execute(
                    select(t.chain_heads.c.last_seq, t.chain_heads.c.last_hash).where(
                        t.chain_heads.c.tenant_id == args.tenant
                    )
                ).one()
            print(f"{head.last_seq} {bytes(head.last_hash).hex()}")
        elif args.cmd == "export-epochs":
            with engine.connect() as conn, open(args.out, "w", encoding="utf-8") as fh:
                n = export_epochs(conn, args.tenant, fh)
            print(f"exported {n} epochs to {args.out}", file=sys.stderr)
        elif args.cmd == "export-bundle":
            with engine.connect() as conn:
                bundle = build_bundle(
                    conn,
                    UUID(args.event_id),
                    tenant_id=None,
                    include_payload=args.include_payload,
                    store=_operator_store(settings) if args.include_payload else None,
                )
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(bundle, fh, indent=1)
            print(
                f"wrote bundle for epoch {bundle['proof']['epoch_no']} to {args.out}",
                file=sys.stderr,
            )
        elif args.cmd == "export-chain":
            with open(args.out, "w", encoding="utf-8") as fh:
                n = export_chain(
                    engine,
                    args.tenant,
                    fh,
                    from_seq=args.from_seq,
                    to_seq=args.to_seq,
                    include_payloads=not args.no_payloads,
                    store=None if args.no_payloads else _operator_store(settings),
                )
            print(f"exported {n} events to {args.out}", file=sys.stderr)
        elif args.cmd in PHASE7_COMMANDS:
            return phase7_command(args, settings, engine)
        else:
            print("revoked" if revoke_key(engine, args.key_id) else "not found")
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
