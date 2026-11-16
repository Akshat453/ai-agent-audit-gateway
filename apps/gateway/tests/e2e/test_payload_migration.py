"""Phase 7 data migration (ADR-0029 §7): Phase 2-6 plaintext -> envelope encryption, on an
isolated database at revision 0007 holding REAL plaintext rows (payloads, a pending approval's
request args, a queued job's dispatch args).

* 0008 refuses while plaintext remains;
* the job is resumable (interrupted after one batch, then resumed) and idempotent;
* every migrated payload is digest-checked against its header and round-tripped;
* a plaintext row that does not match its header is NOT migrated and keeps 0008 blocked;
* after 0008 the plaintext columns are gone, payloads decrypt to the original bytes, and the
  pending approval and queued job still complete from their sealed args.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text

from agw_gateway.admin import create_key, ensure_agent, ensure_tenant
from agw_gateway.api.app import build_state, create_app
from agw_gateway.db import create_db_engine
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.evidence.payloads import LegacyPlaintextPayloadStore
from agw_gateway.privacy.migrate import migrate_plaintext

from ..approvalkit import decide, make_humans
from ..conftest import (
    ALL_SCOPES,
    GATEWAY_DIR,
    Gw,
    World,
    init_database,
    make_registry,
    make_settings,
    make_spies,
    start_postgres,
)
from ..privacykit import verify_export

pytestmark = pytest.mark.e2e


def _upgrade(urls: Any, rev: str = "head") -> None:
    cfg = Config(str(GATEWAY_DIR / "alembic.ini"))
    cfg.attributes["url"] = urls.migrator
    command.upgrade(cfg, rev)


def test_reencrypt_phase2_plaintext_then_drop_it(tmp_path: Path) -> None:
    container = start_postgres()
    try:
        urls = init_database(container, revision="0007_phase7_encryption")
        # Shim: the CURRENT gateway code reads two Phase 8 columns (ADR-0030). They are added
        # early here only so this test can use today's gateway to create Phase-6-shaped rows
        # on a 0007 schema; 0009 adds them with IF NOT EXISTS.
        with psycopg.connect(urls.superuser, autocommit=True) as conn:
            conn.execute("ALTER TABLE agent_credentials ADD COLUMN audience text NULL")
            conn.execute("ALTER TABLE actions ADD COLUMN delegation_id uuid NULL")
        app = create_db_engine(urls.app, pool_size=5)
        mig = create_db_engine(urls.migrator, pool_size=2)
        tenant = "t-migrate"
        ensure_tenant(mig, tenant, "migration tenant")
        ensure_agent(mig, tenant, "demo-agent", ALL_SCOPES)
        world = World(tenant, uuid.uuid4(), create_key(mig, tenant, "demo-agent"),
                      uuid.uuid4(), "", uuid.uuid4(), "", "", "", "")  # fmt: skip
        spies = make_spies()
        # No delegation key: the Phase 8 tables do not exist on a 0007 schema.
        settings = make_settings(urls.app, tmp_path, delegation_signing_key_file=None)
        state = build_state(settings, engine=app, registry=make_registry(spies))
        state.sync()
        with TestClient(create_app(state, sync_registry=False)) as client:
            gw = Gw(state=state, client=client, spies=spies, world=world, engine=app)
            humans = make_humans(mig, client, tenant)
            # --- Phase 6-shaped operational rows: plaintext JSONB, no sealed copy
            pending = gw.post("send_email", {"to": ["x@partner.example"], "subject": "q4"}).json()
            queued = gw.post("test_echo", {"text": "queued before upgrade"}).json()
            with mig.begin() as conn:
                conn.execute(
                    text("UPDATE actions SET request_args = :a, request_args_sealed = NULL "
                         "WHERE action_id = :i"),
                    {"a": '{"to": ["x@partner.example"], "subject": "q4", "body": ""}',
                     "i": pending["action_id"]},
                )  # fmt: skip
                conn.execute(
                    text("UPDATE outbox_jobs SET args = :a, args_sealed = NULL "
                         "WHERE action_id = :i"),
                    {"a": '{"text": "queued before upgrade"}', "i": queued["action_id"]},
                )  # fmt: skip
            # --- Phase 2-shaped payload rows: plaintext evidence_payloads.content
            legacy = EvidenceWriter(LegacyPlaintextPayloadStore())
            ids = []
            with app.begin() as conn:
                for i in range(5):
                    stored = legacy.append(conn, tenant, [NewEvent(
                        type="DISCLOSURE_GRANTED", actor_kind="system", actor_id="phase2",
                        fields={"disclosure": {"grant": uuid.uuid4().bytes,
                                               "auditor": uuid.uuid4().bytes, "key": "0" * 32,
                                               "mode": "hpke", "scope": "events"}},
                        payload={"disclosure": {"purpose": f"legacy plaintext {i}"}},
                    )])  # fmt: skip
                    ids.append(stored[0].event_id)
            with app.connect() as conn:
                originals = {
                    e: bytes(conn.execute(text("SELECT content FROM evidence_payloads "
                                               "WHERE event_id = :e"), {"e": e}).scalar_one())
                    for e in ids
                }  # fmt: skip
            # an insider altered one plaintext payload after the fact
            victim = ids[2]
            with psycopg.connect(urls.superuser, autocommit=True) as su:
                su.execute("SET session_replication_role = replica")
                su.execute("UPDATE evidence_payloads SET content = %s WHERE event_id = %s",
                           (originals[victim][:-1] + b"X", victim))  # fmt: skip

            with pytest.raises(RuntimeError, match="not re-encrypted yet"):
                _upgrade(urls)  # 0008 refuses while plaintext remains

            store, cipher = state.payloads, state.cipher
            assert store is not None and cipher is not None
            first = migrate_plaintext(mig, store, cipher, batch=2, max_batches=1)  # "crash"
            assert first.payloads_encrypted == 2 and first.payloads_verified == 2
            second = migrate_plaintext(mig, store, cipher, batch=2)  # resume
            assert second.payloads_encrypted == 2  # the remaining good ones
            assert second.mismatched == [str(victim)]
            assert (second.dispatch_args_sealed, second.request_args_sealed) == (0, 0)
            assert (first.dispatch_args_sealed, first.request_args_sealed) == (1, 1)
            again = migrate_plaintext(mig, store, cipher)  # idempotent
            assert again.payloads_encrypted == 0 and again.mismatched == [str(victim)]
            with pytest.raises(RuntimeError, match="not re-encrypted yet"):
                _upgrade(urls)  # still blocked by the mismatching row
            # operator investigates and restores the original bytes (from a verified backup)
            with psycopg.connect(urls.superuser, autocommit=True) as su:
                su.execute("SET session_replication_role = replica")
                su.execute("UPDATE evidence_payloads SET content = %s WHERE event_id = %s",
                           (originals[victim], victim))  # fmt: skip
            assert migrate_plaintext(mig, store, cipher).payloads_encrypted == 1
            _upgrade(urls)  # 0008 applies: plaintext columns dropped
            with app.connect() as conn:
                cols = {
                    (r.table_name, r.column_name)
                    for r in conn.execute(text(
                        "SELECT table_name, column_name FROM information_schema.columns "
                        "WHERE table_name IN ('evidence_payloads', 'outbox_jobs', 'actions')"))
                }  # fmt: skip
                assert ("evidence_payloads", "content") not in cols
                assert ("outbox_jobs", "args") not in cols
                assert ("actions", "request_args") not in cols
                for e in ids:
                    assert store.load_payload(conn, e) == originals[e]
            # the migrated operational rows still drive real work
            decide(gw, humans, pending["approval"]["approval_id"])
            gw.drain()
            assert spies.email.calls == [uuid.UUID(pending["action_id"])]
            assert spies.echo.calls == [uuid.UUID(queued["action_id"])]
            assert verify_export(gw).result == "VERIFIED"
        app.dispose()
        mig.dispose()
    finally:
        container.stop()
