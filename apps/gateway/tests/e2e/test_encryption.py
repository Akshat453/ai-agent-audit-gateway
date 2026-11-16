"""Phase 7: payload encryption at rest, key management, minimization, retention (ADR-0029).

Required tests (prompt) -> test:
  ciphertext swap between two events -> decryption fails ... test_ciphertext_swap_between_events_fails
  DB-only attacker cannot read payloads ..................... test_db_only_attacker_cannot_read_payloads
  rotation preserves decryptability and verification ........ test_kek_rotation_preserves_*
  deleted payload -> INCOMPLETE, not TAMPERED ................ test_retention_deletes_*
(grant/expiry tests: test_disclosure.py; canary leak test: test_telemetry_canary.py)
"""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, select, text

from agw_gateway.db import tables as t
from agw_gateway.evidence.blobs import S3BlobStore
from agw_gateway.evidence.payloads import PayloadUnavailable, dek_context
from agw_gateway.keys import (
    KeyUnavailable,
    LocalKeyProvider,
    UnwrapFailed,
    VaultTransitKeyProvider,
    WrappedKey,
)
from agw_gateway.privacy.rotation import remaining, rewrap_all

from ..conftest import SECRET_RECEIVED, Gw, PgUrls, ServiceUrl, World
from ..privacykit import (
    canary,
    dump_database,
    event_id,
    export_lines,
    gateway,
    header,
    headers_blob,
    payload,
    su,
    verify_export,
)

pytestmark = pytest.mark.e2e


def echo(gw: Any, text_: str = "hello") -> str:
    aid = str(gw.post("test_echo", {"text": text_}).json()["action_id"])
    gw.drain()
    return aid


# ============================================================================ at rest
def test_payloads_at_rest_are_ciphertext_and_digest_commits_to_plaintext(gw: Gw) -> None:
    secret_note = canary("conf")
    aid = gw.post("send_email", {"to": ["a@corp.example"], "subject": secret_note}).json()[
        "action_id"
    ]
    eid = event_id(gw, aid, "ACTION_REQUESTED")
    with gw.engine.connect() as conn:
        obj = conn.execute(
            select(t.payload_objects).where(t.payload_objects.c.event_id == eid)
        ).one()
        key = conn.execute(select(t.payload_keys).where(t.payload_keys.c.event_id == eid)).one()
        plaintext = gw.state.payloads.load_payload(conn, eid)
    assert obj.alg == "A256GCM" and obj.storage == "inline" and len(bytes(obj.nonce)) == 12
    assert secret_note.encode() not in bytes(obj.ciphertext)
    assert obj.ct_sha256 == hashlib.sha256(bytes(obj.ciphertext)).digest()
    assert (key.kek_id, key.kek_version) == ("test", 1) and len(bytes(key.wrapped_dek)) == 48
    h = header(gw, eid)
    from agw_gateway.crypto.canonical import payload_digest

    assert h["payload"]["digest"] == payload_digest(plaintext) and h["payload"]["ref"] == "inline"
    assert secret_note in str(payload(gw, eid))
    assert verify_export(gw).result == "VERIFIED"


def test_ciphertext_swap_between_events_fails(gw: Gw, pg: PgUrls) -> None:
    a, b = echo(gw, "alpha"), echo(gw, "bravo")
    ea, eb = event_id(gw, a, "ACTION_REQUESTED"), event_id(gw, b, "ACTION_REQUESTED")
    swap = (
        "UPDATE payload_objects p SET ciphertext = q.ciphertext, nonce = q.nonce, "
        "ct_len = q.ct_len, ct_sha256 = q.ct_sha256 FROM payload_objects q "
        "WHERE (p.event_id = %s AND q.event_id = %s) OR (p.event_id = %s AND q.event_id = %s)"
    )
    # 1) swap only the ciphertexts (each keeps its own DEK): wrong key and wrong AAD
    su(pg, swap, (ea, eb, eb, ea))
    for e in (ea, eb):
        with pytest.raises(PayloadUnavailable) as exc, gw.engine.connect() as conn:
            gw.state.payloads.load_payload(conn, e)
        assert exc.value.code == "DECRYPT_FAILED"
    # 2) also swap the wrapped DEKs: the wrap is bound to tenant + event id
    su(
        pg,
        "UPDATE payload_keys p SET wrapped_dek = q.wrapped_dek, wrap_nonce = q.wrap_nonce "
        "FROM payload_keys q WHERE (p.event_id = %s AND q.event_id = %s) "
        "OR (p.event_id = %s AND q.event_id = %s)",
        (ea, eb, eb, ea),
    )
    with pytest.raises(PayloadUnavailable) as exc, gw.engine.connect() as conn:
        gw.state.payloads.load_payload(conn, ea)
    assert exc.value.code == "DECRYPT_FAILED"
    # 3) an insider WITH the KEK re-wraps B's DEK for A: the AES-GCM AAD (event A's id, seq
    #    and committed digest) still rejects B's ciphertext under A
    provider = gw.state.key_provider
    with gw.engine.connect() as conn:
        kb = conn.execute(select(t.payload_keys).where(t.payload_keys.c.event_id == ea)).one()
    dek_b = provider.unwrap(
        WrappedKey(kb.kek_id, kb.kek_version, bytes(kb.wrap_nonce), bytes(kb.wrapped_dek)),
        dek_context(gw.world.tenant_id, eb),
    )
    rew = provider.wrap(dek_b, dek_context(gw.world.tenant_id, ea))
    su(
        pg,
        "UPDATE payload_keys SET wrapped_dek = %s, wrap_nonce = %s WHERE event_id = %s",
        (rew.ciphertext, rew.nonce, ea),
    )
    with pytest.raises(PayloadUnavailable) as exc, gw.engine.connect() as conn:
        gw.state.payloads.load_payload(conn, ea)
    assert exc.value.code == "DECRYPT_FAILED"
    report = verify_export(gw)
    assert report.result == "TAMPERED"
    assert report.reason == "PAYLOAD_DECRYPT_FAILED"


def test_db_only_attacker_cannot_read_payloads(gw: Gw, pg: PgUrls, tmp_path: Path) -> None:
    conf, sec = canary("conf"), canary("secret")
    # completed actions, a pending approval (sealed request) and a queued job (sealed args)
    gw.post("test_secret_tool", {"endpoint": "https://api.example", "api_token": sec, "note": conf})
    gw.drain()
    pend = gw.post("send_email", {"to": ["x@partner.example"], "subject": conf, "body": conf})
    assert pend.json()["status"] == "PENDING_APPROVAL"
    queued = gw.post("test_secret_tool", {"endpoint": "e", "api_token": sec, "note": conf})
    assert queued.status_code == 201  # not drained: its args sit sealed in the outbox
    dump = dump_database(pg)
    assert len(dump) > 10_000
    for value in (conf, sec):
        assert value.encode() not in dump
    # Without the KEK the wrapped DEKs are useless: another KEK does not unwrap them.
    LocalKeyProvider.generate(tmp_path, "test")
    stranger = LocalKeyProvider.from_dir(tmp_path, "test")
    eid = event_id(gw, pend.json()["action_id"], "ACTION_REQUESTED")
    with gw.engine.connect() as conn:
        k = conn.execute(select(t.payload_keys).where(t.payload_keys.c.event_id == eid)).one()
    with pytest.raises(UnwrapFailed):
        stranger.unwrap(
            WrappedKey(k.kek_id, k.kek_version, bytes(k.wrap_nonce), bytes(k.wrapped_dek)),
            dek_context(gw.world.tenant_id, eid),
        )
    gw.drain()


def test_no_kek_fails_closed(pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path) -> None:
    with gateway(pg, app_engine, world, tmp_path, kek_dir=tmp_path / "missing") as g:
        assert g.state.key_provider is None
        before = g.count_events("ACTION_REQUESTED")
        r = g.post("test_echo", {"text": "x"})
        assert (r.status_code, r.json()["error"]["code"]) == (503, "KEY_UNAVAILABLE")
        assert g.count_events("ACTION_REQUESTED") == before  # nothing written
        assert g.client.get("/v1/ready").status_code == 503
        assert g.spies.echo.calls == []
        # The store itself refuses too (other writers: approval decisions, gate failures):
        from agw_gateway.evidence import EvidenceWriter, NewEvent

        with pytest.raises(KeyUnavailable), g.engine.begin() as conn:
            EvidenceWriter().append(conn, world.tenant_id, [NewEvent(
                type="DISCLOSURE_GRANTED", actor_kind="system", actor_id="t",
                fields={"disclosure": {"grant": bytes(16), "auditor": bytes(16), "key": "0" * 32,
                                       "mode": "hpke", "scope": "events"}},
                payload={"disclosure": {"purpose": "x"}},
            )])  # fmt: skip
        assert g.count_events("DISCLOSURE_GRANTED") == 0


# ============================================================================ rotation
def test_kek_rotation_preserves_decryptability_and_verification(
    pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path
) -> None:
    ring = tmp_path / "ring"
    LocalKeyProvider.generate(ring, "rot")
    v1 = LocalKeyProvider.from_dir(ring, "rot")
    with gateway(pg, app_engine, world, tmp_path, key_provider=v1, kek_id="rot") as g:
        old = [echo(g, f"before-{i}") for i in range(3)]
        tok = canary("tok")
        s1 = g.post("test_secret_tool", {"endpoint": "e", "api_token": tok}).json()["action_id"]
        g.drain()
        p1 = payload(g, event_id(g, s1, "ACTION_REQUESTED"))
        assert p1 is not None
        marker_v1 = p1["intent"]["args"]["api_token"]  # salt wrapped under v1
        lines_before = export_lines(g)
    assert LocalKeyProvider.generate(ring, "rot") == 2
    v2 = LocalKeyProvider.from_dir(ring, "rot")
    with gateway(pg, app_engine, world, tmp_path, key_provider=v2, kek_id="rot") as g:
        new = echo(g, "after")
        e_new = event_id(g, new, "ACTION_REQUESTED")
        with g.engine.connect() as conn:
            versions = set(
                conn.execute(
                    select(t.payload_keys.c.kek_version).where(
                        t.payload_keys.c.tenant_id == world.tenant_id
                    )
                ).scalars()
            )
            assert versions == {1, 2}  # old DEKs still under v1, new ones under v2
            assert (
                conn.execute(
                    select(t.payload_keys.c.kek_version).where(t.payload_keys.c.event_id == e_new)
                ).scalar_one()
                == 2
            )
        assert payload(g, event_id(g, old[0], "ACTION_REQUESTED")) is not None  # lazy: v1 ok
        assert remaining(g.engine, v2, tenant=world.tenant_id) > 0
        n = rewrap_all(g.engine, v2, tenant=world.tenant_id)
        assert n > 0 and remaining(g.engine, v2, tenant=world.tenant_id) == 0
    (ring / "rot.v1.key").unlink()  # destroy the old KEK version
    v2_only = LocalKeyProvider.from_dir(ring, "rot")
    with gateway(pg, app_engine, world, tmp_path, key_provider=v2_only, kek_id="rot") as g:
        for aid in [*old, new]:
            p = payload(g, event_id(g, aid, "ACTION_COMPLETED"))
            assert p is not None and p["effects"]["result"]["echo"]
        lines_after = export_lines(g)
        assert verify_export(g).result == "VERIFIED"
        # the per-tenant redaction salt was re-wrapped too: same secret, same marker
        s2 = g.post("test_secret_tool", {"endpoint": "e", "api_token": tok}).json()["action_id"]
        g.drain()
        p2 = payload(g, event_id(g, s2, "ACTION_REQUESTED"))
        assert p2 is not None and p2["intent"]["args"]["api_token"] == marker_v1
    # the evidence bytes (headers, hashes) and the plaintext payloads did not change at all
    assert lines_after[1 : len(lines_before)] == lines_before[1:]


# ============================================================================ minimization
def test_secret_fields_are_never_stored(gw: Gw) -> None:
    token, note = canary("tok"), canary("note")
    SECRET_RECEIVED.clear()
    r = gw.post("test_secret_tool", {"endpoint": "https://api.example", "api_token": token,
                                     "note": note})  # fmt: skip
    aid = r.json()["action_id"]
    gw.drain()
    assert [token] == SECRET_RECEIVED  # the tool itself got the real credential
    req = payload(gw, event_id(gw, aid, "ACTION_REQUESTED"))
    disp = payload(gw, event_id(gw, aid, "ACTION_DISPATCHED"))
    done = payload(gw, event_id(gw, aid, "ACTION_COMPLETED"))
    assert req and disp and done
    marker = req["intent"]["args"]["api_token"]
    assert marker.startswith("[REDACTED:sha256:") and token not in marker
    assert disp["execution"]["params"]["api_token"] == marker
    assert req["intent"]["args"]["note"] == note  # confidential: kept, but encrypted
    assert done["effects"]["result"]["session_token"].startswith("[REDACTED:sha256:")
    assert done["effects"]["result"]["detail"].endswith(note)
    view = gw.client.get(f"/v1/actions/{aid}", headers=gw.headers()).json()
    assert view["result"] == {"status": "ok"}  # only public/internal results in plaintext
    # same secret, same tenant -> same marker (correlation without disclosure)
    r2 = gw.post("test_secret_tool", {"endpoint": "e", "api_token": token}).json()["action_id"]
    gw.drain()
    p2 = payload(gw, event_id(gw, r2, "ACTION_REQUESTED"))
    assert p2 and p2["intent"]["args"]["api_token"] == marker
    with gw.engine.connect() as conn:
        assert (
            conn.execute(
                select(t.outbox_jobs.c.args_sealed).where(
                    t.outbox_jobs.c.action_id == uuid.UUID(aid)
                )
            ).scalar_one()
            is None
        )


def test_headers_carry_no_field_values(gw: Gw, migrator_engine: Engine) -> None:
    """Header lint: canaries in every arg of every tool, through allow / approval / deny /
    invalid / unknown-tool paths; no stored header (canonical bytes or JSONB) contains one."""
    from ..approvalkit import decide, make_humans

    c: dict[str, str] = {k: canary(k) for k in (
        "query", "title", "body", "to", "subject", "ebody", "dest", "principal", "endpoint",
        "token", "note", "doc", "invalid", "unknown", "summary",
    )}  # fmt: skip
    humans = make_humans(migrator_engine, gw.client, gw.world.tenant_id)
    gw.post("public_doc_search", {"query": c["query"]}, intent={"summary": c["summary"]})
    gw.post("create_ticket", {"title": c["title"], "body": c["body"]})
    em = gw.post("send_email", {"to": [c["to"] + "@ext.example"], "subject": c["subject"],
                                "body": c["ebody"]}).json()  # fmt: skip
    decide(gw, humans, em["approval"]["approval_id"])
    gw.post("export_customer_data", {"destination": "s3://" + c["dest"], "limit": 5,
                                     "fields": ["id"]})  # fmt: skip
    gw.post("update_iam_role", {"principal": c["principal"].lower(), "role": "viewer"})
    gw.post("test_secret_tool", {"endpoint": c["endpoint"], "api_token": c["token"],
                                 "note": c["note"]})  # fmt: skip
    gw.post("test_bigdoc", {"text": c["doc"]})
    gw.post("public_doc_search", {"query": c["invalid"], "limit": "nope"})
    gw.post("no_such_tool", {"x": c["unknown"]})
    gw.post("delete_record", {"record_id": str(uuid.uuid4())})
    gw.drain()
    blob = headers_blob(gw)
    assert gw.count_events("ACTION_COMPLETED") >= 5
    leaked = [k for k, v in c.items() if v.encode() in blob or v.lower().encode() in blob]
    assert leaked == []


def test_sealed_args_swapped_between_jobs_never_dispatch(gw: Gw, pg: PgUrls) -> None:
    a = gw.post("test_echo", {"text": "a"}).json()["action_id"]
    b = gw.post("test_echo", {"text": "b"}).json()["action_id"]
    su(
        pg,
        "UPDATE outbox_jobs p SET args_sealed = q.args_sealed FROM outbox_jobs q "
        "WHERE (p.action_id = %s AND q.action_id = %s) OR (p.action_id = %s AND q.action_id = %s)",
        (a, b, b, a),
    )
    gw.drain()
    assert gw.spies.echo.calls == []  # neither adapter ran with the other action's args
    assert gw.action_status(a) == gw.action_status(b) == "FAILED"


# ============================================================================ retention
def _policy(migrator: Engine, tenant: str, tool: str, days: int = 1) -> str:
    pid = f"p-{uuid.uuid4().hex[:10]}"
    with migrator.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO retention_policies (policy_id, tenant_id, tool_id, retain_days) "
                "VALUES (:p, :t, :tool, :d)"
            ),
            {"p": pid, "t": tenant, "tool": tool, "d": days},
        )
    return pid


def _age(pg: PgUrls, tenant: str, days: int = 3) -> None:
    su(
        pg,
        "UPDATE payload_objects SET created_at = now() - make_interval(days => %s) "
        "WHERE tenant_id = %s",
        (days, tenant),
    )


def test_retention_deletes_payload_header_and_chain_still_verify(
    gw: Gw, pg: PgUrls, migrator_engine: Engine
) -> None:
    aid = echo(gw, "retained")
    held = echo(gw, "on hold")
    keep = gw.post("create_ticket", {"title": "other tool"}).json()["action_id"]
    gw.drain()
    pid = _policy(migrator_engine, gw.world.tenant_id, "test_echo")
    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO legal_holds (hold_id, tenant_id, scope, scope_id, reason, created_by) "
                "VALUES (:h, :t, 'action', :a, 'litigation', 'test')"
            ),
            {"h": uuid.uuid4(), "t": gw.world.tenant_id, "a": held},
        )
    _age(pg, gw.world.tenant_id)
    assert gw.state.retention is not None
    deleted = gw.state.retention.run_once()
    assert deleted == 3  # REQUESTED, DISPATCHED, COMPLETED of the echo action
    for et in ("ACTION_REQUESTED", "ACTION_DISPATCHED", "ACTION_COMPLETED"):
        e = event_id(gw, aid, et)
        with pytest.raises(PayloadUnavailable) as exc, gw.engine.connect() as conn:
            gw.state.payloads.load_payload(conn, e)
        assert exc.value.code == "DELETED"
        assert payload(gw, event_id(gw, held, et)) is not None  # legal hold
    assert payload(gw, event_id(gw, keep, "ACTION_REQUESTED")) is not None  # other tool
    with gw.engine.connect() as conn:
        bodies = (
            conn.execute(
                select(t.evidence_events.c.canonical_bytes).where(
                    t.evidence_events.c.tenant_id == gw.world.tenant_id,
                    t.evidence_events.c.event_type == "PAYLOAD_DELETED",
                )
            )
            .scalars()
            .all()
        )
    from agw_gateway.crypto.canonical import decode

    erasures = [decode(bytes(b))["erasure"] for b in bodies]
    assert {(x["reason"], x["policy"]) for x in erasures} == {("RETENTION", pid)}
    report = verify_export(gw)
    assert report.result == "INCOMPLETE"  # payloads unavailable, NOT tampered
    assert len(report.missing_payloads) == 3
    # idempotent; the erasure path refuses held payloads
    assert (
        gw.state.retention.erase(gw.world.tenant_id, event_id(gw, aid, "ACTION_REQUESTED")) is False
    )
    from agw_gateway.privacy.retention import LegalHold

    with pytest.raises(LegalHold):
        gw.state.retention.erase(gw.world.tenant_id, event_id(gw, held, "ACTION_REQUESTED"))


# ============================================================================ object storage
@pytest.fixture
def blobs(minio: ServiceUrl) -> S3BlobStore:
    store = S3BlobStore(
        endpoint=minio.endpoint,
        access_key=minio.user,
        secret_key=minio.secret,
        bucket=f"agw-t-{uuid.uuid4().hex[:12]}",
        secure=False,
    )
    store.ensure_private_bucket()
    return store


def test_large_payloads_go_to_private_object_storage(
    pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path, blobs: S3BlobStore,
    minio: ServiceUrl,
) -> None:  # fmt: skip
    marker = canary("blob")
    with gateway(pg, app_engine, world, tmp_path, blob_store=blobs) as g:
        aid = g.post("test_bigdoc", {"text": "A" * 70_000 + marker}).json()["action_id"]
        small = g.post("test_echo", {"text": "small"}).json()["action_id"]
        g.drain()
        eid = event_id(g, aid, "ACTION_REQUESTED")
        assert header(g, eid)["payload"]["ref"] == "blob"
        assert header(g, event_id(g, small, "ACTION_REQUESTED"))["payload"]["ref"] == "inline"
        with g.engine.connect() as conn:
            obj = conn.execute(
                select(t.payload_objects).where(t.payload_objects.c.event_id == eid)
            ).one()
        assert obj.storage == "blob" and obj.ciphertext is None
        key = f"{world.tenant_id}/{eid}"
        assert obj.blob_key == key
        stored = blobs.get(key)
        assert stored is not None and marker.encode() not in stored  # ciphertext only
        assert hashlib.sha256(stored).digest() == bytes(obj.ct_sha256)
        assert marker in str(payload(g, eid))
        anon = httpx.get(f"http://{minio.endpoint}/{blobs.bucket}/{key}")
        assert anon.status_code == 403  # private bucket, no public URL
        assert verify_export(g).result == "VERIFIED"
        # availability check: a missing object is INCOMPLETE, an altered one TAMPERED
        blobs.delete(key)
        assert verify_export(g).result == "INCOMPLETE"
        blobs.put(key, stored[:-1] + bytes([stored[-1] ^ 1]))
        assert verify_export(g).result == "TAMPERED"
        blobs.put(key, stored)
        # an orphan (rolled-back write) is garbage-collected, live objects are kept
        blobs.put(f"{world.tenant_id}/{uuid.uuid4()}", b"orphan")
        assert g.state.retention is not None
        assert g.state.retention.collect_orphans(min_age_seconds=0) == 1
        assert blobs.get(key) == stored


def test_object_storage_down_fails_closed_for_large_payloads_only(
    pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path
) -> None:
    dead = S3BlobStore(endpoint="127.0.0.1:9", access_key="x", secret_key="y",
                       bucket="agw-dead", secure=False)  # fmt: skip
    with gateway(pg, app_engine, world, tmp_path, blob_store=dead) as g:
        big = g.post("test_bigdoc", {"text": "B" * 70_000})
        assert (big.status_code, big.json()["error"]["code"]) == (503, "STORAGE_UNAVAILABLE")
        assert g.post("test_echo", {"text": "small"}).status_code == 201


# ============================================================================ Vault Transit
def test_vault_transit_provider(vault: ServiceUrl, pg: PgUrls, app_engine: Engine,
                                world: World, tmp_path: Path) -> None:  # fmt: skip
    p = VaultTransitKeyProvider(vault.endpoint, vault.secret, "agw-kek")
    v_before = p.active_version
    w = p.wrap(b"d" * 32, b"ctx")
    assert w.kek_id == "vault-transit:agw-kek" and b"d" * 32 not in w.ciphertext
    assert p.unwrap(w, b"ctx") == b"d" * 32
    with pytest.raises(UnwrapFailed):
        p.unwrap(w, b"other-ctx")
    with gateway(pg, app_engine, world, tmp_path, key_provider=p) as g:
        aid = echo(g, "via vault")
        assert payload(g, event_id(g, aid, "ACTION_COMPLETED")) is not None
        assert p.rotate() == v_before + 1
        assert payload(g, event_id(g, aid, "ACTION_REQUESTED")) is not None  # old version ok
        assert rewrap_all(g.engine, p, tenant=world.tenant_id) > 0
        assert remaining(g.engine, p, tenant=world.tenant_id) == 0
        assert payload(g, event_id(g, aid, "ACTION_REQUESTED")) is not None
        assert verify_export(g).result == "VERIFIED"
    bad = VaultTransitKeyProvider(vault.endpoint, "wrong-token", "agw-kek")
    with pytest.raises(KeyUnavailable):
        bad.wrap(b"d" * 32, b"ctx")
