"""Phase 7 selective disclosure (ADR-0029 §6).

Required tests (prompt) -> test:
  grant for event X cannot decrypt event Y in the same epoch ... test_grant_for_x_cannot_open_y_*
  expired grant -> 403 + evidence ............................. test_expired_grant_is_403_and_evidenced
  deleted payload -> INCOMPLETE, not TAMPERED ................. test_deleted_payload_bundle_is_incomplete
End to end: auditor key -> grant -> export -> decrypt -> digest -> proof -> on-chain anchor
(test_auditor_flow_verified_end_to_end).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import Engine, select, text

from agw_gateway.admin import ensure_human
from agw_gateway.crypto import envelope as env
from agw_gateway.crypto.canonical import decode
from agw_gateway.db import tables as t
from agw_verifier.disclosure import keygen, read_private_key

from ..anchorkit import Chain, register, sealer, trust_file, verify
from ..approvalkit import PASSWORD, make_humans
from ..conftest import Gw
from ..privacykit import canary, event_id, header

pytestmark = pytest.mark.e2e


class People:
    def __init__(self, gw: Gw, migrator: Engine, tmp: Path) -> None:
        self.gw = gw
        h = make_humans(migrator, gw.client, gw.world.tenant_id)  # alice, bob, audrey(auditor)
        self.ids = dict(h.ids)
        self.sessions = dict(h.sessions)
        for name, roles in (("adam", ["admin"]), ("aud2", ["auditor"])):
            self.ids[name] = ensure_human(migrator, gw.world.tenant_id, name, PASSWORD, roles)
            r = gw.client.post(
                "/v1/auth/login",
                json={"tenant": gw.world.tenant_id, "username": name, "password": PASSWORD},
            )
            self.sessions[name] = r.json()["session_token"]
        self.key_file = str(tmp / f"auditor-{uuid.uuid4().hex[:6]}.key")
        pub, self.key_id = keygen(self.key_file)
        r = self.post("audrey", "/v1/auditor-keys", {"public_key": pub})
        assert r.status_code == 201 and r.json()["key_id"] == self.key_id, r.text

    def h(self, who: str) -> dict[str, str]:
        return {"Authorization": f"Session {self.sessions[who]}"}

    def post(self, who: str, path: str, body: Any = None) -> Any:
        return self.gw.client.post(path, json=body, headers=self.h(who))

    def grant(self, events: list[uuid.UUID], who: str = "adam", **kw: Any) -> Any:
        body = {
            "auditor_id": self.ids["audrey"],
            "auditor_key_id": self.key_id,
            "event_ids": [str(e) for e in events],
            "purpose": kw.pop("purpose", "quarterly audit"),
            **kw,
        }
        return self.post(who, "/v1/disclosures", body)

    def export(self, grant_id: str, who: str = "audrey", events: Any = None) -> Any:
        body = {"event_ids": [str(e) for e in events]} if events else None
        return self.post(who, f"/v1/disclosures/{grant_id}/export", body)


@pytest.fixture
def people(gw: Gw, migrator_engine: Engine, tmp_path: Path) -> People:
    return People(gw, migrator_engine, tmp_path)


def two_events_one_epoch(gw: Gw) -> tuple[uuid.UUID, uuid.UUID]:
    a = gw.post("send_email", {"to": ["x@corp.example"], "subject": canary("x")}).json()
    b = gw.post("send_email", {"to": ["y@corp.example"], "subject": canary("y")}).json()
    x, y = (
        event_id(gw, a["action_id"], "ACTION_REQUESTED"),
        event_id(gw, b["action_id"], "ACTION_REQUESTED"),
    )
    s = sealer(gw, max_events=1000)
    with gw.engine.connect() as conn:
        head = conn.execute(
            select(t.chain_heads.c.last_seq).where(t.chain_heads.c.tenant_id == gw.world.tenant_id)
        ).scalar_one()
    s.request_seal(gw.world.tenant_id, int(head), "MANUAL")
    s.drain()
    return x, y


def epoch_of(gw: Gw, eid: uuid.UUID) -> int:
    seq = header(gw, eid)["seq"]
    with gw.engine.connect() as conn:
        return int(
            conn.execute(
                select(t.epochs.c.epoch_no).where(
                    t.epochs.c.tenant_id == gw.world.tenant_id,
                    t.epochs.c.first_seq <= seq,
                    t.epochs.c.last_seq >= seq,
                )
            ).scalar_one()
        )


def accesses(gw: Gw) -> list[dict[str, Any]]:
    with gw.engine.connect() as conn:
        rows = conn.execute(
            select(t.evidence_events.c.canonical_bytes)
            .where(
                t.evidence_events.c.tenant_id == gw.world.tenant_id,
                t.evidence_events.c.event_type == "DISCLOSURE_ACCESSED",
            )
            .order_by(t.evidence_events.c.seq)
        ).scalars()
        return [decode(bytes(r)) for r in rows]


# ============================================================================ end to end
def test_auditor_flow_verified_end_to_end(
    gw: Gw, people: People, chain: Chain, migrator_engine: Engine, tmp_path: Path
) -> None:
    rec = register(chain, migrator_engine, gw)
    x, _ = two_events_one_epoch(gw)
    purpose = canary("purpose")
    g = people.grant([x], purpose=purpose)
    assert g.status_code == 201, g.text
    grant_id = g.json()["grant_id"]
    exp = people.export(grant_id)
    assert exp.status_code == 200, exp.text
    doc = exp.json()
    assert doc["format"] == "agw-disclosure-export/v1" and len(doc["bundles"]) == 1
    bundle = doc["bundles"][0]
    d = bundle["disclosure"]
    assert d["mode"] == "hpke" and "payload" not in d and "payload" not in bundle["event"]
    a = rec.anchorer()
    a.tick()
    a.tick()  # anchor everything sealed so far (incl. the event's epoch)
    args = ["--auditor-key", people.key_file, "--chain-rpc", chain.rpc,
            "--trust-config", trust_file(tmp_path, rec.trust())]  # fmt: skip
    rc, report = verify(tmp_path, "event", bundle, *args)
    assert (rc, report["result"]) == (0, "VERIFIED"), report
    assert "payload decrypted with the auditor key" in report["notes"]
    # without the key the payload is not checked: never VERIFIED
    rc, report = verify(tmp_path, "event", bundle, "--chain-rpc", chain.rpc,
                        "--trust-config", trust_file(tmp_path, rec.trust()))  # fmt: skip
    assert (rc, report["result"]) == (2, "INCOMPLETE")
    assert report["reason"].startswith("PAYLOAD_NOT_CHECKED")
    # evidence: the grant (purpose only in the encrypted payload) and the access
    with gw.engine.connect() as conn:
        granted = conn.execute(
            select(t.evidence_events.c.canonical_bytes).where(
                t.evidence_events.c.tenant_id == gw.world.tenant_id,
                t.evidence_events.c.event_type == "DISCLOSURE_GRANTED",
            )
        ).scalar_one()
    gh = decode(bytes(granted))
    assert gh["disclosure"]["n"] == 1 and purpose.encode() not in bytes(granted)
    assert gh["disclosure"]["grant"] == uuid.UUID(grant_id).bytes
    assert [(e["outcome"]["status"], e["disclosure"]["n"]) for e in accesses(gw)] == [
        ("COMPLETED", 1)
    ]


# ============================================================================ X vs Y
def test_grant_for_x_cannot_open_y_in_the_same_epoch(
    gw: Gw, people: People, tmp_path: Path
) -> None:
    x, y = two_events_one_epoch(gw)
    assert epoch_of(gw, x) == epoch_of(gw, y)
    grant_id = people.grant([x]).json()["grant_id"]
    # (a) the API refuses Y, and records the attempt
    r = people.export(grant_id, events=[y])
    assert (r.status_code, r.json()["error"]["code"]) == (403, "EVENT_NOT_GRANTED")
    assert accesses(gw)[-1]["outcome"] == {"status": "DENIED", "code": "EVENT_NOT_GRANTED"}
    bundle = people.export(grant_id).json()["bundles"][0]
    with gw.engine.connect() as conn:
        oy = conn.execute(select(t.payload_objects).where(t.payload_objects.c.event_id == y)).one()
    # (b) Y's ciphertext (e.g. from a DB dump) inside X's bundle does not open
    forged = json.loads(json.dumps(bundle))
    forged["disclosure"]["nonce"] = bytes(oy.nonce).hex()
    forged["disclosure"]["ciphertext"] = bytes(oy.ciphertext).hex()
    rc, report = verify(tmp_path, "event", forged, "--auditor-key", people.key_file)
    assert (rc, report["result"], report["reason"]) == (1, "TAMPERED", "PAYLOAD_DECRYPT_FAILED")
    # (c) even with X's DEK in hand (opened with the auditor key), Y stays sealed
    d = bundle["disclosure"]
    info = env.disclosure_info(
        gw.world.tenant_id, uuid.UUID(grant_id).bytes, x.bytes, people.key_id
    )
    dek_x = env.open_from_sender(
        bytes.fromhex(d["sealed_dek"]), read_private_key(people.key_file), info
    )
    hy = header(gw, y)
    aad_y = env.payload_aad(gw.world.tenant_id, y.bytes, hy["seq"], hy["payload"]["digest"], 1)
    with pytest.raises(InvalidTag):
        AESGCM(dek_x).decrypt(bytes(oy.nonce), bytes(oy.ciphertext), aad_y)
    # (d) X's own bundle verifies (offline: payload + proof; no trust root -> UNANCHORED)
    rc, report = verify(tmp_path, "event", bundle, "--auditor-key", people.key_file)
    assert (rc, report["result"]) == (4, "UNANCHORED"), report


# ============================================================================ grant rules
def test_expired_grant_is_403_and_evidenced(
    gw: Gw, people: People, migrator_engine: Engine
) -> None:
    x, _ = two_events_one_epoch(gw)
    grant_id = people.grant([x]).json()["grant_id"]
    with migrator_engine.begin() as conn:
        conn.execute(
            text("UPDATE disclosure_grants SET expires_at = now() - interval '1 second' "
                 "WHERE grant_id = :g"),
            {"g": grant_id},
        )  # fmt: skip
    r = people.export(grant_id)
    assert (r.status_code, r.json()["error"]["code"]) == (403, "GRANT_EXPIRED")
    last = accesses(gw)[-1]
    assert last["outcome"] == {"status": "DENIED", "code": "GRANT_EXPIRED"}
    assert last["actor"]["id"] == people.ids["audrey"]
    assert last["disclosure"]["grant"] == uuid.UUID(grant_id).bytes


def test_grant_roles_separation_and_revocation(gw: Gw, people: People) -> None:
    x, _ = two_events_one_epoch(gw)
    assert people.grant([x], who="audrey").json()["error"]["code"] == "ROLE_REQUIRED"
    self_grant = people.post(
        "adam",
        "/v1/disclosures",
        {"auditor_id": people.ids["adam"], "auditor_key_id": people.key_id,
         "event_ids": [str(x)], "purpose": "p"},
    )  # fmt: skip
    assert self_grant.status_code == 422  # nobody grants to themselves
    other_tenant_event = people.grant([uuid.uuid4()])
    assert other_tenant_event.status_code == 422
    grant_id = people.grant([x]).json()["grant_id"]
    r = people.export(grant_id, who="aud2")
    assert (r.status_code, r.json()["error"]["code"]) == (403, "NOT_GRANTEE")
    agent = gw.client.post(f"/v1/disclosures/{grant_id}/export", headers=gw.headers())
    assert (agent.status_code, agent.json()["error"]["code"]) == (403, "AGENT_NOT_PERMITTED")
    assert people.post("adam", f"/v1/disclosures/{grant_id}/revoke").status_code == 204
    r = people.export(grant_id)
    assert (r.status_code, r.json()["error"]["code"]) == (403, "GRANT_REVOKED")
    codes = [e["outcome"].get("code") for e in accesses(gw)]
    assert codes == ["NOT_GRANTEE", "GRANT_REVOKED"]


def test_plaintext_delivery_and_wrong_keys(gw: Gw, people: People, tmp_path: Path) -> None:
    x, _ = two_events_one_epoch(gw)
    plain = people.grant([x], delivery="plaintext").json()["grant_id"]
    b = people.export(plain).json()["bundles"][0]
    assert b["disclosure"]["payload_status"] == "PLAINTEXT"
    rc, report = verify(tmp_path, "event", b)
    assert (rc, report["result"]) == (4, "UNANCHORED")  # payload checked, no trust root
    hp = people.export(people.grant([x]).json()["grant_id"]).json()["bundles"][0]
    other = str(tmp_path / "other.key")
    keygen(other)
    rc, report = verify(tmp_path, "event", hp, "--auditor-key", other)
    assert (rc, report["reason"]) == (2, "NOT_THE_RECIPIENT_KEY")
    bad = json.loads(json.dumps(hp))
    s = bad["disclosure"]["sealed_dek"]
    bad["disclosure"]["sealed_dek"] = s[:-2] + ("00" if s[-2:] != "00" else "01")
    rc, report = verify(tmp_path, "event", bad, "--auditor-key", people.key_file)
    assert (rc, report["result"], report["reason"]) == (1, "TAMPERED", "SEALED_DEK_DOES_NOT_OPEN")


def test_deleted_payload_bundle_is_incomplete(gw: Gw, people: People, tmp_path: Path) -> None:
    x, _ = two_events_one_epoch(gw)
    grant_id = people.grant([x]).json()["grant_id"]
    assert gw.state.retention is not None
    assert gw.state.retention.erase(gw.world.tenant_id, x)
    bundle = people.export(grant_id).json()["bundles"][0]
    assert bundle["disclosure"]["payload_status"] == "DELETED"
    rc, report = verify(tmp_path, "event", bundle, "--auditor-key", people.key_file)
    assert (rc, report["result"], report["reason"]) == (
        2, "INCOMPLETE", "PAYLOAD_UNAVAILABLE:DELETED",
    )  # fmt: skip
    assert "header, inclusion proof and anchor were checked regardless" in report["notes"]
