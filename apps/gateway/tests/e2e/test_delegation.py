"""Phase 8 delegation (ADR-0030): the required tests.

* child requests a scope the parent lacks -> DENY (at issue and at use)
* expired / revoked / over-used token -> DENY
* token tampering / forged signature -> DENY
* depth > limit -> DENY
* parent scope reduced (or parent revoked) after delegation -> child loses it immediately,
  including an already-authorized action that has not been dispatched yet and an action
  waiting for approval
plus evidence shape (DELEGATION_CREATED, hash-linked child requests) and concurrent over-use.
"""

from __future__ import annotations

import base64
import os
import threading
import uuid
from typing import Any

import pytest
from sqlalchemy import Engine, select

from agw_gateway.crypto.canonical import decode, encode
from agw_gateway.db import tables as t
from agw_gateway.delegation.token import Claims, DelegationSigner

from ..approvalkit import EXTERNAL, decide, make_humans
from ..delegationkit import act, delegate, expire, new_agent, set_scopes, ticket
from ..privacykit import event_id, header, payload, verify_export

pytestmark = pytest.mark.e2e


def _reasons(body: dict[str, Any]) -> list[str]:
    return list(body["decision"]["reasons"])


@pytest.fixture
def pair(gw: Any, migrator_engine: Engine) -> dict[str, Any]:
    """Parent = the world's demo-agent; child = a fresh agent with its own scopes."""
    child_id, child_token = new_agent(migrator_engine, gw.world.tenant_id, "child")
    return {"child_id": child_id, "child": child_token}


# --------------------------------------------------------------------------- scope
def test_parent_cannot_delegate_a_scope_it_lacks(gw: Any, pair: dict[str, Any]) -> None:
    # demo-readonly holds only tools:public_doc_search
    r = delegate(
        gw,
        pair["child_id"],
        token=gw.world.readonly_token,
        scopes=("tools:create_ticket",),
        tools=("create_ticket",),
        expect=403,
    )
    assert r["error"]["code"] == "DELEGATION_EXCEEDS_PARENT"
    assert gw.count_events("DELEGATION_CREATED") == 0
    # the refused attempt is evidence: SECURITY_VIOLATION{DELEGATION_REFUSED}
    assert gw.count_events("SECURITY_VIOLATION") == 1


def test_child_using_a_scope_the_chain_lacks_is_denied(gw: Any, pair: dict[str, Any]) -> None:
    d = delegate(
        gw, pair["child_id"], scopes=("tools:public_doc_search",), tools=("public_doc_search",)
    )
    body = act(gw, "create_ticket", ticket(), pair["child"], d["token"])
    assert body["status"] == "DENIED"
    assert _reasons(body) == ["DELEGATION_SCOPE_MISSING"]
    # The child HOLDS the scope itself; without the token it could call directly. With the
    # token it is bound by the delegation. Nothing reached the adapter.
    gw.drain()
    assert gw.spies.ticket.calls == []


def test_tool_outside_allowlist_and_risk_above_cap_denied(gw: Any, pair: dict[str, Any]) -> None:
    d = delegate(
        gw,
        pair["child_id"],
        scopes=("tools:create_ticket", "tools:public_doc_search"),
        tools=("public_doc_search",),
    )
    body = act(gw, "create_ticket", ticket(), pair["child"], d["token"])
    assert _reasons(body) == ["DELEGATION_TOOL_NOT_ALLOWED"]
    low = delegate(gw, pair["child_id"], max_risk="LOW")
    body = act(gw, "create_ticket", ticket(), pair["child"], low["token"])  # MEDIUM
    assert body["status"] == "DENIED" and _reasons(body) == ["DELEGATION_RISK_EXCEEDED"]
    gw.drain()
    assert gw.spies.ticket.calls == []


# --------------------------------------------------------------------------- lifecycle
def test_expired_token_denied(gw: Any, pair: dict[str, Any], migrator_engine: Engine) -> None:
    d = delegate(gw, pair["child_id"])
    assert act(gw, "create_ticket", ticket(1), pair["child"], d["token"])["status"] == "AUTHORIZED"
    expire(migrator_engine, d["delegation_id"])
    body = act(gw, "create_ticket", ticket(2), pair["child"], d["token"])
    assert body["status"] == "DENIED" and _reasons(body) == ["DELEGATION_EXPIRED"]


def test_revoked_token_denied_and_revocation_recorded(gw: Any, pair: dict[str, Any]) -> None:
    d = delegate(gw, pair["child_id"])
    r = gw.client.post(
        f"/v1/delegations/{d['delegation_id']}/revoke",
        headers={"Authorization": f"Bearer {gw.world.token}"},
    )
    assert r.status_code == 200, r.text
    body = act(gw, "create_ticket", ticket(), pair["child"], d["token"])
    assert body["status"] == "DENIED" and _reasons(body) == ["DELEGATION_REVOKED"]
    assert gw.count_events("DELEGATION_REVOKED") == 1
    # The child cannot revoke (it is not an issuer); an outsider gets 404 (no oracle).
    other = delegate(gw, pair["child_id"])
    r = gw.client.post(
        f"/v1/delegations/{other['delegation_id']}/revoke",
        headers={"Authorization": f"Bearer {pair['child']}"},
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "DELEGATION_NOT_REVOCABLE"


def test_over_used_token_denied(gw: Any, pair: dict[str, Any]) -> None:
    d = delegate(gw, pair["child_id"], max_uses=2)
    statuses = [
        act(gw, "public_doc_search", {"query": "gateway"}, pair["child"], d["token"])["status"]
        for _ in range(3)
    ]
    assert statuses[:2] == ["AUTHORIZED", "AUTHORIZED"]
    last = act(gw, "public_doc_search", {"query": "x"}, pair["child"], d["token"])
    assert last["status"] == "DENIED" and _reasons(last) == ["DELEGATION_EXHAUSTED"]
    assert statuses[2] == "DENIED"


def test_concurrent_over_use_never_exceeds_max_uses(gw: Any, pair: dict[str, Any]) -> None:
    d = delegate(gw, pair["child_id"], max_uses=3)
    out: list[str] = []
    lock = threading.Lock()

    def one(i: int) -> None:
        r = gw.post(
            "public_doc_search",
            {"query": f"q{i}"},
            token=pair["child"],
            delegation={"token": d["token"]},
        )
        with lock:
            out.append(r.json()["status"])

    threads = [threading.Thread(target=one, args=(i,)) for i in range(12)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert out.count("AUTHORIZED") == 3 and out.count("DENIED") == 9
    with gw.engine.connect() as conn:
        uses = conn.execute(
            select(t.delegations.c.uses).where(
                t.delegations.c.delegation_id == uuid.UUID(d["delegation_id"])
            )
        ).scalar_one()
    assert uses == 3


# --------------------------------------------------------------------------- tampering
def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def test_tampered_and_forged_tokens_denied(gw: Any, pair: dict[str, Any]) -> None:
    d = delegate(
        gw, pair["child_id"], scopes=("tools:public_doc_search",), tools=("public_doc_search",)
    )
    _, claims_b64, sig_b64 = d["token"].split(".")
    rec = decode(_unb64(claims_b64))
    # (1) widen the scopes, keep the gateway's signature
    widened = dict(
        rec,
        sc=["tools:create_ticket", "tools:public_doc_search"],
        tl=["create_ticket", "public_doc_search"],
    )
    forged_1 = f"agwd1.{_b64(encode(widened))}.{sig_b64}"
    # (2) widen and re-sign with an attacker key that claims the gateway's key id
    attacker = DelegationSigner(os.urandom(32))
    cbor = encode(widened)
    forged_2 = (
        f"agwd1.{_b64(cbor)}.{_b64(attacker._private.sign(b'\x15AGW/delegation-sig/v1' + cbor))}"
    )
    # (3) flip one signature bit
    sig = bytearray(_unb64(sig_b64))
    sig[0] ^= 1
    forged_3 = f"agwd1.{claims_b64}.{_b64(bytes(sig))}"
    # (4) validly SIGNED by the real key (an insider with the key) but never issued/stored
    real = gw.state.delegations._signer
    # same delegation id as the issued token, widened scopes: only the STORED hash tells
    # them apart (the DB row, not the token, is authoritative)
    fresh = Claims.from_record(widened)
    forged_4 = real.sign(fresh).text
    for forged in (forged_1, forged_2, forged_3, forged_4, "agwd1.AAAA.AAAA" + "A" * 20):
        body = act(gw, "create_ticket", ticket(), pair["child"], forged)
        assert body["status"] == "DENIED", forged
        assert _reasons(body) == ["DELEGATION_INVALID"]
    gw.drain()
    assert gw.spies.ticket.calls == []


def test_token_presented_by_another_agent_denied(gw: Any, pair: dict[str, Any]) -> None:
    d = delegate(gw, pair["child_id"])
    stolen = act(gw, "create_ticket", ticket(), gw.world.other_token, d["token"])
    assert stolen["status"] == "DENIED" and _reasons(stolen) == ["DELEGATION_NOT_FOR_AGENT"]


def test_declared_depth_and_token_together_rejected(gw: Any, pair: dict[str, Any]) -> None:
    d = delegate(gw, pair["child_id"])
    r = gw.post(
        "create_ticket", ticket(), token=pair["child"], delegation={"token": d["token"], "depth": 0}
    )
    assert r.status_code == 422


# --------------------------------------------------------------------------- depth
def test_depth_limit_at_issue_and_at_use(
    gw: Any, pair: dict[str, Any], migrator_engine: Engine
) -> None:
    g_id, g_token = new_agent(migrator_engine, gw.world.tenant_id, "grandchild")
    h_id, _ = new_agent(migrator_engine, gw.world.tenant_id, "great-grandchild")
    d1 = delegate(gw, pair["child_id"])
    d2 = delegate(gw, g_id, token=pair["child"], parent_token=d1["token"], max_uses=5)
    assert d2["depth"] == 2
    ok = act(gw, "create_ticket", ticket(), g_token, d2["token"])
    assert ok["status"] == "AUTHORIZED"
    # depth 3 > default limit 2: refused at issue
    r = delegate(gw, h_id, token=g_token, parent_token=d2["token"], expect=403)
    assert r["error"]["code"] == "DELEGATION_DEPTH_EXCEEDED"
    # the operator lowers the limit: the existing depth-2 token stops working at once
    gw.state.delegations.max_depth = 1
    body = act(gw, "create_ticket", ticket(2), g_token, d2["token"])
    assert body["status"] == "DENIED" and _reasons(body) == ["DELEGATION_DEPTH_EXCEEDED"]


def test_subdelegation_can_only_narrow(
    gw: Any, pair: dict[str, Any], migrator_engine: Engine
) -> None:
    g_id, _ = new_agent(migrator_engine, gw.world.tenant_id, "grandchild")
    d1 = delegate(gw, pair["child_id"], tools=("public_doc_search",), max_risk="MEDIUM", max_uses=3)
    for over in (
        {"tools": ("create_ticket", "public_doc_search")},  # tool the parent chain lacks
        {"max_risk": "HIGH"},
        {"max_uses": 4},
        {"scopes": ("tools:delete_record",), "tools": ("delete_record",)},
    ):
        r = delegate(gw, g_id, token=pair["child"], parent_token=d1["token"], expect=403, **over)
        assert r["error"]["code"] == "DELEGATION_EXCEEDS_PARENT", over


# --------------------------------------------------------------------------- live re-check
def test_parent_scope_reduced_child_loses_it_immediately(
    gw: Any, pair: dict[str, Any], migrator_engine: Engine
) -> None:
    d = delegate(gw, pair["child_id"])
    first = act(gw, "create_ticket", ticket(1), pair["child"], d["token"])
    assert first["status"] == "AUTHORIZED"
    # authorized but NOT dispatched yet ...
    queued = act(gw, "create_ticket", ticket(2), pair["child"], d["token"])
    assert queued["status"] == "AUTHORIZED"
    # ... the parent loses tools:create_ticket (operator change)
    parent_scopes = [s for s in ("tools:public_doc_search", "tools:send_email")]
    set_scopes(migrator_engine, gw.world.agent_id, parent_scopes)
    after = act(gw, "create_ticket", ticket(3), pair["child"], d["token"])
    assert after["status"] == "DENIED" and _reasons(after) == ["DELEGATION_SCOPE_MISSING"]
    gw.drain()
    # Neither queued action was dispatched: the executor re-checks the chain before dispatch.
    assert gw.spies.ticket.calls == []
    assert gw.action_status(first["action_id"]) == "FAILED"
    assert gw.events(queued["action_id"])[-1] == "ACTION_FAILED"
    with gw.engine.connect() as conn:
        code = conn.execute(
            select(t.actions.c.error_code).where(
                t.actions.c.action_id == uuid.UUID(queued["action_id"])
            )
        ).scalar_one()
    assert code == "DELEGATION_INVALID"


def test_root_revocation_cascades_to_subdelegation(
    gw: Any, pair: dict[str, Any], migrator_engine: Engine
) -> None:
    g_id, g_token = new_agent(migrator_engine, gw.world.tenant_id, "grandchild")
    d1 = delegate(gw, pair["child_id"])
    d2 = delegate(gw, g_id, token=pair["child"], parent_token=d1["token"], max_uses=5)
    assert act(gw, "create_ticket", ticket(), g_token, d2["token"])["status"] == "AUTHORIZED"
    # the ROOT issuer revokes the FIRST link; the grandchild's own link is untouched
    r = gw.client.post(
        f"/v1/delegations/{d1['delegation_id']}/revoke",
        headers={"Authorization": f"Bearer {gw.world.token}"},
    )
    assert r.status_code == 200
    body = act(gw, "create_ticket", ticket(2), g_token, d2["token"])
    assert body["status"] == "DENIED" and _reasons(body) == ["DELEGATION_REVOKED"]
    # the root issuer may also revoke the grandchild link directly (an issuer in its chain)
    r = gw.client.post(
        f"/v1/delegations/{d2['delegation_id']}/revoke",
        headers={"Authorization": f"Bearer {gw.world.token}"},
    )
    assert r.status_code == 200


def test_revocation_while_pending_approval_blocks_authorization(
    gw: Any, pair: dict[str, Any], migrator_engine: Engine
) -> None:
    d = delegate(
        gw,
        pair["child_id"],
        scopes=("tools:send_email",),
        tools=("send_email",),
        max_risk="HIGH",
    )
    body = act(gw, "send_email", {"to": EXTERNAL, "subject": "summary"}, pair["child"], d["token"])
    assert body["status"] == "PENDING_APPROVAL"
    humans = make_humans(migrator_engine, gw.client, gw.world.tenant_id)
    gw.client.post(
        f"/v1/delegations/{d['delegation_id']}/revoke",
        headers={"Authorization": f"Bearer {gw.world.token}"},
    )
    r = decide(gw, humans, body["approval"]["approval_id"])
    assert r.status_code == 200, r.text
    gw.drain()
    assert gw.action_status(body["action_id"]) == "DENIED"
    assert gw.spies.email.calls == []


def test_approval_binds_the_delegation(
    gw: Any, pair: dict[str, Any], migrator_engine: Engine
) -> None:
    d = delegate(gw, pair["child_id"], scopes=("tools:send_email",), tools=("send_email",))
    body = act(gw, "send_email", {"to": EXTERNAL, "subject": "summary"}, pair["child"], d["token"])
    humans = make_humans(migrator_engine, gw.client, gw.world.tenant_id)
    r = decide(gw, humans, body["approval"]["approval_id"])
    assert r.status_code == 200, r.text
    gw.drain()
    assert gw.action_status(body["action_id"]) == "COMPLETED"
    assert len(gw.spies.email.calls) == 1


# --------------------------------------------------------------------------- evidence
def test_evidence_links_child_actions_to_the_delegation(
    gw: Any, pair: dict[str, Any], migrator_engine: Engine
) -> None:
    run = str(uuid.uuid4())
    g_id, g_token = new_agent(migrator_engine, gw.world.tenant_id, "grandchild")
    d1 = delegate(gw, pair["child_id"], run_id=run)
    d2 = delegate(gw, g_id, token=pair["child"], parent_token=d1["token"], max_uses=2)
    body = act(gw, "create_ticket", ticket(), g_token, d2["token"])
    gw.drain()
    with gw.engine.connect() as conn:
        created = {
            r.event_id: r
            for r in conn.execute(
                select(t.evidence_events).where(
                    t.evidence_events.c.tenant_id == gw.world.tenant_id,
                    t.evidence_events.c.event_type == "DELEGATION_CREATED",
                )
            )
        }
    c1 = created[uuid.UUID(d1["created_event_id"])]
    c2 = created[uuid.UUID(d2["created_event_id"])]
    h1, h2 = header(gw, c1.event_id), header(gw, c2.event_id)
    assert h1["class"] == "A2A" and h1["run"] == uuid.UUID(run).bytes
    assert h1["delegation"]["to"] == uuid.UUID(pair["child_id"]).bytes
    assert h1["delegation"]["th"] == bytes.fromhex(d1["token_hash"])
    assert "refs" not in h1
    assert h2["refs"]["parent"] == bytes(c1.event_hash)  # sub-delegation hash-linked
    assert h2["delegation"]["par"] == uuid.UUID(d1["delegation_id"]).bytes
    p1 = payload(gw, c1.event_id)
    assert p1 is not None and p1["delegation"]["purpose"] == "create ticket + email summary"
    req = header(gw, event_id(gw, body["action_id"], "ACTION_REQUESTED"))
    assert req["delegation"]["ev"] == c2.event_id.bytes
    assert req["delegation"]["root"] == gw.world.agent_id.bytes
    assert req["delegation"]["from"] == uuid.UUID(pair["child_id"]).bytes
    assert req["refs"]["parent"] == bytes(c2.event_hash)
    rp = payload(gw, event_id(gw, body["action_id"], "ACTION_REQUESTED"))
    assert rp is not None and rp["delegation"]["declared_by"] == "gateway"
    assert rp["delegation"]["chain"] == [
        uuid.UUID(d1["delegation_id"]).bytes,
        uuid.UUID(d2["delegation_id"]).bytes,
    ]
    pe = header(gw, event_id(gw, body["action_id"], "POLICY_EVALUATED"))
    depth = next(f for f in pe["risk"]["f"] if f["n"] == "delegation_depth")
    assert depth["v"] == "two_hops" and "DELEGATION_VERIFIED" in pe["risk"]["reasons"]
    # The issuer's timeline view shows the delegation tree and the child's events.
    r = gw.client.get(
        f"/v1/delegations/{d1['delegation_id']}/timeline",
        headers={"Authorization": f"Bearer {gw.world.token}"},
    )
    assert r.status_code == 200, r.text
    tl = r.json()
    assert [d["depth"] for d in tl["delegations"]] == [1, 2]
    types = [e["type"] for e in tl["events"]]
    assert types[:2] == ["DELEGATION_CREATED", "DELEGATION_CREATED"]
    assert "ACTION_COMPLETED" in types
    # an unrelated agent cannot see it (404, no oracle)
    r = gw.client.get(
        f"/v1/delegations/{d1['delegation_id']}/timeline",
        headers={"Authorization": f"Bearer {gw.world.other_token}"},
    )
    assert r.status_code == 404
    # and the whole chain, including the A2A events, verifies offline
    assert verify_export(gw).result == "VERIFIED"


def test_no_signing_key_fails_closed(gw: Any, pair: dict[str, Any]) -> None:
    d = delegate(gw, pair["child_id"])
    gw.state.delegations._signer = None
    r = gw.client.post(
        "/v1/delegations",
        json={
            "child_agent_id": pair["child_id"],
            "scopes": ["tools:create_ticket"],
            "tools": ["create_ticket"],
            "max_risk_level": "LOW",
            "expires_at": "2099-01-01T00:00:00Z",
            "max_uses": 1,
            "purpose": "x",
        },
        headers={"Authorization": f"Bearer {gw.world.token}"},
    )
    assert r.status_code == 503 and r.json()["error"]["code"] == "DELEGATION_UNAVAILABLE"
    body = act(gw, "create_ticket", ticket(), pair["child"], d["token"])
    assert body["status"] == "DENIED" and _reasons(body) == ["DELEGATION_INVALID"]
