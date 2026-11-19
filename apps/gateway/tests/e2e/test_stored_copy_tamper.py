"""ADR-0038: the readable copy (``body``) and indexed columns of an evidence row are checked
against the SEALED record, and screens show the sealed record.

Before this, an insider could rewrite ``body`` (e.g. a policy effect) and every hash check still
passed, because only ``canonical_bytes`` is hashed: the console showed the edited value with a
VERIFIED badge.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import Engine

from agw_gateway.admin import ensure_human

from ..approvalkit import PASSWORD, make_humans
from ..privacykit import su
from .test_monitoring import _activity, monitor

pytestmark = pytest.mark.e2e


@pytest.fixture
def humans(gw: Any, migrator_engine: Engine) -> Any:
    ensure_human(migrator_engine, gw.world.tenant_id, "adam", PASSWORD, ["admin"])
    return make_humans(migrator_engine, gw.client, gw.world.tenant_id)


def _get(gw: Any, humans: Any, path: str) -> Any:
    r = gw.client.get(path, headers=humans.headers("alice"))
    assert r.status_code == 200, r.text
    return r.json()


def _policy_event(gw: Any, humans: Any, action_id: str) -> dict[str, Any]:
    events = _get(gw, humans, f"/v1/dashboard/actions/{action_id}")["events"]
    return next(e for e in events if e["type"] == "POLICY_EVALUATED")


def test_clean_rows_match_their_sealed_record(gw: Any, humans: Any) -> None:
    action_id = gw.post("test_echo", {"text": "hello"}).json()["action_id"]
    gw.drain()
    events = _get(gw, humans, f"/v1/dashboard/actions/{action_id}")["events"]
    assert events and all(e["stored_copy_ok"] is True for e in events)
    _activity(gw)
    rep = monitor(gw).run_once([gw.world.tenant_id])[0]
    assert rep.report["stored_copy"]["result"] == "VERIFIED", rep.report
    assert rep.report["stored_copy"]["events_checked"] >= len(events)
    assert rep.result == "VERIFIED"


def test_edited_readable_copy_is_tampered_and_screens_show_the_sealed_value(
    gw: Any, humans: Any, pg: Any
) -> None:
    action_id = gw.post("test_echo", {"text": "hello"}).json()["action_id"]
    gw.drain()
    _activity(gw)
    m = monitor(gw)
    assert m.run_once([gw.world.tenant_id])[0].result == "VERIFIED"
    victim = _policy_event(gw, humans, action_id)
    before = _get(gw, humans, f"/v1/dashboard/events/{victim['event_id']}")
    sealed_effect = before["header"]["policy"]["effect"]
    forged = "deny" if sealed_effect != "deny" else "allow"
    # An insider rewrites only the readable copy (hashes untouched).
    su(
        pg,
        "UPDATE evidence_events SET body = jsonb_set(body, '{policy,effect}', to_jsonb(%s::text))"
        " WHERE event_id = %s",
        (forged, victim["event_id"]),
    )
    after = _get(gw, humans, f"/v1/dashboard/events/{victim['event_id']}")
    assert after["node"]["hash_ok"] is True  # the hash alone cannot see it...
    assert after["node"]["stored_copy_ok"] is False  # ...this check does
    assert after["header"]["policy"]["effect"] == sealed_effect  # screens show the sealed value
    assert after["node"]["decision"] == sealed_effect
    assert _policy_event(gw, humans, action_id)["stored_copy_ok"] is False
    # The agent-facing action view also reads the sealed record.
    agent_view = gw.client.get(f"/v1/actions/{action_id}", headers=gw.headers()).json()
    assert agent_view["decision"]["reasons"] == before["header"]["policy"]["reasons"]
    # The monitor flags it in ONE cycle; the hash chain itself still verifies.
    rep = m.run_once([gw.world.tenant_id])[0]
    assert rep.result == "TAMPERED", rep.report
    assert rep.report["chain"]["result"] == "VERIFIED"
    assert rep.report["stored_copy"]["mismatched_seqs"] == [victim["seq"]]
    assert any(
        a["kind"] == "VERIFICATION_FAILED" and a["detail"].get("check") == "stored_copy"
        for a in rep.alerts
    )


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE evidence_events SET event_type = 'ACTION_DENIED' WHERE event_id = %s",
        "UPDATE evidence_events SET action_id = gen_random_uuid() WHERE event_id = %s",
        "UPDATE evidence_events SET body = body - 'policy' WHERE event_id = %s",
    ],
    ids=["event_type", "action_id", "body-key-removed"],
)
def test_edited_columns_are_tampered(gw: Any, humans: Any, pg: Any, sql: str) -> None:
    action_id = gw.post("test_echo", {"text": "hello"}).json()["action_id"]
    gw.drain()
    victim = _policy_event(gw, humans, action_id)
    su(pg, sql, (victim["event_id"],))
    after = _get(gw, humans, f"/v1/dashboard/events/{victim['event_id']}")
    assert after["node"]["hash_ok"] is True and after["node"]["stored_copy_ok"] is False
    rep = monitor(gw).run_once([gw.world.tenant_id])[0]
    assert rep.report["stored_copy"]["result"] == "TAMPERED"
    assert victim["seq"] in rep.report["stored_copy"]["mismatched_seqs"]
