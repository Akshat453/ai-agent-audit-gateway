"""Endpoint contracts (11 §5), uniform error model (11 §2), canary never leaks (T24)."""

import logging
import uuid

import pytest

pytestmark = pytest.mark.e2e

CANARY = "CANARY-7f3a9c-DO-NOT-LOG"


def test_health_ready_and_request_id(gw) -> None:
    h = gw.client.get("/v1/health")
    assert (h.status_code, h.json()) == (200, {"status": "ok"})
    assert uuid.UUID(h.headers["X-Request-Id"]).version == 7
    r = gw.client.get("/v1/ready")
    assert (r.status_code, r.json()) == (200, {"status": "ready"})


def test_tools_filtered_by_scope(gw) -> None:
    full = gw.client.get("/v1/tools", headers=gw.headers()).json()["tools"]
    assert {t["tool_id"] for t in full} >= {"public_doc_search", "create_ticket", "delete_record"}
    ro = gw.client.get("/v1/tools", headers=gw.headers(gw.world.readonly_token)).json()["tools"]
    assert [t["tool_id"] for t in ro] == ["public_doc_search"]
    entry = ro[0]
    assert set(entry) == {
        "tool_id",
        "version",
        "operation_type",
        "environments_allowed",
        "args_schema",
    }
    assert entry["args_schema"]["additionalProperties"] is False


def test_get_action_owner_only(gw) -> None:
    r = gw.post("public_doc_search", {"query": CANARY})
    aid = r.json()["action_id"]
    gw.drain()
    mine = gw.client.get(f"/v1/actions/{aid}", headers=gw.headers())
    assert mine.status_code == 200
    data = mine.json()
    assert data["status"] == "COMPLETED"
    assert data["decision"]["matched_rule_ids"] == ["allow-low"]
    assert CANARY not in mine.text  # raw args are never returned
    for token in (gw.world.other_token, gw.world.readonly_token):
        other = gw.client.get(f"/v1/actions/{aid}", headers=gw.headers(token))
        assert other.status_code == 404
        assert other.json()["error"]["code"] == "NOT_FOUND"
    missing = gw.client.get(f"/v1/actions/{uuid.uuid4()}", headers=gw.headers())
    assert missing.json() == {
        **missing.json(),
        "error": {**missing.json()["error"], "code": "NOT_FOUND"},
    }
    assert gw.client.get("/v1/actions/not-a-uuid", headers=gw.headers()).status_code == 422


def test_timeline_only_own_events(gw) -> None:
    rid = str(uuid.uuid4())
    gw.post("public_doc_search", {"query": "x"}, run_id=rid)
    gw.post("delete_record", {"record_id": str(uuid.uuid4())}, run_id=rid)
    gw.post("public_doc_search", {"query": "y"}, run_id=rid, token=gw.world.other_token)
    gw.drain()
    tl = gw.client.get(f"/v1/runs/{rid}/timeline", headers=gw.headers()).json()["events"]
    types = [e["type"] for e in tl]
    assert types == [
        "ACTION_REQUESTED",
        "POLICY_EVALUATED",
        "ACTION_AUTHORIZED",
        "ACTION_REQUESTED",
        "POLICY_EVALUATED",
        "ACTION_DENIED",
        "ACTION_DISPATCHED",
        "ACTION_COMPLETED",
    ]
    assert [e["seq"] for e in tl] == sorted(e["seq"] for e in tl)
    assert tl[1]["decision"] == "ALLOW" and tl[4]["decision"] == "DENY"
    assert tl[4]["reasons"] == ["POLICY_RULE_DENY", "CRITICAL_DENIED"]  # policy-v2 (ADR-0026)
    assert tl[-1]["status"] == "COMPLETED"
    other = gw.client.get(
        f"/v1/runs/{rid}/timeline", headers=gw.headers(gw.world.other_token)
    ).json()["events"]
    assert len(other) == 5  # only the other agent's own action


@pytest.mark.parametrize(
    ("body", "fields"),
    [
        ({"tool": "public_doc_search", "environment": "dev", "args": {}}, ["run_id"]),
        (
            {"run_id": "x", "tool": "public_doc_search", "environment": "dev", "args": {}},
            ["run_id"],
        ),
        (
            {"run_id": str(uuid.uuid4()), "tool": "t", "environment": "moon", "args": {}},
            ["environment"],
        ),
        (
            {"run_id": str(uuid.uuid4()), "tool": "t", "environment": "dev", "args": [CANARY]},
            ["args"],
        ),
        (
            {"run_id": str(uuid.uuid4()), "tool": "t", "environment": "dev", "args": {}, CANARY: 1},
            [CANARY],
        ),
    ],
)
def test_envelope_errors_422_field_names_only(gw, body, fields) -> None:
    r = gw.client.post("/v1/actions", json=body, headers=gw.headers())
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "REQUEST_INVALID"
    assert err["fields"] == fields
    assert err["message"] == "Request envelope is invalid."
    if CANARY not in fields:
        assert CANARY not in r.text


def test_ambiguous_or_unknown_version_and_bad_json(gw) -> None:
    r = gw.post("public_doc_search", {"query": "x"}, tool_version="9.9.9")
    assert r.json()["decision"]["matched_rule_ids"] == ["SYS-TOOL-UNKNOWN"]
    bad = gw.client.post("/v1/actions", content=b"{not json", headers=gw.headers())
    assert bad.status_code == 422


def test_payload_too_large(gw) -> None:
    big = {
        "run_id": str(uuid.uuid4()),
        "tool": "t",
        "environment": "dev",
        "args": {"q": "x" * 300_000},
    }
    r = gw.client.post("/v1/actions", json=big, headers=gw.headers())
    assert (r.status_code, r.json()["error"]["code"]) == (413, "PAYLOAD_TOO_LARGE")


def test_unknown_route_and_method(gw) -> None:
    assert gw.client.get("/v1/nope").json()["error"]["code"] == "NOT_FOUND"
    assert gw.client.delete("/v1/tools", headers=gw.headers()).status_code == 405


def test_canary_never_in_logs_or_error_bodies(gw, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    bodies = [
        gw.post("public_doc_search", {"query": CANARY, "limit": CANARY}).text,  # invalid -> DENY
        gw.post("transfer_funds", {"to": CANARY}).text,  # unknown tool
        gw.post("create_ticket", {"title": CANARY}, env="prod").text,  # forbidden env
        gw.post("create_ticket", {"title": CANARY}, key="canary-key").text,
        gw.post("create_ticket", {"title": CANARY + "x"}, key="canary-key").text,  # 409
        gw.post("delete_record", {"record_id": CANARY}).text,
    ]

    def boom(args, ctx):
        raise ValueError(f"adapter blew up with {args}")

    gw.spies.echo.behavior = boom
    bodies.append(gw.post("test_echo", {"text": CANARY}).text)
    # path-parameter validation goes through FastAPI's validator: must not echo input either
    path_err = gw.client.get(f"/v1/actions/{CANARY}", headers=gw.headers())
    assert path_err.status_code == 422
    bodies.append(path_err.text)
    gw.drain()
    for text in bodies:
        assert CANARY not in text
    # httpx records are the *test client's* own request lines (agent side), not gateway output.
    server = [r for r in caplog.records if not r.name.startswith("httpx")]
    assert server  # logging did happen
    for rec in server:
        assert CANARY not in rec.getMessage()
        assert CANARY not in repr(rec.__dict__)
