"""INV-2 end to end: random tool names and arg dicts never reach an adapter unless the tool is
registered AND the args are valid AND the decision is ALLOW."""

import uuid
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import select

from agw_gateway.db import tables as t

pytestmark = [pytest.mark.e2e, pytest.mark.property]

json_scalars = st.none() | st.booleans() | st.integers(-(2**31), 2**31) | st.text(max_size=20)
values = st.recursive(
    json_scalars,
    lambda c: st.lists(c, max_size=2) | st.dictionaries(st.text(max_size=5), c, max_size=2),
    max_leaves=5,
)
keys = st.sampled_from(
    ["query", "limit", "title", "body", "priority", "record_id", "text", "name"]
) | st.text(max_size=6)
tools = st.sampled_from(
    [
        "public_doc_search",
        "create_ticket",
        "delete_record",
        "test_echo",
        "test_restricted_update",
        "rm_rf",
        "Create_Ticket",
    ]
) | st.from_regex(r"[A-Za-z0-9_.\-]{1,20}", fullmatch=True)


@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    tool=tools,
    args=st.dictionaries(keys, values, max_size=3),
    env=st.sampled_from(["dev", "staging", "prod"]),
)
def test_random_calls_reach_adapter_only_if_allowed(
    gw, tool: str, args: dict[str, Any], env: str
) -> None:
    before = gw.spies.total_calls()
    r = gw.post(tool, args, env=env)
    assert r.status_code == 201
    data = r.json()
    gw.drain()
    called = gw.spies.total_calls() - before
    spec = gw.state.registry.resolve(tool, None)
    valid = spec is not None and spec.validate_args(args) is not None
    if called:
        assert called == 1
        assert spec is not None and valid and data["decision"]["effect"] == "ALLOW"
        assert tool not in {"delete_record", "test_restricted_update"}
    if data["decision"]["effect"] != "ALLOW":
        assert called == 0
        with gw.engine.connect() as conn:
            jobs = conn.execute(
                select(t.outbox_jobs.c.job_id).where(
                    t.outbox_jobs.c.action_id == uuid.UUID(data["action_id"])
                )
            ).all()
        assert jobs == []
