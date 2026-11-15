"""Tool spec contract, strict validation, registry lookup, crash points, evidence record schema."""

import uuid
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.evidence.writer import EvidenceSchemaError, NewEvent
from agw_gateway.execution.crash import CrashPoints, SimulatedCrash
from agw_gateway.ids import uuid7
from agw_gateway.tools.demo import PUBLIC_DOC_SEARCH, demo_tool_specs
from agw_gateway.tools.metadata import ToolMetadata
from agw_gateway.tools.registry import AmbiguousToolVersion, ToolRegistry
from agw_gateway.tools.spec import ToolSpec, ToolSpecError

pytestmark = pytest.mark.unit

SPECS = {s.meta.tool_id: s for s in demo_tool_specs()}


class Lax(BaseModel):
    q: str


class Floaty(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    amount: float


@pytest.mark.parametrize("model", [Lax, Floaty])
def test_spec_rejects_non_strict_or_float_models(model: type[BaseModel]) -> None:
    with pytest.raises(ToolSpecError):
        ToolSpec(PUBLIC_DOC_SEARCH, model, SPECS["public_doc_search"].adapter)


@pytest.mark.parametrize(
    ("tool", "args", "ok"),
    [
        ("public_doc_search", {"query": "x"}, True),
        ("public_doc_search", {"query": "x", "limit": 20}, True),
        ("public_doc_search", {"query": ""}, False),
        ("public_doc_search", {"query": "x", "limit": "5"}, False),  # strict: no coercion
        ("public_doc_search", {"query": "x", "limit": 5.0}, False),
        ("public_doc_search", {"query": "x", "extra": 1}, False),  # extra=forbid
        ("public_doc_search", ["query"], False),
        ("create_ticket", {"title": "t", "priority": "urgent"}, False),
        ("create_ticket", {"title": "t" * 121}, False),
        ("delete_record", {"record_id": str(uuid.uuid4())}, True),
        ("delete_record", {"record_id": "not-a-uuid"}, False),
    ],
)
def test_strict_arg_validation(tool: str, args: Any, ok: bool) -> None:
    assert (SPECS[tool].validate_args(args) is not None) is ok


def test_metadata_validation() -> None:
    with pytest.raises(ValueError):
        ToolMetadata("Bad-Id", "1.0.0", "read", "public", "LOW", frozenset(), "s", True, False)
    with pytest.raises(ValueError):
        ToolMetadata("ok_id", "1.0", "read", "public", "LOW", frozenset(), "s", True, False)
    with pytest.raises(ValueError):
        ToolMetadata("ok_id", "1.0.0", "read", "public", "LOW", frozenset(), "", True, False)


def test_registry_unsynced_is_deny_all_and_duplicates_rejected() -> None:
    reg = ToolRegistry(demo_tool_specs())
    assert reg.resolve("public_doc_search", None) is None
    assert reg.resolve("public_doc_search", "1.0.0") is None
    agent = AuthenticatedAgent("t", uuid.uuid4(), "a", frozenset({"tools:public_doc_search"}))
    assert reg.callable_for(agent) == []
    assert reg.get_any("public_doc_search", "1.0.0") is not None
    with pytest.raises(ToolSpecError):
        ToolRegistry([*demo_tool_specs(), *demo_tool_specs()])


def test_registry_ambiguous_version() -> None:
    v1 = SPECS["public_doc_search"]
    from dataclasses import replace

    v2 = ToolSpec(replace(v1.meta, version="2.0.0"), v1.args_model, v1.adapter)
    reg = ToolRegistry([v1, v2])
    reg._enabled = frozenset({v1.key, v2.key})  # simulate a sync with both enabled
    with pytest.raises(AmbiguousToolVersion):
        reg.resolve("public_doc_search", None)
    assert reg.resolve("public_doc_search", "2.0.0") is v2


def test_crash_points_disabled_outside_test() -> None:
    with pytest.raises(RuntimeError):
        CrashPoints("prod").arm("after_tx1_commit")
    cp = CrashPoints("test")
    with pytest.raises(ValueError):
        cp.arm("nowhere")
    cp.arm("after_claim")
    with pytest.raises(SimulatedCrash):
        cp.hit("after_claim")
    cp.hit("after_claim")  # one-shot


@pytest.mark.parametrize(
    "kwargs",
    [
        {"type": "ACTION_TELEPORTED"},
        {"actor_kind": "robot"},
        {"fields": {"args_plaintext": "x"}},  # unknown record key (05 §4)
        {"fields": {"env": None}},  # absent fields are omitted, never null
    ],
)
def test_event_schema_rejects(kwargs: dict) -> None:
    base: dict[str, Any] = {"type": "ACTION_REQUESTED", "actor_kind": "agent", "actor_id": "a"}
    base.update(kwargs)
    with pytest.raises(EvidenceSchemaError):
        NewEvent(**base)


def test_uuid7_shape_and_order() -> None:
    a, b = uuid7(), uuid7()
    assert a.version == 7 and a.variant == "specified in RFC 4122"
    assert a.int >> 80 <= b.int >> 80
