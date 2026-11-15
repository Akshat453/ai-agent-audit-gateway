"""Policy v1 (04 §3-4): system checks, deny-overrides, default deny, caps, loader fail-closed."""

import copy
import importlib.util
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.policies import (
    EvaluationInput,
    PolicyLoadError,
    ReasonCode,
    evaluate,
    load_policy_document,
)
from agw_gateway.policies.default_policy import DEFAULT_POLICY_DOCUMENT
from agw_gateway.risk import classify
from agw_gateway.tools.demo import CREATE_TICKET, DELETE_RECORD, PUBLIC_DOC_SEARCH
from agw_gateway.tools.metadata import ToolMetadata

pytestmark = pytest.mark.unit

POLICY = load_policy_document(DEFAULT_POLICY_DOCUMENT)
ALL = frozenset(
    {"tools:public_doc_search", "tools:create_ticket", "tools:delete_record", "tools:x"}
)
AGENT = AuthenticatedAgent("demo", uuid.uuid4(), "demo-agent", ALL)


def run(
    tool: ToolMetadata | None,
    *,
    env: str = "dev",
    valid: bool = True,
    agent: AuthenticatedAgent = AGENT,
    policy: Any = POLICY,
) -> Any:
    return evaluate(
        EvaluationInput(
            agent=agent,
            tool=tool,
            args_valid=valid,
            args={} if valid else None,
            environment=env,
            policy=policy,
            risk=classify(tool, env),
            now=datetime.now(UTC),
        )
    )


def test_demo_outcomes_04_s6() -> None:
    d = run(PUBLIC_DOC_SEARCH)
    assert (d.effect, d.matched_rule_ids, d.reasons) == ("ALLOW", ("allow-low-read",), ())
    d = run(CREATE_TICKET)
    assert (d.effect, d.matched_rule_ids) == ("ALLOW", ("allow-medium-ticket",))
    d = run(DELETE_RECORD)
    assert d.effect == "DENY"
    assert d.matched_rule_ids == ("deny-delete-record", "deny-critical")  # all, document order
    d = run(None)
    assert (d.effect, d.matched_rule_ids) == ("DENY", ("SYS-TOOL-UNKNOWN",))
    assert d.risk.level.name == "HIGH"
    assert (d.policy_id, d.policy_version, d.engine_version) == ("default", 1, "policy-v1")


@pytest.mark.parametrize(
    ("kwargs", "rule", "reason"),
    [
        ({"tool": None}, "SYS-TOOL-UNKNOWN", ReasonCode.TOOL_NOT_REGISTERED),
        ({"valid": False}, "SYS-ARGS-INVALID", ReasonCode.ARGS_SCHEMA_INVALID),
        (
            {"tool": CREATE_TICKET, "env": "prod"},
            "SYS-ENV-FORBIDDEN",
            ReasonCode.ENVIRONMENT_NOT_ALLOWED,
        ),
        (
            {
                "agent": replace(AGENT, scopes=frozenset({"tools:public_doc_search"})),
                "tool": CREATE_TICKET,
            },
            "SYS-SCOPE-MISSING",
            ReasonCode.SCOPE_MISSING,
        ),
        ({"agent": replace(AGENT, active=False)}, "SYS-AGENT-DISABLED", ReasonCode.AGENT_DISABLED),
    ],
)
def test_system_checks_deny(kwargs: dict, rule: str, reason: ReasonCode) -> None:
    kwargs.setdefault("tool", PUBLIC_DOC_SEARCH)
    tool = kwargs.pop("tool")
    d = run(tool, **kwargs)
    assert (d.effect, d.matched_rule_ids, d.reasons) == ("DENY", (rule,), (reason,))


def test_system_check_order_unknown_before_args() -> None:
    assert run(None, valid=False).matched_rule_ids == ("SYS-TOOL-UNKNOWN",)


def test_default_deny_when_nothing_matches() -> None:
    d = run(PUBLIC_DOC_SEARCH, env="prod")  # prod -> MEDIUM; allow-low-read needs LOW
    assert d.effect == "DENY"
    assert d.matched_rule_ids == ("default-deny",)
    assert d.reasons == (ReasonCode.NO_MATCHING_ALLOW,)


def test_high_risk_requires_approval() -> None:
    tool = replace(
        PUBLIC_DOC_SEARCH,
        tool_id="tx",
        sensitivity="restricted",
        operation_type="update",
        required_scope="tools:x",
    )
    d = run(tool)
    assert d.effect == "REQUIRE_APPROVAL"
    assert "approve-high" in d.matched_rule_ids


def _policy(rules: list[dict[str, Any]]) -> Any:
    return load_policy_document(
        {"policy_id": "p", "version": 3, "default_effect": "DENY", "rules": rules}
    )


def test_cap_critical_allow_becomes_approval() -> None:
    p = _policy([{"rule_id": "allow-all", "effect": "ALLOW"}])
    d = run(DELETE_RECORD, policy=p)
    assert d.effect == "REQUIRE_APPROVAL"
    assert d.matched_rule_ids == ("allow-all", "CAP-CRITICAL-APPROVAL")


def test_cap_high_allow_becomes_approval_unless_exempt() -> None:
    high = replace(
        PUBLIC_DOC_SEARCH,
        tool_id="tx",
        sensitivity="restricted",
        operation_type="update",
        required_scope="tools:x",
        is_idempotent=True,
    )
    p = _policy([{"rule_id": "allow-all", "effect": "ALLOW"}])
    assert run(high, policy=p).matched_rule_ids[-1] == "CAP-HIGH-APPROVAL"
    exempt = _policy(
        [{"rule_id": "allow-all", "effect": "ALLOW", "allow_high_without_approval": True}]
    )
    assert run(high, policy=exempt).effect == "ALLOW"
    non_idem = replace(high, is_idempotent=False)
    assert run(non_idem, policy=exempt).effect == "REQUIRE_APPROVAL"


def test_deny_overrides_and_controls_and_match_fields() -> None:
    p = _policy(
        [
            {"rule_id": "a", "effect": "ALLOW", "control_ids": ["C1"]},
            {
                "rule_id": "b",
                "effect": "REQUIRE_APPROVAL",
                "match": {"scopes_any": ["tools:x"]},
                "control_ids": ["C2", "C1"],
            },
            {
                "rule_id": "c",
                "effect": "DENY",
                "match": {
                    "agent_ids": [str(AGENT.agent_id)],
                    "tool_versions": ["1.0.0"],
                    "sensitivities": ["public"],
                },
            },
            {"rule_id": "d", "effect": "DENY", "match": {"scopes_any": ["nope"]}},
        ]
    )
    d = run(PUBLIC_DOC_SEARCH, policy=p)
    assert (d.effect, d.matched_rule_ids, d.control_ids) == ("DENY", ("a", "b", "c"), ("C1", "C2"))
    other = replace(AGENT, agent_id=uuid.uuid4())
    assert run(PUBLIC_DOC_SEARCH, policy=p, agent=other).effect == "REQUIRE_APPROVAL"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(default_effect="ALLOW"),
        lambda d: d["rules"][0]["match"].update(tool_name=["x"]),  # unknown match key
        lambda d: d["rules"][0].update(effect="MAYBE"),
        lambda d: d["rules"].append(dict(d["rules"][0])),  # duplicate rule_id
        lambda d: d.update(version=0),
        lambda d: d.update(surprise=True),
        lambda d: d["rules"][0]["match"].update(risk_levels=["SEVERE"]),
    ],
)
def test_loader_fails_closed(mutate: Any) -> None:
    doc = copy.deepcopy(DEFAULT_POLICY_DOCUMENT)
    mutate(doc)
    with pytest.raises(PolicyLoadError):
        load_policy_document(doc)


def test_default_policy_matches_migration_seed() -> None:
    path = Path(__file__).resolve().parents[2] / "migrations/versions/0001_phase1_core.py"
    spec = importlib.util.spec_from_file_location("mig0001", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.DEFAULT_POLICY_V1 == DEFAULT_POLICY_DOCUMENT


def test_deterministic_replay() -> None:
    assert run(CREATE_TICKET) == run(CREATE_TICKET)
