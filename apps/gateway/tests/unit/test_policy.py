"""Policy engine v2 (04 §3-4, ADR-0026): system checks, risk-forced effects, document rules
(deny-overrides, default deny), per-level defaults, CRITICAL exceptions, loader fail-closed."""

import copy
import importlib.util
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from agw_gateway.policies import PolicyLoadError, ReasonCode, load_policy_document
from agw_gateway.policies.default_policy import DEFAULT_POLICY_DOCUMENT, DEFAULT_POLICY_V2
from agw_gateway.tools.demo import (
    CREATE_TICKET,
    DELETE_RECORD,
    PUBLIC_DOC_SEARCH,
    UPDATE_IAM_ROLE,
)

from ..riskkit import ALL_TOOL_SCOPES, decide

pytestmark = pytest.mark.unit

SEARCH = {"query": "evidence", "limit": 3}
TICKET = {"title": "t"}
RID = {"record_id": "0190f4c4-0000-7000-8000-000000000001"}
IAM = {"principal": "svc-build", "role": "editor"}


def _policy(rules: list[dict[str, Any]], version: int = 3) -> Any:
    return load_policy_document(
        {"policy_id": "p", "version": version, "default_effect": "DENY", "rules": rules}
    )


def test_demo_outcomes() -> None:
    d = decide("public_doc_search", SEARCH)
    assert (d.effect, d.matched_rule_ids, d.reasons) == ("ALLOW", ("allow-low",), ())
    assert d.risk.level.name == "LOW"
    d = decide("create_ticket", TICKET)
    assert (d.effect, d.matched_rule_ids, d.risk.level.name) == (
        "ALLOW",
        ("allow-medium",),
        "MEDIUM",
    )
    d = decide("delete_record", RID)
    assert d.effect == "DENY"
    assert d.matched_rule_ids == ("deny-delete-record", "CAP-CRITICAL-DENY")
    assert d.reasons == (ReasonCode.POLICY_RULE_DENY, ReasonCode.CRITICAL_DENIED)
    d = decide("transfer_funds", {"amount": "1"})
    assert (d.effect, d.matched_rule_ids) == ("DENY", ("SYS-TOOL-UNKNOWN",))
    assert d.risk.level.name == "HIGH"
    assert (d.policy_id, d.policy_version, d.engine_version) == ("default", 2, "policy-v2")


@pytest.mark.parametrize(
    ("kwargs", "rule", "reason"),
    [
        ({"tool_id": "nope"}, "SYS-TOOL-UNKNOWN", ReasonCode.TOOL_NOT_REGISTERED),
        ({"args": {"query": 5}}, "SYS-ARGS-INVALID", ReasonCode.ARGS_SCHEMA_INVALID),
        (
            {"tool_id": "create_ticket", "args": TICKET, "env": "prod"},
            "SYS-ENV-FORBIDDEN",
            ReasonCode.ENVIRONMENT_NOT_ALLOWED,
        ),
        ({"env": None}, "SYS-ENV-FORBIDDEN", ReasonCode.ENVIRONMENT_NOT_ALLOWED),
        (
            {"tool_id": "create_ticket", "args": TICKET, "scopes": frozenset({"x"})},
            "SYS-SCOPE-MISSING",
            ReasonCode.SCOPE_MISSING,
        ),
        ({"active": False}, "SYS-AGENT-DISABLED", ReasonCode.AGENT_DISABLED),
    ],
)
def test_system_checks_deny(kwargs: dict, rule: str, reason: ReasonCode) -> None:
    kwargs.setdefault("tool_id", "public_doc_search")
    kwargs.setdefault("args", SEARCH)
    d = decide(kwargs.pop("tool_id"), kwargs.pop("args"), **kwargs)
    assert (d.effect, d.matched_rule_ids, d.reasons) == ("DENY", (rule,), (reason,))


def test_system_check_order_unknown_before_args() -> None:
    assert decide("nope", {"x": 1}).matched_rule_ids == ("SYS-TOOL-UNKNOWN",)


def test_missing_scope_is_also_a_risk_rule() -> None:
    """The risk engine sees the missing scope too (MR-NO-SCOPE -> DENY, floor HIGH), so the
    denial is sealed promptly even though the system check already denies it."""
    d = decide("public_doc_search", SEARCH, scopes=frozenset())
    assert "MR-NO-SCOPE" in d.risk.matched_rules
    assert d.risk.forced_effect == "DENY"
    assert d.risk.level.name == "HIGH"


def test_default_deny_when_no_document_rule_matches() -> None:
    p = _policy([{"rule_id": "only-search", "effect": "ALLOW", "match": {"tools": ["x"]}}])
    d = decide("public_doc_search", SEARCH, policy=p)
    assert (d.effect, d.matched_rule_ids, d.reasons) == (
        "DENY",
        ("default-deny",),
        (ReasonCode.NO_MATCHING_ALLOW,),
    )


def test_medium_follows_tool_config() -> None:
    p = _policy([{"rule_id": "allow-all", "effect": "ALLOW"}])
    allow = decide("create_ticket", TICKET, policy=p)
    assert (allow.risk.level.name, allow.effect) == ("MEDIUM", "ALLOW")
    approval_tool = replace(CREATE_TICKET, medium_effect="REQUIRE_APPROVAL")
    d = decide("create_ticket", TICKET, policy=p, tool=approval_tool)
    assert (d.effect, d.matched_rule_ids[-1]) == ("REQUIRE_APPROVAL", "LVL-MEDIUM-APPROVAL")
    assert d.reasons == (ReasonCode.MEDIUM_REQUIRES_APPROVAL,)
    missing = replace(CREATE_TICKET, medium_effect=None)  # missing config -> approval
    assert decide("create_ticket", TICKET, policy=p, tool=missing).effect == "REQUIRE_APPROVAL"


def test_high_requires_approval_unless_exempt() -> None:
    high = replace(PUBLIC_DOC_SEARCH, base_risk="HIGH", is_idempotent=True)
    p = _policy([{"rule_id": "allow-all", "effect": "ALLOW"}])
    d = decide("public_doc_search", SEARCH, policy=p, tool=high)
    assert (d.effect, d.matched_rule_ids) == (
        "REQUIRE_APPROVAL",
        ("allow-all", "CAP-HIGH-APPROVAL"),
    )
    exempt = _policy(
        [{"rule_id": "allow-all", "effect": "ALLOW", "allow_high_without_approval": True}]
    )
    assert decide("public_doc_search", SEARCH, policy=exempt, tool=high).effect == "ALLOW"
    non_idem = replace(high, is_idempotent=False)
    assert decide("public_doc_search", SEARCH, policy=exempt, tool=non_idem).effect == (
        "REQUIRE_APPROVAL"
    )
    # Default v2 document: approve-high fires as well.
    d = decide(
        "export_customer_data",
        {"destination": "s3://x.corp.example/e", "limit": 5, "fields": ["id"]},
    )
    assert d.risk.level.name == "HIGH"
    assert d.effect == "REQUIRE_APPROVAL"
    assert {"approve-high", "CAP-HIGH-APPROVAL"} <= set(d.matched_rule_ids)


def test_critical_is_deny_even_if_the_document_allows() -> None:
    p = _policy([{"rule_id": "allow-all", "effect": "ALLOW"}])
    d = decide("delete_record", RID, policy=p)
    assert (d.effect, d.matched_rule_ids, d.reasons) == (
        "DENY",
        ("allow-all", "CAP-CRITICAL-DENY"),
        (ReasonCode.CRITICAL_DENIED,),
    )


def test_critical_exception_rule_gives_approval_never_allow() -> None:
    no_admin = decide("update_iam_role", IAM)
    assert (no_admin.risk.level.name, no_admin.effect) == ("CRITICAL", "DENY")
    assert "MR-PRIVILEGE" in no_admin.risk.matched_rules
    admin = decide("update_iam_role", IAM, scopes=ALL_TOOL_SCOPES | {"iam:admin"})
    assert admin.effect == "REQUIRE_APPROVAL"
    assert admin.matched_rule_ids == ("iam-change-exception", "CAP-CRITICAL-EXCEPTION")
    assert admin.reasons == (
        ReasonCode.POLICY_REQUIRES_APPROVAL,
        ReasonCode.CRITICAL_REQUIRES_APPROVAL,
    )
    assert {"HITL-APPROVAL", "SOD-REVIEW", "AGW-CTRL-03"} <= set(admin.control_ids)
    prod = decide("update_iam_role", IAM, env="prod", scopes=ALL_TOOL_SCOPES | {"iam:admin"})
    assert prod.effect == "DENY"  # the exception is limited to dev/staging
    assert UPDATE_IAM_ROLE.tags == frozenset({"privilege_change"})


def test_exception_rules_must_require_approval() -> None:
    with pytest.raises(PolicyLoadError):
        _policy([{"rule_id": "x", "effect": "ALLOW", "critical_exception": True}])


def test_risk_forced_effects_beat_document_allow() -> None:
    p = _policy([{"rule_id": "allow-all", "effect": "ALLOW"}])
    ext = {"destination": "https://evil.example/drop", "limit": 5, "fields": ["email"]}
    d = decide("export_customer_data", ext, policy=p)
    assert d.risk.forced_effect == "REQUIRE_APPROVAL"
    assert d.matched_rule_ids[0] == "MR-EXTERNAL-TRANSFER"
    assert ReasonCode.RISK_RULE_REQUIRES_APPROVAL in d.reasons
    bulk = {**ext, "limit": 5000}
    d = decide("export_customer_data", bulk, policy=p)
    assert d.effect == "DENY"
    assert d.reasons[0] == ReasonCode.RISK_RULE_DENY
    assert "MR-PII-EXTERNAL-BULK" in d.matched_rule_ids


def test_deny_overrides_and_controls_and_match_fields() -> None:
    p = _policy(
        [
            {"rule_id": "a", "effect": "ALLOW", "control_ids": ["C1"]},
            {
                "rule_id": "b",
                "effect": "REQUIRE_APPROVAL",
                "match": {"scopes_any": ["tools:public_doc_search"]},
                "control_ids": ["C2", "C1"],
            },
            {
                "rule_id": "c",
                "effect": "DENY",
                "match": {
                    "agent_ids": ["00000000-0000-0000-0000-000000000007"],
                    "tool_versions": ["1.0.0"],
                    "sensitivities": ["public"],
                },
            },
            {"rule_id": "d", "effect": "DENY", "match": {"scopes_any": ["nope"]}},
        ]
    )
    d = decide("public_doc_search", SEARCH, policy=p)
    assert (d.effect, d.matched_rule_ids, d.control_ids) == ("DENY", ("a", "b", "c"), ("C1", "C2"))
    p2 = _policy([r for r in p.model_dump()["rules"] if r["rule_id"] != "c"])
    assert decide("public_doc_search", SEARCH, policy=p2).effect == "REQUIRE_APPROVAL"


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
    doc = copy.deepcopy(DEFAULT_POLICY_V2)
    mutate(doc)
    with pytest.raises(PolicyLoadError):
        load_policy_document(doc)


def _migration(name: str) -> Any:
    path = Path(__file__).resolve().parents[2] / f"migrations/versions/{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_default_policies_match_migration_seeds() -> None:
    assert _migration("0001_phase1_core").DEFAULT_POLICY_V1 == DEFAULT_POLICY_DOCUMENT
    assert _migration("0004_phase4_risk").DEFAULT_POLICY_V2 == DEFAULT_POLICY_V2
    load_policy_document(DEFAULT_POLICY_DOCUMENT)  # v1 still loads (old decisions replay)


def test_demo_tool_risk_backfill_matches_code() -> None:
    backfill = _migration("0004_phase4_risk").DEMO_TOOL_RISK
    for meta in (PUBLIC_DOC_SEARCH, CREATE_TICKET, DELETE_RECORD):
        assert backfill[(meta.tool_id, meta.version)] == meta.risk_attributes()


def test_deterministic_replay() -> None:
    assert decide("create_ticket", TICKET) == decide("create_ticket", TICKET)
    assert ALL_TOOL_SCOPES
