"""Risk engine v2 (ADR-0026): factors, missing => worst, mandatory rules, thresholds, records."""

from dataclasses import replace
from typing import Any

import pytest

from agw_gateway.crypto.canonical import encode
from agw_gateway.risk import RequestContext, RiskLevel, build_context, evaluate
from agw_gateway.tools.demo import (
    CREATE_TICKET,
    DELETE_RECORD,
    EXPORT_CUSTOMER_DATA,
    PUBLIC_DOC_SEARCH,
    SEND_EMAIL,
    UPDATE_IAM_ROLE,
)
from agw_gateway.tools.metadata import ToolMetadata

from ..riskkit import RISK_POLICY, decide

pytestmark = pytest.mark.unit


def ctx(
    tool: ToolMetadata | None, args: Any = None, env: str | None = "dev", **kw: Any
) -> RequestContext:
    scopes = kw.pop("scopes", frozenset({tool.required_scope}) if tool else frozenset())
    return build_context(
        tool_id=tool.tool_id if tool else "unknown_tool",
        tool=tool,
        args=args,
        environment=env,
        agent_scopes=scopes,
        agent_trust_tier=kw.pop("tier", "standard"),
        delegation_depth=kw.pop("depth", None),
    )


def risk(tool: ToolMetadata | None, args: Any = None, env: str | None = "dev", **kw: Any) -> Any:
    return evaluate(ctx(tool, args, env, **kw), kw.pop("policy", RISK_POLICY))


def factor(r: Any, name: str) -> Any:
    return next(f for f in r.factor_values if f.name == name)


def zero_weights(**over: Any) -> Any:
    factors = {n: f.model_copy(update={"weight": 0}) for n, f in RISK_POLICY.factors.items()}
    return RISK_POLICY.model_copy(update={"factors": factors, **over})


# --------------------------------------------------------------------------- demo tools
@pytest.mark.parametrize(
    ("tool", "args", "env", "score", "level"),
    [
        (PUBLIC_DOC_SEARCH, {"query": "q"}, "dev", 5, "LOW"),
        (PUBLIC_DOC_SEARCH, {"query": "q"}, "prod", 15, "LOW"),
        (CREATE_TICKET, {"title": "t"}, "dev", 20, "MEDIUM"),  # base MEDIUM wins
        (CREATE_TICKET, {"title": "t"}, "staging", 25, "MEDIUM"),
        (DELETE_RECORD, {}, "dev", 50, "CRITICAL"),  # base CRITICAL
        (SEND_EMAIL, {"to": ["a@corp.example"]}, "dev", 30, "MEDIUM"),
        (SEND_EMAIL, {"to": ["a@gmail.example"]}, "dev", 45, "HIGH"),
        (SEND_EMAIL, {"to": [f"u{i}@corp.example" for i in 50 * [0]]}, "dev", 40, "MEDIUM"),
        (
            EXPORT_CUSTOMER_DATA,
            {"destination": "s3://b.corp.example/x", "limit": 10},
            "dev",
            50,
            "HIGH",
        ),
        (UPDATE_IAM_ROLE, {"principal": "p"}, "dev", 50, "CRITICAL"),  # MR-PRIVILEGE
    ],
)
def test_demo_tool_scores(tool: ToolMetadata, args: Any, env: str, score: int, level: str) -> None:
    r = risk(tool, args, env)
    assert (r.score, r.level.name) == (score, level)
    assert r.policy_digest == RISK_POLICY.digest()
    assert (r.policy_id, r.policy_version, r.engine_version) == ("risk-default", 1, "risk-v2")


def test_factor_values_are_vocabulary_labels_not_raw_args() -> None:
    r = risk(SEND_EMAIL, {"to": ["secret.person@gmail.example"]})
    values = {f.name: f.value for f in r.factor_values}
    assert values == {
        "tool_sensitivity": "internal",
        "operation": "create",
        "environment": "dev",
        "data_classification": "internal",
        "reversibility": "irreversible",
        "external_destination": "external",
        "agent_trust_tier": "standard",
        "volume": "single",
        "delegation_depth": "direct",
    }
    assert "secret.person" not in repr(r.to_record())


# --------------------------------------------------------------------------- unknown / missing
def test_unknown_tool_is_high_and_not_scored() -> None:
    r = risk(None, env="dev")
    assert (r.level, r.score, r.matched_rules, r.reasons) == (
        RiskLevel.HIGH,
        0,
        ("MR-MISSING-META",),
        ("TOOL_NOT_REGISTERED",),
    )
    assert r.factor_values == ()


@pytest.mark.parametrize(
    ("change", "env", "missing", "worst"),
    [
        ({"operation_type": None}, "dev", "operation", "execute"),
        ({"operation_type": "obliterate"}, "dev", "operation", "execute"),
        ({"sensitivity": None}, "dev", "tool_sensitivity", "restricted"),
        ({"data_classification": None}, "dev", "data_classification", "pii"),
        ({"reversible": None}, "dev", "reversibility", "irreversible"),
        ({}, None, "environment", "prod"),
        ({}, "mars", "environment", "prod"),
    ],
)
def test_missing_factor_scores_worst_and_floors_high(
    change: dict, env: str | None, missing: str, worst: str
) -> None:
    r = risk(replace(PUBLIC_DOC_SEARCH, **change), {"query": "q"}, env)
    f = factor(r, missing)
    assert (f.value, f.missing) == (worst, True)
    assert f"FACTOR_MISSING:{missing}" in r.reasons
    assert "MR-MISSING-META" in r.matched_rules
    assert r.level >= RiskLevel.HIGH
    assert f.to_record()["miss"] is True


def test_missing_trust_tier_is_untrusted() -> None:
    r = risk(PUBLIC_DOC_SEARCH, {"query": "q"}, tier=None)
    assert (factor(r, "agent_trust_tier").value, factor(r, "agent_trust_tier").missing) == (
        "untrusted",
        True,
    )


def test_missing_base_risk_is_critical() -> None:
    r = risk(replace(PUBLIC_DOC_SEARCH, base_risk=None), {"query": "q"})
    assert r.level is RiskLevel.CRITICAL
    assert "FACTOR_MISSING:base_risk" in r.reasons
    assert "BASE_RISK:CRITICAL" in r.reasons


# --------------------------------------------------------------------------- destination
@pytest.mark.parametrize(
    ("to", "value", "missing"),
    [
        (["a@corp.example"], "internal", False),
        (["a@mail.corp.example"], "internal", False),  # subdomain
        (["a@corp.example.evil"], "external", False),  # suffix trick
        (["a@notcorp.example"], "external", False),
        (["a@corp.example", "b@x.example"], "external", False),  # any external -> external
        (["no-at-sign"], "external", False),  # unparseable -> external
        (["a@b@corp.example"], "external", False),
        ([], "external", True),  # empty -> missing -> worst
        ([1], "external", True),
        ("a@internal.example", "internal", False),  # single string
    ],
)
def test_email_destinations(to: Any, value: str, missing: bool) -> None:
    r = risk(SEND_EMAIL, {"to": to})
    f = factor(r, "external_destination")
    assert (f.value, f.missing) == (value, missing)


@pytest.mark.parametrize(
    ("dest", "value"),
    [
        ("s3://bucket.corp.example/path", "internal"),
        ("https://user@files.internal.example:8443/x", "internal"),
        ("https://corp.example.attacker.example/x", "external"),
        ("https:///nohost", "external"),
        ("ftp://evil.example", "external"),
    ],
)
def test_url_destinations(dest: str, value: str) -> None:
    r = risk(EXPORT_CUSTOMER_DATA, {"destination": dest, "limit": 1})
    assert factor(r, "external_destination").value == value


def test_destination_field_absent_is_missing() -> None:
    r = risk(EXPORT_CUSTOMER_DATA, {"limit": 1})
    assert factor(r, "external_destination").missing


def test_static_external_effect_without_destination_field() -> None:
    assert (
        factor(
            risk(replace(PUBLIC_DOC_SEARCH, external_effect=True), {}), "external_destination"
        ).value
        == "external"
    )


# --------------------------------------------------------------------------- volume, delegation
@pytest.mark.parametrize(
    ("limit", "label", "missing"),
    [
        (1, "single", False),
        (10, "few", False),
        (11, "many", False),
        (1000, "bulk", False),
        (1001, "mass", False),
        (-5, "mass", True),
        (True, "mass", True),  # bool is not a count
        ("7", "mass", True),
        (None, "mass", True),
    ],
)
def test_volume_buckets(limit: Any, label: str, missing: bool) -> None:
    r = risk(EXPORT_CUSTOMER_DATA, {"destination": "s3://b.corp.example/x", "limit": limit})
    f = factor(r, "volume")
    assert (f.value, f.missing) == (label, missing)


def test_tool_without_volume_field_is_single() -> None:
    assert factor(risk(DELETE_RECORD, {}), "volume").value == "single"


def test_negative_volume_in_context_is_missing() -> None:
    c = replace(ctx(EXPORT_CUSTOMER_DATA, {"destination": "x", "limit": 1}), volume=-1)
    assert factor(evaluate(c, RISK_POLICY), "volume").missing


@pytest.mark.parametrize(
    ("depth", "label", "rule"),
    [
        (None, "direct", False),
        (0, "direct", False),
        (1, "one_hop", False),
        (2, "two_hops", False),
        (3, "deep", True),
        (9, "deep", True),
    ],
)
def test_delegation_depth(depth: int | None, label: str, rule: bool) -> None:
    r = risk(PUBLIC_DOC_SEARCH, {"query": "q"}, depth=depth)
    assert factor(r, "delegation_depth").value == label
    assert ("MR-DEEP-DELEGATION" in r.matched_rules) is rule
    assert ("DELEGATION_SELF_DECLARED" in r.reasons) is (depth is not None)
    if rule:
        assert r.forced_effect == "REQUIRE_APPROVAL"


def test_missing_delegation_depth_matches_depth_rule() -> None:
    c = replace(ctx(PUBLIC_DOC_SEARCH, {"query": "q"}), delegation_depth=None)
    r = evaluate(c, RISK_POLICY)
    assert factor(r, "delegation_depth").missing
    assert "MR-DEEP-DELEGATION" in r.matched_rules


# --------------------------------------------------------------------------- mandatory rules
@pytest.mark.parametrize(
    ("tool", "args", "env", "kw", "rule", "floor"),
    [
        (PUBLIC_DOC_SEARCH, {"query": "q"}, "dev", {"scopes": frozenset()}, "MR-NO-SCOPE", "HIGH"),
        (
            replace(DELETE_RECORD, environments_allowed=frozenset({"prod"})),
            {},
            "prod",
            {},
            "MR-DELETE-PROD",
            "CRITICAL",
        ),
        (UPDATE_IAM_ROLE, {"principal": "p"}, "dev", {}, "MR-PRIVILEGE", "CRITICAL"),
        (UPDATE_IAM_ROLE, {"principal": "p"}, "dev", {}, "MR-RESTRICTED-WRITE", "HIGH"),
        (
            EXPORT_CUSTOMER_DATA,
            {"destination": "https://x.example", "limit": 1},
            "dev",
            {},
            "MR-EXTERNAL-TRANSFER",
            "HIGH",
        ),
        (
            EXPORT_CUSTOMER_DATA,
            {"destination": "https://x.example", "limit": 1000},
            "dev",
            {},
            "MR-PII-EXTERNAL-BULK",
            "CRITICAL",
        ),
        (CREATE_TICKET, {"title": "t"}, "dev", {"tier": "untrusted"}, "MR-UNTRUSTED-WRITE", "HIGH"),
    ],
)
def test_each_mandatory_rule(
    tool: Any, args: Any, env: str, kw: dict, rule: str, floor: str
) -> None:
    r = risk(tool, args, env, **kw)
    assert rule in r.matched_rules
    assert r.level >= RiskLevel[floor]
    assert set(
        RISK_POLICY.mandatory_rules[
            [m.rule_id for m in RISK_POLICY.mandatory_rules].index(rule)
        ].control_ids
    ) <= set(r.control_ids)


@pytest.mark.parametrize(
    ("tool", "args", "env", "kw", "rule"),
    [
        (DELETE_RECORD, {}, "dev", {}, "MR-DELETE-PROD"),
        (CREATE_TICKET, {"title": "t"}, "dev", {}, "MR-PRIVILEGE"),
        (
            EXPORT_CUSTOMER_DATA,
            {"destination": "s3://b.corp.example", "limit": 5000},
            "dev",
            {},
            "MR-PII-EXTERNAL-BULK",
        ),
        (SEND_EMAIL, {"to": ["a@x.example"]}, "dev", {}, "MR-EXTERNAL-TRANSFER"),  # internal data
        (PUBLIC_DOC_SEARCH, {"query": "q"}, "dev", {"tier": "untrusted"}, "MR-UNTRUSTED-WRITE"),
        (PUBLIC_DOC_SEARCH, {"query": "q"}, "dev", {"tier": "trusted"}, "MR-UNTRUSTED-WRITE"),
        (CREATE_TICKET, {"title": "t"}, "dev", {}, "MR-RESTRICTED-WRITE"),
        (
            EXPORT_CUSTOMER_DATA,
            {"destination": "https://x.example", "limit": 5},
            "dev",
            {},
            "MR-PII-EXTERNAL-BULK",
        ),
    ],
)
def test_rules_do_not_fire_when_conditions_fail(
    tool: Any, args: Any, env: str, kw: dict, rule: str
) -> None:
    assert rule not in risk(tool, args, env, **kw).matched_rules


def test_mandatory_rule_beats_score_prod_delete_without_scope_is_deny() -> None:
    """Required test: with every weight zero the score is 0 (LOW), yet the rules force DENY
    and a CRITICAL floor; the decision is DENY."""
    policy = zero_weights()
    prod_delete = replace(DELETE_RECORD, base_risk="LOW", environments_allowed=frozenset({"prod"}))
    r = risk(prod_delete, {}, "prod", scopes=frozenset(), policy=policy)
    assert r.score == 0
    assert "SCORE_LEVEL:LOW" in r.reasons
    assert (r.level, r.forced_effect) == (RiskLevel.CRITICAL, "DENY")
    assert set(r.forcing_rules) == {"MR-NO-SCOPE"}
    assert {"MR-NO-SCOPE", "MR-DELETE-PROD"} <= set(r.matched_rules)
    d = decide(
        "delete_record",
        {"record_id": "0190f4c4-0000-7000-8000-000000000001"},
        "prod",
        scopes=frozenset(),
        tool=prod_delete,
        risk_policy=policy,
    )
    assert d.effect == "DENY"
    # Even WITH the scope and a permissive document, the CRITICAL floor still denies.
    from agw_gateway.policies import load_policy_document

    allow_all = load_policy_document(
        {
            "policy_id": "p",
            "version": 1,
            "default_effect": "DENY",
            "rules": [{"rule_id": "allow-all", "effect": "ALLOW"}],
        }
    )
    d = decide(
        "delete_record",
        {"record_id": "0190f4c4-0000-7000-8000-000000000001"},
        "prod",
        tool=prod_delete,
        risk_policy=policy,
        policy=allow_all,
    )
    assert (d.risk.score, d.effect) == (0, "DENY")


def test_forced_effects_take_the_strictest() -> None:
    rules = list(RISK_POLICY.mandatory_rules)
    approval = rules[0].model_copy(
        update={"rule_id": "A", "effect": "REQUIRE_APPROVAL", "floor": None}
    )
    deny = rules[0].model_copy(update={"rule_id": "D", "effect": "DENY"})
    approval2 = rules[0].model_copy(update={"rule_id": "A2", "effect": "REQUIRE_APPROVAL"})
    policy = RISK_POLICY.model_copy(update={"mandatory_rules": (approval, deny, approval2)})
    r = risk(PUBLIC_DOC_SEARCH, {"query": "q"}, scopes=frozenset(), policy=policy)
    assert (r.forced_effect, r.forcing_rules) == ("DENY", ("A", "D", "A2"))
    assert not any(x.startswith("RULE_FLOOR:A:") for x in r.reasons)


@pytest.mark.parametrize(
    ("score_policy", "level"),
    [
        ({"MEDIUM": 6, "HIGH": 7, "CRITICAL": 8}, "LOW"),
        ({"MEDIUM": 5, "HIGH": 7, "CRITICAL": 8}, "MEDIUM"),
        ({"MEDIUM": 1, "HIGH": 5, "CRITICAL": 8}, "HIGH"),
        ({"MEDIUM": 1, "HIGH": 2, "CRITICAL": 5}, "CRITICAL"),
    ],
)
def test_threshold_boundaries(score_policy: dict, level: str) -> None:
    th = RISK_POLICY.thresholds.model_copy(update=score_policy)
    r = risk(
        PUBLIC_DOC_SEARCH, {"query": "q"}, policy=RISK_POLICY.model_copy(update={"thresholds": th})
    )
    assert r.score == 5
    assert r.level is RiskLevel[level]


def test_risk_record_is_canonical_and_complete() -> None:
    r = risk(EXPORT_CUSTOMER_DATA, {"destination": "https://x.example", "limit": 1})
    rec = r.to_record()
    assert set(rec) == {
        "level",
        "score",
        "rules",
        "cv",
        "pid",
        "pver",
        "pd",
        "f",
        "reasons",
        "forced",
    }
    assert rec["forced"] == "REQUIRE_APPROVAL"
    assert encode(rec) == encode(
        risk(EXPORT_CUSTOMER_DATA, {"destination": "https://x.example", "limit": 1}).to_record()
    )
    assert "forced" not in risk(PUBLIC_DOC_SEARCH, {"query": "q"}).to_record()
    from agw_schemas.events import Risk

    Risk.model_validate(rec)  # the header model accepts it
