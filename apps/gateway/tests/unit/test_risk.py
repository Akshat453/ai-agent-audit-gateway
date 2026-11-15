"""Risk v1 (04 §2): score bands, base risk, every mandatory rule, missing metadata."""

from dataclasses import replace

import pytest

from agw_gateway.risk import RiskLevel, classify
from agw_gateway.risk.classifier import score_level
from agw_gateway.tools.demo import CREATE_TICKET, DELETE_RECORD, PUBLIC_DOC_SEARCH

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (0, "LOW"),
        (24, "LOW"),
        (25, "MEDIUM"),
        (49, "MEDIUM"),
        (50, "HIGH"),
        (74, "HIGH"),
        (75, "CRITICAL"),
    ],
)
def test_score_bands(score: int, level: str) -> None:
    assert score_level(score) is RiskLevel[level]


def test_demo_table_04_s6() -> None:
    s = classify(PUBLIC_DOC_SEARCH, "dev")
    assert (s.level, s.score, s.mandatory_rule_ids) == (RiskLevel.LOW, 0, ())
    c = classify(CREATE_TICKET, "dev")
    assert (c.level, c.score) == (RiskLevel.MEDIUM, 20)  # score LOW, base MEDIUM wins
    d = classify(DELETE_RECORD, "dev")
    assert d.level is RiskLevel.CRITICAL
    assert classify(None, "dev").level is RiskLevel.HIGH
    assert classify(None, "dev").mandatory_rule_ids == ("MR-MISSING-META",)


def test_environment_raises_score() -> None:
    assert classify(PUBLIC_DOC_SEARCH, "staging").score == 10
    assert classify(PUBLIC_DOC_SEARCH, "prod").level is RiskLevel.MEDIUM
    assert classify(PUBLIC_DOC_SEARCH, "mars").score == 30  # unknown env scored as prod


@pytest.mark.parametrize(
    ("changes", "env", "rule", "floor"),
    [
        (
            {"operation_type": "delete", "base_risk": "LOW", "sensitivity": "public"},
            "prod",
            "MR-DELETE-PROD",
            "CRITICAL",
        ),
        ({"tags": frozenset({"privilege_change"})}, "dev", "MR-PRIVILEGE", "CRITICAL"),
        ({"tags": frozenset({"credential_access"})}, "dev", "MR-PRIVILEGE", "CRITICAL"),
        (
            {"sensitivity": "restricted", "operation_type": "create"},
            "dev",
            "MR-RESTRICTED-WRITE",
            "HIGH",
        ),
        (
            {"external_effect": True, "sensitivity": "confidential"},
            "dev",
            "MR-EXTERNAL-TRANSFER",
            "HIGH",
        ),
        ({"operation_type": None}, "dev", "MR-MISSING-META", "HIGH"),
        ({"sensitivity": "weird"}, "dev", "MR-MISSING-META", "HIGH"),
        ({"base_risk": None}, "dev", "MR-MISSING-META", "HIGH"),
    ],
)
def test_mandatory_rules_raise_level(changes: dict, env: str, rule: str, floor: str) -> None:
    tool = replace(PUBLIC_DOC_SEARCH, **changes)
    r = classify(tool, env)
    assert rule in r.mandatory_rule_ids
    assert r.level >= RiskLevel[floor]


def test_mandatory_rules_never_lower() -> None:
    tool = replace(DELETE_RECORD, tags=frozenset({"privilege_change"}))
    assert classify(tool, "dev").level is RiskLevel.CRITICAL


def test_deterministic() -> None:
    assert classify(CREATE_TICKET, "staging") == classify(CREATE_TICKET, "staging")
