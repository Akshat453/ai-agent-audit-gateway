"""ADR-0039: every rule id a decision can carry has a plain-English description.

Rule ids are collected from the SOURCE (string literals in the places that emit them), so a new
rule without a description fails here."""

from __future__ import annotations

import re
from pathlib import Path

from agw_gateway.policies import descriptions
from agw_gateway.policies.default_policy import DEFAULT_POLICY_DOCUMENT, DEFAULT_POLICY_V2
from agw_gateway.risk.policy import load_risk_policy_toml

SRC = Path(__file__).resolve().parents[2] / "src" / "agw_gateway"
_ID = re.compile(
    r'"((?:PATH|CMD|GIT|CONTENT|WEB|MCP|CODE|SECRET|PKG|NET|REPO|HITL|APPROVAL|SYS|CAP|LVL|CX|GH)'
    r'-[A-Z0-9-]+)"'
)


def _literal_ids() -> set[str]:
    ids: set[str] = set()
    for sub in ("coding", "policies", "github", "connectors"):
        for f in (SRC / sub).rglob("*.py"):
            ids.update(_ID.findall(f.read_text("utf-8")))
    return ids


def test_every_emitted_rule_id_has_a_description() -> None:
    ids = _literal_ids()
    assert len(ids) > 60, ids  # the scan really found the coding + system rules
    missing = sorted(i for i in ids if descriptions.describe(i) is None)
    assert missing == []


def test_policy_documents_and_risk_rules_are_described() -> None:
    doc_ids = {
        r["rule_id"] for d in (DEFAULT_POLICY_DOCUMENT, DEFAULT_POLICY_V2) for r in d["rules"]
    }
    risk = load_risk_policy_toml((SRC / "risk" / "default_risk_policy.toml").read_text("utf-8"))
    risk_ids = {r.rule_id for r in risk.mandatory_rules}
    missing = sorted(
        i for i in doc_ids | risk_ids | {"default-deny"} if descriptions.describe(i) is None
    )
    assert missing == []


def test_dynamic_families_use_patterns() -> None:
    assert "version 3" in (descriptions.describe("REPO-OVERLAY-v3") or {})["why"]
    assert "gh@v7" in (descriptions.describe("cx:gh@v7") or {})["why"]
    assert "CLONE_FAILED" in (descriptions.describe("GH-CLONE_FAILED") or {})["why"]
    assert descriptions.describe("NOT-A-RULE") is None


def test_descriptions_are_short_plain_sentences() -> None:
    d = descriptions.load()
    for rid, e in {**d["rules"], **d["patterns"]}.items():
        assert 0 < len(e["name"]) <= 40, rid
        assert e["why"].endswith(".") and len(e["why"]) <= 160, rid
    assert {"policy_id": "coding-mintrail", "versions": [1, 2]} in d["policies"]
