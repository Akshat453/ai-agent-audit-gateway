"""Labeled-action regression for the risk engine (Phase 4; start of RQ/E4).

Runs every case in ``labeled_actions.jsonl`` through the PRODUCTION pure pipeline
(``agw_gateway.policies.pipeline.decide_action``: tool registry metadata, strict arg validation,
risk policy ``risk-default`` v1, policy document ``default`` v2) and compares the result with
the hand label. Prints confusion matrices for risk level and decision.

    uv run python experiments/risk/risk_eval.py [--dataset PATH] [--strict]

Dataset format (one JSON object per line):
    id, tool, args, env (null = missing), scopes ("ALL" | "ALL+IAM_ADMIN" | [..]),
    tier (null = missing), depth (null = not declared), expected_level, expected_decision,
    category, note.
    ``{"$emails": [domain, n]}`` in args expands to n addresses u0@domain .. u{n-1}@domain.

Caveat: the labels and the policy weights were written by the same author. Agreement measures
consistency with the intended policy, not validity against real incidents.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.policies import load_policy_document
from agw_gateway.policies.default_policy import DEFAULT_POLICY_V2
from agw_gateway.policies.pipeline import decide_action
from agw_gateway.risk import RiskPolicy, load_risk_policy_toml
from agw_gateway.risk_store import default_risk_policy_text
from agw_gateway.tools.demo import demo_tool_specs

HERE = Path(__file__).resolve().parent
DATASET = HERE / "labeled_actions.jsonl"
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
DECISIONS = ("ALLOW", "REQUIRE_APPROVAL", "DENY")
SPECS = {s.meta.tool_id: s for s in demo_tool_specs()}
TOOL_SCOPES = frozenset(s.meta.required_scope for s in SPECS.values())
NOW = datetime(2026, 11, 15, tzinfo=UTC)  # fixed: evaluation must not depend on the clock


@dataclass(frozen=True)
class Outcome:
    case: dict[str, Any]
    level: str
    decision: str
    rules: tuple[str, ...]
    risk_rules: tuple[str, ...]
    score: int

    @property
    def ok(self) -> bool:
        return (self.level, self.decision) == (
            self.case["expected_level"],
            self.case["expected_decision"],
        )


def _expand(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"$emails"}:
            domain, n = value["$emails"]
            return [f"u{i}@{domain}" for i in range(int(n))]
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def load_dataset(path: Path = DATASET) -> list[dict[str, Any]]:
    cases = [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]
    for c in cases:
        c["args"] = _expand(c["args"])
    return cases


def _scopes(spec: Any) -> frozenset[str]:
    if spec == "ALL":
        return TOOL_SCOPES
    if spec == "ALL+IAM_ADMIN":
        return TOOL_SCOPES | {"iam:admin"}
    return frozenset(spec)


def evaluate_case(case: dict[str, Any], risk_policy: RiskPolicy) -> Outcome:
    spec = SPECS.get(case["tool"])
    validated = spec.validate_args(case["args"]) if spec is not None else None
    d = decide_action(
        agent=AuthenticatedAgent(
            "demo",
            __import__("uuid").UUID(int=1),
            "labeled-agent",
            _scopes(case["scopes"]),
            trust_tier=case["tier"],
        ),
        tool_id=case["tool"],
        tool=spec.meta if spec else None,
        args=validated.model_dump(mode="json") if validated is not None else None,
        environment=case["env"],
        risk_policy=risk_policy,
        policy=load_policy_document(DEFAULT_POLICY_V2),
        now=NOW,
        delegation_depth=case["depth"],
    )
    return Outcome(
        case=case,
        level=d.risk.level.name,
        decision=d.effect,
        rules=d.matched_rule_ids,
        risk_rules=d.risk.matched_rules,
        score=d.risk.score,
    )


def run(path: Path = DATASET, risk_policy: RiskPolicy | None = None) -> list[Outcome]:
    policy = risk_policy or load_risk_policy_toml(default_risk_policy_text())
    return [evaluate_case(c, policy) for c in load_dataset(path)]


def confusion(pairs: list[tuple[str, str]], labels: tuple[str, ...]) -> str:
    """Markdown confusion matrix: rows = expected (label), columns = predicted (engine)."""
    counts = Counter(pairs)
    head = "| expected \\ predicted | " + " | ".join(labels) + " |"
    sep = "|---|" + "---|" * len(labels)
    body = [
        f"| **{e}** | " + " | ".join(str(counts.get((e, p), 0)) for p in labels) + " |"
        for e in labels
    ]
    return "\n".join([head, sep, *body])


def report(outcomes: list[Outcome]) -> str:
    n = len(outcomes)
    lvl_ok = sum(o.level == o.case["expected_level"] for o in outcomes)
    dec_ok = sum(o.decision == o.case["expected_decision"] for o in outcomes)
    lines = [
        f"cases: {n}   level agreement: {lvl_ok}/{n}   decision agreement: {dec_ok}/{n}",
        "",
        "Risk level (rows = hand label, columns = engine):",
        "",
        confusion([(o.case["expected_level"], o.level) for o in outcomes], LEVELS),
        "",
        "Decision (rows = hand label, columns = engine):",
        "",
        confusion([(o.case["expected_decision"], o.decision) for o in outcomes], DECISIONS),
    ]
    bad = [o for o in outcomes if not o.ok]
    if bad:
        lines += ["", "Disagreements:"]
        lines += [
            f"  {o.case['id']} {o.case['tool']:<22} expected {o.case['expected_level']}/"
            f"{o.case['expected_decision']} got {o.level}/{o.decision} (score {o.score}; "
            f"{', '.join(o.risk_rules) or '-'}) - {o.case['note']}"
            for o in bad
        ]
    cats = Counter(o.case["category"] for o in outcomes)
    lines += ["", "categories: " + ", ".join(f"{k} {v}" for k, v in sorted(cats.items()))]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", type=Path, default=DATASET)
    ap.add_argument("--risk-policy", type=Path, default=None, help="TOML file (default: bundled)")
    ap.add_argument("--strict", action="store_true", help="exit 1 on any disagreement")
    args = ap.parse_args()
    policy = load_risk_policy_toml(args.risk_policy.read_text()) if args.risk_policy else None
    outcomes = run(args.dataset, policy)
    print(report(outcomes))
    return 1 if args.strict and not all(o.ok for o in outcomes) else 0


if __name__ == "__main__":
    sys.exit(main())
