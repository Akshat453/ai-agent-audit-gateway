"""Required regression: every hand-labeled action gets its expected risk level and decision
through the production pipeline (experiments/risk/labeled_actions.jsonl, ADR-0026)."""

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[4]
_spec = importlib.util.spec_from_file_location("risk_eval", REPO / "experiments/risk/risk_eval.py")
assert _spec is not None and _spec.loader is not None
risk_eval = importlib.util.module_from_spec(_spec)
sys.modules["risk_eval"] = risk_eval  # dataclasses resolve their module via sys.modules
_spec.loader.exec_module(risk_eval)
OUTCOMES = risk_eval.run()


def test_dataset_shape() -> None:
    cases = [o.case for o in OUTCOMES]
    assert len(cases) >= 60
    assert len({c["id"] for c in cases}) == len(cases)
    tools = {c["tool"] for c in cases}
    assert {
        "public_doc_search",
        "create_ticket",
        "delete_record",
        "send_email",
        "export_customer_data",
        "update_iam_role",
    } <= tools
    notes = " ".join(c["note"] for c in cases)
    for edge in ("environment missing", "100k internal recipients", "prod delete WITH scope"):
        assert edge in notes  # the adversarial edge cases the prompt asks for
    assert any(c["depth"] for c in cases)  # delegated calls
    assert {o.case["expected_level"] for o in OUTCOMES} == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@pytest.mark.parametrize("outcome", OUTCOMES, ids=lambda o: o.case["id"])
def test_labeled_action(outcome) -> None:
    c = outcome.case
    assert (outcome.level, outcome.decision) == (c["expected_level"], c["expected_decision"]), (
        c["note"],
        outcome.rules,
        outcome.risk_rules,
        outcome.score,
    )


def test_confusion_matrix_is_diagonal() -> None:
    text = risk_eval.report(OUTCOMES)
    assert f"level agreement: {len(OUTCOMES)}/{len(OUTCOMES)}" in text
    assert f"decision agreement: {len(OUTCOMES)}/{len(OUTCOMES)}" in text
