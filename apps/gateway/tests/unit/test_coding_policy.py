"""C1: the coding policy table (>= 100 labeled actions, every MintRail trap) must pass 100 %."""

from __future__ import annotations

from typing import Any

import pytest

from agw_gateway.coding.commands import CommandUnparseable, parse
from agw_gateway.coding.globs import glob_match, normalize_path
from agw_gateway.coding.model import CodingAction
from agw_gateway.coding.policy import CodingPolicy
from tests.unit.coding_policy_cases import CASES

pytestmark = pytest.mark.unit
ROOT = "/w/mintrail"
POLICY = CodingPolicy.strict()  # the C1 table pins the STRICT profile (v1)


def action(kind: str, target: str, **extra: Any) -> CodingAction:
    targets: dict[str, Any] = {}
    if kind in ("file_read", "file_write", "file_delete", "search"):
        targets["paths"] = [target]
    elif kind == "command_exec":
        targets["command"] = target
    elif kind == "web_fetch":
        targets["url"] = target
    elif kind == "mcp_call":
        server, tool = target.split("/", 1)
        targets["mcp"] = {"server": server, "tool": tool}
    return CodingAction.model_validate(
        {
            "agent_kind": "claude_code",
            "action_type": kind,
            "workspace_root": ROOT,
            "targets": targets,
            **extra,
        }
    )


def test_table_is_large_enough_and_ids_unique() -> None:
    ids = [c[0] for c in CASES]
    assert len(ids) >= 100
    assert len(ids) == len(set(ids))
    traps = [i for i in ids if i.startswith("TRAP-")]
    assert len(traps) >= 20


@pytest.mark.parametrize(("case_id", "kind", "target", "diff", "effect", "rule", "role"), CASES)
def test_policy_table(
    case_id: str,
    kind: str,
    target: str,
    diff: str | None,
    effect: str,
    rule: str | None,
    role: str | None,
) -> None:
    d = POLICY.evaluate(action(kind, target), diff)
    assert d.effect == effect, (case_id, d)
    if rule is not None:
        assert rule in d.rule_ids, (case_id, d)
    assert d.approval_role == role, (case_id, d)
    if effect == "deny":
        assert d.level in ("HIGH", "CRITICAL")
    if effect == "ask":
        assert d.approval_role is not None


def test_decision_is_deterministic_and_carries_policy_identity() -> None:
    a = action("command_exec", "curl https://example.com")
    assert POLICY.evaluate(a) == POLICY.evaluate(a)
    d = POLICY.evaluate(a)
    assert (d.policy_id, d.policy_version, len(d.policy_digest)) == ("coding-mintrail", 1, 32)


def test_incomplete_never_allows() -> None:
    d = POLICY.evaluate(action("file_read", "api/src/app.ts", incomplete=True))
    assert d.effect == "ask"


def test_reasons_never_echo_diff_content() -> None:
    secret = "AKIAIOSFODNN7EXAMPLQ"
    diff = f'+const k = "{secret}";\n'
    d = POLICY.evaluate(action("file_write", "api/src/x.ts"), diff)
    assert d.effect == "deny"
    assert secret not in d.reason


def test_policy_digest_changes_with_content() -> None:
    raw = POLICY.raw.replace(b"version = 1", b"version = 2")
    other = CodingPolicy(raw)
    assert other.digest != POLICY.digest
    assert other.version == 2


@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        ("api/src/app.ts", "*.ts", True),
        ("a/b/.env", ".env", True),
        ("a/b/.ENV", ".env", True),
        (".github/workflows/ci.yml", ".github/**", True),
        ("x/.github/ci.yml", ".github/**", False),
        ("/Users/x/mintrail-private/a.md", "**/mintrail-private/**", True),
        ("signal/src/signing.ts", "signal/**/sign*", True),
        ("ledger", "ledger/**", False),
    ],
)
def test_glob(path: str, pattern: str, expected: bool) -> None:
    assert glob_match(path, pattern) is expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("api/src/x.ts", "api/src/x.ts"),
        ("/w/mintrail/api/x.ts", "api/x.ts"),
        ("api/../../etc/passwd", "/w/etc/passwd"),
        ("~/.ssh/id_rsa", "~/.ssh/id_rsa"),
        ("/w/mintrail-private/x", "/w/mintrail-private/x"),  # sibling, not inside the root
    ],
)
def test_normalize(raw: str, expected: str) -> None:
    assert normalize_path(raw, ROOT) == expected


def test_parser_lifts_substitutions_and_heredocs() -> None:
    p = parse("git commit -m \"$(cat <<'EOF'\nmsg; curl x\nEOF\n)\" && echo `whoami`")
    assert [s.argv[0] for s in p.segments] == ["git", "echo"]
    assert len(p.substitutions) == 2
    with pytest.raises(CommandUnparseable):
        parse("echo 'x")


def test_committed_json_schema_matches_the_model() -> None:
    """The CLI validates against the committed file; it must equal the gateway's model."""
    import json
    from pathlib import Path

    path = (
        Path(__file__).resolve().parents[4] / "packages/schemas/coding/coding-action-v1.schema.json"
    )
    committed = json.loads(path.read_text())
    generated = CodingAction.model_json_schema(by_alias=True)
    generated["$id"] = "https://agentguard.local/schemas/agw.coding-action/1"
    generated["title"] = "agw.coding-action/1"
    assert committed == json.loads(json.dumps(generated, sort_keys=True))
