"""ADR-0039: what the console may show about a coding action. Secrets in commands never survive;
diffs are reduced to counts."""

from __future__ import annotations

import pytest

from agw_gateway.coding.display import MARK, diff_summary, display_target, redact
from agw_gateway.coding.model import CodingAction

SECRETS = [
    ("export GITHUB_TOKEN=ghp_" + "a" * 36 + " && make test", "ghp_" + "a" * 36),
    ("API_KEY=sk_live_abcdefghijklmnop12 node app.js", "sk_live_abcdefghijklmnop12"),
    ("STRIPE_SECRET='s3cr3tvalue99' pnpm dev", "s3cr3tvalue99"),
    ("curl -H 'Authorization: Bearer eyJabcdef' http://localhost:3000", "eyJabcdef"),
    ('curl -H "X-API-Key: k-123456789" http://localhost', "k-123456789"),
    ("psql postgres://admin:hunter2pass@db.internal:5432/app", "hunter2pass"),
    ("mysql --password=topsecret123 -u root", "topsecret123"),
    ("tool --token abcdef123456 run", "abcdef123456"),
    ("echo AKIA" + "B" * 16, "AKIA" + "B" * 16),
    ("DB_PASSWORD=correcthorsebattery ./run.sh", "correcthorsebattery"),
]


@pytest.mark.parametrize(("command", "secret"), SECRETS)
def test_secrets_in_commands_are_redacted(command: str, secret: str) -> None:
    out = redact(command)
    assert secret not in out, out
    assert MARK in out


@pytest.mark.parametrize(
    "command",
    [
        "pnpm test --grep token handling",
        "git log --author akshat",
        "make lint",
        "TOKEN=$GITHUB_TOKEN make release",  # a variable reference, not a value
        "cat docs/password-policy.md",
    ],
)
def test_ordinary_commands_are_untouched(command: str) -> None:
    assert redact(command) == command


def test_display_target_redacts_command_url_and_argv_keeps_paths() -> None:
    a = CodingAction.model_validate(
        {
            "agent_kind": "claude_code",
            "action_type": "command_exec",
            "native_tool": "Bash",
            "workspace_root": "/w/repo",
            "targets": {
                "command": "PASSWORD=abc12345678 make x",
                "argv": ["--token", "zzz9876543210"],
                "url": "https://u:pw123456@example.com/x",
                "paths": ["/w/repo/api/src/refunds.ts"],
            },
        }
    )
    shown = display_target(a)
    text = repr(shown)
    for s in ("abc12345678", "pw123456"):
        assert s not in text
    assert shown["paths"] == ["api/src/refunds.ts"]
    assert shown["native_tool"] == "Bash"
    assert "make x" in shown["command"]


def test_long_values_are_clipped() -> None:
    a = CodingAction.model_validate(
        {
            "agent_kind": "claude_code",
            "action_type": "command_exec",
            "targets": {"command": "echo " + "x" * 5000},
        }
    )
    assert display_target(a)["command"].endswith("[TRUNCATED]")


def test_diff_summary_counts_only() -> None:
    diff = (
        "--- a/ledger/src/a.ts\n+++ b/ledger/src/a.ts\n@@ -1,2 +1,3 @@\n-old\n+new\n+more\n"
        "--- /dev/null\n+++ b/ledger/src/b.ts\n@@ -0,0 +1 @@\n+created\n"
    )
    s = diff_summary(diff)
    assert s is not None and (s.files, s.added, s.removed) == (2, 3, 1)
    assert diff_summary(None) is None and diff_summary("") is None
