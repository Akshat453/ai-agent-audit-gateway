"""agw-approve (Phase 5 test CLI) against the in-process gateway."""

from __future__ import annotations

import contextlib
import uuid
from typing import Any

import pytest
from sqlalchemy import Engine

from agw_sdk.approve_cli import CliError, run

from ..approvalkit import PASSWORD, email, make_humans

pytestmark = pytest.mark.e2e


def _cli(gw: Any, monkeypatch: pytest.MonkeyPatch, *argv: str, user: str = "alice") -> int:
    monkeypatch.setenv("AGW_APPROVER_TENANT", gw.world.tenant_id)
    monkeypatch.setenv("AGW_APPROVER_USER", user)
    monkeypatch.setenv("AGW_APPROVER_PASSWORD", PASSWORD)
    try:
        return run(list(argv), client_factory=lambda **_: contextlib.nullcontext(gw.client))
    finally:
        gw.client.headers.pop("Authorization", None)


def test_cli_list_show_approve(
    gw: Any, migrator_engine: Engine, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    make_humans(migrator_engine, gw.client, gw.world.tenant_id)
    action_id, approval_id = email(gw)
    assert approval_id
    assert _cli(gw, monkeypatch, "list") == 0
    assert approval_id in capsys.readouterr().out
    assert _cli(gw, monkeypatch, "show", approval_id) == 0
    out = capsys.readouterr().out
    assert "send_email@1.0.0" in out and "bob@partner.example" in out and "HIGH" in out
    assert _cli(gw, monkeypatch, "approve", approval_id, "--reason", "ok", "--yes") == 0
    assert '"state": "APPROVED"' in capsys.readouterr().out
    gw.drain()
    assert gw.spies.email.calls == [uuid.UUID(action_id)]


def test_cli_confirmation_and_errors(
    gw: Any, migrator_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_humans(migrator_engine, gw.client, gw.world.tenant_id)
    action_id, approval_id = email(gw)
    assert approval_id
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    assert _cli(gw, monkeypatch, "reject", approval_id) == 1  # declined at the prompt
    assert gw.action_status(action_id) == "PENDING_APPROVAL"
    with pytest.raises(CliError, match="403 FORBIDDEN"):
        _cli(gw, monkeypatch, "approve", approval_id, "--yes", user="audrey")
    monkeypatch.setenv("AGW_APPROVER_PASSWORD", "wrong-password-xyz")
    with pytest.raises(CliError, match="401"):
        run(["list"], client_factory=lambda **_: contextlib.nullcontext(gw.client))
