"""Phase 6 operator CLI (``python -m agw_worker.anchoring.admin``): deploy + deployment record,
recorder registration (on-chain + DB, idempotent, refuses re-pointing), auditor trust config."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, select

from agw_gateway.anchoring import recorder_id
from agw_gateway.db import tables as t
from agw_worker.anchoring import admin

from ..anchorkit import SALT, Chain, new_key
from ..conftest import Gw, PgUrls

pytestmark = pytest.mark.e2e


def _env(monkeypatch: pytest.MonkeyPatch, **values: str) -> None:
    for k, v in values.items():
        monkeypatch.setenv(k, v)


def test_admin_deploy_register_trust_config(
    chain: Chain,
    gw: Gw,
    pg: PgUrls,
    migrator_engine: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    owner = tmp_path / "owner.key"
    owner.write_text(chain.owner_key + "\n")
    out = tmp_path / "deployments" / "anvil.json"
    assert (
        admin.main(
            ["deploy", "--owner-key-file", str(owner), "--rpc", chain.rpc, "--out", str(out)]
        )
        == 0
    )
    dep: dict[str, Any] = json.loads(out.read_text())
    assert dep["chain_id"] == 31337 and dep["owner"] == dep["deployer"]
    assert len(dep["runtime_code_sha256"]) == 64 and dep["compiler"]["solc"] == "0.8.28"
    assert chain.owner_key[2:] not in capsys.readouterr().out  # keys are never printed

    # the forge-script path: the same record from a broadcast file
    broadcast = tmp_path / "run-latest.json"
    broadcast.write_text(
        json.dumps(
            {
                "transactions": [
                    {
                        "transactionType": "CREATE",
                        "hash": dep["deploy_tx"],
                        "contractAddress": dep["address"],
                        "transaction": {"from": dep["deployer"]},
                    }
                ],
                "receipts": [
                    {"transactionHash": dep["deploy_tx"], "blockNumber": hex(dep["block_number"])}
                ],
            }
        )
    )
    out2 = tmp_path / "rec.json"
    assert admin.main(["record-deployment", "--broadcast", str(broadcast), "--rpc", chain.rpc,
                       "--out", str(out2)]) == 0  # fmt: skip
    assert json.loads(out2.read_text()) == dep

    sub_key, sub_addr = new_key(chain)
    sub_file = tmp_path / "submitter.key"
    sub_file.write_text(sub_key)
    _env(
        monkeypatch,
        AGW_ENV="test",
        AGW_DATABASE_URL=pg.app,
        AGW_MIGRATOR_DATABASE_URL=pg.migrator,
        AGW_ANCHOR_RPC_URL=chain.rpc,
        AGW_ANCHOR_CHAIN_ID="31337",
        AGW_ANCHOR_CONTRACT=dep["address"],
        AGW_ANCHOR_SUBMITTER_KEY_FILE=str(sub_file),
        AGW_ANCHOR_DEPLOYMENT_SALT=SALT.hex(),
    )
    tenant = gw.world.tenant_id
    capsys.readouterr()
    assert admin.main(["recorder-id", "--tenant", tenant]) == 0
    rid = capsys.readouterr().out.strip()
    assert rid == recorder_id(tenant, SALT).hex()

    for _ in range(2):  # idempotent
        assert admin.main(["register", "--tenant", tenant, "--owner-key-file", str(owner)]) == 0
    with migrator_engine.connect() as conn:
        row = conn.execute(
            select(t.anchor_recorders).where(t.anchor_recorders.c.tenant_id == tenant)
        ).one()
    assert (bytes(row.recorder_id).hex(), row.contract, row.submitter) == (
        rid,
        dep["address"],
        sub_addr,
    )

    # the same recorder cannot be re-pointed to another submitter
    other_key, _ = new_key(chain)
    sub_file.write_text(other_key)
    assert admin.main(["register", "--tenant", tenant, "--owner-key-file", str(owner)]) == 2
    assert "different submitter" in capsys.readouterr().err

    trust = tmp_path / "pinned.json"
    assert admin.main(["trust-config", "--tenant", tenant, "--deployment", str(out),
                       "--finality", "confirmations:2", "--out", str(trust)]) == 0  # fmt: skip
    doc = json.loads(trust.read_text())
    assert doc == {
        "format": "agw-anchor-trust/v1",
        "chain_id": 31337,
        "contract": dep["address"],
        "recorder_id": rid,
        "finality": "confirmations:2",
        "code_sha256": dep["runtime_code_sha256"],
    }
    assert SALT.hex() not in trust.read_text()  # auditors get the recorder id, never the salt


def test_admin_rejects_bad_key_file_without_echoing_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], chain: Chain
) -> None:
    bad = tmp_path / "bad.key"
    bad.write_text("not-a-key-SECRETVALUE")
    rc = admin.main(["deploy", "--owner-key-file", str(bad), "--rpc", chain.rpc,
                     "--out", str(tmp_path / "x.json")])  # fmt: skip
    assert rc == 2
    assert "SECRETVALUE" not in capsys.readouterr().err


def test_admin_requires_settings(
    monkeypatch: pytest.MonkeyPatch, pg: PgUrls, tmp_path: Path
) -> None:
    _env(monkeypatch, AGW_ENV="test", AGW_DATABASE_URL=pg.app)
    monkeypatch.delenv("AGW_ANCHOR_DEPLOYMENT_SALT", raising=False)
    assert admin.main(["recorder-id", "--tenant", "acme"]) == 2
    key = tmp_path / "k"
    key.write_text("11" * 32)
    assert admin.main(["register", "--tenant", "acme", "--owner-key-file", str(key)]) == 2
