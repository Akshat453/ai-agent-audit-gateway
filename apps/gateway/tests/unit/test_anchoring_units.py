"""Phase 6 pure pieces (ADR-0028): recorder identity, finality levels, the CRITICAL gate
policy, settings, the verifier's ABI constants and trust-root validation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from eth_utils import keccak

from agw_gateway.anchoring import Finality, GatePolicy, recorder_id
from agw_gateway.config import ConfigError, load_settings
from agw_verifier import anchor as vanchor
from agw_verifier.cli import main as verify_main
from agw_worker.anchoring.evm import EPOCH_ANCHOR_ABI

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[4]
ARTIFACT = json.loads((REPO / "contracts/artifacts/EpochAnchor.json").read_text())
SALT = bytes(range(32))


# --------------------------------------------------------------------------- recorder id
def test_recorder_id_matches_spec_bytes() -> None:
    expected = hashlib.sha256(
        bytes([15]) + b"AGW/recorder/v1" + (4).to_bytes(2, "big") + b"acme" + SALT
    ).hexdigest()
    assert recorder_id("acme", SALT).hex() == expected
    # frozen vector (docs/gateway/06 §10; tenant "acme", salt 00 01 .. 1f)
    assert expected == "3559e18e6a0c528f27792b8d211ea73d69e6100322e15812ba44c1937be9d8f8"


def test_recorder_id_separates_tenant_and_salt() -> None:
    # length prefix: ("ab", salt) and ("a", "b"+salt[:-1]) never collide
    assert recorder_id("ab", SALT) != recorder_id("a", b"b" + SALT[:-1])
    assert recorder_id("acme", SALT) != recorder_id("acme", bytes(32))  # salt matters
    assert recorder_id("acme", SALT) != recorder_id("acmf", SALT)
    with pytest.raises(ValueError, match="salt"):
        recorder_id("acme", b"short")
    with pytest.raises(ValueError, match="tenant"):
        recorder_id("", SALT)


# --------------------------------------------------------------------------- finality
@pytest.mark.parametrize(
    ("spec", "latest", "tagged", "final"),
    [
        ("included", 100, None, 100),
        ("confirmations:1", 100, None, 100),
        ("confirmations:12", 100, None, 89),
        ("safe", 100, 68, 68),
        ("finalized", 100, 36, 36),
        ("finalized", 100, None, -1),  # node without the tag: nothing counts as final
    ],
)
def test_finality_levels(spec: str, latest: int, tagged: int | None, final: int) -> None:
    f = Finality.parse(spec)
    assert f.label == spec
    assert f.final_block(latest, tagged) == final


@pytest.mark.parametrize("bad", ["", "latest", "confirmations:0", "confirmations:x", "final"])
def test_finality_rejects_unknown(bad: str) -> None:
    with pytest.raises(ValueError, match="finality"):
        Finality.parse(bad)


# --------------------------------------------------------------------------- gate policy
def test_gate_policy_matrix() -> None:
    every = GatePolicy(frozenset({"*"}), 60)
    some = GatePolicy(frozenset({"iam-change-exception"}), 60)
    off = GatePolicy(frozenset(), 60)
    assert every.required("CRITICAL", [])
    assert not every.required("HIGH", ["iam-change-exception"])  # only CRITICAL is gated
    assert some.required("CRITICAL", ["iam-change-exception", "x"])
    assert not some.required("CRITICAL", ["other-rule"])
    assert not off.required("CRITICAL", ["iam-change-exception"])


# --------------------------------------------------------------------------- settings
def _base(**kw: object) -> dict[str, object]:
    return {"env": "test", "database_url": "postgresql+psycopg://u:p@h/db", **kw}


def test_settings_defaults_fail_closed() -> None:
    s = load_settings(**_base())
    assert s.pre_anchor_rules == ("*",)  # every CRITICAL action is pre-anchored by default
    assert s.anchor_finality == "finalized" and s.anchor_rpc_url is None


def test_settings_rule_list_and_anchor_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGW_PRE_ANCHOR_RULES", "iam-change-exception, MR-1")
    assert load_settings(**_base()).pre_anchor_rules == ("iam-change-exception", "MR-1")
    with pytest.raises(ConfigError) as exc:
        load_settings(**_base(anchor_rpc_url="http://node:8545"))  # no chain id/contract/salt
    assert "http://node" not in str(exc.value)  # never echo values (may hold an API key)
    with pytest.raises(ConfigError):
        load_settings(
            **_base(
                anchor_rpc_url="http://n",
                anchor_chain_id=1,
                anchor_contract="0x" + "11" * 20,
                anchor_deployment_salt="abcd",
            )
        )
    with pytest.raises(ConfigError):
        load_settings(**_base(anchor_finality="eventually"))


# --------------------------------------------------------------------------- ABI constants
def test_verifier_selectors_are_keccak_of_signatures() -> None:
    assert keccak(text="getAnchor(bytes32,uint64)")[:4].hex() == vanchor.SEL_GET_ANCHOR
    assert keccak(text="nextEpoch(bytes32)")[:4].hex() == vanchor.SEL_NEXT_EPOCH


def test_worker_abi_is_a_subset_of_the_committed_artifact() -> None:
    def shape(e: dict[str, Any]) -> tuple[Any, ...]:
        return (
            e["type"],
            e["name"],
            tuple(i["type"] for i in e.get("inputs", [])),
            tuple(o["type"] for o in e.get("outputs", [])),
        )

    full = {shape(e) for e in ARTIFACT["abi"] if "name" in e}
    assert {shape(e) for e in EPOCH_ANCHOR_ABI} <= full


# --------------------------------------------------------------------------- trust roots
def test_make_trust_validates_pins() -> None:
    t = vanchor.make_trust(84532, "0x" + "AB" * 20, "11" * 32, "finalized", "cd" * 32)
    assert t.contract == "0x" + "ab" * 20 and t.chain_id == 84532
    with pytest.raises(vanchor.TrustConfigError, match="TRUST_ROOTS_NOT_PINNED"):
        vanchor.make_trust(None, "0x" + "ab" * 20, "11" * 32)
    for bad in (
        (0, "0x" + "ab" * 20, "11" * 32),
        (1, "0xabc", "11" * 32),
        (1, "0x" + "ab" * 20, "11" * 31),
    ):
        with pytest.raises(vanchor.TrustConfigError):
            vanchor.make_trust(*bad)
    with pytest.raises(vanchor.TrustConfigError):
        vanchor.make_trust(1, "0x" + "ab" * 20, "11" * 32, "eventually")


def test_cli_chain_mode_usage_and_untrusted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    b = tmp_path / "b.json"
    b.write_text("{}")
    # chain mode cannot be mixed with a hand-supplied root
    assert (
        verify_main(
            ["event", "--bundle", str(b), "--chain-rpc", "http://x", "--trusted-root", "00" * 32]
        )
        == 64
    )
    # an RPC without pinned trust roots -> UNTRUSTED_ANCHOR (5), never "use the bundle's"
    assert verify_main(["event", "--bundle", str(b), "--chain-rpc", "http://x"]) == 5
    assert "UNTRUSTED_ANCHOR" in capsys.readouterr().out
    cfg = tmp_path / "t.json"
    cfg.write_text(json.dumps({"format": "agw-anchor-trust/v1", "chain_id": 1}))
    assert (
        verify_main(["event", "--bundle", str(b), "--trust-config", str(cfg), "--chain-id", "2"])
        == 64
    )
