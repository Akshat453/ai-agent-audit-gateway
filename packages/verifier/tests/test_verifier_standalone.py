"""Verifier: independent codec vs frozen vectors; chain checks on synthetic exports."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from agw_verifier.cbor import NonCanonical, dumps, loads
from agw_verifier.chain import event_hash, verify_lines
from agw_verifier.cli import main

pytestmark = pytest.mark.unit

VECTORS = Path(__file__).resolve().parents[2] / "schemas" / "test-vectors"
VALID = json.loads((VECTORS / "cbor/valid.json").read_text())["vectors"]
REJECT = json.loads((VECTORS / "cbor/reject.json").read_text())["vectors"]
CHAIN = json.loads((VECTORS / "event/event-chain.json").read_text())


def untyped(v: Any) -> Any:
    if isinstance(v, dict):
        if set(v) == {"$bytes"}:
            return bytes.fromhex(v["$bytes"])
        return {k: untyped(x) for k, x in v.items()}
    if isinstance(v, list):
        return [untyped(x) for x in v]
    return v


@pytest.mark.parametrize("vec", VALID, ids=[v["name"] for v in VALID])
def test_independent_codec_valid(vec: dict) -> None:
    assert dumps(untyped(vec["value"])).hex() == vec["hex"]
    assert loads(bytes.fromhex(vec["hex"])) == untyped(vec["value"])


@pytest.mark.parametrize("vec", REJECT, ids=[v["name"] for v in REJECT])
def test_independent_codec_rejects(vec: dict) -> None:
    with pytest.raises(NonCanonical) as exc:
        loads(bytes.fromhex(vec["hex"]))
    assert exc.value.code == vec["error"]


def test_independent_event_hashes() -> None:
    for ev in CHAIN["events"]:
        assert event_hash(bytes.fromhex(ev["canonical_hex"])).hex() == ev["event_hash"]


# ------------------------------------------------------------------ synthetic exports
def export_lines(drop_payload: bool = False) -> list[str]:
    meta = {
        "format": "agw-export/v1",
        "tenant": "acme",
        "from_seq": 0,
        "to_seq": 2,
        "count": 3,
        "payloads": True,
    }
    lines = [json.dumps(meta)]
    payload_for = {
        0: CHAIN["payloads"][0]["canonical_hex"],
        2: CHAIN["payloads"][1]["canonical_hex"],
    }
    for ev in CHAIN["events"]:
        rec = untyped(ev["record"])
        line = {"seq": rec["seq"], "header": ev["canonical_hex"], "event_hash": ev["event_hash"]}
        if rec["seq"] in payload_for and not drop_payload:
            line["payload"] = payload_for[rec["seq"]]
        lines.append(json.dumps(line))
    return lines


HEAD = bytes.fromhex(CHAIN["events"][-1]["event_hash"])


def flip(hex_str: str, pos: int) -> str:
    b = bytearray(bytes.fromhex(hex_str))
    b[pos] ^= 0x01
    return b.hex()


def mutate(lines: list[str], idx: int, **changes: Any) -> list[str]:
    out = list(lines)
    d = json.loads(out[idx])
    d.update(changes)
    out[idx] = json.dumps(d)
    return out


def test_clean_export_verified_with_and_without_trusted_head() -> None:
    assert verify_lines(export_lines()).result == "VERIFIED"
    r = verify_lines(export_lines(), trusted_head=HEAD, trusted_seq=2)
    assert (r.result, r.events_checked, r.last_hash) == ("VERIFIED", 3, HEAD.hex())


@pytest.mark.parametrize("line_idx", [1, 2, 3])
def test_any_header_byte_flip_is_tampered_at_that_seq(line_idx: int) -> None:
    lines = export_lines()
    header = json.loads(lines[line_idx])["header"]
    for pos in range(len(header) // 2):
        bad = mutate(lines, line_idx, header=flip(header, pos))
        r = verify_lines(bad)
        assert r.result == "TAMPERED", pos
        assert r.first_bad_seq in (line_idx - 1, None) or r.reason == "SEQ_LABEL_MISMATCH"


def test_every_payload_byte_flip_is_tampered() -> None:
    lines = export_lines()
    payload = json.loads(lines[1])["payload"]
    for pos in range(len(payload) // 2):
        r = verify_lines(mutate(lines, 1, payload=flip(payload, pos)))
        assert (r.result, r.first_bad_seq) == ("TAMPERED", 0), pos


def test_delete_middle_is_detected() -> None:
    lines = export_lines()
    r = verify_lines([lines[0], lines[1], lines[3]])
    assert r.result in ("TAMPERED", "INCOMPLETE")
    assert r.missing_ranges == [(1, 1)]


def test_delete_suffix_undetected_without_trusted_head_detected_with_it() -> None:
    prefix = export_lines()[:3]  # seq 0..1 only
    assert verify_lines(prefix).result == "VERIFIED"  # documented limit
    r = verify_lines(prefix, trusted_head=HEAD, trusted_seq=2)
    assert (r.result, r.reason, r.first_bad_seq) == ("TAMPERED", "TRUNCATED_BEFORE_TRUSTED_HEAD", 2)


def test_reorder_is_tampered() -> None:
    lines = export_lines()
    r = verify_lines([lines[0], lines[2], lines[1], lines[3]])
    assert r.result == "TAMPERED"


def test_wrong_trusted_head_and_stored_hash_and_missing_payload() -> None:
    assert (
        verify_lines(export_lines(), trusted_head=bytes(32), trusted_seq=2).reason
        == "TRUSTED_HEAD_MISMATCH"
    )
    bad = mutate(export_lines(), 2, event_hash="00" * 32)
    assert verify_lines(bad).reason == "STORED_EVENT_HASH_MISMATCH"
    r = verify_lines(export_lines(drop_payload=True))
    assert (r.result, r.missing_payloads) == ("INCOMPLETE", [0, 2])
    assert verify_lines(mutate(export_lines(), 2, payload="a0")).reason == "UNEXPECTED_PAYLOAD"
    swapped = mutate(export_lines(), 1, payload=json.loads(export_lines()[3])["payload"])
    assert verify_lines(swapped).reason == "PAYLOAD_DIGEST_MISMATCH"


def test_duplicate_id_and_genesis_and_metadata() -> None:
    lines = export_lines()
    assert verify_lines([lines[0], lines[1], lines[1]]).reason == "SEQ_ORDER"
    assert verify_lines(["{}"]).reason == "BAD_EXPORT_METADATA"
    assert verify_lines([]).reason == "BAD_EXPORT_METADATA"
    other_tenant = lines[0].replace('"acme"', '"other"')
    assert verify_lines([other_tenant, *lines[1:]]).reason == "TENANT_MISMATCH"
    assert verify_lines([lines[0], '{"seq": 0, "header": "zz"}']).reason == "BAD_EXPORT_LINE"
    # a chain that starts mid-way is INCOMPLETE (missing 0..0)
    r = verify_lines([lines[0], lines[2], lines[3]])
    assert (r.result, r.missing_ranges) == ("INCOMPLETE", [(0, 0)])


def test_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "e.jsonl"
    f.write_text("\n".join(export_lines()) + "\n")
    args = ["chain", "--export", str(f), "--trusted-head", HEAD.hex(), "--trusted-seq", "2"]
    assert main([*args, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["result"] == "VERIFIED"
    assert main(args) == 0
    assert capsys.readouterr().out.startswith("RESULT: VERIFIED")
    f.write_text("\n".join(export_lines()[:3]) + "\n")
    assert (
        main(["chain", "--export", str(f), "--trusted-head", HEAD.hex(), "--trusted-seq", "2"]) == 1
    )
    f.write_text("\n".join(export_lines(drop_payload=True)) + "\n")
    assert main(["chain", "--export", str(f)]) == 2
    assert main(["chain", "--export", str(f), "--trusted-head", "abc", "--trusted-seq", "1"]) == 64
    assert main(["chain", "--export", str(f), "--trusted-seq", "1"]) == 64


def test_verifier_hash_matches_spec_layout() -> None:
    raw = bytes.fromhex(CHAIN["events"][0]["canonical_hex"])
    assert event_hash(raw) == hashlib.sha256(b"\x0cAGW/event/v1" + raw).digest()


# ------------------------------------------------------------------ forged (re-encoded) chains
def forged(records: list[dict[str, Any]]) -> list[str]:
    """An attacker who can re-encode headers canonically (no payloads, no stored hashes)."""
    meta = {"format": "agw-export/v1", "tenant": "acme", "payloads": False}
    out = [json.dumps(meta)]
    for original in records:
        rec = {k: v for k, v in original.items() if k != "payload"}
        out.append(json.dumps({"seq": rec["seq"], "header": dumps(rec).hex()}))
    return out


def test_relabelled_seq_after_deletion_breaks_prev_link() -> None:
    r0, _, r2 = (untyped(e["record"]) for e in CHAIN["events"])
    r2 = {**r2, "seq": 1}  # delete seq 1, renumber seq 2 -> 1 (canonically re-encoded)
    r = verify_lines(forged([r0, r2]))
    assert (r.result, r.reason, r.first_bad_seq) == ("TAMPERED", "PREV_HASH_MISMATCH", 1)


def test_duplicate_event_id_in_consistent_chain() -> None:
    r0, r1, _ = (untyped(e["record"]) for e in CHAIN["events"])
    r0 = {k: v for k, v in r0.items() if k != "payload"}
    dup = {**r1, "id": r0["id"], "prev": event_hash(dumps(r0))}
    r = verify_lines(forged([r0, dup]))
    assert (r.result, r.reason, r.first_bad_seq) == ("TAMPERED", "DUPLICATE_EVENT_ID", 1)
