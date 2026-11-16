"""``agw-verify`` command line.

    agw-verify chain  --export export.jsonl [--trusted-head HEX --trusted-seq N] [--json]
    agw-verify event  --bundle b.json [--trusted-root HEX [--trusted-epoch N]] [--json]
    agw-verify epochs --export epochs.jsonl [--events export.jsonl]
                      [--trusted-root HEX [--trusted-epoch N]] [--json]

Phase 6, on-chain trust roots (event and epochs):

    agw-verify event --bundle b.json --chain-rpc URL
                     (--trust-config pinned.json | --chain-id N --contract 0x.. --recorder-id HEX)
                     [--finality finalized|safe|latest|confirmations:N] [--code-sha256 HEX]

The chain id, contract and recorder id are TRUST ROOTS: they must come from a pinned config the
auditor obtained independently (``--trust-config``, format agw-anchor-trust/v1) or from the
command line, never from the bundle. Anything less -> UNTRUSTED_ANCHOR. The RPC URL is not a
trust root (it is checked against the pinned chain id); it may also come from the config.

Phase 7, disclosure bundles (from POST /v1/disclosures/{grant}/export):

    agw-verify auditor-keygen --out auditor.key      # X25519; prints public key + key id
    agw-verify event --bundle b.json --auditor-key auditor.key [chain-mode flags]

The payload is decrypted with the auditor key, its digest checked against the header, then the
proof and (with pinned trust roots) the anchor: VERIFIED only if all pass. A deleted payload is
INCOMPLETE (header and proof still checked). Needs ``agw-verifier[disclosure]``.

Exit codes: 0 VERIFIED, 1 TAMPERED, 2 INCOMPLETE, 3 INVALID_PROOF, 4 UNANCHORED (all checks
passed but no external trust root, or the anchor is not yet final), 5 UNTRUSTED_ANCHOR,
64 usage error. ``--json`` prints a machine-readable report; otherwise a short summary.
Without ``--trusted-epoch``, ``--trusted-root`` is compared with the LAST epoch in the material.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

from agw_verifier import STATEMENT
from agw_verifier.anchor import ChainView, Rpc, TrustConfigError, load_trust_file, make_trust
from agw_verifier.chain import verify_lines
from agw_verifier.disclosure import DisclosureProblem, keygen, open_bundle, read_private_key
from agw_verifier.epochs import (
    Result,
    verify_bundle,
    verify_bundle_on_chain,
    verify_epochs,
    verify_epochs_on_chain,
)

EXIT = {
    "VERIFIED": 0,
    "TAMPERED": 1,
    "INCOMPLETE": 2,
    "INVALID_PROOF": 3,
    "UNANCHORED": 4,
    "UNTRUSTED_ANCHOR": 5,
}
USAGE = 64


def _hex32(value: str | None, name: str) -> bytes | None:
    if value is None:
        return None
    try:
        b = bytes.fromhex(value)
    except ValueError:
        b = b""
    if len(b) != 32:
        raise SystemExit(f"{name} must be 64 hex characters")
    return b


def _emit(report: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, indent=2, default=str))
        return
    print(f"RESULT: {report['result']}")
    for key in (
        "reason",
        "first_bad_seq",
        "first_bad_epoch",
        "events_checked",
        "epochs_checked",
        "last_seq",
        "last_epoch_no",
        "trusted_epoch",
        "chain_last_epoch",
        "unsealed_events",
    ):
        if report.get(key) is not None:
            print(f"  {key}: {report[key]}")
    if report.get("anchor"):
        a = report["anchor"]
        print(
            f"  anchor: epoch {a['epoch_no']} in block {a['block_number']} "
            f"(final at {a['finality']}, final block {a['final_block']})"
        )
    for note in report.get("notes", []):
        print(f"  note: {note}")
    print(f"  {STATEMENT}")


def _chain_view(args: argparse.Namespace) -> ChainView | Result | None:
    """None: no chain mode. Result: UNTRUSTED_ANCHOR (trust roots not pinned)."""
    if not (args.chain_rpc or args.trust_config):
        return None
    pinned: dict[str, Any] = load_trust_file(args.trust_config) if args.trust_config else {}
    flags = {
        "chain_id": args.chain_id,
        "contract": args.contract,
        "recorder_id": args.recorder_id,
        "finality": args.finality,
        "code_sha256": args.code_sha256,
    }
    for k, v in flags.items():
        if v is not None:
            if k in pinned and str(pinned[k]).lower() != str(v).lower():
                raise SystemExit(f"--{k.replace('_', '-')} conflicts with --trust-config")
            pinned[k] = v
    rpc = args.chain_rpc or pinned.get("rpc")
    if not rpc:
        raise SystemExit("--chain-rpc (or rpc in --trust-config) is required")
    try:
        trust = make_trust(
            pinned.get("chain_id"),
            pinned.get("contract"),
            pinned.get("recorder_id"),
            pinned.get("finality"),
            pinned.get("code_sha256"),
        )
    except TrustConfigError as exc:
        res = Result().fail("UNTRUSTED_ANCHOR", str(exc))
        res.notes.append("chain id, contract and recorder id must be pinned out of band")
        return res
    return ChainView(Rpc(str(rpc)), trust)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agw-verify")
    sub = parser.add_subparsers(dest="cmd", required=True)
    ch = sub.add_parser("chain", help="verify a per-tenant hash-chain export")
    ch.add_argument("--export", required=True)
    ch.add_argument("--trusted-head")
    ch.add_argument("--trusted-seq", type=int)
    ev = sub.add_parser("event", help="verify one event's evidence bundle")
    ev.add_argument("--bundle", required=True)
    ev.add_argument("--auditor-key", help="X25519 private key (hex file) for disclosure bundles")
    kg = sub.add_parser("auditor-keygen", help="create an auditor X25519 key pair")
    kg.add_argument("--out", required=True, help="private key file to create (0600)")
    ep = sub.add_parser("epochs", help="verify epoch continuity (optionally against events)")
    ep.add_argument("--export", required=True)
    ep.add_argument("--events", help="chain export to recompute every epoch's Merkle root")
    for p in (ev, ep):
        p.add_argument("--trusted-root")
        p.add_argument("--trusted-epoch", type=int)
        p.add_argument("--chain-rpc", help="JSON-RPC URL of a node on the pinned chain")
        p.add_argument("--trust-config", help="pinned agw-anchor-trust/v1 JSON (out of band)")
        p.add_argument("--chain-id", type=int)
        p.add_argument("--contract")
        p.add_argument("--recorder-id")
        p.add_argument("--finality")
        p.add_argument("--code-sha256")
    for p in (ch, ev, ep):
        p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    args = parser.parse_args(argv)

    if args.cmd == "auditor-keygen":
        try:
            pub, kid = keygen(args.out)
        except (OSError, DisclosureProblem) as exc:
            print(exc, file=sys.stderr)
            return USAGE
        print(json.dumps({"public_key": pub, "key_id": kid, "private_key_file": args.out}))
        return 0
    try:
        if args.cmd == "chain":
            if (args.trusted_head is None) != (args.trusted_seq is None):
                print("--trusted-head and --trusted-seq must be given together", file=sys.stderr)
                return USAGE
            head = _hex32(args.trusted_head, "--trusted-head")
            with open(args.export, encoding="utf-8") as fh:
                report = verify_lines(fh, trusted_head=head, trusted_seq=args.trusted_seq).as_dict()
        else:
            if args.trusted_epoch is not None and args.trusted_root is None:
                print("--trusted-epoch requires --trusted-root", file=sys.stderr)
                return USAGE
            view = _chain_view(args)
            if view is not None and args.trusted_root is not None:
                print("--trusted-root cannot be combined with chain mode", file=sys.stderr)
                return USAGE
            root = _hex32(args.trusted_root, "--trusted-root")
            if isinstance(view, Result):
                res = view
            elif args.cmd == "event":
                with open(args.bundle, encoding="utf-8") as fh:
                    try:
                        bundle = json.load(fh)
                    except json.JSONDecodeError:
                        bundle = None
                problem: DisclosureProblem | None = None
                note: str | None = None
                try:
                    key = read_private_key(args.auditor_key) if args.auditor_key else None
                    bundle, note = open_bundle(bundle, key)
                except DisclosureProblem as exc:
                    problem = exc
                except ValueError as exc:
                    raise SystemExit(str(exc)) from None
                if view is not None:
                    res = verify_bundle_on_chain(bundle, view)
                else:
                    res = verify_bundle(bundle, trusted_root=root, trusted_epoch=args.trusted_epoch)
                if problem is not None:
                    res.fail(problem.result, problem.reason)
                    res.notes.append("header, inclusion proof and anchor were checked regardless")
                if note:
                    res.notes.append(note)
            else:
                with open(args.export, encoding="utf-8") as fh:
                    lines = fh.read().splitlines()
                events = None
                if args.events:
                    with open(args.events, encoding="utf-8") as fh:
                        events = fh.read().splitlines()
                if view is not None:
                    res = verify_epochs_on_chain(lines, view, event_lines=events)
                else:
                    res = verify_epochs(
                        lines,
                        trusted_root=root,
                        trusted_epoch=args.trusted_epoch,
                        event_lines=events,
                    )
            report = res.as_dict()
    except (SystemExit, TrustConfigError, OSError) as exc:
        print(exc, file=sys.stderr)
        return USAGE
    _emit(report, args.json)
    return EXIT[report["result"]]


if __name__ == "__main__":
    raise SystemExit(main())
