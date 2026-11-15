"""``agw-verify`` command line.

    agw-verify chain  --export export.jsonl [--trusted-head HEX --trusted-seq N] [--json]
    agw-verify event  --bundle b.json [--trusted-root HEX [--trusted-epoch N]] [--json]
    agw-verify epochs --export epochs.jsonl [--events export.jsonl]
                      [--trusted-root HEX [--trusted-epoch N]] [--json]

Exit codes: 0 VERIFIED, 1 TAMPERED, 2 INCOMPLETE, 3 INVALID_PROOF, 4 UNANCHORED (all checks
passed but no external trust root: "locally sealed only"), 64 usage error.
``--json`` prints a machine-readable report; otherwise a short human summary.
Without ``--trusted-epoch``, ``--trusted-root`` is compared with the LAST epoch in the material.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

from agw_verifier import STATEMENT
from agw_verifier.chain import verify_lines
from agw_verifier.epochs import verify_bundle, verify_epochs

EXIT = {"VERIFIED": 0, "TAMPERED": 1, "INCOMPLETE": 2, "INVALID_PROOF": 3, "UNANCHORED": 4}
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
        "unsealed_events",
    ):
        if report.get(key) is not None:
            print(f"  {key}: {report[key]}")
    for note in report.get("notes", []):
        print(f"  note: {note}")
    print(f"  {STATEMENT}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agw-verify")
    sub = parser.add_subparsers(dest="cmd", required=True)
    ch = sub.add_parser("chain", help="verify a per-tenant hash-chain export")
    ch.add_argument("--export", required=True)
    ch.add_argument("--trusted-head")
    ch.add_argument("--trusted-seq", type=int)
    ev = sub.add_parser("event", help="verify one event's evidence bundle")
    ev.add_argument("--bundle", required=True)
    ep = sub.add_parser("epochs", help="verify epoch continuity (optionally against events)")
    ep.add_argument("--export", required=True)
    ep.add_argument("--events", help="chain export to recompute every epoch's Merkle root")
    for p in (ev, ep):
        p.add_argument("--trusted-root")
        p.add_argument("--trusted-epoch", type=int)
    for p in (ch, ev, ep):
        p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    args = parser.parse_args(argv)

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
            root = _hex32(args.trusted_root, "--trusted-root")
            if args.cmd == "event":
                with open(args.bundle, encoding="utf-8") as fh:
                    try:
                        bundle = json.load(fh)
                    except json.JSONDecodeError:
                        bundle = None
                res = verify_bundle(bundle, trusted_root=root, trusted_epoch=args.trusted_epoch)
            else:
                with open(args.export, encoding="utf-8") as fh:
                    lines = fh.read().splitlines()
                events = None
                if args.events:
                    with open(args.events, encoding="utf-8") as fh:
                        events = fh.read().splitlines()
                res = verify_epochs(
                    lines, trusted_root=root, trusted_epoch=args.trusted_epoch, event_lines=events
                )
            report = res.as_dict()
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return USAGE
    _emit(report, args.json)
    return EXIT[report["result"]]


if __name__ == "__main__":
    raise SystemExit(main())
