"""``agw-verify`` command line.

    agw-verify chain --export export.jsonl [--trusted-head <hex> --trusted-seq N]

Exit codes: 0 VERIFIED, 1 TAMPERED, 2 INCOMPLETE, 64 usage error. Prints a JSON report.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from agw_verifier.chain import verify_lines

EXIT = {"VERIFIED": 0, "TAMPERED": 1, "INCOMPLETE": 2}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agw-verify")
    sub = parser.add_subparsers(dest="cmd", required=True)
    ch = sub.add_parser("chain", help="verify a per-tenant hash chain export")
    ch.add_argument("--export", required=True, help="export.jsonl produced by the gateway")
    ch.add_argument("--trusted-head", help="hex event_hash obtained out of band")
    ch.add_argument("--trusted-seq", type=int, help="seq of the trusted head")
    args = parser.parse_args(argv)

    if (args.trusted_head is None) != (args.trusted_seq is None):
        print("--trusted-head and --trusted-seq must be given together", file=sys.stderr)
        return 64
    head = None
    if args.trusted_head is not None:
        try:
            head = bytes.fromhex(args.trusted_head)
        except ValueError:
            head = b""
        if len(head) != 32:
            print("--trusted-head must be 64 hex chars", file=sys.stderr)
            return 64
    with open(args.export, encoding="utf-8") as fh:
        report = verify_lines(fh, trusted_head=head, trusted_seq=args.trusted_seq)
    print(json.dumps(report.as_dict(), indent=2))
    return EXIT[report.result]


if __name__ == "__main__":
    raise SystemExit(main())
