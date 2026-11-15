"""Run the tamper matrix on real exports and print a markdown table.

    uv run python experiments/tampering/run_tamper_suite.py \
        --events export.jsonl --epochs epochs.jsonl [--attacked-epoch 1]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from tamper_suite import Material, markdown, run_matrix


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", required=True)
    ap.add_argument("--epochs", required=True)
    ap.add_argument("--attacked-epoch", type=int, default=1)
    a = ap.parse_args()
    m = Material.load(
        Path(a.events).read_text().splitlines(), Path(a.epochs).read_text().splitlines()
    )
    print(markdown(run_matrix(m, a.attacked_epoch)))


if __name__ == "__main__":
    main()
