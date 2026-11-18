"""Environment capture, run directories, CSV writing and bootstrap statistics."""

from __future__ import annotations

import csv
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import tomllib
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]


def _cmd(*argv: str) -> str:
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=20
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def environment(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """CPU, RAM, OS, Python, Docker, Postgres image, git commit (+dirty) - committed with the
    raw results so a reviewer can see what produced them."""
    mem = _cmd("sysctl", "-n", "hw.memsize") if sys.platform == "darwin" else ""
    if not mem and Path("/proc/meminfo").exists():
        first = Path("/proc/meminfo").read_text().splitlines()[0]
        mem = str(int(first.split()[1]) * 1024)
    cpu = (
        _cmd("sysctl", "-n", "machdep.cpu.brand_string")
        if sys.platform == "darwin"
        else platform.processor()
    )
    env = {
        "captured_at": datetime.now(UTC).isoformat(),
        "cpu": cpu or platform.processor(),
        "cpu_count": os.cpu_count(),
        "ram_bytes": int(mem) if mem.isdigit() else None,
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": sys.version.split()[0],
        "docker": _cmd("docker", "version", "--format", "{{.Server.Version}}"),
        "postgres_image": "postgres:16",
        "git_commit": _cmd("git", "-C", str(REPO), "rev-parse", "HEAD"),
        "git_dirty": bool(_cmd("git", "-C", str(REPO), "status", "--porcelain")),
    }
    env.update(extra or {})
    return env


def load_config(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text())


def results_dir(experiment: Path) -> Path:
    out = experiment / "results"
    out.mkdir(parents=True, exist_ok=True)
    return out


def write_csv(
    path: Path, rows: Iterable[dict[str, Any]], fields: Sequence[str] | None = None
) -> int:
    rows = list(rows)
    fields = list(fields or (rows[0].keys() if rows else []))
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in fields})
    return len(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open() as fh:
        return list(csv.DictReader(fh))


def write_json(path: Path, doc: Any) -> None:
    path.write_text(json.dumps(doc, indent=1, sort_keys=True, default=str) + "\n")


def percentile(xs: Sequence[float], p: float) -> float:
    s = sorted(xs)
    if not s:
        return float("nan")
    k = (len(s) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def bootstrap_ci(
    values: Sequence[float],
    stat: Callable[[Sequence[float]], float] = statistics.fmean,
    *,
    n: int = 2000,
    alpha: float = 0.05,
    seed: int = 0,
) -> tuple[float, float, float]:
    """(point estimate, lower, upper) percentile bootstrap over the given per-run values."""
    rng = random.Random(seed)
    vals = list(values)
    if len(vals) < 2:
        v = stat(vals) if vals else float("nan")
        return v, v, v
    boots = sorted(stat([rng.choice(vals) for _ in vals]) for _ in range(n))
    return stat(vals), boots[int(n * alpha / 2)], boots[int(n * (1 - alpha / 2)) - 1]
