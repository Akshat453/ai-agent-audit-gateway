"""Phase 8 containment (ADR-0030 §9): the agent container cannot reach tool endpoints, the
database or the internet; only the gateway. Builds images, so it is ``slow`` and runs via
``make containment`` (this test wraps the same script)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.slow]
REPO = Path(__file__).resolve().parents[4]


def test_agent_container_reaches_only_the_gateway() -> None:
    proc = subprocess.run(
        ["/bin/bash", str(REPO / "examples/containment/run.sh")],
        capture_output=True, text=True, timeout=900, check=False,
    )  # fmt: skip
    report = json.loads(proc.stdout[proc.stdout.index("{") :])
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert report["result"] == "CONTAINED"
    assert report["reachable"] == {"gateway:8080": "CONNECTED"}
    assert all(v != "CONNECTED" for v in report["unreachable"].values())
    assert len(report["unreachable"]) >= 10
    assert report["credential_env_vars"] == [] and report["creds_dir"] == ["agent.token"]
    assert report["gateway_calls"]["public_api_get"]["status"] == "COMPLETED"
    assert report["gateway_calls"]["delete_record"]["status"] == "DENIED"
