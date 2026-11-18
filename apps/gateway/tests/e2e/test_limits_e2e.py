"""Phase 10 hardening on the real gateway app: every endpoint has the body limit (not only
/v1/actions), and the per-credential rate limit returns 429 before authentication runs."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import Engine

from ..conftest import PgUrls, World
from ..privacykit import gateway

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(
    "path",
    ["/v1/auth/login", "/v1/delegations", "/v1/oauth/token", "/v1/approvals/x/decision"],
)
def test_body_limit_on_every_endpoint(
    path: str, pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path
) -> None:
    with gateway(pg, app_engine, world, tmp_path, max_body_bytes=1024) as gw:
        r = gw.client.post(path, content=b"{" + b" " * 2048 + b"}",
                           headers={"Authorization": f"Bearer {world.token}",
                                    "Content-Type": "application/json"})  # fmt: skip
        assert r.status_code == 413, (path, r.status_code)
        assert r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_rate_limit_on_real_app(
    pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path
) -> None:
    # 1 token per minute: no refill can happen while the test runs, even on a loaded machine
    # (at 60/min a slow request 5 -> 6 refilled a token and the test flaked under `make test`).
    with gateway(pg, app_engine, world, tmp_path, rate_limit_per_minute=1,
                 rate_limit_burst=5) as gw:  # fmt: skip
        codes = [gw.post("test_echo", {"text": "x"}).status_code for _ in range(8)]
        assert codes[:5] == [201] * 5
        assert codes[5:] == [429] * 3
        # a different credential still gets through; bad credentials are limited too
        assert gw.client.get("/v1/actions/00000000-0000-0000-0000-000000000000",
                             headers={"Authorization": f"Bearer {world.other_token}"}
                             ).status_code == 404  # fmt: skip
        bad = {"Authorization": "Bearer agw_guess"}
        assert [gw.client.get("/v1/dashboard/config", headers=bad).status_code
                for _ in range(7)][-1] == 429  # fmt: skip
        assert gw.client.get("/v1/health").status_code == 200
