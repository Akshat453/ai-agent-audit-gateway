"""Write the gateway's OpenAPI schema (Phase 9): the dashboard's typed client is generated from
it (``npm run gen:api`` in apps/dashboard). The running gateway does NOT serve the schema
(``openapi_url=None``); this builds the routers without a database.

    python -m agw_gateway.openapi --out apps/dashboard/openapi.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fastapi import FastAPI

from agw_gateway import __version__
from agw_gateway.api.approval_routes import router as approval_router
from agw_gateway.api.c2_routes import router as c2_router
from agw_gateway.api.coding_routes import coding_router
from agw_gateway.api.console_routes import router as console_router
from agw_gateway.api.dashboard_routes import router as dashboard_router
from agw_gateway.api.delegation_routes import router as delegation_router
from agw_gateway.api.disclosure_routes import router as disclosure_router
from agw_gateway.api.mcp_routes import router as mcp_router
from agw_gateway.api.routes import router


def schema() -> dict[str, object]:
    app = FastAPI(title="AI Agent Audit Gateway", version=__version__)
    routers = (
        router,
        approval_router,
        disclosure_router,
        delegation_router,
        console_router,
        coding_router,
        c2_router,
        mcp_router,
    )  # C1/C2 (ADR-0034, ADR-0035)
    for r in (*routers, dashboard_router):
        app.include_router(r)
    return app.openapi()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    args = p.parse_args()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(schema(), indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
