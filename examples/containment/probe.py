"""Runs INSIDE the agent container (Phase 8 containment demo, ADR-0030 §9).

1. Network probe: the gateway must be reachable; every tool endpoint, the database and the
   internet must NOT be (by name AND by IP; the host test passes the tool containers' IPs
   as arguments ``name=ip:port``).
2. Credential probe: the agent holds only its own gateway key (no SMTP / tool secrets).
3. Through the gateway the same agent CAN use the tools it is permitted to: the gateway, which
   holds the credentials, reaches them on its behalf; a forbidden action is DENIED.
Prints one JSON document; exit 0 only if every expectation holds.
"""

from __future__ import annotations

import errno
import json
import os
import socket
import sys
import uuid
from typing import Any

from agw_sdk import Client, Denied

FORBIDDEN_BY_NAME = [
    ("mailpit", 1025),  # SMTP sink (tool)
    ("mailpit", 8025),
    ("public-api", 8000),  # read-only API (tool)
    ("postgres", 5432),  # evidence store
    ("one.one.one.one", 443),  # internet (DNS + HTTPS)
]
FORBIDDEN_BY_IP = [("1.1.1.1", 443), ("8.8.8.8", 53)]


def reach(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "CONNECTED"
    except socket.gaierror:
        return "NO_DNS"
    except TimeoutError:
        return "TIMEOUT"
    except OSError as exc:
        return errno.errorcode.get(exc.errno or 0, type(exc).__name__)


def main() -> int:
    out: dict[str, Any] = {"reachable": {}, "unreachable": {}, "gateway_calls": {}}
    ok = True
    gw_host = os.environ["AGW_GATEWAY_URL"].split("//")[1].split(":")[0]
    out["reachable"][f"{gw_host}:8080"] = reach(gw_host, 8080)
    ok &= out["reachable"][f"{gw_host}:8080"] == "CONNECTED"
    extra = [(a.split("=")[0], a.split("=")[1]) for a in sys.argv[1:] if "=" in a]
    targets = [*FORBIDDEN_BY_NAME, *FORBIDDEN_BY_IP]
    targets += [(ipport.split(":")[0], int(ipport.split(":")[1])) for _, ipport in extra]
    for host, port in targets:
        result = reach(host, port)
        out["unreachable"][f"{host}:{port}"] = result
        ok &= result != "CONNECTED"
    secrets_in_env = sorted(k for k in os.environ if "SMTP" in k or "PASSWORD" in k)
    out["credential_env_vars"] = secrets_in_env
    out["creds_dir"] = sorted(os.listdir("/creds"))
    ok &= not secrets_in_env and out["creds_dir"] == ["agent.token"]

    token = open("/creds/agent.token", encoding="ascii").read().strip()  # noqa: SIM115
    with Client(os.environ["AGW_GATEWAY_URL"], token) as client:
        run = str(uuid.uuid4())
        r = client.call("public_api_get", {"url": "http://public-api:8000/status.json"},
                        run_id=run, timeout=20)  # fmt: skip
        out["gateway_calls"]["public_api_get"] = {"status": r.status, "body": r.result["body"]}
        ok &= r.status == "COMPLETED" and r.result["body"].get("service") == "public-api"
        try:
            client.call("delete_record", {"record_id": str(uuid.uuid4())}, run_id=run)
            out["gateway_calls"]["delete_record"] = "EXECUTED"
            ok = False
        except Denied as exc:
            out["gateway_calls"]["delete_record"] = {"status": "DENIED", "reasons": exc.reasons}
    out["result"] = "CONTAINED" if ok else "NOT_CONTAINED"
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
