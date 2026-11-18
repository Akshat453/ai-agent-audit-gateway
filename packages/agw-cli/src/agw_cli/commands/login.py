"""``agw login`` / ``agw logout`` (C2): the RFC 8628 device authorization grant.

The CLI shows a short code and a URL; the developer approves in the browser (signed in to the
dashboard); the CLI polls and receives a device key exactly once, which it stores in the OS
keychain (or a 0600 file outside any repository). The key is never printed.
"""

from __future__ import annotations

import argparse
import contextlib
import socket
import sys
import time
import webbrowser
from collections.abc import Callable
from typing import Any

from agw_cli.client import GatewayUnavailable, public_call
from agw_cli.config import read_file_config, save_file_config
from agw_cli.keystore import KeystoreError, available_backend, delete, store


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("login", help="enroll this device (browser approval)")
    p.add_argument("--url", required=False, help="gateway URL (default: from config)")
    p.add_argument("--tenant", required=False, help="tenant id (default: from config)")
    p.add_argument("--agent-kind", default="other", help="the main agent on this device")
    p.add_argument("--label", default=None, help="device label (default: hostname)")
    p.add_argument("--keystore", choices=("keychain", "file"), default=None)
    p.add_argument("--no-browser", action="store_true")
    p.set_defaults(func=main)
    q = sub.add_parser("logout", help="forget this device's key")
    q.set_defaults(func=logout)


def _say(text: str) -> None:
    print(text, flush=True)  # the code must reach the developer before polling starts


def _label(raw: str | None) -> str:
    base = raw or socket.gethostname().split(".")[0] or "device"
    clean = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in base)[:64]
    return clean or "device"


def run_login(
    url: str,
    tenant: str,
    *,
    agent_kind: str = "other",
    label: str | None = None,
    keystore: str | None = None,
    open_browser: bool = True,
    out: Callable[[str], None] = _say,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    if not url.startswith(("http://", "https://")):
        raise ValueError("--url must be http(s)")
    status, auth = public_call(
        url,
        "/v1/device/authorize",
        {"tenant": tenant, "agent_kind": agent_kind, "label": _label(label)},
    )
    if status != 200 or not isinstance(auth.get("device_code"), str):
        raise GatewayUnavailable("device authorization refused")
    out(
        f"To enroll this device, open {auth['verification_uri']} and enter the code:\n\n"
        f"    {auth['user_code']}\n"
    )
    if open_browser:
        # Headless machines: the URL is printed above.
        with contextlib.suppress(Exception):
            webbrowser.open(str(auth.get("verification_uri_complete", auth["verification_uri"])))
    interval = float(auth.get("interval", 5))
    deadline = clock() + float(auth.get("expires_in", 600))
    while clock() < deadline:
        sleep(interval)
        status, body = public_call(url, "/v1/device/token", {"device_code": auth["device_code"]})
        err = body.get("error")
        if status == 200 and isinstance(body.get("device_key"), str):
            backend = keystore or available_backend()
            account = f"{tenant}@{url}"
            try:
                ref = store(account, body["device_key"], backend)
            except KeystoreError:
                ref = store(account, body["device_key"], "file")
            save_file_config(
                {
                    "url": url.rstrip("/"),
                    "tenant": tenant,
                    "device_key_ref": ref,
                    "device_id": body.get("device_id", ""),
                    "developer": body.get("developer", ""),
                    "device_key_file": None,
                }
            )
            out(
                f"Enrolled as {body.get('developer')} (device {body.get('device_id')}). "
                f"Key stored in {'the OS keychain' if ref.startswith('keychain:') else ref}."
            )
            return {
                "developer": body.get("developer"),
                "device_id": body.get("device_id"),
                "ref": ref,
            }
        if err == "slow_down":
            interval += 5
            continue
        if err == "authorization_pending":
            continue
        raise PermissionError(
            {
                "access_denied": "The enrollment was denied.",
                "expired_token": "The code expired; run agw login again.",
            }.get(str(err), f"Enrollment failed ({err}).")
        )
    raise PermissionError("The code expired; run agw login again.")


def main(args: argparse.Namespace) -> int:
    cfg = read_file_config()
    url = args.url or cfg.get("url")
    tenant = args.tenant or cfg.get("tenant")
    if not url or not tenant:
        print("agw login needs --url and --tenant (first time).", file=sys.stderr)
        return 2
    try:
        run_login(
            str(url),
            str(tenant),
            agent_kind=args.agent_kind,
            label=args.label,
            keystore=args.keystore,
            open_browser=not args.no_browser,
        )
    except (GatewayUnavailable, PermissionError, ValueError) as exc:
        print(f"Login failed: {exc}", file=sys.stderr)
        return 1
    return 0


def logout(args: argparse.Namespace) -> int:
    cfg = read_file_config()
    ref = cfg.get("device_key_ref")
    if isinstance(ref, str) and ref:
        delete(ref)
    save_file_config({"device_key_ref": None, "device_id": None, "developer": None})
    print(
        "Logged out: the device key was removed from this machine. Ask an admin to disable "
        "the device in the dashboard if it may have been copied."
    )
    return 0
