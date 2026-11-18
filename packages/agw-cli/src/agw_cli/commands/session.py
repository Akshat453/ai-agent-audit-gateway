"""``agw session start|end``: explicit sessions (e.g. to declare the issue being worked on).

``start`` records the session for ``--agent`` under ``--native-session`` (default "default"),
so the hooks of that agent use it; the issue text is hashed locally (only the digest leaves
the machine).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from agw_cli import UNAVAILABLE
from agw_cli.adapters import REGISTRY
from agw_cli.client import GatewayClient, GatewayRefused, GatewayUnavailable
from agw_cli.config import ConfigError, load
from agw_cli.normalize import find_repo_root, git_info
from agw_cli.state import SessionState


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("session", help="start or end a coding session")
    ss = p.add_subparsers(dest="session_cmd", required=True)
    st = ss.add_parser("start")
    st.add_argument("--agent", required=True, choices=sorted(REGISTRY))
    st.add_argument("--native-session", default="default")
    st.add_argument("--issue", type=int, default=None, help="issue number")
    st.add_argument("--issue-file", default=None, help="file with the issue text (hashed)")
    en = ss.add_parser("end")
    en.add_argument("--agent", required=True, choices=sorted(REGISTRY))
    en.add_argument("--native-session", default="default")
    p.set_defaults(func=main)


def main(args: argparse.Namespace) -> int:
    try:
        cfg = load()
        client = GatewayClient(cfg)
        state = SessionState(cfg.state_dir, args.agent)
        if args.session_cmd == "start":
            root = find_repo_root(os.getcwd())
            body: dict[str, object] = {
                "agent_kind": args.agent,
                "native_session_id": args.native_session,
            }
            if root is not None:
                body["workspace_root"] = root.as_posix()
                repo = git_info(root)
                if repo:
                    body["repo"] = repo
            if args.issue is not None:
                text = Path(args.issue_file).read_bytes() if args.issue_file else b""
                body["issue"] = {
                    "number": args.issue,
                    "text_sha256": hashlib.sha256(text).hexdigest(),
                }
            sid = client.start_session(body)
            state.put(args.native_session, sid)
            print(json.dumps({"session_id": sid, "run_id": sid}))
            return 0
        ended = state.drop(args.native_session)
        if ended is None:
            print(json.dumps({"error": "no open session for this agent"}))
            return 1
        print(json.dumps(client.end_session(ended)))
        return 0
    except (ConfigError, GatewayUnavailable, GatewayRefused, OSError) as exc:
        print(json.dumps({"error": f"{UNAVAILABLE} ({type(exc).__name__}: {exc})"}))
        return 1
