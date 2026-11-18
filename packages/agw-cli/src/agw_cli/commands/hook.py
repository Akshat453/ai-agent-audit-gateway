"""``agw hook <agent_kind> <event>``: the pre/post-action hook every coding agent calls.

Pre-action: normalize -> ``POST /v1/coding/decide`` -> allow | deny | ask. On ask the hook
waits (polling the approval, bounded by ``approval_wait_seconds`` and safely below the agent's
own hook timeout); approved -> the identical retry consumes the approval -> allow; rejected ->
deny; still pending -> block with "Approval pending: <link>. Retry after approval.".

FAIL CLOSED: missing configuration, gateway unreachable, timeout, malformed response, an
unreadable native payload or ANY internal error blocks a pre-action. Post-action and session
events can never block (the agents ignore it), so their failures are reported on stderr only.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable
from typing import Any

from agw_cli import UNAVAILABLE
from agw_cli.adapters import Adapter, PayloadError, Rendered, Verdict, get
from agw_cli.adapters.generic import McpGenericAdapter
from agw_cli.client import GatewayClient, GatewayRefused, GatewayUnavailable
from agw_cli.config import Config, ConfigError, load
from agw_cli.normalize import HookInput, PreAction, find_repo_root, git_info
from agw_cli.state import SessionState

MAX_STDIN = 8 * 1024 * 1024
POLL_SLICE = 20.0  # one long-poll request waits at most this long


def _deny(user: str, agent: str | None = None) -> Verdict:
    return Verdict(allow=False, user_message=user, agent_message=agent or user)


class HookRun:
    def __init__(
        self,
        adapter: Adapter,
        event: str,
        cfg: Config,
        client: GatewayClient,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.adapter, self.event, self.cfg, self.client, self.clock = (
            adapter,
            event,
            cfg,
            client,
            clock,
        )
        self.state = SessionState(cfg.state_dir, adapter.kind)
        self.started = clock()

    # ---------------------------------------------------------------- sessions
    def start_session(self, hi: HookInput) -> str:
        root = find_repo_root(hi.cwd)
        body: dict[str, Any] = {
            "agent_kind": self.adapter.kind,
            "native_session_id": hi.native_session,
        }
        if hi.agent_version:
            body["agent_version"] = hi.agent_version
        if root is not None:
            body["workspace_root"] = root.as_posix()
            repo = git_info(root)
            if repo:
                body["repo"] = repo
        if self.cfg.issue_number and self.cfg.issue_sha256:
            body["issue"] = {"number": self.cfg.issue_number, "text_sha256": self.cfg.issue_sha256}
        sid = self.client.start_session(body)
        self.state.put(hi.native_session, sid)
        return sid

    def session(self, hi: HookInput) -> str:
        return self.state.get(hi.native_session) or self.start_session(hi)

    # ---------------------------------------------------------------- pre
    def decide(self, hi: HookInput, pre: PreAction) -> Verdict:
        sid = self.session(hi)
        body = self._body(sid, pre)
        try:
            resp = self.client.decide(body)
        except GatewayRefused as exc:
            if exc.code not in ("CODING_SESSION_CLOSED", "NOT_FOUND"):
                raise
            sid = self.start_session(hi)  # the gateway session ended or is unknown: renew
            body = self._body(sid, pre)
            resp = self.client.decide(body)
        return self._verdict(resp, body)

    @staticmethod
    def _body(sid: str, pre: PreAction) -> dict[str, Any]:
        body: dict[str, Any] = {"session_id": sid, "action": {**pre.action, "session_id": sid}}
        if pre.diff is not None:
            body["diff"] = pre.diff
        if pre.correlation:
            body["correlation_id"] = pre.correlation[:128]
        return body

    def _verdict(self, resp: dict[str, Any], body: dict[str, Any]) -> Verdict:
        decision, reason = resp["decision"], resp.get("reason", "")
        rules = ", ".join(str(r) for r in resp.get("rule_ids", [])[:6])
        if decision == "allow":
            return Verdict(True, f"AgentGuard: allowed ({rules}).", "")
        if decision == "deny":
            return _deny(
                f"AgentGuard denied this action: {reason}",
                f"AgentGuard denied this action: {reason} [rules: {rules}]. Do not retry it "
                "unchanged; choose a different approach or ask the developer.",
            )
        return self._wait(resp, body)

    def _budget(self) -> float:
        cap = self.adapter.max_wait(self.cfg.hook_timeout)
        return max(0.0, min(self.cfg.approval_wait, cap) - (self.clock() - self.started))

    def _wait(self, resp: dict[str, Any], body: dict[str, Any]) -> Verdict:
        approval = resp["approval"]
        link = str(approval.get("link", ""))
        role = str(approval.get("required_role", "approver"))
        pending = _deny(
            f"Approval pending: {link}. Retry after approval.",
            f"Approval pending: {link}. Retry after approval. This action needs a human "
            f"approval (role: {role}); retry the IDENTICAL action once it is approved.",
        )
        deadline = self.clock() + self._budget()
        action_id = resp["action_id"]
        while self.clock() < deadline:
            remaining = deadline - self.clock()
            st = self.client.action_status(action_id, wait=min(POLL_SLICE, remaining))
            state = st.get("approval_state")
            if state == "APPROVED":
                again = self.client.decide(body)  # the identical retry consumes the approval
                if again["decision"] == "allow":
                    return Verdict(True, "AgentGuard: approved by a human.", "")
                if again["decision"] == "deny":
                    return self._verdict(again, body)
                return pending
            if state == "REJECTED" or st.get("status") == "DENIED":
                return _deny(
                    "AgentGuard: a human rejected this action.",
                    "A human reviewer rejected this action. Do not retry it unchanged.",
                )
            if state in ("EXPIRED", "INVALIDATED", "CONSUMED") or st.get("status") == "EXPIRED":
                return pending
        return pending

    # ---------------------------------------------------------------- post / session
    def observe(self, hi: HookInput) -> None:
        sid = self.session(hi)
        body: dict[str, Any] = {"session_id": sid, "success": hi.success, "files_touched": hi.files}
        for key, value in (
            ("correlation_id", hi.correlation),
            ("action_type", hi.action_type),
            ("exit_code", hi.exit_code),
            ("result_sha256", hi.result_sha256),
            ("duration_ms", hi.duration_ms),
        ):
            if value is not None:
                body[key] = value
        if hi.correlation is not None:
            body["correlation_id"] = hi.correlation[:128]
        self.client.observe(body)

    def end(self, hi: HookInput) -> None:
        sid = self.state.drop(hi.native_session)
        if sid is not None:
            self.client.end_session(sid)


def run_hook(
    kind: str,
    event: str,
    raw: str,
    *,
    loader: Callable[[], Config] = load,
    client_factory: Callable[[Config], GatewayClient] = GatewayClient,
    clock: Callable[[], float] = time.monotonic,
) -> Rendered:
    adapter = get(kind)
    if adapter is None:
        return Rendered(stderr=f"{UNAVAILABLE}: unknown agent kind {kind!r}", exit_code=2)
    phase = adapter.phase(event)
    if phase == "unknown":
        return Rendered(stderr=f"{UNAVAILABLE}: unknown event {event!r} for {kind}", exit_code=2)
    payload: dict[str, Any] | None = None
    try:
        parsed = json.loads(raw) if raw.strip() else None
        payload = parsed if isinstance(parsed, dict) else None
    except ValueError:
        payload = None
    if phase != "pre":
        return _non_blocking(adapter, event, payload, loader, client_factory, clock)
    return _pre(adapter, event, payload, loader, client_factory, clock)


def _render_pre(
    adapter: Adapter,
    event: str,
    verdict: Verdict,
    cfg: Config | None,
    payload: dict[str, Any] | None,
) -> Rendered:
    if isinstance(adapter, McpGenericAdapter):
        return adapter.render_pre_with_request(payload or {}, verdict)
    return adapter.render_pre(event, verdict, cfg.allow_mode if cfg else "defer")


def _pre(
    adapter: Adapter,
    event: str,
    payload: dict[str, Any] | None,
    loader: Callable[[], Config],
    client_factory: Callable[[Config], GatewayClient],
    clock: Callable[[], float],
) -> Rendered:
    cfg: Config | None = None
    try:
        cfg = loader()
    except ConfigError as exc:
        return _render_pre(adapter, event, _deny(f"{UNAVAILABLE} ({exc})"), None, payload)
    if payload is None:
        return _render_pre(
            adapter,
            event,
            _deny("AgentGuard could not read the agent's request - action blocked"),
            cfg,
            payload,
        )
    try:
        hi = adapter.parse(event, payload)
    except (PayloadError, ValueError, TypeError, KeyError):
        return _render_pre(
            adapter,
            event,
            _deny("AgentGuard could not interpret the agent's request - action blocked"),
            cfg,
            payload,
        )
    try:
        run = HookRun(adapter, event, cfg, client_factory(cfg), clock)
        verdict = Verdict(True, "AgentGuard: allowed.", "")
        for pre in hi.actions:
            verdict = run.decide(hi, pre)
            if not verdict.allow:
                break
    except GatewayRefused as exc:
        verdict = _deny(f"{UNAVAILABLE} (gateway refused: {exc.code})")
    except GatewayUnavailable as exc:
        verdict = _deny(f"{UNAVAILABLE} ({exc})")
    except Exception as exc:
        verdict = _deny(f"{UNAVAILABLE} (internal error: {type(exc).__name__})")
    return _render_pre(adapter, event, verdict, cfg, payload)


def _non_blocking(
    adapter: Adapter,
    event: str,
    payload: dict[str, Any] | None,
    loader: Callable[[], Config],
    client_factory: Callable[[Config], GatewayClient],
    clock: Callable[[], float],
) -> Rendered:
    note = ""
    try:
        cfg = loader()
        hi = adapter.parse(event, payload or {})
        run = HookRun(adapter, event, cfg, client_factory(cfg), clock)
        if hi.phase == "post":
            run.observe(hi)
        elif hi.phase == "session_start":
            run.start_session(hi)
        elif hi.phase == "session_end":
            run.end(hi)
    except (ConfigError, GatewayUnavailable, GatewayRefused, PayloadError) as exc:
        note = f"AgentGuard: could not record {event} ({type(exc).__name__})"
    except Exception as exc:
        note = f"AgentGuard: could not record {event} ({type(exc).__name__})"
    out = adapter.render_other(event, payload)
    return Rendered(stdout=out.stdout, stderr=note, exit_code=0)


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("hook", help="run as an agent hook: native JSON on stdin")
    p.add_argument(
        "agent_kind", help="claude_code | codex | cursor | gemini_cli | mcp_generic | other"
    )
    p.add_argument("event", help="the agent's native hook event name (or pre/post)")
    p.set_defaults(func=main)


def main(args: argparse.Namespace) -> int:
    try:
        raw = sys.stdin.read(MAX_STDIN + 1)
        if len(raw) > MAX_STDIN:
            raw = ""  # oversized: unreadable -> blocked for pre events
        out = run_hook(args.agent_kind, args.event, raw)
    except Exception as exc:
        sys.stderr.write(f"{UNAVAILABLE} (internal error: {type(exc).__name__})\n")
        return 2
    if out.stdout:
        sys.stdout.write(out.stdout + "\n")
    if out.stderr:
        sys.stderr.write(out.stderr + "\n")
    return out.exit_code
