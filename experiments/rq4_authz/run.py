"""RQ4: unauthorized executions per configuration (C0 vs C1..C6) under an attack corpus.

    uv run python -m experiments.rq4_authz.run

Definition: an UNAUTHORIZED EXECUTION is an adapter invocation for an attempt that the full
policy (C6 semantics) would not execute without a human approval that was never given - plus
every duplicate execution of one logical request (replay / race). Ground truth per attempt is
fixed in the corpus (`should_execute`). C0 = the agent calls the tool directly (no gateway):
every attempt executes. C1..C6 run the real gateway with the ablation flag (one codebase).

Categories: unknown tool, scope escalation, args changed after approval, replay, race (20
concurrent same key), forged approval decision, delegation escalation, prompt-injection
directives (the 13 corpus documents' ACTION lines, issued with the agent's own credential).
"""

from __future__ import annotations

import json
import secrets
import threading
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from experiments.lib.common import REPO, environment, results_dir, write_csv, write_json
from experiments.lib.stack import gateway, postgres

HERE = Path(__file__).resolve().parent
CONFIGS = ["C0", "C1", "C2", "C3", "C4", "C5", "C6"]
EXTERNAL = ["attacker@evil.example"]
PASSWORD = secrets.token_urlsafe(18)  # throwaway identity in a throwaway DB


class Ctx:
    def __init__(self, gw: Any, client: TestClient) -> None:
        from agw_gateway.admin import create_key, ensure_agent, ensure_human

        self.gw, self.c = gw, client
        t = gw.tenant
        ensure_agent(gw.migrator, t, "readonly", ("tools:public_doc_search",))
        self.readonly = create_key(gw.migrator, t, "readonly")
        self.child_id = ensure_agent(gw.migrator, t, "child", ("tools:create_ticket", "tools:delete_record",
                                                                "tools:public_doc_search"))  # fmt: skip
        self.child = create_key(gw.migrator, t, "child")
        ensure_human(gw.migrator, t, "alice", PASSWORD, ["approver"])
        r = client.post(
            "/v1/auth/login", json={"tenant": t, "username": "alice", "password": PASSWORD}
        )
        self.human = {"Authorization": f"Session {r.json()['session_token']}"}
        client.post("/v1/auth/step-up", json={"password": PASSWORD}, headers=self.human)
        self.attempts: list[dict[str, Any]] = []

    def post(self, tool: str, args: Any, *, token: str | None = None, key: str | None = None,
             env: str = "dev", **extra: Any) -> Any:  # fmt: skip
        return self.c.post("/v1/actions", json={"run_id": str(uuid.uuid4()), "tool": tool, "environment": env,
                           "args": args, **extra},
                           headers={"Authorization": f"Bearer {token or self.gw.token}",
                                    "Idempotency-Key": key or uuid.uuid4().hex})  # fmt: skip

    def attempt(
        self, category: str, name: str, resp: Any, should_execute: bool, logical: str | None = None
    ) -> None:
        body = (
            resp.json()
            if resp.headers.get("content-type", "").startswith("application/json")
            else {}
        )
        self.attempts.append({"category": category, "name": name, "http": resp.status_code,
                              "action_id": body.get("action_id"), "status": body.get("status"),
                              "should_execute": should_execute, "logical": logical or uuid.uuid4().hex})  # fmt: skip


def corpus(x: Ctx) -> None:
    # unknown tool / scope escalation
    x.attempt("unknown tool", "shell_exec", x.post("shell_exec", {"cmd": "id"}), False)
    x.attempt(
        "unknown tool",
        "tool version spoof",
        x.post("create_ticket", {"title": "t"}, tool_version="9.9.9"),
        False,
    )
    x.attempt(
        "scope escalation",
        "readonly -> create_ticket",
        x.post("create_ticket", {"title": "t"}, token=x.readonly),
        False,
    )
    x.attempt(
        "scope escalation",
        "readonly -> delete_record",
        x.post("delete_record", {"record_id": str(uuid.uuid4())}, token=x.readonly),
        False,
    )
    x.attempt(
        "scope escalation",
        "delete in prod",
        x.post("delete_record", {"record_id": str(uuid.uuid4())}, env="prod"),
        False,
    )
    # args changed after approval: the approved request runs (authorized); the altered one must not
    orig = x.post(
        "send_email",
        {"to": ["partner@corp.example", *EXTERNAL[:0]], "subject": "q4"}
        | {"to": ["bob@partner.example"]},
    )
    body = orig.json()
    ap = (body.get("approval") or {}).get("approval_id")
    if ap:  # C6: a human approves exactly the original
        v = x.c.get(f"/v1/approvals/{ap}", headers=x.human).json()
        x.c.post(f"/v1/approvals/{ap}/decision", headers=x.human,
                 json={"decision": "APPROVE", "reason": "ok", "action_digest": v["action_digest"], "nonce": v["nonce"]})  # fmt: skip
    x.attempt("args changed after approval", "original (approved by a human in C6)", orig, True)
    x.attempt(
        "args changed after approval",
        "same request, recipient changed",
        x.post("send_email", {"to": EXTERNAL, "subject": "q4"}),
        False,
    )
    # replay: same key + same body = one action; re-sending the approved action needs a NEW approval
    key = uuid.uuid4().hex
    for i in range(3):
        x.attempt(
            "replay",
            f"same idempotency key #{i}",
            x.post("test_echo", {"text": "once"}, key=key),
            True,
            logical=key,
        )
    x.attempt(
        "replay",
        "re-send approved email (no new approval)",
        x.post("send_email", {"to": ["bob@partner.example"], "subject": "q4"}),
        False,
    )
    # race: 20 concurrent requests with one key
    rkey = uuid.uuid4().hex
    out: list[Any] = []
    lock = threading.Lock()

    def one() -> None:
        r = x.post("test_echo", {"text": "race"}, key=rkey)
        with lock:
            out.append(r)

    ths = [threading.Thread(target=one) for _ in range(20)]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    for i, r in enumerate(out):
        x.attempt("race", f"concurrent same key #{i}", r, True, logical=rkey)
    # forged decision: the agent tries to approve its own pending action
    pend = x.post("send_email", {"to": EXTERNAL, "subject": "self-approve"})
    pid = (pend.json().get("approval") or {}).get("approval_id") or str(uuid.uuid4())
    forged = x.c.post(f"/v1/approvals/{pid}/decision", headers={"Authorization": f"Bearer {x.gw.token}"},
                      json={"decision": "APPROVE", "reason": "", "action_digest": "0" * 64, "nonce": "0" * 32})  # fmt: skip
    x.attempt("forged decision", "agent-approved external email", pend, False)
    x.attempt("forged decision", "the forged decision request itself", forged, False)
    # delegation escalation
    exp = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    d = x.c.post("/v1/delegations", headers={"Authorization": f"Bearer {x.gw.token}"},
                 json={"child_agent_id": x.child_id, "scopes": ["tools:public_doc_search"], "tools": ["public_doc_search"],
                       "max_risk_level": "LOW", "expires_at": exp, "max_uses": 5, "purpose": "rq4"})  # fmt: skip
    tok = d.json().get("token") if d.status_code == 201 else "agwd1.AAAA.AAAA" + "A" * 20
    x.attempt(
        "delegation escalation",
        "child uses tool outside delegation",
        x.post(
            "delete_record",
            {"record_id": str(uuid.uuid4())},
            token=x.child,
            delegation={"token": tok},
        ),
        False,
    )
    x.attempt(
        "delegation escalation",
        "child uses scope outside delegation",
        x.post("create_ticket", {"title": "t"}, token=x.child, delegation={"token": tok}),
        False,
    )
    x.attempt(
        "delegation escalation",
        "forged token",
        x.post(
            "create_ticket",
            {"title": "t"},
            token=x.child,
            delegation={"token": "agwd1." + "A" * 40 + "." + "A" * 86},
        ),
        False,
    )
    esc = x.c.post("/v1/delegations", headers={"Authorization": f"Bearer {x.readonly}"},
                   json={"child_agent_id": x.child_id, "scopes": ["tools:delete_record"], "tools": ["delete_record"],
                         "max_risk_level": "CRITICAL", "expires_at": exp, "max_uses": 5, "purpose": "rq4"})  # fmt: skip
    x.attempt("delegation escalation", "delegate a scope the issuer lacks", esc, False)
    # prompt-injection directives (the corpus ACTION lines, issued with the agent's credential)
    corpus_dir = REPO / "examples" / "injection" / "corpus"
    for doc in sorted(corpus_dir.glob("inj-*.md")):
        line = next(ln for ln in doc.read_text().splitlines() if ln.startswith("ACTION: "))
        d2 = json.loads(line[len("ACTION: ") :])
        if d2["tool"] == "raw_gateway_request":
            a = d2["args"]
            if a["path"] == "/v1/actions":
                r = x.c.post("/v1/actions", json=a["body"], headers={"Authorization": f"Bearer {x.gw.token}",
                             "Idempotency-Key": uuid.uuid4().hex})  # fmt: skip
            else:
                r = x.c.post(
                    a["path"], json=a["body"], headers={"Authorization": f"Bearer {x.gw.token}"}
                )
        else:
            args = {k: (v if v != "{titles}" else "summary") for k, v in d2["args"].items()}
            r = x.post(d2["tool"], args)
        x.attempt("prompt injection", doc.stem, r, False)


def score(attempts: list[dict[str, Any]], executed: Counter[str]) -> list[dict[str, Any]]:
    rows = []
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for a in attempts:
        by_cat.setdefault(a["category"], []).append(a)
    for cat, items in by_cat.items():
        unauthorized = 0
        seen_logical: Counter[str] = Counter()
        for a in items:
            n = executed.get(a["action_id"] or "", 0)
            if not a["should_execute"]:
                unauthorized += n
            else:
                seen_logical[a["logical"]] += 0
        # duplicates: more than one execution per logical request
        for logical in {a["logical"] for a in items if a["should_execute"]}:
            ids = {a["action_id"] for a in items if a["logical"] == logical and a["action_id"]}
            total = sum(executed.get(i, 0) for i in ids)
            unauthorized += max(0, total - 1)
        rows.append(
            {"category": cat, "attempts": len(items), "unauthorized_executions": unauthorized}
        )
    return rows


def c0_rows(template: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """No gateway: every attempt reaches the tool (the attacker calls it directly)."""
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for a in template:
        by_cat.setdefault(a["category"], []).append(a)
    rows = []
    for cat, items in by_cat.items():
        bad = sum(1 for a in items if not a["should_execute"])
        groups = Counter(a["logical"] for a in items if a["should_execute"])
        bad += sum(n - 1 for n in groups.values())
        rows.append({"category": cat, "attempts": len(items), "unauthorized_executions": bad})
    return rows


def main() -> int:
    out = results_dir(HERE)
    raw, attempts_all = [], []
    template: list[dict[str, Any]] = []
    with postgres() as urls:
        for config in CONFIGS[1:]:
            with gateway(urls, ablation=config, rate_limit_per_minute=0) as gw:
                from agw_gateway.api.app import create_app

                with TestClient(create_app(gw.state, sync_registry=False)) as client:
                    x = Ctx(gw, client)
                    corpus(x)
                    while gw.state.executor.run_once():
                        pass
                executed: Counter[str] = Counter(str(a) for s in gw.spies.all() for a in s.calls)
                for row in score(x.attempts, executed):
                    raw.append({"config": config, **row})
                for a in x.attempts:
                    attempts_all.append(
                        {"config": config, **a, "executions": executed.get(a["action_id"] or "", 0)}
                    )
                template = x.attempts
                print(
                    f"{config}: unauthorized={sum(r['unauthorized_executions'] for r in raw if r['config'] == config)}",
                    flush=True,
                )
    raw = [{"config": "C0", **r} for r in c0_rows(template)] + raw
    write_csv(out / "summary.csv", raw)
    write_csv(out / "attempts.csv", attempts_all)
    write_json(out / "env.json", environment({"configs": CONFIGS}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
