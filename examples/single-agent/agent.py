"""Demo agent (Phase 1, 14 §9 task 13; Phase 4 mixed-risk section).

Default: a scripted, non-LLM agent. Phase 1 part shows the four required outcomes:
  1. public_doc_search  -> ALLOW -> COMPLETED
  2. unknown tool       -> DENIED (SYS-TOOL-UNKNOWN)
  3. delete_record      -> DENIED (deny-delete-record, deny-critical); the agent HAS the scope
  4. bad args           -> DENIED (SYS-ARGS-INVALID), adapter never called
plus create_ticket -> COMPLETED and an idempotent replay.

Phase 4 part (ADR-0026): mixed traffic in its own run. LOW actions are batched (not sealed),
a HIGH action is sealed within a worker tick (seal_reason RISK_HIGH, together with the older
pending events, which are never skipped), a CRITICAL action is DENIED and sealed at once
(RISK_CRITICAL, anchor priority CRITICAL), and later LOW actions wait for the next batch.
The run timeline shows risk level, reasons and the sealing epoch of every event.

``--llm`` (off by default, never in CI): Claude chooses tool calls; every call still goes
through the gateway, which alone decides. Needs the ``anthropic`` package + credentials.

Env: AGW_GATEWAY_URL, AGW_AGENT_TOKEN (printed once by ``agw_gateway.admin create-agent-key``).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from typing import Any

from agw_sdk import Client, GatewayError


def _line(label: str, action: dict[str, Any]) -> None:
    d = action["decision"]
    print(
        f"  {label:<34} status={action['status']:<11} effect={d['effect']:<8} "
        f"risk={d['risk_level']:<8} rules={','.join(d['matched_rule_ids'])}"
    )


def scripted(client: Client) -> int:
    run_id = str(uuid.uuid4())
    print(f"run {run_id}")
    print("tools visible to this agent:", [t["tool_id"] for t in client.list_tools()])
    failures = 0

    def step(label: str, expect: str, **kwargs: Any) -> dict[str, Any]:
        nonlocal failures
        submitted = client.submit_action(run_id=run_id, **kwargs)
        final = client.wait_for_terminal(submitted.action_id)
        _line(label, final)
        if final["status"] != expect:
            failures += 1
            print(f"    !! expected {expect}")
        return final

    search = step(
        "search (allowed)",
        "COMPLETED",
        tool="public_doc_search",
        args={"query": "evidence", "limit": 3},
    )
    print("    result:", json.dumps(search["result"]))
    step("unknown tool", "DENIED", tool="transfer_funds", args={"amount": "100"})
    step(
        "delete_record (critical)",
        "DENIED",
        tool="delete_record",
        args={"record_id": str(uuid.uuid4())},
    )
    step(
        "schema-violating args",
        "DENIED",
        tool="public_doc_search",
        args={"query": "", "limit": "lots", "extra": 1},
    )
    step(
        "create_ticket (allowed)",
        "COMPLETED",
        tool="create_ticket",
        args={"title": "Demo ticket", "priority": "low"},
    )

    key = f"demo-replay-{run_id}"
    first = client.submit_action(
        run_id=run_id, tool="public_doc_search", args={"query": "ticket"}, idempotency_key=key
    )
    again = client.submit_action(
        run_id=run_id, tool="public_doc_search", args={"query": "ticket"}, idempotency_key=key
    )
    same = first.action_id == again.action_id and again.replayed
    print(
        f"  idempotent replay                  same_action={same} replayed_header={again.replayed}"
    )
    failures += 0 if same else 1
    try:
        client.submit_action(
            run_id=run_id, tool="public_doc_search", args={"query": "other"}, idempotency_key=key
        )
        failures += 1
        print("    !! expected 409 for key reuse with a different body")
    except GatewayError as err:
        print(f"  key reuse, different body          http={err.status} code={err.code}")

    print("timeline:")
    for ev in client.timeline(run_id):
        extra = ev.get("decision") or ev.get("status") or ""
        print(f"  seq={ev['seq']:<5} {ev['type']:<24} {extra}")
    failures += mixed_risk(client)
    print("DEMO OK" if failures == 0 else f"DEMO FAILED ({failures})")
    return 0 if failures == 0 else 1


def _epoch(ev: dict[str, Any]) -> str:
    e = ev.get("epoch")
    if e is None:
        return "pending (batched)"
    return f"epoch {e['epoch_no']} {e['seal_reason']}/{e['anchor_priority']}"


def _wait_sealed(client: Client, run_id: str, action_id: str, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        evs = [e for e in client.timeline(run_id) if e["action_id"] == action_id]
        if evs and all(e["epoch"] is not None for e in evs):
            return True
        time.sleep(0.25)
    return False


def mixed_risk(client: Client) -> int:
    """Phase 4 acceptance: LOW batched, HIGH sealed by risk, CRITICAL denied (ADR-0026)."""
    run_id = str(uuid.uuid4())
    print(f"\nPhase 4 mixed-risk run {run_id}")
    failures = 0

    def act(label: str, expect: str, tool: str, args: dict[str, Any], **kw: Any) -> str:
        nonlocal failures
        sub = client.submit_action(run_id=run_id, tool=tool, args=args, **kw)
        final = client.wait_for_terminal(sub.action_id)
        _line(label, final)
        if final["status"] != expect:
            failures += 1
            print(f"    !! expected {expect}")
        return sub.action_id

    for i in range(3):
        act(f"LOW search #{i + 1}", "COMPLETED", "public_doc_search", {"query": f"q{i}"})
    act(
        "MEDIUM internal email",
        "COMPLETED",
        "send_email",
        {"to": ["team@corp.example"], "subject": "status"},
    )
    time.sleep(2.5)  # > 2 sealer ticks: LOW/MEDIUM must still be pending (300 s / 60 s rules)
    sealed = [e for e in client.timeline(run_id) if e["epoch"] is not None]
    print(f"  after 2.5 s: {len(sealed)} of this run's events sealed (expected 0: batched)")
    # Leftover LOW events of an earlier demo run may legitimately reach MAX_AGE/MAX_EVENTS and
    # take these with them; anything else sealing LOW/MEDIUM early would be a bug.
    failures += sum(e["epoch"]["seal_reason"] not in {"MAX_AGE", "MAX_EVENTS"} for e in sealed)

    high = act(
        "HIGH PII export (internal)",
        "PENDING_APPROVAL",
        "export_customer_data",
        {"destination": "s3://exports.corp.example/q4", "limit": 10, "fields": ["id"]},
    )
    if not _wait_sealed(client, run_id, high):
        failures += 1
        print("    !! HIGH action was not sealed within 15 s (is the worker running?)")
    crit = act(
        "CRITICAL IAM change",
        "DENIED",
        "update_iam_role",
        {"principal": "svc-build", "role": "admin"},
    )
    if not _wait_sealed(client, run_id, crit):
        failures += 1
        print("    !! CRITICAL action was not sealed within 15 s")
    act("LOW search after", "COMPLETED", "public_doc_search", {"query": "after"})

    print("timeline (seq, type, risk, decision/status, sealing, reasons):")
    for ev in client.timeline(run_id):
        what = ev.get("decision") or ev.get("status") or ""
        why = ""
        if "risk" in ev:
            r = ev["risk"]
            why = f"score={r['score']} rules={','.join(r['rules']) or '-'}"
            if ev.get("reasons"):
                why += f" policy={','.join(ev['reasons'])}"
        print(
            f"  {ev['seq']:<5} {ev['type']:<22} {ev['risk_level'] or '-':<8} {what:<17} "
            f"{_epoch(ev):<36} {why}"
        )
    tl = client.timeline(run_id)
    high_epochs = {e["epoch"]["seal_reason"] for e in tl if e["action_id"] == high}
    crit_epochs = {e["epoch"]["anchor_priority"] for e in tl if e["action_id"] == crit}
    last_low_pending = tl[-1]["epoch"] is None
    ok = high_epochs == {"RISK_HIGH"} and crit_epochs == {"CRITICAL"} and last_low_pending
    print(
        "  checks: HIGH sealed by RISK_HIGH, CRITICAL epoch has anchor priority CRITICAL, "
        f"trailing LOW still batched -> {'OK' if ok else 'FAILED'}"
    )
    return failures + (0 if ok else 1)


def llm(client: Client, task: str) -> int:  # pragma: no cover - optional, needs credentials
    try:
        import anthropic
    except ImportError:
        print("--llm needs the 'anthropic' package: uv pip install anthropic", file=sys.stderr)
        return 2
    run_id = str(uuid.uuid4())
    tools = [
        {
            "name": t["tool_id"],
            "description": f"{t['operation_type']} tool exposed by the audit gateway",
            "input_schema": t["args_schema"],
        }
        for t in client.list_tools()
    ]
    claude = anthropic.Anthropic()
    messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
    for _ in range(8):
        # Server-side fallback on refusal is enabled by default for this model.
        response = claude.beta.messages.create(
            model="claude-opus-5-5",
            max_tokens=16000,
            tools=tools,
            messages=messages,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        if response.stop_reason in ("refusal", "max_tokens"):
            print(f"stopped: {response.stop_reason}")
            return 1
        messages.append({"role": "assistant", "content": response.content})
        if response.stop_reason == "pause_turn":
            continue
        calls = [b for b in response.content if b.type == "tool_use"]
        if not calls:
            print("".join(b.text for b in response.content if b.type == "text"))
            return 0
        results = []
        for call in calls:
            # The gateway, not the model, decides. Denials come back as normal results.
            submitted = client.submit_action(run_id=run_id, tool=call.name, args=dict(call.input))
            final = client.wait_for_terminal(submitted.action_id)
            _line(f"llm -> {call.name}", final)
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": call.id,
                    "content": json.dumps(
                        {
                            "status": final["status"],
                            "result": final["result"],
                            "reasons": final["decision"]["reasons"],
                        }
                    ),
                    "is_error": final["status"] != "COMPLETED",
                }
            )
        messages.append({"role": "user", "content": results})
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--llm", action="store_true", help="use Claude to choose tool calls (optional)"
    )
    parser.add_argument(
        "--task",
        default=(
            "Find our guidance on evidence retention, "
            "then open a low-priority ticket summarizing it."
        ),
    )
    args = parser.parse_args()
    url = os.environ.get("AGW_GATEWAY_URL", "http://127.0.0.1:8080")
    token = os.environ.get("AGW_AGENT_TOKEN")
    if not token:
        print("AGW_AGENT_TOKEN (missing)", file=sys.stderr)
        return 2
    with Client(url, token) as client:
        return llm(client, args.task) if args.llm else scripted(client)


if __name__ == "__main__":
    raise SystemExit(main())
