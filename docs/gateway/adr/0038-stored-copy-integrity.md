# ADR-0038: Screens read the sealed record; the readable copy is checked against it
Status: Accepted · Date: 2026-11-19 · Deciders: the owner (Akshat), after a tamper walkthrough

## Context
Each `evidence_events` row holds the record twice, plus some indexed columns:
- `canonical_bytes`: hashed, chained, sealed into epochs and anchored;
- `body`: a JSON projection for queries (05 §7, "derived, non-authoritative");
- the columns `tenant_id`, `seq`, `event_type`, `action_id`, `run_id`.

Only `canonical_bytes` is covered by a hash. The console's checks (`hash_ok`, `link_ok`) and the monitor (via `agw_verifier`) verify the canonical bytes only. The screens, however, showed values from `body`: the decision, status, reasons, the header view, the security incidents and the approver's view of the policy result.

A database superuser could therefore change `body.policy.effect` from `deny` to `allow`. The console would show "allow" next to a VERIFIED badge, and the monitor would stay VERIFIED. An external `agw-verify` run on an export was never affected, because exports carry only the canonical bytes.

## Decision
1. **Screens show the sealed record.** `evidence/sealed.py`:
   - `header_for_display(canonical)` decodes the canonical bytes into the same JSON projection. If they do not decode it returns `{}`; it never falls back to `body`.
   - Used by: console event and action nodes, event detail, the run timeline (console and agent API), the events lists (dashboard and agent API), security incidents, the delegation view, the agent action view and the approval detail.
   - `body` remains in use only for SQL filtering (tool, connector id, retention tool lookup). Its result rows are still displayed from the sealed bytes.
2. **The copy is checked.** `stored_copy_ok(canonical, body, tenant_id=, seq=, event_type=, action_id=, run_id=)` is true only if `body` equals the decoded projection and every column passed equals the matching sealed field. A NULL `action_id` or `run_id` must match an absent field.
3. **Console.** `EvidenceNode.stored_copy_ok`. The event page shows a third check, "readable copy and columns match the sealed record". The overall badge, the action page and the timeline treat a mismatch as TAMPERED.
4. **Monitor.** Each cycle compares every row in the checked range (streamed, 2,000 rows per batch) and adds a `stored_copy` section to the report: `result`, `events_checked`, `mismatched`, and the first 20 `mismatched_seqs`.
   - A mismatch makes the report TAMPERED.
   - It raises a critical `VERIFICATION_FAILED` alert with `check="stored_copy"`.

## Consequences
- Editing only the readable copy is now visible in one monitor cycle and on the event page, and it can no longer change what a reviewer sees.
- `risk_level` and `occurred_at` are columns that the sealed record does not carry in the same form (`risk_level` is inherited per action; `ts` is microseconds). They are not compared. `risk_level` is display-only, and `actions` rows are separate mutable state that this ADR does not cover.
- Cost: one CBOR decode per displayed row, and one decode per row per monitor cycle (bounded by `monitor_max_events`).
- Tests:
  - `tests/unit/test_sealed_view.py` covers the helpers;
  - `tests/e2e/test_stored_copy_tamper.py` covers an edited `body`, `event_type`, `action_id` and a removed key: the console flips, the screens keep the sealed value, and the monitor reports TAMPERED with the alert while the hash chain still verifies.
