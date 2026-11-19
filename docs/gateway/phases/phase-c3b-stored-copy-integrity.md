# Phase C3b: stored-copy integrity (ADR-0038)

## Why
During a tamper walkthrough we found that the console displayed `evidence_events.body`, which is not hashed. An insider could edit it, for example turn a `deny` into an `allow`, and the screens would still say VERIFIED.

## Changes
- `apps/gateway/src/agw_gateway/evidence/sealed.py` (new):
  - `sealed_header` and `header_for_display` decode the canonical bytes;
  - `stored_copy_ok` compares `body` and the indexed columns with the sealed record.
- Console API (`api/console_routes.py`): nodes and event detail are built from the sealed record. New field `stored_copy_ok`.
- Dashboard, agent and delegation routes (`dashboard_routes.py`, `routes.py`, `delegation_routes.py`) and the approval detail (`approvals/service.py`) now read the canonical bytes instead of `body`.
- Monitor (`apps/worker/.../monitor.py`): new `stored_copy` report section. A mismatch means TAMPERED plus a critical `VERIFICATION_FAILED` alert with `check="stored_copy"`.
- Dashboard: the event page has a third check line, and the action page and timeline count mismatches as broken. `openapi.json` and `schema.d.ts` were regenerated.

## Tests (written for the invariant)
- `tests/unit/test_sealed_view.py`: 4 tests.
- `tests/e2e/test_stored_copy_tamper.py`: 5 tests covering a clean tenant, a forged policy effect, a changed `event_type`, a changed `action_id` and a removed key.

## How to see it yourself
With the stack running and some activity recorded:
```sql
-- docker compose exec postgres psql -U postgres -d agw_ui
BEGIN;
SET LOCAL session_replication_role = replica;   -- triggers off, as an insider would
UPDATE evidence_events SET body = jsonb_set(body, '{policy,effect}', '"deny"')
 WHERE tenant_id = 'akshat' AND event_type = 'POLICY_EVALUATED'
   AND seq = (SELECT min(seq) FROM evidence_events WHERE tenant_id='akshat' AND event_type='POLICY_EVALUATED');
COMMIT;
```
- **Event page:** the badge shows TAMPERED, the third check line fails, and the decision still shows the sealed value.
- **Overview:** within about 60 s it turns red, and the monitor report has `stored_copy.result = TAMPERED`.

## Also in this phase: plain-English log view
- `apps/dashboard/lib/explain.ts` turns a sealed record into a sentence plus details:
  - who did it and what kind of action it was (shell command, file change, push, PR …);
  - the decision, the policy's reasons, the rules that matched, and the risk;
  - when it happened.
- **Event page:** a "What happened" card above the "Raw record" (renamed from "Header"), with links to the action and the session.
- **Action timeline:** each step has a one-line explanation.
- Display only. The command text and file contents stay encrypted in the payload (privacy design, ADR-0029), so the explanation names the kind of action, not its exact arguments.
- Test: `e2e/console.spec.ts` › "plain-English explanations".
