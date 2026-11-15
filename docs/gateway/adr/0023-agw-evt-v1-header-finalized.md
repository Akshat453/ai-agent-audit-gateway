# ADR-0023: AGW-EVT v1 header and AGW-PAY v1 payload as implemented in Phase 2
Status: Accepted · Date: 2026-11-15 · Deciders: Phase 2 implementation (pending owner review)

## Context
05 §4 says unknown record keys require `v = 2` and an ADR. No v1 record had been hashed before Phase 2 (Phase 1 rows have no canonical bytes), and test vectors freeze now. The Phase 2 prompt asks for metadata 05 §4 lacked: observed_at, concurrency_group, payload_ref, an agent-declared code version, and a delegation field that is "present, null".
## Decision
AGW-EVT v1 is final as implemented in `agw_schemas.events`, still `v = 1`. Additions to 05 §4:

| Key | Type | Meaning |
|---|---|---|
| `obs` | uint (µs) | observed_at: when the executor or reconciler observed the occurrence (DISPATCHED, COMPLETED, FAILED, OUTCOME_UNKNOWN). `ts` remains recorded_at. |
| `dispatch.cg` | tstr | concurrency group: `<worker>/<claim batch>`. Actions claimed together; their relative seq order is not causal. |
| `payload.ref` | tstr | where the payload lives: `"inline"` (Postgres) in Phase 2. |
| `code.adapter` | tstr | `<adapter class>@<tool version>` |
| `code.agent` | tstr | agent-declared version (an unauthenticated claim, recorded as such) |

Also decided:
- `args` (the canonical args digest, 06 §3) is set on ACTION_AUTHORIZED and ACTION_DISPATCHED.
- `code` is on ACTION_REQUESTED (`gw`, `agent`) and ACTION_AUTHORIZED (`gw`, `adapter`, `agent`). `code.policy` is **not** implemented: 06 §2 registers no tag for a policy-document digest.
- Header `null` stays forbidden (05 §6). Paper B's delegation field therefore lives in the **payload**: ACTION_REQUESTED payloads carry `delegation: null`, which is allowed there.
- Payload values that the profile cannot encode, such as raw args of a denied request containing floats, are stored as sorted compact JSON **text** under `<key>_json` (`intent.args_json`, `effects.result_json`). Values are never altered silently.
- Error text in `effects.error` is sanitized to `CODE[:ExceptionType]`, never the exception message.
- No field anywhere captures agent reasoning or chain-of-thought. The request envelope rejects a `reasoning` key (422).
## Consequences
+ All eight Paper B fields have a home (mapping table in `agw_schemas/events.py`). + Frozen vectors exist (`test-vectors/event/event-chain.json`).
− Any further header key needs `v = 2` and a new ADR.
