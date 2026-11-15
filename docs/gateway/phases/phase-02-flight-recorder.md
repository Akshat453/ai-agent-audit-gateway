# Phase 2 — Structured Flight Recorder

Status: **Done**, 2026-11-15. Goal: turn Phase 1's lifecycle events into Paper B-style evidence. That means eight semantic fields, deterministic CBOR, SHA-256 digests, a per-tenant hash chain with transactional seq allocation, and a standalone chain verifier.

> **Claim boundary.** A VERIFIED chain means the exported records are unchanged and correctly ordered relative to the trusted inputs the verifier was given. It does not mean the actions were truthful, authorized, complete or correct.

## 1. What changed

| Area | Files |
|---|---|
| Canonical codec (normative) | `packages/schemas/src/agw_schemas/cbor.py` (AGW-CBOR-v1 strict encoder and decoder) |
| Event and payload models | `packages/schemas/src/agw_schemas/events.py` (one model per event type, schema v1, eight-field mapping) |
| Frozen vectors | `packages/schemas/test-vectors/cbor/{valid,reject}.json` (52 + 36), `event/event-chain.json` (3-event chain, 2 payloads, args digest), `generate_phase2.py` (`make vectors` checks for diffs and never overwrites) |
| Hashing helpers | `apps/gateway/src/agw_gateway/crypto/canonical.py` (event hash, payload digest, args digest, JSON projection), `crypto/tags.py` |
| Writer | `evidence/writer.py` rewritten: chain-head lock, salted payload, canonical header encoded once, `event_hash` over the stored bytes |
| Payload store | `evidence/payloads.py`: `PayloadStore` interface, `PlaintextPayloadStore` (**plaintext; encryption swaps it later**) |
| Export | `evidence/export.py`, plus `admin export-chain` and `admin chain-head` |
| Flow | `execution/service.py`: intent and context payloads, `code` provenance, `agent_version` envelope field. `execution/executor.py`: execution and effects payloads, `obs`, concurrency group, args digest |
| Provenance | `provenance.py` (gateway git commit, `+dirty`, or `AGW_BUILD_COMMIT`) |
| API | `GET /v1/events` (headers only, filters, scope-limited) |
| Schema | `migrations/versions/0002_phase2_flight_recorder.py`: `chain_heads`, `evidence_events.event_hash`, `canonical_bytes NOT NULL`, append-only `evidence_payloads`, drops `tenants.next_seq`; refuses to run over Phase 1 evidence |
| Verifier | `packages/verifier/src/agw_verifier/{cbor,chain,cli}.py`: stdlib only, its own codec, CLI `agw-verify chain` |
| Tooling | `Makefile` (`vectors`, `verify-isolated`, `bench`), CI job `vectors-and-verifier-isolation`, import-linter: the verifier may not import `agw_schemas`, pydantic or sqlalchemy |
| Demo | `run_demo.sh` now exports the demo tenant's chain and runs `agw-verify` against the chain head |
| Benchmark | `experiments/benchmarks/phase2_event_latency.py` |

## 2. Where Paper B's eight fields live

| Field | Event | Location |
|---|---|---|
| Intent | ACTION_REQUESTED | payload `intent` (`args` = validated args, or `args_json` = raw text if invalid; `summary`) |
| Policy evaluation | POLICY_EVALUATED | header `policy` + `risk` |
| Human approval | APPROVAL_GRANTED / DENIED / EXPIRED | header `approval` (models only; not written yet) |
| Execution | ACTION_DISPATCHED | payload `execution.params` (exact adapter input); header `args` digest |
| Effects | COMPLETED / FAILED / OUTCOME_UNKNOWN | payload `effects` (`result` / `result_json` / sanitized `error`) |
| Context provenance | ACTION_REQUESTED | payload `context.sources` (uri + 32-byte digest); header `env` |
| Code provenance | REQUESTED, AUTHORIZED | header `code` {`gw` commit, `adapter` = class@version, `agent` = declared} |
| Delegation provenance | ACTION_REQUESTED | payload `delegation: null` (present, null until delegation exists) |

There is no reasoning or chain-of-thought field anywhere, and a `reasoning` key in a request is rejected with 422.

Header naming: `prev` = prev_event_hash, `ts` = recorded_at, `obs` = observed_at, `dispatch.cg` = concurrency_group, `payload.ref` = payload_ref.

**`seq` is recording order, not causal order.** Actions claimed in one executor batch share a `dispatch.cg`; their relative seq order says only which evidence committed first.

## 3. Decisions

| Decision | Why | Record |
|---|---|---|
| Hand-written CBOR codec, plus a second one in the verifier | `cbor2` 6.3.0's decoder accepted every non-canonical input tried (unsorted and duplicate keys, non-shortest ints, indefinite lengths, floats, tags, undefined) | [ADR-0021](../adr/0021-own-agw-cbor-codec.md) |
| `chain_heads` table + `SELECT … FOR UPDATE` | Phase 2 prompt; supersedes ADR-0018's `tenants.next_seq` mechanism | [ADR-0022](../adr/0022-chain-heads-table.md) |
| Header additions `obs`, `dispatch.cg`, `payload.ref`, `code.adapter`/`code.agent`; delegation in the payload (header null is forbidden); `*_json` text for values the profile can't encode | Prompt asks for these fields; 05 §6 forbids null and floats in records | [ADR-0023](../adr/0023-agw-evt-v1-header-finalized.md) |
| Plaintext payload store behind an interface; export via operator CLI only; `/v1/events` own-events unless `audit:events:read` | Encryption arrives later; exports contain plaintext | [ADR-0024](../adr/0024-phase2-payload-store-export-events-api.md) |
| Hash tags are length-prefixed (`0x0c "AGW/event/v1"`), not the raw string the prompt shows | ADR-0006 defines the prompt's `"AGW/event/v1" \|\| …` notation as exactly this encoding | ADR-0006 |
| The verifier shares no code with the gateway, only the frozen vectors | 10 §1: a gateway bug must not hide in shared code | ADR-0021 |
| Phase 1 evidence is not backfilled; migration 0002 refuses to run unless `AGW_ALLOW_DEV_EVIDENCE_RESET=1` and `AGW_ENV=dev\|test` | Append-only rows can't gain canonical bytes | 14 §8 |

### Differences between the Phase 2 prompt and the docs (flagged for the owner)
- The prompt's "read first" list names `10-privacy-and-storage.md`, which doesn't exist. I read `07-key-management-and-privacy.md` and `10-verification-and-evaluation.md` instead.
- The prompt's phase numbers differ from [13-roadmap.md](../13-roadmap.md). The prompt puts encryption in Phase 7, approvals in Phase 5 and delegation in Phase 8; the roadmap says 5, 4 and 10. Code comments say "later phase" rather than a number. **Owner: please confirm which roadmap is authoritative.**
- The roadmap freezes test vectors in Phase 3. The prompt asked for frozen CBOR vectors now, so CBOR and event-chain vectors are frozen in Phase 2; Merkle and epoch vectors remain Phase 3.

## 4. Verification results
- **Clean-state acceptance** (`.env`, `.venv`, stack and volume removed): `make up && make migrate && make test && make demo` exit 0. 376 tests pass. Coverage: 97% on policies/auth/tools/execution, 93% overall. `writer.py` 90%, `agw_schemas.cbor` 100%, verifier `chain.py` 90%, `cbor.py` 95%. The demo ends with `agw-verify` → `"result": "VERIFIED"` over 24 events.
- **Verifier isolation**: `make verify-isolated` installs only `agw-verifier` into a fresh venv. `uv pip list` shows `agw-verifier 0.1.0` alone; `agw_gateway`, `agw_schemas`, `pydantic` and `sqlalchemy` are absent; `agw-verify` runs.
- **Vectors**: `make vectors` reports all three files `ok`. Every valid vector is identical to `cbor2` canonical output, and every reject vector fails with its expected code.
- **Mutation checks** (remove a protection, its test must fail): 11 of 11 were caught. The first run found 2 weak verifier tests (prev link, duplicate id); forged-chain tests were added for both.
- **Benchmark** (local, unvalidated, `make bench`, n = 2000):

| Measure | P50 | P95 |
|---|---|---|
| CPU: canonicalize + hash per event | 54.3 µs | 63.5 µs |
| Phase 2 append tx (1 event + payload) | 2.50 ms | 4.77 ms |
| Baseline JSONB insert tx | 1.00 ms | 1.60 ms |
| **Added per event** | **+1.50 ms** | **+3.17 ms** |

Contention: 8 threads into 1 tenant reached 470 events/s; 8 threads into 8 tenants reached 1,222 events/s. This is the single-writer-per-tenant limit.

## 5. Known limits and gaps
- **Suffix deletion is not detectable without a trusted head.** A privileged attacker can delete the newest events and rewind `chain_heads` consistently; the remaining prefix verifies (asserted by `test_suffix_deletion_needs_a_trusted_head`). With an out-of-band head (`--trusted-head/--trusted-seq`) it is TAMPERED. Epochs (Phase 3) and anchors provide that head.
- Deleting a middle event shows up as a seq gap (INCOMPLETE with the missing range). Renumbering to hide the gap is TAMPERED.
- Payloads are **plaintext** in `evidence_payloads` and in exports until encryption lands.
- Single writer per tenant (see benchmark). Two reconcilers could deadlock across tenants in rare orderings; Postgres aborts one and the loop retries.
- `code.policy` (policy-document digest) is not implemented: no hash tag is registered for it.
- Verifier lifecycle conformance (10 §3 V9) is not implemented; it belongs to the verifier phase.
- Running `make migrate` on an existing dev database that holds Phase 1 rows requires `AGW_ALLOW_DEV_EVIDENCE_RESET=1`, which wipes dev evidence.
- `run_demo.sh` leaves its export file in the system temp directory.

## 6. Ready for Phase 3
- Every event has `canonical_bytes` and `event_hash`, chained per tenant from genesis. These are exactly the leaf inputs 06 §6.1 needs.
- `chain_heads` gives the sealer a consistent head to seal up to. `outbox_jobs.kind` can gain `SEAL`.
- The vectors layout is in place for the Merkle and epoch vectors.
