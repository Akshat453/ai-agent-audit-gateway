# Phase 3 — Merkle Epochs + Offline Verifier

Status: **Done**, 2026-11-15. Goal: reproduce Paper B's Merkle batching and epoch-root chaining with our corrected construction (06 §6–7), sealed by a durable worker and verified by an independent CLI.

> **Claim boundary.** In Phase 3 the only trust root is a **locally sealed** epoch root reported by this system. Without a root obtained out of band, the verifier answers UNANCHORED ("locally sealed only"), never VERIFIED. Anchoring (a later phase) supplies external roots. Even then, VERIFIED means "unchanged and correctly ordered", not "truthful, authorized, complete or correct".

## 1. What changed

| Area | Files |
|---|---|
| Merkle + epoch root (gateway) | `apps/gateway/src/agw_gateway/crypto/merkle.py`: RFC 9162 leaf/node hashes, split at the largest power of two, no duplication, audit paths, RFC 9162 §2.1.3.2 verification, `R_t` with the exact 06 §7 byte layout; n = 0 rejected |
| Merkle + epochs (verifier, independent) | `packages/verifier/src/agw_verifier/merkle.py` (stack-based tree, separately written), `epochs.py` (epoch continuity, bundle verification, trust handling) |
| Vectors (frozen) | `packages/schemas/test-vectors/merkle/`: trees of 1, 2, 3, 4, 5, 7 and 8 leaves with every leaf hash and a proof for every index, `merkle-negative.json` (10 must-fail proofs + the Paper B duplication pair), `epoch-root.json` (3-epoch chain with every hash input), `epoch-root-negative.json` (7 field mutations), `tags.json`. Generator: `generate_phase3.py`. Every value is cross-checked between the two implementations; `make vectors` checks for diffs and never overwrites |
| Schema | `migrations/versions/0003_phase3_merkle_epochs.py`: `epoch_heads`; append-only `epochs` with a tiling trigger (contiguous numbers, `first = prev.last + 1`, `prev_root = R_{t−1}`, not beyond the chain head); `outbox_jobs` kind `SEAL` (+ `up_to_seq`, `seal_reason`, at most one open SEAL job per tenant); event type `EPOCH_SEALED` |
| Sealer | `apps/worker/src/agw_worker/sealing/sealer.py`: `schedule()` (max_events / max_age triggers → durable SEAL job), `run_once()` (claim with SKIP LOCKED, advisory lock, `epoch_heads` lock, self-check, tree, epoch, receipt, all in one transaction), bounded `drain()`. Wired into `python -m agw_worker` through `BackgroundRunner(periodic=...)` |
| Receipts | `EPOCH_SEALED` header model (`agw_schemas.events.EpochSealed`, key `epoch`), appended to the tenant's own chain; lands in a later epoch |
| API | `GET /v1/epochs/latest`, `GET /v1/epochs/{n}`, `GET /v1/events/{id}/proof` (bundle, no payload; 409 `EVENT_NOT_SEALED`). Own tenant only; `?tenant=` for another tenant needs scope `admin:evidence:read` |
| Bundles | `evidence/bundle.py` (`agw-bundle/v1`, `agw-epochs/v1`), JSON Schema `packages/schemas/bundle/evidence-bundle.v1.schema.json`, `admin export-bundle` / `export-epochs` |
| Verifier CLI | `agw-verify event --bundle b.json [--trusted-root HEX [--trusted-epoch N]] [--json]` and `agw-verify epochs --export epochs.jsonl [--events export.jsonl] [--trusted-root …] [--json]`. Human output by default; `--json` for automation (this also applies to `chain` now) |
| Tamper suite | `experiments/tampering/tamper_suite.py` (reusable; naive and full-rewrite adversaries; three trust settings), `run_tamper_suite.py`, `make tamper EVENTS=… EPOCHS=…` |
| Demo | `run_demo.sh` now starts gateway + worker, fetches a bundle and the trusted root (`fetch_bundle.py`), **stops both**, then verifies offline. SDK gained `events()`, `epoch()`, `proof()` |

### Verifier result codes

| Result | Exit | Meaning |
|---|---|---|
| VERIFIED | 0 | All checks pass, and the external trusted root covers the material (for a bundle: the event's epoch) |
| TAMPERED | 1 | A check failed: non-canonical bytes, hash/link/root mismatch, broken tiling, trusted-root mismatch, truncation before the trusted root |
| INCOMPLETE | 2 | Material missing: bad bundle, missing events/payloads, a trusted epoch outside the material or before the event's epoch |
| INVALID_PROOF | 3 | Inclusion proof fails, or its position or size disagrees with the authenticated epoch header |
| UNANCHORED | 4 | Internally consistent, but no external trust root (or it covers only part of an epochs export): **locally sealed only** |
| usage error | 64 | Bad arguments |

## 2. Decisions

| Decision | Why | Record |
|---|---|---|
| Epoch membership is derived from tiled ranges; no column or table on events | Evidence rows stay immutable; the DB trigger guarantees tiling | ADR-0025 |
| Proofs computed on demand, no cache table | A cache could disagree with the data; O(tree_size) per request | ADR-0025 |
| `EPOCH_SEALED` receipt in the tenant's own chain; receipts alone never trigger a seal | The prompt asked for it; without the rule, seals trigger each other forever (a mutation proved it) | ADR-0025 |
| Three sealer locks: SKIP LOCKED job claim + per-tenant advisory lock + `epoch_heads FOR UPDATE`; one transaction per seal | One sealer per tenant; crash → rollback → identical rerun | ADR-0025 |
| `AGW_EPOCH_MAX_AGE_SECONDS` default **300 s** (09 §2 said 60 s) | Phase 3 prompt value | ADR-0025, 09 §2 note |
| Seal self-check failure stops sealing for that tenant | Never seal over a break (09 §2) | ADR-0025 |
| Verifier takes `tree_size` and `leaf_index` from the epoch header, not the proof | An RFC 9162 path also verifies under other claimed sizes: leaf 0 of a 5-leaf tree verifies with sizes 5–8 (tested) | 06 §6.3 |
| Code lives in `crypto/merkle.py` (prompt) rather than `agw_gateway/merkle/` (00 §2 layout) | Both are inside the fixed layout; followed the prompt | — |
| An epochs export trusted only up to an earlier epoch reports UNANCHORED, not VERIFIED | Later epochs are not covered by that root | ADR-0025 |

## 3. Tamper results (attack × detected? × required trust root)

Produced by `test_tamper_matrix` on real exports from the gateway: 25 events plus receipts, 5 epochs, attack on epoch 1. Columns are trust settings; the cells are the verifier's result and reason.

| Attack | Adversary | No trust root | Trusted root **before** attacked epoch | Trusted root **at/after** attacked epoch |
|---|---|---|---|---|
| edit event | naive | **detected** (TAMPERED, EVENTS_PREV_HASH_MISMATCH) | **detected** | **detected** |
| edit event | rewriter | not detected (UNANCHORED) | not detected (UNANCHORED) | **detected** (TAMPERED, TRUSTED_ROOT_MISMATCH) |
| delete event | rewriter | not detected (UNANCHORED) | not detected (UNANCHORED) | **detected** (TAMPERED, TRUSTED_ROOT_MISMATCH) |
| reorder two events | rewriter | not detected (UNANCHORED) | not detected (UNANCHORED) | **detected** (TAMPERED, TRUSTED_ROOT_MISMATCH) |
| delete whole epoch | naive | **detected** (TAMPERED, EPOCH_NUMBER_GAP) | **detected** | **detected** |
| delete whole epoch | rewriter | not detected (UNANCHORED) | not detected (UNANCHORED) | **detected** (TAMPERED, TRUNCATED_BEFORE_TRUSTED_ROOT) |
| truncate tail (from epoch) | rewriter | not detected (UNANCHORED) | not detected (**VERIFIED**) | **detected** (TAMPERED, TRUNCATED_BEFORE_TRUSTED_ROOT) |
| fork epoch (same prev, other root) | rewriter | not detected (UNANCHORED) | not detected (UNANCHORED) | **detected** (TAMPERED, TRUSTED_ROOT_MISMATCH) |

**Which trust root each attack needs:**
- A *naive* edit or deletion is caught by the chain and continuity checks alone.
- An insider with full DB control who recomputes everything consistently (the *rewriter*) is caught **only** by a trusted root for an epoch **at or after** the attacked one. "Not detected" never shows up as VERIFIED except in one case: tail truncation checked against an older root. That root genuinely covers everything that remains.
- A fork (two different epoch t with the same `prev_root`) is equivocation. The local system cannot prevent it. A trusted root for any epoch ≥ t exposes it, and the anchoring phase's append-only contract makes the second root unpublishable.
- These are exactly the limits anchoring (a later phase) is designed to close.

## 4. Verification results
- **Clean-state acceptance** (`.env`, `.venv`, stack and volume removed): `make up && make migrate && make test && make demo` exit 0. Migrations 0001 → 0003 applied. 412 tests pass. Coverage: 97% on policies/auth/tools/execution, 91% overall. `crypto/merkle.py` 98%, `evidence/bundle.py` 98%, `sealer.py` 90%, verifier `merkle.py` 100%, `epochs.py` 82%, `cli.py` 73%.
- **Acceptance (stopped stack):** the demo seals with a separate worker process and fetches the bundle over HTTP. With gateway **and** worker stopped: `agw-verify event … --trusted-root …` → `RESULT: VERIFIED` (exit 0); without a root → exit 4 (UNANCHORED); `agw-verify epochs --events … --trusted-root …` → VERIFIED. `test_cli_verifies_exports_after_gateway_stopped` repeats this through subprocesses.
- **Required tests:**
  - vectors in both implementations;
  - Hypothesis: proofs verify, and a bit flip in leaf, path, root or index fails; size flips are caught at the bundle level (header-bound);
  - second preimage (interior node as leaf) fails;
  - `[a,b,c]` vs `[a,b,c,c]` give different roots (Paper B's give the same);
  - tamper matrix;
  - crash mid-seal → identical rerun;
  - four racing sealers → one contiguous chain;
  - no events → no seal (receipts alone never seal).
- **Mutation checks:** all caught. 8 of 11 on the first run; the 3 escapes led to new tests:
  - subtree root with a truncated path (a real attack the final `sn == 0` check stops);
  - an epoch re-rooted onto another `prev_root`;
  - the locking layers removed together (each one alone is masked by the other two).
  
  The receipt-loop mutation originally hung the suite; `drain()` is now bounded.

## 5. Known limits and gaps
- **Trust roots are local.** Every "not detected" row above needs an external root, which arrives with anchoring.
- **Risk-triggered sealing** (HIGH/CRITICAL) is out of scope; `request_seal()` is the interface that phase will use.
- The newest seal's receipt stays pending until the next real trigger.
- Proof cost is O(tree_size); large `MAX_AGE` epochs make proofs slower (not measured).
- Consistency proofs between tree sizes are skipped (optional in the prompt).
- The verifier does not cross-check `EPOCH_SEALED` receipts against epoch records (a full rewriter would rewrite them anyway).
- The gateway's in-process mode does not seal; sealing needs `python -m agw_worker` (the demo runs it).
- `run_demo.sh` leaves its artifacts directory in the system temp dir.
- Roadmap numbering differs between the phase prompts and `13-roadmap.md` (flagged in Phase 2; still open).

## 6. Ready for the next phase
- `request_seal(tenant, up_to_seq, reason)` plus the `RISK_HIGH`/`RISK_CRITICAL` seal reasons (already allowed by the DB check) are the hooks for risk-triggered sealing.
- `epochs.epoch_root` and `prev_root` are exactly what the anchoring registry needs (06 §7, 09 §7).
- The bundle's `trust_root.source` already allows `"anchor"`.
