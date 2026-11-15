# ADR-0025: Phase 3 epochs — derived membership, on-demand proofs, in-chain seal receipts, sealer locking, 300 s max-age default
Status: Accepted · Date: 2026-11-15 · Deciders: Phase 3 implementation (pending owner review)

## Context
The Phase 3 prompt gives options or requirements that the Phase 0 docs did not settle, or settle differently:
- **Membership:** "epoch_members or epoch_id column on events (set once, NULL→value trigger)".
- **Proofs:** "computed on demand ... or cached in merkle_proofs (choose; document why)".
- **Receipt:** an `EPOCH_SEALED` monitoring event in the tenant's own chain. ADR-0019 puts the *monitor's* reports in a separate `_monitor` tenant.
- **Locking:** one sealer per tenant via an advisory lock. 09 §2 says lock `epoch_heads`.
- **Default:** `max_age` 300 s. 09 §2 says 60 s.

## Decision
1. **Membership is derived, not stored.** Epochs tile the seq range with no gap and no overlap, and a DB trigger enforces it on insert: contiguous `epoch_no`, `first_seq(t) = last_seq(t−1)+1`, `prev_root = R_{t−1}`, `tree_size` consistent, never beyond the committed chain head. An event's epoch is therefore the unique row with `first_seq ≤ seq ≤ last_seq`. No column is added to `evidence_events`, which stays fully immutable, and no extra table can drift out of sync.
2. **Proofs are computed on demand** from the stored `event_hash` values of the epoch's range: O(n) hashing for n = `tree_size` (100 by default). There is no `merkle_proofs` cache: it would be a second copy that could disagree with the data. Revisit if large `MAX_AGE` epochs make proof latency measurable.
3. **`EPOCH_SEALED` receipt.** It is a SYS event in the tenant's own chain, appended in the seal transaction, so it lands in a later epoch. The header has a new optional key, `epoch` = {no, first, last, size, mroot, prev, root, reason}. Receipts alone never trigger a seal; otherwise every seal would trigger the next, forever (a mutation test showed exactly that loop). This is a seal *receipt*. The supervisory `MONITOR_REPORT` stream of ADR-0019 is still a separate `_monitor` tenant, built in the monitoring phase.
4. **Sealer locking, three layers:**
   - the job row is claimed `FOR UPDATE SKIP LOCKED`;
   - the sealer takes `pg_try_advisory_xact_lock(hashtextextended('agw-seal:'||tenant, 0))`;
   - it locks the `epoch_heads` row `FOR UPDATE`.
   
   The whole seal is one transaction, so a crash before COMMIT leaves the job PENDING and the rerun produces the identical epoch (`sealed_at` is not part of R_t).
5. **Defaults:** `AGW_EPOCH_MAX_EVENTS=100`, `AGW_EPOCH_MAX_AGE_SECONDS=300` (the Phase 3 prompt's value; 09 §2's 60 s is superseded), `AGW_SEALER_INTERVAL_SECONDS=1`.
6. **A failed self-check stops sealing.** When the self-check fails (stored bytes don't hash to `event_hash`, broken prev link, seq gap), the job is marked FAILED with `SEAL_SELF_CHECK_FAILED`, a CRITICAL log is emitted, and that tenant gets no further seals until an operator resolves it. It never seals over a break.
7. **Verifier results add `INVALID_PROOF` and `UNANCHORED`.** UNANCHORED means every check passed but no external trust root was supplied ("locally sealed only"). An epochs export whose trusted root covers only part of the material is also UNANCHORED, with a note. An event bundle is VERIFIED when the trusted epoch is at or after the event's epoch.

## Consequences
+ Evidence rows never change. + Proofs can't be stale. + Sealing is deterministic and race-safe, and both properties are tested.
− Proof generation costs O(tree_size) per request. − A receipt is always pending after a seal, so the newest seal's receipt is sealed only by the next real trigger.
