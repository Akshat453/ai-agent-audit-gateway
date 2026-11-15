# 10 — Verification and Evaluation Plan

Status: Accepted (Phase 0). Verifier in Phase 7, experiments in Phase 8. Sources: Paper B
§III-D (verification workflow), §V (verifier outputs), §VI (RQ1–RQ4, ablations), §VIII-C
(threats to validity); Paper A §5 (GRC mappings, monitoring stream), §8 (limitations).

## 1. Standalone verifier (`packages/verifier`, CLI `agw-verify`)

- Depends only on `packages/schemas`, `cryptography` and a read-only JSON-RPC client. It
  **never** imports `apps/*` or calls the gateway (import-linter enforced, 00 §3).
- It re-implements 06 from the spec, sharing the frozen test vectors and not the code.
- Inputs: an evidence bundle (§2), `--rpc URL` (repeatable; results must agree), `--manifest`
  (signed operator manifest pinning chain id, contract address, tenant keys), optional
  `--keys` (disclosed DEKs).
- Output: a JSON report plus a human summary. Each check is `VERIFIED`, `TAMPERED` or
  `INCOMPLETE` (Paper B §V), and the overall result is the worst of them.
- Every report carries the fixed statement: *"Verified means the records are unchanged since
  they were anchored and are correctly ordered. It does not mean the recorded actions were
  truthful, authorized, complete or correct."* (Paper A §2, §8)

## 2. Evidence bundle (`.agwb`, Phase 7)

A directory or zip with:
- `manifest.cbor`: tenant, epoch range, file list with SHA-256 digests. Its
  `bundle_digest = H(TAG("AGW/bundle/v1") ‖ manifest)`.
- `epochs/<epoch_no>.cbor`: epoch headers (06 §7).
- `events/<seq>.cbor`: exact `canonical_bytes` for the included range.
- `proofs/<seq>.cbor`: inclusion proofs (06 §6.3), for selective bundles that omit some events.
- `anchors.json`: chain id, contract, tx hash, block number per epoch (hints only; the verifier
  re-reads the chain).
- `payloads/<event_id>.bin` + `keys/<event_id>.key` (optional disclosure, 07 §5).

## 3. Checks

| Id | Check | Detects | Result if fails |
|---|---|---|---|
| V1 | Strict CBOR decode + re-encode equality for every record | non-canonical / altered encoding | TAMPERED |
| V2 | Recompute `event_hash`. `prev` links. `seq` contiguity within the range. | edit, delete, reorder, insert | TAMPERED |
| V3 | Inclusion proofs / full-tree recomputation → `M_t` | edit of sealed event, phantom leaves | TAMPERED |
| V4 | Recompute `R_t` from header. Header consistency (`tree_size`, tiling). | tail truncation in epoch, size games, renumbering | TAMPERED |
| V5 | On-chain `getAnchor(tenantKey, epoch)` equals `R_t`, and `prevRoot` equals `R_{t−1}` | post-anchor rewrite, fork, deleted epoch | TAMPERED |
| V6 | Anchor finality per requested level. Agreement across RPCs. | reorg, lying RPC | INCOMPLETE (not final) / TAMPERED (RPCs disagree on a finalized block) |
| V7 | Events after the last anchored epoch | unsealed tail | INCOMPLETE (reported, never VERIFIED) |
| V8 | Payload decrypt → digest → `payload.event == id` | payload swap or edit | TAMPERED |
| V9 | Lifecycle conformance per action (05 §2 ordering) | missing AUTHORIZED before DISPATCHED, DISPATCHED without result or OUTCOME_UNKNOWN | TAMPERED (order) / INCOMPLETE (pending) |
| V10 | GRC assertions (Paper A §5 Table 1): approval precedes dispatch for HIGH/CRITICAL. Dispatched `args` digest = approved binding's args digest. CRITICAL dispatch has `dispatch.anchor` and the anchored epoch precedes it. | approved ≠ executed (Paper A §2) | TAMPERED |
| V11 | Contract identity / tenant key matches the signed manifest | substitute contract | TAMPERED |

## 4. Tamper experiments (`experiments/tampering/`, Phase 8)

Paper B's four classes (§II-C, §VI-E), plus classes it does not cover, are each injected at
interior and terminal positions (Paper B used 8 interior + the 2 terminal positions of a
10K-event log):

| Attack | Expected first detecting check | Paper B comparison (Table IV) |
|---|---|---|
| Edit payload of a sealed event | V8 (with disclosure) / V3 | Merkle: 100% |
| Edit record field | V2/V3 | Chain 90%, Merkle 100% |
| Delete interior event | V2 | Chain 90%, Merkle 100% |
| Reorder two events | V2 | Chain 100% |
| Equivocation (fork from a common prefix) | V5 (the contract refuses a second root for the same epoch) | Full: 100% |
| Truncate tail **inside** a sealed epoch | V4 | not tested |
| Truncate **unsealed** tail | V7 reports INCOMPLETE. Expected to be undetectable as TAMPERED (R2). | not tested |
| Delete a whole epoch | V5 continuity | via back-pointer |
| Cross-tenant splice | V2 (tenant in record) / V5 (tenant key) | not applicable |
| Paper-B-style duplicated-leaf root | V3 | n/a (their design) |
| Ciphertext swap between events | V8 (AAD + digest) | not tested |
| Approval replay / args change after approval | V10 + Phase 4 enforcement tests | not tested |
| Strategic anchoring delay | Monitoring stream alert (Phase 8) | listed as limitation §VIII-A(6) |

We report detection *and* false-positive rates per configuration. Following Paper B §VIII-C,
we state that the tamper runs are deterministic and synthetic.

## 5. Benchmarks, risk and ablation experiments (Phase 8)

| Experiment | Measures | Notes |
|---|---|---|
| `benchmarks/action-latency` | p50/p95/p99 POST→COMPLETED for no-op adapter, per configuration | Our per-event cost includes a Postgres tx. Paper B's ~48 µs (§VI-C) is in-process and not comparable. We say so in the report. |
| `benchmarks/tenant-throughput` | actions/s per tenant (chain-head lock) and across tenants | Validates ADR-0018 |
| `benchmarks/seal-cost` | seal time vs epoch size (10, 50, 100, 500, 1000, as in Paper B §VI-B) | |
| `benchmarks/anchor-gas`, `anchor-latency` | gas per `anchor`/`anchorBatch`. Time to included/safe/finalized on Anvil and Base Sepolia. | Paper B: 91,800 gas mean (prior only) |
| `risk/adaptive-vs-fixed` | Time from event commit to anchor finality for HIGH events. Anchors per 10K events. Compromise window. Fixed epochs vs risk-triggered. | Our main new evaluation question |
| `risk/critical-gate` | Added latency of the CRITICAL gate. `ANCHOR_TIMEOUT` rate under RPC faults. | |
| `ablations/` | Cumulative configs. Paper B's Baseline ⊂ Schema ⊂ Chain ⊂ Merkle ⊂ Full (§VI-B), extended with **+Gateway enforcement** (deny path), **+Risk-adaptive sealing**, **+CRITICAL gate** | Attribute overhead and detection to each layer |

Workloads: a seeded synthetic generator (as Paper B §VI-B) **and** recorded traces from the
example agents (`examples/`). Results report environment, seeds, N runs, and raw data in
`experiments/*/results/`. No number goes into docs or a paper unless a committed script
reproduces it.

## 6. Monitoring evidence stream (Phase 8; Paper A §5)

The monitor periodically runs V1–V7 and V9 against the live DB and chain for each tenant. It
also checks anchor regularity (overdue `max_age` epochs, a SUBMITTED anchor stuck longer than
a threshold) and that DB `actions.status` agrees with the event-derived status. Each run
appends a `MONITOR_REPORT` event to the `_monitor` tenant chain (ADR-0019), which is sealed and
anchored like any other tenant. This evidences *when and how* integrity was checked, not
semantic correctness (Paper A §5).
