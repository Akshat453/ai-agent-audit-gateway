# 09 — Batching (Epochs) and Anchoring

Status: Accepted (Phase 0). Sealing in Phase 3, anchoring in Phase 6. ADRs: 0008 (one chain
per tenant; separate risk queues rejected), 0009 (CRITICAL pre-action anchoring), 0014
(on-chain registry). Sources: Paper A §3 (Merkle aggregation), §4 (anchor time, ordering),
§5 (routine batching vs immediate anchoring); Paper B §III-C (epochs), §IV-A (protocol,
frequency trade-off), §VI-D (cost), §VIII-A(5,6).

## 1. Model

- **One sequenced chain per tenant.** Every event of the tenant, whatever its risk or class, gets the next `seq`.
- **Epochs are contiguous seq ranges** `[first_seq, last_seq]` that tile the chain without gaps or overlap (06 §7).
- **Risk changes when an epoch is sealed and how urgently it is anchored, never which chain or order an event belongs to.**

This is how we read Paper A §5's "routine ... periodic Merkle batches" vs "high-impact ...
immediate or individual anchoring": both are realized inside one ordered chain by choosing the
seal point.

## 2. Seal triggers

> Phase 3 (implemented): `max_events` (default 100) and `max_age` (default **300 s**, changed from
> 60 s by ADR-0025) via `apps/worker` sealer; risk triggers come later. Membership is derived from
> tiled ranges and proofs are computed on demand (ADR-0025).

The sealer seals pending events (seq > `sealed_up_to`) when **any** trigger fires:

| Trigger | Condition | Epoch(s) produced | `seal_reason` |
|---|---|---|---|
| `max_events` | pending count ≥ `AGW_EPOCH_MAX_EVENTS` (default 100, as in Paper B's main configuration §VI-B) | `[first_pending, first_pending + max_events − 1]`, repeated while enough are pending | `MAX_EVENTS` |
| `max_age` | oldest pending event older than `AGW_EPOCH_MAX_AGE_SECONDS` (default 60) | all pending | `MAX_AGE` |
| risk ≥ HIGH | a committed event with `risk.level ∈ {HIGH, CRITICAL}` at seq `s` | everything pending **up to and including** `s` | `RISK_HIGH` |
| CRITICAL authorization | `ACTION_AUTHORIZED` for a CRITICAL action at seq `s` | `[first_pending, s−1]` (if non-empty), **then** `[s, s]` as its own epoch | `RISK_CRITICAL` |

Mechanics:
- A HIGH/CRITICAL event's tx1 also inserts `outbox_jobs(kind=SEAL, tenant, up_to_seq=s,
  mode)`, so the seal request is as durable as the event (no in-memory trigger).
- `max_age` and `max_events` are evaluated by a periodic sealer scan (every 1 s).
- Seal tx: lock `epoch_heads(tenant)` (separate from the `tenants` chain-head row, so sealing
  doesn't block event writes). Read events `(sealed_up_to, up_to]` ordered by seq.
  **Self-check**: recompute every `event_hash` from `canonical_bytes` and check `prev` links, so
  DB tampering is caught *before* it gets sealed. Then build the RFC 9162 tree, compute `R_t`,
  insert `epochs` and `anchors(status=PENDING)`, enqueue `ANCHOR`, and commit. A self-check
  failure stops sealing for the tenant and raises a critical alert. It never seals over a break.
- Only committed events are sealed. Seq allocation is gap-free and commit-ordered (08 §3), so
  the pending set is always a prefix-closed range.

### Why the CRITICAL authorization gets its own epoch

With `tree_size = 1` the audit path is empty and `M_t = H(0x00 ‖ event_hash)`. The dispatch
gate, and any later verifier, checks the authorization with one hash and one anchor lookup, and
no other event's timing can delay it. Everything pending before it is still sealed first,
consistent with the HIGH rule above, so ordering and continuity are preserved. CRITICAL actions
are rare, so the extra anchor costs little.

## 3. Comparison: one chain with risk-triggered sealing vs separate risk queues

| Criterion | **One chain per tenant, risk-triggered seals (adopted)** | Separate queue/chain per risk level (rejected) |
|---|---|---|
| Total order across all events | Yes: `seq` | No. Cross-queue order needs a merge rule or timestamps, and timestamps aren't an ordering source (Paper A §4). |
| Reconstruct "review before execution" (Paper A §5, segregation of duties) when the steps have different risk | Direct seq comparison | Needs cross-chain references, which can be forged or missing |
| Gap / suppression detection | One continuity check | Per-queue checks. An attacker can suppress the *low* queue, which is anchored rarely, without touching the high one. |
| Latency for HIGH evidence | Immediate seal | Immediate |
| Anchors per unit time | `routine + #HIGH-triggered seals` | `#queues × cadence`, more on average |
| Verifier complexity | One chain, one epoch sequence | N chains plus a merge rule |
| Tenant isolation | Preserved | Preserved |
| Failure mode | A burst of HIGH events → many small epochs (more anchors). Bounded by batching several roots per block (§7) and monitored. | Queue starvation and ordering ambiguity |

Decision recorded in [ADR-0008](adr/0008-one-chain-per-tenant-risk-triggered-sealing.md).

## 4. Anchoring urgency by risk

| Risk | Seal | Anchor | Dispatch waits for anchor? |
|---|---|---|---|
| LOW | `max_events` / `max_age` | normal queue | no |
| MEDIUM | `max_events` / `max_age` | normal queue | no |
| HIGH | immediately (up to and including the event) | **priority** (next tx, ahead of routine) | no (approval required instead, 04 §4.3) |
| CRITICAL | own epoch for ACTION_AUTHORIZED | **priority** | **yes**, until configured finality (§5) |

## 5. CRITICAL pre-action anchoring gate (ADR-0009)

1. The CRITICAL action is authorized (Phase 1: never, since policy denies or caps; Phase 4: after
   a valid bound approval). In the authorizing tx: `ACTION_AUTHORIZED` at seq `s`,
   `outbox_jobs(DISPATCH, status=WAITING_ANCHOR, gate_deadline = now() + AGW_CRITICAL_ANCHOR_TIMEOUT_SECONDS)`,
   and `outbox_jobs(SEAL, up_to_seq=s, mode=CRITICAL)`. COMMIT.
2. The sealer seals `[first_pending, s−1]` (if any) as epoch `k` and `[s, s]` as epoch `k+1`.
3. The anchorer submits `k` then `k+1`. The contract requires epoch order. Both can land in the
   same block via consecutive nonces.
4. The anchor tracker advances `anchors(k+1)` through SUBMITTED → INCLUDED → FINALIZED.
5. When `anchors(k+1)` reaches `AGW_ANCHOR_FINALITY`, one tx locks the job (`FOR UPDATE`),
   re-checks `status = WAITING_ANCHOR` and `now() < gate_deadline`, and sets it `PENDING`. The
   executor then dispatches normally. The ACTION_DISPATCHED record includes
   `dispatch.anchor = {epoch_no, tx_hash, block_number, finality}`.
6. Timeout: a sweeper locks jobs with `status = WAITING_ANCHOR AND gate_deadline <= now()` and
   writes `ACTION_FAILED(code=ANCHOR_TIMEOUT)`, job `FAILED`. **No side effect.** Both 5 and 6
   take the row lock and check status first, so exactly one wins. An anchor that finalizes
   *after* the timeout never releases the job.
7. Anchoring is an **additional precondition**, not an authorization. A finalized anchor can't
   authorize anything that policy and approval didn't.

What this buys: before any CRITICAL side effect, a public commitment to the exact authorization
record (agent, tool+version, args digest, approval binding, policy version) exists, and the
operator can no longer rewrite it afterwards. What it doesn't buy: proof that the authorization
was *correct*, or that the side effect matched it. The latter is checked from the later
ACTION_DISPATCHED / ACTION_COMPLETED records.

## 6. Anchor states

```
PENDING ──submit──▶ SUBMITTED ──receipt in block──▶ INCLUDED ──finality reached──▶ FINALIZED
   ▲                    │  ▲                            │
   │                    │  └──── reorg: block hash no longer canonical ──┘
   └── dropped/replaced tx (nonce reused) ◀┘
FAILED: contract revert other than "already anchored with same root" → alert (possible equivocation / key compromise)
```

`anchors` columns: `tenant_id, epoch_no, root, prev_root, status, chain_id, contract,
tx_hash, nonce, block_number, block_hash, submitted_at, included_at, finalized_at, attempts,
last_error`.

Finality setting `AGW_ANCHOR_FINALITY` ∈ `included` | `confirmations:<N>` | `safe` |
`finalized`. The last two use the JSON-RPC block tags of the same name.

| Environment | Chain | Default routine target | Default CRITICAL gate | Default CRITICAL timeout |
|---|---|---|---|---|
| dev / test | Anvil (chain id 31337) | `included` | `included` | 60 s |
| testnet | Base Sepolia (chain id 84532) | `finalized` | `safe` (configurable to `finalized`) | 1800 s |

The time to reach `safe`/`finalized` on Base Sepolia is **not assumed**. Phase 6 measures it
(`experiments/benchmarks/anchor-latency`) and the defaults are revisited by ADR if needed.
Paper A §4 defines anchor time as when the commitment "obtains verifiable inclusion and, where
applicable, finality". The verifier reports which of the two it confirmed.

Reorg handling: the tracker re-reads the receipt and block hash each poll until FINALIZED. If
the included block is no longer canonical, status goes back to SUBMITTED. If the tx is gone, it
is re-submitted with the same `(epochNo, root, prevRoot)`. An "already anchored with the same
root" revert counts as success.

## 7. On-chain registry (Phase 6; Solidity + Foundry)

```solidity
// SPDX-License-Identifier: Apache-2.0
// Interface sketch, not final code. Phase 6 pins the exact solc version.
interface IAgwAnchorRegistry {
    event TenantRegistered(bytes32 indexed tenantKey, address submitter);
    event SubmitterRotated(bytes32 indexed tenantKey, address oldSubmitter, address newSubmitter);
    event Anchored(bytes32 indexed tenantKey, uint64 indexed epochNo, bytes32 root, bytes32 prevRoot);

    function registerTenant(bytes32 tenantKey, address submitter) external;          // onlyOwner, once
    function rotateSubmitter(bytes32 tenantKey, address newSubmitter) external;      // onlyOwner
    function anchor(bytes32 tenantKey, uint64 epochNo, bytes32 root, bytes32 prevRoot) external;
    function anchorBatch(bytes32 tenantKey, uint64 firstEpochNo, bytes32[] calldata roots, bytes32 prevRoot) external;
    function getAnchor(bytes32 tenantKey, uint64 epochNo)
        external view returns (bytes32 root, bytes32 prevRoot, uint64 blockNumber, uint64 timestamp);
    function nextEpoch(bytes32 tenantKey) external view returns (uint64);
}
```

`anchor` MUST revert unless all of the following hold:
1. `msg.sender == submitter[tenantKey]` (authorized anchoring, Paper A §3).
2. `epochNo == nextEpoch[tenantKey]`: contiguous, so no gaps and no second anchor for the same epoch.
3. `prevRoot == (epochNo == 0 ? bytes32(0) : roots[tenantKey][epochNo − 1])`: the back-pointer matches.
4. `root != bytes32(0)`.

The contract is **append-only**: no overwrite, no delete, no proxy or upgradeability, no
selfdestruct. The owner can only register tenants and rotate submitters. A rotation is itself an
on-chain event, visible to verifiers.

`tenantKey = H(TAG("AGW/tenant-key/v1") || u16(len(tenant)) || utf8(tenant))`. The raw tenant
name never goes on-chain. Note: tenant names can be guessed from the key. If names are
sensitive, choose non-descriptive tenant ids.

On-chain data per anchor: tenantKey (32 B), epochNo (8 B), root (32 B), prevRoot (32 B), block
number/time. **No event content, no payload digests, no agent or tool identifiers** (Paper A §3,
Paper B §IV-A).

Differences from Paper B §III-D/§IV-A: Paper B stores `H(R_{t−1})` and resolves duplicate
epochs by "earlier-included is canonical". We store `R_{t−1}` directly and *refuse* duplicates
and gaps on-chain, so equivocation by the authorized submitter can't be anchored at all.
Equivocation through a *different* contract or key remains possible. Verifiers MUST pin the
contract address, chain id and tenant key from a signed operator manifest (Paper B §III-D).

## 8. Cost expectations (to be measured, not assumed)

Paper B §VI-D measured a mean 91,800 gas per `anchor()` on Base Sepolia (100 txs) for a
contract that stores root + back-pointer. Ours adds a submitter check and a contiguity check, so
gas will differ. Phase 6 measures cold/warm `anchor` and `anchorBatch` gas on Anvil and Base
Sepolia (`experiments/benchmarks/anchor-gas`). Cost per event depends on `max_events`,
`max_age` and the HIGH/CRITICAL rate. The risk experiments (10 §5) report anchors per 10K
events for realistic mixes.
