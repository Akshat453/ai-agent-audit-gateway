# ADR-0028: Phase 6 blockchain anchoring
Status: Accepted · Date: 2026-11-16 · Deciders: Phase 6 implementation (pending owner review)

## Context
The Phase 6 prompt asks to anchor epoch roots outside our trust boundary. The pieces it asks for:
- an append-only Solidity registry;
- an anchor worker with risk-aware priority and inclusion/finality tracking;
- a fail-closed pre-action anchoring option for CRITICAL actions;
- a verifier that checks anchors against the chain using pinned trust roots;
- deployment to Anvil, with Base Sepolia when a funded key is supplied;
- gas measured from at least 30 real anchors.

The existing spec for this is 09 §5–§8 plus ADR-0009 and ADR-0014, written in Phase 0.

**Docs and the prompt disagree on the contract design:**

| | 09 §7 / ADR-0014 (Phase 0) | Phase 6 prompt |
|---|---|---|
| Contract name | `AgwAnchorRegistry` | `EpochAnchor.sol` |
| Key | `tenantKey = H(TAG("AGW/tenant-key/v1") ‖ u16 ‖ tenant)` (unsalted, guessable) | `recorderId = SHA256("AGW/recorder/v1" ‖ tenant ‖ deployment_salt)` |
| Stored per epoch | `root`, `prevRoot`, block number, timestamp | `root`, `treeSize`, `lastSeq`, `timestamp` |
| Continuity | `prevRoot` must equal the stored previous root | `epochNo == lastEpoch + 1` |
| Batch call | `anchorBatch` | (not mentioned) |

This ADR follows the prompt and supersedes ADR-0014 and 09 §7 on those points, as below.

The prompt also says "`lastEpoch` ... `epochNo == lastEpoch + 1`". Our epochs are numbered from 0 (06 §7), so epoch 0 cannot satisfy `0 == lastEpoch + 1` with a zero default. The contract therefore stores the **count** of anchored epochs (`nextEpoch`) and requires `epochNo == nextEpoch`; `lastEpoch()` returns `(exists, nextEpoch − 1)`.

## Decision

### 1. Contract `contracts/src/EpochAnchor.sol` (solc 0.8.28, no dependencies)

**Storage**
- `anchors[recorderId][epochNo] = Anchor{root, treeSize, lastSeq, timestamp, blockNumber}`.
- `blockNumber` is an addition to the prompt's struct. It packs into the same slot as `treeSize`, `lastSeq` and `timestamp` (4 × uint64), so it costs no extra gas. It lets the worker adopt an anchor that is already on-chain at its block.
- Per recorder: `nextEpoch[recorderId]` and `submitterOf[recorderId]`.
- `owner` is immutable.

**`anchor(...)` reverts unless all of these hold:**
1. The sender is the recorder's registered submitter (`NotSubmitter`).
2. `epochNo == nextEpoch`, so there are no gaps, overwrites or replays (`EpochOutOfOrder`).
3. `root ≠ 0` (`ZeroRoot`).
4. `1 ≤ treeSize ≤ lastSeq + 1` (`EmptyEpoch`).
5. **Seq tiling:** `lastSeq − treeSize + 1 == previous lastSeq + 1`, and the first epoch starts at 0 (`SeqNotTiled`). This is our addition: a gap or overlap in the anchored seq ranges is refused on-chain.

On success it emits `Anchored(recorderId, epochNo, root, treeSize, lastSeq)`.

**Owner functions**
- `registerRecorder` is owner-only and once per recorder. Zero recorder ids and zero submitters are rejected.
- `rotateSubmitter` is owner-only; history is kept and a `SubmitterRotated` event is emitted (09 §7).

**Not included**
- No proxy, upgrade, delete or selfdestruct.
- No `anchorBatch`. We measured one transaction per epoch, and nonces pipeline up to `AGW_ANCHOR_MAX_INFLIGHT`. Batching is an optimisation for later.

**No on-chain `prevRoot`.** `R_t` already commits to `R_{t−1}` (06 §7), so the verifier checks continuity by recomputing roots. Storing `prevRoot` would cost one more storage slot per anchor for no extra integrity.

**Tests and analysis**
- Foundry tests use a minimal cheatcode interface (`test/Vm.sol`) instead of forge-std, so the build has no git-submodule or network inputs besides solc.
- The suite has 16 tests: overwrite, gap, replay, wrong submitter, unregistered recorder, recorder isolation, zero root, empty epoch, seq gap/overlap, owner-only registration and rotation, plus 4 fuzz tests at 1,024 runs each.
- Slither 0.11.6: 0 findings (102 detectors).
- A gas report is committed.

**Tooling**
- All Foundry tooling runs in the pinned image `ghcr.io/foundry-rs/foundry:v1.3.5`; nothing is installed on the host.
- `contracts/artifacts/EpochAnchor.json` (ABI and bytecode) is committed. `make contracts-check` requires a fresh build to reproduce it byte for byte.

### 2. Recorder identity (no tenant name on-chain)
```
recorderId = SHA-256(TAG("AGW/recorder/v1") || u16(len(tenant)) || utf8(tenant) || salt32)
```
- **Length prefix.** The `u16` length makes the tenant/salt split unambiguous (the prompt wrote `tenant_id ‖ deployment_salt`).
- **Salt.** The salt is per deployment (`AGW_ANCHOR_DEPLOYMENT_SALT[_FILE]`). It closes 09 §7's "tenant names can be guessed from the key".
- **Who sees what.** Auditors receive the recorder id, never the salt.
- **What goes on-chain.** Only recorderId, epochNo, root, treeSize, lastSeq and block data. There are no payloads, tenant names, agent or tool identifiers.

### 3. Deployment
- `contracts/script/Deploy.s.sol` (Foundry script) deploys.
- `python -m agw_worker.anchoring.admin record-deployment` writes `contracts/deployments/<chain>.json` from the broadcast receipt. The record holds:
  - chain id, address, deploy tx and block;
  - deployer and owner;
  - SHA-256 of the creation code; SHA-256 and keccak-256 of the runtime code;
  - the compiler settings.
- **Anvil:**
  - Run `contracts/deploy-anvil.sh` (Anvil runs as the compose `anvil` service).
  - The dev keys are Anvil's public test mnemonic (accounts 0 and 1), derived inside the container into git-ignored `secrets/` with mode 0600.
  - The address is deterministic: `0x5fbdb2315678afecb367f032d93f642f64180aa3`.
- **Base Sepolia:** no funded key was supplied, so the phase stops after Anvil. The exact commands are in the Phase 6 doc.

### 4. Anchor worker (`apps/worker/src/agw_worker/anchoring/`, web3.py 7.16)

**State machine:** `anchors(tenant, epoch)` moves PENDING → SUBMITTED → INCLUDED → FINALIZED, plus FAILED.

**Ordering**
- Recorders are served by (highest pending priority desc, lowest pending epoch asc).
- Within one recorder, epochs go strictly in order: epoch N is sent only once N−1 is on-chain or in flight.
- Priority shortens the wait and never reorders. A PRIORITY or CRITICAL epoch sends the whole queue up to it at the next tick. ROUTINE epochs wait up to `AGW_ANCHOR_ROUTINE_DELAY_SECONDS` (default 60) so several go out together.
- `epochs.anchor_priority` is set by the Phase 4 sealer.

**Write-ahead submission**
- The transaction is signed, then the row becomes SUBMITTED with `tx_hash`, `nonce` and `raw_tx`, and that **commits before the broadcast**.
- A crash, RPC failure, dropped transaction or reorg leads to re-broadcasting the **identical bytes**, so there is never a different root for an epoch.
- The DB enforces this. A trigger requires the anchor row's root, size and last seq to equal the sealed epoch. `agw_app` has no UPDATE grant on those columns, nor on `anchor_recorders.recorder_id`, `contract` or `submitter`.

**Reorgs:** an INCLUDED row whose block hash is no longer canonical goes back to SUBMITTED, and the same raw transaction is re-broadcast.

**Idempotency**
- Before submitting, the worker reads the chain.
- If the epoch is already there with the same root and size, it is adopted (INCLUDED at the chain's block, `tx_hash` null).
- If it is there with a **different** root, the row becomes FAILED with `CHAIN_ROOT_MISMATCH`, the recorder is halted, a CRITICAL log is written and `agw_anchor_equivocations_total` increases.
- The worker also recomputes `R_t` from the stored epoch header before publishing. A mismatch halts the recorder with `EPOCH_HEADER_MISMATCH`.

**Reverted or replaced transactions:** if the epoch is not on-chain, the row returns to PENDING with backoff, and becomes FAILED after `AGW_ANCHOR_MAX_ATTEMPTS`.

**Nonces and signer**
- One signer per recorder; one worker per signer, enforced by a session advisory lock.
- The nonce is `max(node pending nonce, highest in-flight nonce + 1)`.
- The gas limit is fixed (`AGW_ANCHOR_GAS_LIMIT`), because `eth_estimateGas` for epoch N+1 reverts while epoch N is still in the mempool.

**Finality:** `AGW_ANCHOR_FINALITY` is `included` | `confirmations:N` | `safe` | `finalized`. The tags come from the node. Anvil reports `safe` = latest − 32 and `finalized` = latest − 64; the demo uses `confirmations:2`.

**Outages**
- An RPC error aborts the tick and backs off exponentially; epochs keep sealing.
- Metrics: `agw_anchor_oldest_unanchored_age_seconds` and `agw_anchor_backlog_alert` (above `AGW_ANCHOR_ALERT_AGE_SECONDS`), plus RPC error, transition, resubmission and equivocation counters.
- LOW to HIGH actions continue (tested).

**Backend interface:** `AnchorBackend` (`backend.py`) is the seam for a later RFC 3161 TSA or transparency-log backend. Only the EVM backend ships. web3 is confined to `agw_worker.anchoring` by a new import-linter contract.

**Anchors rows are derived from `epochs`** by the worker, instead of being inserted in the seal transaction as 09 §2 says. This keeps the sealer independent of anchoring configuration, and back-fills epochs sealed before a tenant was registered.

### 5. CRITICAL pre-action anchoring (ADR-0009, now implemented)

**Which actions are gated.** `AGW_PRE_ANCHOR_RULES` is a comma-separated list of policy or risk rule ids, or `*` for every CRITICAL action. It is the "configurable per rule" setting. The default is `*`; the test fixtures of earlier phases opt out because they have no chain.

**What the authorization does.** For a gated action, the authorizing transaction (approval path, or the ALLOW path in tx1) inserts the DISPATCH job as `WAITING_ANCHOR`, with:
- `gate_seq` = the ACTION_AUTHORIZED seq;
- `gate_deadline` = now() + `AGW_CRITICAL_ANCHOR_TIMEOUT_SECONDS`, on the DB clock.

**Sealing.** The sealer seals `[.., s−1]` and then `[s, s]` as its own one-leaf epoch (09 §2), both with `RISK_CRITICAL`. This rule takes precedence over the count, age and risk triggers.

**Release or fail.**
- The gate releases the job (PENDING plus `gate_anchor`) only when that epoch's anchor is FINALIZED and the deadline has not passed, under the job row lock.
- The sweeper, under the same lock, writes `ACTION_FAILED(ANCHOR_TIMEOUT)` and marks the job FAILED. Exactly one of the two wins.
- An anchor that finalizes after the deadline never releases the job.
- `ACTION_DISPATCHED.dispatch.anchor = {epoch, block, tx, fin}` is a new optional field in AGW-EVT v1.

**What it proves.** The pre-action anchor proves that **intent and authorization** were publicly committed before the side effect. It proves nothing about the result: ACTION_COMPLETED is anchored later, routinely.

### 6. Verifier (`agw-verify`, stdlib only)

**Usage**
```
agw-verify event --bundle b.json --chain-rpc URL
                 (--trust-config pinned.json | --chain-id N --contract 0x.. --recorder-id HEX)
                 [--finality finalized|safe|latest|confirmations:N] [--code-sha256 HEX]
```
`epochs` takes the same flags.

**Trust roots.** These are the chain id, contract, recorder id, finality and, optionally, the runtime-code SHA-256.
- They come only from the pinned config (`agw-anchor-trust/v1`, made by `admin trust-config` and handed to the auditor out of band) or from the command line.
- Bundles now carry an informational `anchor` claim. If it disagrees with the pins, the result is **UNTRUSTED_ANCHOR** (exit 5).
- If no pins are given, the result is also UNTRUSTED_ANCHOR (`TRUST_ROOTS_NOT_PINNED`).

**Identity checks:** the RPC's chain id must equal the pin, there must be code at the pinned address, and its hash must match if pinned.

**Anchor checks.** Each epoch in the material is read with `eth_call` **at the finality block**.
- A root, size or last-seq mismatch → TAMPERED (`ANCHOR_ROOT_MISMATCH`).
- In whole-export mode, if the chain holds more epochs than the material → TAMPERED (`EPOCHS_MISSING_VS_CHAIN`), catching tail deletion.
- An event is VERIFIED only if its epoch, or a later epoch in the material, is anchored at finality.
- Anchored but not final → UNANCHORED (`ANCHOR_NOT_FINAL`).
- RPC down → INCOMPLETE (`CHAIN_UNAVAILABLE`).

**Results:** VERIFIED, TAMPERED, INCOMPLETE, UNANCHORED, INVALID_PROOF, UNTRUSTED_ANCHOR.

**Selectors.** Function selectors are constants, because keccak is not in `hashlib`. A test recomputes them with `eth_utils`.

### 7. Gas
Measured from 40 mined `anchor()` transactions on Anvil (`make anchor-gas`; results in `experiments/anchoring/results/`):

| Transaction | Gas |
|---|---|
| First anchor of a recorder | 96,171 |
| Later anchors | median 81,569 |
| Deploy | 709,850 |
| `registerRecorder` | 46,294 |

- **Cost table.** It multiplies measured gas by **stated** gas-price assumptions. Paper B's dollar figure is not reused.
- **Base Sepolia.** The L1 data fee and the time to `safe`/`finalized` are unmeasured until a funded key is supplied.

## Consequences
**Gains**
- **Tamper detection outside our system.** A post-anchor rewrite of the history is detected against the chain even when it is internally consistent (tested: re-partitioned epochs pass every offline check and fail only against the anchor). Tail deletion is detected against the chain's last epoch.
- **No forged history on-chain.** The authorized submitter cannot anchor a forked or gapped history, because the contract checks contiguity and seq tiling.
- **CRITICAL actions:** a side effect is impossible without a final public commitment to the authorization (tested with the RPC down; adapter call count 0).
- **Evidence:** 24 end-to-end tests against a real Anvil node, 20 unit tests, 4 verifier tests against a scripted RPC and 16 Foundry tests. 21 guard mutations (17 Python, 4 Solidity) are each caught by a named test.

**Costs and limits**
- **Trust config is not signed.** The pinned config must be delivered out of band. 10 §3 V11 asked for a *signed* operator manifest; that is a gap.
- **Single RPC.** The verifier queries one RPC; cross-RPC agreement (10 §3 V6) is a gap. A lying RPC can only make a check fail or look unanchored if the auditor pins the chain id, but it could hide a reorg.
- **Gas price.** Fees are 2 × base + tip, with no fee bumping for stuck transactions; the same transaction is re-broadcast instead.
- **No batching.** There is no `anchorBatch`.
- **Owner key.** The owner can rotate a submitter. This is visible on-chain, but the verifier does not yet inspect `SubmitterRotated` history.
- **Chain outage.** CRITICAL actions fail closed during a chain outage (intended, ADR-0009).
- **Claim boundary (unchanged).** An anchor proves a commitment existed by a time, not that the action was truthful, authorized, complete or correct.
