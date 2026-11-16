# Phase 6: Blockchain anchoring

Date: 2026-11-16 · ADR: [0028](../adr/0028-phase6-blockchain-anchoring.md) · Status: done on Anvil;
Base Sepolia pending a funded key (§5).

## What this phase delivers
- **Anchoring.** Epoch roots now go to an append-only contract outside our trust boundary, by the risk priority the sealer assigns. Each anchor is tracked to finality.
- **Pinned verification.** The offline verifier checks anchors against the chain using trust roots the auditor pins out of band.
- **CRITICAL actions.** A CRITICAL action is never dispatched before the epoch holding its authorization is anchored and final. On timeout it fails closed.

**Claim boundary (unchanged).** An anchor proves a commitment existed by a block. It does **not** prove the recorded action was truthful, authorized, complete or correct. A CRITICAL pre-action anchor proves that intent and authorization were committed before the side effect; it says nothing about the result.

## 1. What changed

| Area | Files | What |
|---|---|---|
| Contract | `contracts/src/EpochAnchor.sol`, `test/EpochAnchor.t.sol`, `test/Vm.sol`, `script/Deploy.s.sol`, `foundry.toml` | Write-once, contiguous epochs per recorder. Seq tiling enforced on-chain. Only the registered submitter may anchor. Owner-only registration and rotation. 16 Foundry tests (4 fuzz, 1,024 runs each). Builds with no external dependencies. |
| Build artifacts | `contracts/artifacts/EpochAnchor.json`, `contracts/tools/export_artifact.py`, `contracts/tools/slither.sh` | Committed ABI and bytecode. `make contracts-check` requires a fresh build to reproduce them. |
| Deployment | `contracts/deploy-anvil.sh`, `contracts/deployments/anvil-31337.json`, compose `anvil` service | Deploys with the Foundry script, then records chain id, address, block, deployer, owner and code hashes. |
| DB | `migrations/versions/0006_phase6_anchoring.py`, `db/tables.py` | New `anchor_recorders` and `anchors` tables, and outbox gate fields (below). |
| Gateway | `anchoring/identity.py`, `anchoring/gate.py`, `approvals/service.py`, `execution/service.py`, `execution/executor.py`, `api/app.py`, `api/state.py`, `api/routes.py`, `evidence/bundle.py`, `config.py`, `metrics.py`, `crypto/tags.py`, `execution/crash.py` | Recorder id and finality levels. The CRITICAL gate (release and timeout). Gated DISPATCH jobs. `dispatch.anchor`. Untrusted `anchor` claims in bundles and the epoch API. `AGW_ANCHOR_*` and `AGW_PRE_ANCHOR_RULES` settings. Anchor metrics. |
| Worker | `agw_worker/anchoring/{backend,evm,anchorer,admin}.py`, `__main__.py`, `sealing/sealer.py` | `AnchorBackend` interface, web3 backend and the anchor state machine. Operator CLI. The worker runs the anchorer and the gate sweeper. The sealer puts each gated ACTION_AUTHORIZED in its own `[s, s]` epoch. |
| Schemas | `agw_schemas/events.py`, `bundle/evidence-bundle.v1.schema.json` | `Dispatch.anchor` (AnchorRef). Optional bundle `anchor` claim. |
| Verifier | `agw_verifier/anchor.py`, `epochs.py`, `cli.py` | Chain mode (stdlib JSON-RPC, pinned trust roots). New result UNTRUSTED_ANCHOR, exit 5. |
| Tests | `tests/anchorkit.py`, `e2e/test_anchoring.py` (21), `e2e/test_anchor_admin.py` (3), `unit/test_anchoring_units.py` (20), `packages/verifier/tests/test_verifier_anchor.py` (4), `conftest.py` | A real Anvil node (pinned image) and an RPC proxy that can be killed mid-request. A scripted RPC for verifier edge cases. Other phases' fixtures set `pre_anchor_rules=()`. |
| Experiments | `experiments/anchoring/{measure_gas.py,mutation_check.py,results/}` | Gas from ≥ 30 mined anchors; 21 guard mutations. |
| Tooling | `Makefile`, `pyproject.toml`, `apps/worker/pyproject.toml`, `.env.example`, `.gitignore`, `run_demo.sh`, `anchor_demo.py`, `fetch_bundle.py`, `admin.py` | New make targets (contract tests, artifact check, gas report, Slither, Anvil deploy, gas measurement, mutations). Anchoring added to the coverage gate. A sixth import contract keeps web3 inside the anchor worker. web3 7.16.0 added. Demo agent `demo-iam-admin`. |
| Docs | ADR-0028; notes in 03 (INV-10), 06 (tag, §8, §10 recorder id), 08 (C7), 09 (§2, §6, §7, §8), 10 (V5, V6, V11, results), 11; ADR-0009/0014 status; ADR index; README status | |

**Migration 0006 in detail**
- **`anchor_recorders`:** each tenant is pinned to one recorder id, chain, contract and submitter. Operators create rows; `agw_app` can only halt one.
- **`anchors`:** an insert trigger requires the row to carry the sealed epoch's exact root. `agw_app` has no UPDATE grant on root, size, last seq or epoch number, and DELETE and TRUNCATE are blocked.
- **`outbox_jobs`:** new status `WAITING_ANCHOR` and columns `gate_seq`, `gate_deadline`, `gate_anchor`.

## 2. Decisions
The full reasoning is in ADR-0028.

1. **The contract follows the prompt, not the 09 §7 sketch.** This was a docs-vs-prompt mismatch; ADR-0028 supersedes ADR-0014 and 09 §7 in part:
   - `recorderId` replaces the unsalted, guessable `tenantKey`.
   - Each epoch stores `{root, treeSize, lastSeq, timestamp}` instead of `prevRoot`.
   - There is no `anchorBatch`.
   - `blockNumber` is added; it packs into the same storage slot, so it costs no gas.
2. **`nextEpoch` counter.** Epochs are numbered from 0, so `epochNo == lastEpoch + 1` cannot accept epoch 0. The contract keeps a count, `nextEpoch`, and `lastEpoch()` returns `(exists, n)`.
3. **On-chain seq tiling.** An addition: the contract checks `first_seq(t) = last_seq(t−1) + 1`.
4. **Length-prefixed recorder id.** `recorderId` includes a `u16` length prefix, so tenant and salt cannot be confused. Auditors get the id, never the salt.
5. **Write-ahead submission.** The raw transaction is stored before it is sent. Retries, crash recovery and reorg recovery re-send identical bytes.
6. **Chain state wins.**
   - The same root already on-chain is adopted.
   - A different root halts the recorder (FAILED, CRITICAL alert).
   - An epoch row edited after sealing halts it too.
7. **Fixed gas limit and fees.** No `eth_estimateGas` (it reverts while the previous epoch is in the mempool). Fees are 2 × base + tip.
8. **Anchors rows come from `epochs`.** The worker creates them, rather than the seal transaction (09 §2).
9. **Per-rule pre-anchoring.** `AGW_PRE_ANCHOR_RULES` takes policy or risk rule ids. The default `*` covers every CRITICAL action and fails closed when no chain is configured.
10. **Release vs timeout.** Both lock the job row. An anchor that finalizes after the deadline never releases the job.
11. **Untrusted bundle claims.** Bundles carry an `anchor` claim but are never trusted for it: pins come from a config the auditor obtains out of band. Any mismatch → UNTRUSTED_ANCHOR.
12. **No host tooling.** Foundry runs from the pinned Docker image `ghcr.io/foundry-rs/foundry:v1.3.5`. Anvil dev keys come from Anvil's public mnemonic, derived inside the container into git-ignored `secrets/`.

## 3. Results

### 3.1 Clean-state acceptance
Setup: stack, volume, `.env` (verified placeholders only) and `.venv` removed. Then:
```
$ (make up && make migrate && make test && make demo); echo "chain exit=$?"
chain exit=0
```

| Check | Result |
|---|---|
| Migrations | 0001 → 0006 applied |
| ruff | `All checks passed!` |
| mypy | `Success: no issues found in 92 source files` |
| import-linter | `Contracts: 6 kept, 0 broken` |
| Tests | `717 passed` (Phase 5: 669) |
| Coverage, overall | 92% |
| Coverage, gated packages (now including both anchoring packages) | 95% (gate 85%) |
| Coverage, `risk/` | 100% |
| Demos | `DEMO OK`, `PHASE 5 DEMO OK`, `PHASE 6 DEMO OK` |

Coverage per anchoring module:

| Module | Coverage |
|---|---|
| `gate.py` | 99% |
| `identity.py` | 100% |
| `anchorer.py` | 87% |
| `evm.py` | 83% |
| `admin.py` | 94% |
| verifier `anchor.py` | 90% |

Other targets:

| Target | Result |
|---|---|
| `make vectors` | exit 0 |
| `make verify-isolated` | `agw-verify runs from the isolated venv` (stdlib only) |
| `make contracts-test` | `16 passed; 0 failed` |
| `make contracts-check` | `artifact matches forge build` |
| `make contracts-slither` | `102 detectors, 0 result(s) found` |
| `make anchor-mutations` | `21/21 mutations caught` |

### 3.2 Demo (`make demo`, Phase 6 part)
The contract is deployed to the compose Anvil with the Foundry script, at `0x5fbdb2315678afecb367f032d93f642f64180aa3`, and the demo tenant is registered.

```
Phase 6 pre-action anchoring run ad3f2853-…
  agent: update_iam_role (dev): status=PENDING_APPROVAL risk=CRITICAL approvals required=2
  alice + bob approved -> status=AUTHORIZED: dispatch waits for the anchor
  agent: long-poll -> status=COMPLETED after 2.4 s (seal own epoch -> anchor -> finality -> release -> dispatch)
  ACTION_AUTHORIZED seq 79 -> anchored epoch 6 in block 145 (confirmations:2) BEFORE ACTION_DISPATCHED seq 82
  its epoch 6: seq 79..79 (tree size 1, RISK_CRITICAL)
PHASE 6 DEMO OK
--- gateway and worker STOPPED; verifying offline with agw-verify ---
agw-verify event  (on-chain anchor)   exit=0
agw-verify event  (CRITICAL ACTION_AUTHORIZED, pre-action anchor) exit=0
agw-verify epochs (on-chain anchors)  exit=0
agw-verify event  (auditor pinned a different contract) exit=5 (5 = UNTRUSTED_ANCHOR)
```

### 3.3 Required tests (all on a real Anvil node)

| Required test | Test | Result |
|---|---|---|
| Seal → anchor → finalized → verifier VERIFIED offline | `test_seal_anchor_finalize_verify` | Not final yet → UNANCHORED (`ANCHOR_NOT_FINAL`). Once final, VERIFIED for the event and for the whole epoch export, through the in-process CLI and the installed `agw-verify`. Exactly one `Anchored` log per epoch; no tenant name in calldata. |
| Edit a DB epoch root after anchoring → TAMPERED | `test_edit_db_epoch_root_after_anchoring` | (a) A blunt root edit → TAMPERED. (b) A consistent re-seal into a different partition passes **every offline check** (UNANCHORED) and is TAMPERED only against the chain (`ANCHOR_ROOT_MISMATCH`). |
| Delete DB tail → missing epochs vs chain | `test_delete_db_tail_detected_vs_chain` | Offline check: UNANCHORED, the shorter history looks fine. With the chain: TAMPERED `EPOCHS_MISSING_VS_CHAIN`, `first_bad_epoch` = first deleted epoch, `chain_last_epoch` = the original last epoch. |
| Wrong contract in bundle → UNTRUSTED_ANCHOR | `test_wrong_contract_in_bundle_untrusted` | Bundle claims another registry → 5 (`BUNDLE_CONTRACT_NOT_PINNED`). Other chain id → `BUNDLE_CHAIN_ID_NOT_PINNED`. No pins → `TRUST_ROOTS_NOT_PINNED`. Pinned chain id ≠ RPC → `RPC_CHAIN_ID_MISMATCH`. Wrong code hash → `CONTRACT_CODE_MISMATCH`. Claims stripped → still VERIFIED against the pins. |
| Kill RPC mid-submit; restart → same root, single anchor | `test_kill_rpc_mid_submit_restart_same_root_single_anchor`, `…_crash_before_broadcast` | Variant 1: the proxy forwards the transaction, then kills the reply. Variant 2: the process dies after the write-ahead, before sending. In both, a new worker instance re-sends **byte-identical** transactions: same tx hash and nonce, same root, one `Anchored` log per epoch. |
| Simulated reorg (snapshot/revert) → same root | `test_reorg_resubmits_same_root` | INCLUDED → `evm_revert` → REORG → SUBMITTED → re-broadcast of the same transaction → INCLUDED → FINALIZED. Same tx hash and root; `resubmissions = 1`. |
| CRITICAL pre-anchor, RPC down → fails closed, adapter never called | `test_critical_pre_anchor_rpc_down_fails_closed` | Job WAITING_ANCHOR → deadline → `ACTION_FAILED{FAILED, ANCHOR_TIMEOUT}`. **IAM adapter calls: 0.** After the RPC returns, the anchor finalizes but the job stays FAILED. |

Further tests:
- `test_critical_pre_anchor_released_only_after_finality`: the authorization sits in its own `[s, s]` epoch; INCLUDED alone does not release the job, FINALIZED does; `dispatch.anchor` is set; the bundle is VERIFIED.
- `test_gate_release_and_timeout_exactly_one_wins`.
- `test_high_actions_are_not_gated`.
- `test_rpc_outage_backs_off_and_metrics_show_backlog`: LOW actions continue during the outage, and the backlog gauge and alert are set.
- `test_idempotent_adopts_existing_same_root`.
- `test_different_root_on_chain_halts_recorder`.
- `test_epoch_row_edited_before_anchoring_halts`.
- `test_priority_shortens_wait_never_reorders`.
- `test_strict_epoch_order_when_predecessor_not_ready`.
- `test_unregistered_recorder_is_not_anchored`.
- `test_runtime_role_cannot_change_an_anchored_root`.
- `test_finalized_block_tag`.
- `test_verifier_chain_unreachable_is_incomplete`.
- Admin CLI: 3 tests (`test_anchor_admin.py`).

### 3.4 Gas (`make anchor-gas`; 40 mined `anchor()` transactions on Anvil)

| Metric | Gas |
|---|---|
| deploy | 709,850 |
| registerRecorder | 46,294 |
| anchor, first for a recorder (cold `nextEpoch` slot) | 96,171 |
| anchor, later (min / median / mean / max) | 81,545 / 81,569 / 81,565.6 / 81,569 |
| anchor, mean of all 40 | 81,930.8 |

- **Cost under stated assumptions.** ETH is taken as $3,000 and only L2 execution gas is counted (assumptions, not market data, 2026-11-16). At 0.01 gwei an anchor costs $0.0025; at 0.1 gwei, $0.025. The full table is in `results/gas-anvil-31337.md`.
- **Not measured on Anvil:** the L1 data fee and time to finality on Base Sepolia (§5).
- **Paper B.** Its figure of about 91,800 gas per anchor (09 §8) is not used as ours, and its dollar figure is not reused.
- **Forge report.** `results/forge-gas-report.txt` excludes the 21,000 base transaction cost and calldata, which is why it differs from the receipts above.

### 3.5 Failing-then-passing evidence
- **Contract.** The first Foundry run failed 10 of 16 tests on a real bug: `lastSeq − treeSize + 1` underflows when an epoch starts at seq 0. The tiling arithmetic moved to `uint256`; the run is now 16/16.
- **Mutation check.** `make anchor-mutations` removes 21 guards one at a time and a named test fails for each (`results/mutations.txt`):
  - worker: write-ahead, same-root re-broadcast, reorg detection, equivocation halt, header self-check, strict order, finality;
  - gate: gating, release only when final, release only before the deadline, timeout, own epoch;
  - verifier: root comparison, missing epochs, bundle claims, RPC chain id, finality block;
  - contract: submitter, next epoch, tiling, owner-only.
- **One survivor, now fixed.** The first mutation run had one survivor, "release only when FINALIZED". The gate test ticked only once, so the anchor was SUBMITTED and never INCLUDED-but-not-final. The test now ticks twice, asserts INCLUDED, and catches the mutation.

## 4. Known gaps
- **Base Sepolia not run** (no funded key in the environment); see §5. Gas there, the L1 data fee and time to `safe`/`finalized` are unmeasured, so 09 §6's testnet defaults stay unverified.
- **Unsigned trust config.** The pinned config (`agw-anchor-trust/v1`) is not signed. 10 §3 V11 asked for a signed operator manifest.
- **One RPC.** Cross-RPC agreement (V6) is not built.
- **Rotations not checked.** The verifier does not inspect `SubmitterRotated` history.
- **Fees and batching.** No fee bumping (stuck transactions are re-broadcast unchanged) and no `anchorBatch`.
- **Signer layout.** A single submitter key per deployment, so one signer serves all its recorders. One worker per signer is enforced by an advisory lock.
- **Halts need an operator.** A halted recorder needs a human: there is no un-halt CLI by design, an operator decides with `agw_migrator`.
- **Plaintext payloads** are unchanged; encryption is a later phase.
- **Other phases' fixtures** run with `pre_anchor_rules=()`; the production default is `*` (tested).
- **Online V10 check.** The executor does not check `dispatch.anchor` against the chain again. Verifier V10 (CRITICAL dispatch has an anchored, earlier epoch) is not built yet.

## 5. Base Sepolia (chain 84532): commands for the owner to run
No funded key was supplied, so the phase stops after Anvil. Run these once you have two Base Sepolia keys with test ETH: an owner/deployer and a separate submitter. The keys go in files, never on the command line or in `.env.example`.

```bash
# 0. Key files (hex private keys, 0600; secrets/ is git-ignored). Use test-only keys.
umask 077; $EDITOR secrets/sepolia-owner.key; $EDITOR secrets/sepolia-submitter.key
export BASE_SEPOLIA_RPC=https://sepolia.base.org            # or your provider URL

# 1. Deploy with the Foundry script (pinned image) and write the deployment record
DEPLOYER_KEY="$(cat secrets/sepolia-owner.key)" docker run --rm -e DEPLOYER_KEY \
  -v "$PWD/contracts":/work -w /work --entrypoint forge ghcr.io/foundry-rs/foundry:v1.3.5 \
  script script/Deploy.s.sol --rpc-url "$BASE_SEPOLIA_RPC" --broadcast
uv run python -m agw_worker.anchoring.admin record-deployment \
  --broadcast contracts/broadcast/Deploy.s.sol/84532/run-latest.json \
  --rpc "$BASE_SEPOLIA_RPC" --out contracts/deployments/base-sepolia-84532.json

# 2. >= 30 real anchors: gas, L1 data fee, inclusion time, time to safe/finalized
ADDR=$(python3 -c "import json;print(json.load(open('contracts/deployments/base-sepolia-84532.json'))['address'])")
uv run python experiments/anchoring/measure_gas.py --n 40 --rpc "$BASE_SEPOLIA_RPC" \
  --chain-id 84532 --contract "$ADDR" --finality-timeout 3600 \
  --owner-key-file secrets/sepolia-owner.key --submitter-key-file secrets/sepolia-submitter.key
#    -> experiments/anchoring/results/gas-chain-84532.{json,md}

# 3. (optional) run the gateway against Base Sepolia
export AGW_ANCHOR_RPC_URL="$BASE_SEPOLIA_RPC" AGW_ANCHOR_CHAIN_ID=84532 AGW_ANCHOR_CONTRACT="$ADDR"
export AGW_ANCHOR_SUBMITTER_KEY_FILE=secrets/sepolia-submitter.key
export AGW_ANCHOR_DEPLOYMENT_SALT_FILE=secrets/anchor-salt.hex AGW_ANCHOR_FINALITY=finalized
export AGW_CRITICAL_ANCHOR_TIMEOUT_SECONDS=1800
uv run python -m agw_worker.anchoring.admin register --tenant demo --owner-key-file secrets/sepolia-owner.key
uv run python -m agw_worker.anchoring.admin trust-config --tenant demo \
  --deployment contracts/deployments/base-sepolia-84532.json --finality finalized \
  --out /tmp/pinned-base-sepolia.json
```

Commit `contracts/deployments/base-sepolia-84532.json`, the `84532` broadcast file and the gas results. The cost table is regenerated from the measured gas, with assumptions you state and date.

## 6. Readiness for the next phase
Anchoring, the CRITICAL gate and chain-pinned verification work end to end on Anvil. Base Sepolia is a manual step (§5).

What comes next depends on the next phase prompt:
- **Roadmap Phase 7 (verifier + bundles, signed operator manifest).** This builds directly on the verifier's chain mode, the bundle `anchor` claim and `dispatch.anchor`. Its signed manifest closes the unsigned-trust-config gap, and it is where V10 belongs.
- **Encryption (roadmap Phase 5).** Still outstanding under the prompt numbering. It needs no anchoring change, because only roots go on-chain. Nothing is committed: HEAD is still `abb5e2a phase3`, and Phases 4–6 are in the working tree.
