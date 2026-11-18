"""Phase 6 mutation check (ADR-0028): remove one anchoring guard, run the test named for it,
expect that test to FAIL, restore the file. Python guards run their pytest test; contract guards
run the Foundry suite in the pinned image.

    uv run python experiments/anchoring/mutation_check.py      (from the repo root)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ANCHORER = Path("apps/worker/src/agw_worker/anchoring/anchorer.py")
GATE = Path("apps/gateway/src/agw_gateway/anchoring/gate.py")
SEALER = Path("apps/worker/src/agw_worker/sealing/sealer.py")
VANCHOR = Path("packages/verifier/src/agw_verifier/anchor.py")
VEPOCHS = Path("packages/verifier/src/agw_verifier/epochs.py")
APPROVALS = Path("apps/gateway/src/agw_gateway/approvals/service.py")
SOL = Path("contracts/src/EpochAnchor.sol")
T = "apps/gateway/tests/e2e/test_anchoring.py"
FORGE = [
    "docker", "run", "--rm", "-v", f"{Path('contracts').resolve()}:/work", "-w", "/work",
    "--entrypoint", "forge", "ghcr.io/foundry-rs/foundry:v1.3.5", "test",
]  # fmt: skip

M: list[tuple[str, Path, str, str, str]] = [
    # ---- worker
    (
        "write-ahead before broadcast",
        ANCHORER,
        '                ANCHOR_TRANSITIONS.labels("SUBMITTED").inc()\n',
        '                ANCHOR_TRANSITIONS.labels("SUBMITTED").inc()\n'
        '                raise AnchorRpcError("MUTANT")\n',
        f"{T}::test_kill_rpc_mid_submit_restart_same_root_single_anchor",
    ),
    (
        "same-root re-broadcast after drop",
        ANCHORER,
        "            self.backend.broadcast(bytes(row.raw_tx))\n            self._bump_resubmission",
        "            self._bump_resubmission",
        f"{T}::test_kill_rpc_mid_submit_restart_crash_before_broadcast",
    ),
    (
        "reorg detection",
        ANCHORER,
        "                if canonical != bytes(row.block_hash):",
        "                if False:",
        f"{T}::test_reorg_resubmits_same_root",
    ),
    (
        "equivocation halt",
        ANCHORER,
        "        if onchain.matches(item):",
        "        if True:",
        f"{T}::test_different_root_on_chain_halts_recorder",
    ),
    (
        "epoch header self-check",
        ANCHORER,
        "                if not self._header_ok(row):",
        "                if False:",
        f"{T}::test_epoch_row_edited_before_anchoring_halts",
    ),
    (
        "strict epoch order",
        ANCHORER,
        "                if epoch_no > onchain_next and not self._predecessor_in_flight(row):",
        "                if False:",
        f"{T}::test_strict_epoch_order_when_predecessor_not_ready",
    ),
    (
        "finality before FINALIZED",
        ANCHORER,
        "                    if receipt.block_number <= final_block:",
        "                    if True:",
        f"{T}::test_seal_anchor_finalize_verify",
    ),
    # ---- CRITICAL gate
    (
        "gate on CRITICAL authorization",
        APPROVALS,
        "        if self._gate.required(action.risk_level, GatePolicy.rule_ids(decision)):",
        "        if False:",
        f"{T}::test_critical_pre_anchor_released_only_after_finality",
    ),
    (
        "release only when FINALIZED",
        GATE,
        "AND j.gate_deadline > now() AND a.status = 'FINALIZED'",
        "AND j.gate_deadline > now() AND a.status IN ('INCLUDED', 'FINALIZED')",
        f"{T}::test_critical_pre_anchor_released_only_after_finality",
    ),
    (
        "release only before deadline",
        GATE,
        "AND j.gate_deadline > now() AND a.status = 'FINALIZED'",
        "AND a.status = 'FINALIZED'",
        f"{T}::test_gate_release_and_timeout_exactly_one_wins",
    ),
    (
        "timeout fails closed",
        GATE,
        "                       AND gate_deadline <= now()",
        "                       AND false",
        f"{T}::test_critical_pre_anchor_rpc_down_fails_closed",
    ),
    (
        "own epoch for ACTION_AUTHORIZED",
        SEALER,
        "                due = gates.get(tenant_id) or decide(window, self.policy)",
        "                due = decide(window, self.policy)",
        f"{T}::test_critical_pre_anchor_released_only_after_finality",
    ),
    # ---- verifier
    (
        "anchored root comparison",
        VANCHOR,
        '            if (\n                on.root.hex() != rec["epoch_root"]',
        '            if False and (\n                on.root.hex() != rec["epoch_root"]',
        f"{T}::test_edit_db_epoch_root_after_anchoring",
    ),
    (
        "epochs missing vs chain",
        VANCHOR,
        "        if whole_export and chain_next - 1 > last_material:",
        "        if False:",
        f"{T}::test_delete_db_tail_detected_vs_chain",
    ),
    (
        "bundle claims vs pinned",
        VEPOCHS,
        "    problem = bundle_claims_problem(bundle, view.trust)",
        "    problem = None",
        f"{T}::test_wrong_contract_in_bundle_untrusted",
    ),
    (
        "RPC chain id pinned",
        VANCHOR,
        "        if got != self.trust.chain_id:",
        "        if False:",
        f"{T}::test_wrong_contract_in_bundle_untrusted",
    ),
    (
        "finality block for checks",
        VANCHOR,
        '            on = view.anchor(rec["epoch_no"], final) if final >= 0 else None',
        '            on = view.anchor(rec["epoch_no"], latest)',
        f"{T}::test_seal_anchor_finalize_verify",
    ),
    # ---- contract (Foundry suite)
    (
        "contract: submitter only",
        SOL,
        "        if (msg.sender != submitterOf[recorderId]) revert NotSubmitter();",
        "",
        "forge",
    ),
    (
        "contract: next epoch only (no overwrite/gap/replay)",
        SOL,
        "        if (epochNo != expected) revert EpochOutOfOrder(expected, epochNo);",
        "",
        "forge",
    ),
    (
        "contract: seq tiling",
        SOL,
        "        if (firstSeq != expectedFirst) revert SeqNotTiled(expectedFirst, firstSeq);",
        "",
        "forge",
    ),
    (
        "contract: owner-only registration",
        SOL,
        "    function registerRecorder(bytes32 recorderId, address submitter) external onlyOwner {",
        "    function registerRecorder(bytes32 recorderId, address submitter) external {",
        "forge",
    ),
]

caught = 0
for name, path, old, new, test in M:
    src = path.read_text()
    assert src.count(old) == 1, (name, src.count(old))
    path.write_text(src.replace(old, new))
    try:
        argv = FORGE if test == "forge" else [
            "uv", "run", "pytest", "-q", "-x", "-p", "no:cacheprovider", test,
        ]  # fmt: skip
        r = subprocess.run(argv, capture_output=True, text=True, check=False)
    finally:
        path.write_text(src)
    ok = r.returncode != 0
    caught += ok
    label = "forge test" if test == "forge" else test.split("::")[1]
    print(f"{'CAUGHT ' if ok else 'SURVIVED'}  {name:<48} {label}")
print(f"{caught}/{len(M)} mutations caught")
sys.exit(0 if caught == len(M) else 1)
