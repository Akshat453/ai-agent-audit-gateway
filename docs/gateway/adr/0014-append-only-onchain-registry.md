# ADR-0014: Append-only Solidity anchor registry; Foundry/Anvil local, Base Sepolia testnet; track submitted/included/finalized
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Paper B §IV-A anchors `R_t` and `H(R_{t−1})` and treats the earlier-included duplicate as canonical (§III-D). Paper A §4 defines anchor time via inclusion and finality.
## Decision
Contract `AgwAnchorRegistry` (09 §7): per tenant key, only the registered submitter may anchor. Epochs must be contiguous. `prevRoot` must equal the stored previous root. There is no overwrite, upgrade or delete. On-chain: tenant key, epoch number, `R_t`, `R_{t−1}` and block data only, nothing sensitive. Local: Foundry + Anvil (31337). Testnet: Base Sepolia (84532). Off-chain states PENDING / SUBMITTED / INCLUDED / FINALIZED (+FAILED), with reorg rollback. Finality level is configurable.
## Consequences
+ Equivocation by the authorized submitter can't be anchored. + Gap detection on-chain.
− The owner key can rotate submitters (visible on-chain). − Another contract or key could carry a fake history, so verifiers pin the contract via the operator manifest.
