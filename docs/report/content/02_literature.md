# Literature Survey

## Paper A: A Black Box for Agentic Processes

Brömme proposes a vendor-neutral "black box" for agentic processes: an externalised, tamper-evident record of critical states for reconstruction after an incident or during an audit [@bromme2026]. It is a position paper without evaluation. It contributes a six-stage pipeline (Capture, Canonicalize, Hash, Anchor, Certify, Verify) in which canonicalisation is security-relevant; a minimal event object with policy, control, artefact, approval and tool references; a threat list including spoofed tool-call records, unclear human-in-the-loop (HITL) approvals and a mismatch between approved and executed actions; governance, risk and compliance (GRC) mappings; *risk-based evidence selection*; and a *monitoring evidence stream*. Its strength is a precise claim boundary: anchoring proves existence and integrity, not authorship, authorisation or truth, and a compromised runtime could anchor a benign substitute. Its gaps are no implementation, JSON Canonicalization (JCS) offered only as an example [@rundgren2020], no binding of an approval to the executed action, and a selection rule that, read literally, omits routine events from the anchored record.

## Paper B: Agent Flight Recorder

Bindschaedler, Botha and Siebenbrunner present a Python prototype of about 1,500 lines with a small Solidity contract [@bindschaedler2026]. Each event binds eight semantic fields (intent, policy evaluation, human approval, execution, effects, and context, code and delegation provenance) as deterministic CBOR [@bormann2020]; integrity comes from a hash chain, Merkle batching and epoch roots R_t = H(M_t || R_t-1) anchored on an Ethereum layer-2 (L2) chain, and payloads are encrypted under an HKDF key hierarchy. It reports about 48 microseconds and 512 bytes per event, 91,800 gas per anchor on Base Sepolia, and 100 % detection of edit, delete, reorder and fork attacks. Its strengths are a clear post-compromise adversary model, content kept off-chain and a cumulative ablation method. Its gaps are last-leaf duplication for odd leaf counts ([a,b,c] and [a,b,c,c] share a root), epoch roots that bind no tenant, epoch number, size or range, forks resolved by "earlier transaction wins" instead of refused, one epoch key revealing every event key in the epoch, and recording without enforcement on mostly synthetic workloads.

## Supporting Work and Standards

The project uses the RFC 9162 Merkle Tree Hash without leaf duplication [@laurie2021], deterministic CBOR (RFC 8949 Section 4.2) under a stricter profile [@bormann2020], AES-256-GCM [@dworkin2007], HPKE [@barnes2022] and Ed25519 [@josefsson2017]. MCP clients and devices authenticate with OAuth 2.0 token exchange [@jones2020] and the device grant [@denniss2019] against the Model Context Protocol (MCP) revision 2026-07-28 [@mcp2026]. Coding agents are integrated through their pre- and post-tool hooks [@anthropic2026hooks; @openai2026hooks; @cursor2026hooks; @google2026hooks], and anchoring uses an Ethereum Virtual Machine (EVM) contract.

## Comparison of Approaches

{tab:compare} compares the two papers with this project.

::table compare | Comparison of Paper A, Paper B and this project
::widths 16,17,25,42
| Dimension | Paper A | Paper B | This project |
|---|---|---|---|
| Enforcement | Out of scope | Out of scope (records only) | Active gateway, deny by default, outbox-gated dispatch |
| Evidence model | Abstract event object | Eight fields, CBOR, chain + Merkle | Eight fields on lifecycle events, strict CBOR profile, chain + RFC 9162 epochs |
| Risk adaptivity | Proposed (selection) | Fixed epochs | Risk changes *when* epochs seal; every event stays in the chain |
| Approvals | Threat named | Field "should" bind | Digest + nonce + expiry + single use, re-evaluated before dispatch |
| Anchoring | Proposed | Base Sepolia, earlier tx wins | Append-only contract refuses a second root; CRITICAL pre-action gate |
| Privacy | Hashes only on-chain | HKDF epoch keys | Random per-event keys, salted digests, HPKE disclosure |
| Evaluation | None | Synthetic + 5 real traces | Attack suites, ablation C0-C6, coding agents |

## Research Gap and Approach

Neither paper prevents an action or makes authorisation durable before the side effect; this project combines enforcement (failing closed) and evidence (failing detectably). {tab:adopt} lists what was adopted, modified and rejected, as recorded in Architecture Decision Records (ADRs) such as ADR-0007 (RFC 9162 without duplication), ADR-0008 (one chain, risk-triggered sealing) and ADR-0012 (per-event keys).

::table adopt | What the project adopted, modified and rejected from the base papers
::widths 14,43,43
| Decision | From Paper A | From Paper B |
|---|---|---|
| Adopted | Claim boundary; pipeline; monitoring stream; minimal on-chain data | Eight fields; CBOR; record/payload split; chained roots; ablation |
| Modified | Selection becomes risk-triggered *sealing*; no event omitted | Root binds tenant, epoch, size and range; second root refused |
| Rejected | JCS as canonical form | Leaf duplication; HKDF epoch keys |
