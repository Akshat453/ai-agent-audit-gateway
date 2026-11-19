# Implementation and Experimental Setup

## Technology Stack

{tab:stack} lists the main technologies with the reason for each choice; the design documents also record the rejected alternatives.

::table stack | Technology stack and rationale
::widths 18,30,52
| Concern | Choice | Reason |
|---|---|---|
| Gateway | Python 3.12+, FastAPI, Pydantic v2 | Mature crypto libraries; strict validation |
| Database | PostgreSQL 16, SQLAlchemy 2, Alembic | Outbox transactions, triggers, column grants |
| Queue | Postgres outbox + worker | Job atomic with its evidence |
| Encoding, crypto | AGW-CBOR-v1, SHA-256, `cryptography` | Strict profile, frozen vectors; audited primitives |
| Contracts | Solidity, Foundry, Anvil | Fast tests; local reorg simulation |
| Console | Next.js 16, TypeScript | Server components; nonce CSP |
| Tests | pytest, Hypothesis, Playwright | Real Postgres; property tests |
| MintRail | TypeScript, Node.js 22, pnpm | Realistic agent workload |

## Repository Structure and Modules

The gateway repository is a `uv` workspace whose import-linter contracts enforce package boundaries; for example, the verifier may not import gateway code, and policy and risk modules must stay pure. Measured in lines (including blank and comment lines), the main modules are `apps/gateway` (API, auth, risk, policy, approvals, execution, evidence, crypto, coding, connectors and GitHub; 26,066), `apps/worker` (sealer, anchorer, approval sweeper, monitor; 2,566), the standalone verifier `packages/verifier` (1,509), the standard-library `agw` CLI `packages/agw-cli` (3,708), `packages/schemas` with the CBOR codec and frozen test vectors (682), the console `apps/dashboard` (9,671, without generated types and tests), the SDK, LangGraph and MCP integrations (1,097) and `EpochAnchor.sol` (108). MintRail is a pnpm monorepo with services `api`, `ledger` (double-entry), `junction` (bank and UPI simulator), `conductor` (risk checks), `signal` (signed webhooks), `depot` (settlements), two Next.js applications, an SDK and shared packages (bigint money, FX, IST dates).

## Phase-wise Development Summary

Each phase ended with a report, ADRs and a clean-state acceptance run (`make up && make migrate && make test && make demo`). In every phase, protections were checked by *mutation*: a guard was removed and a named test had to fail. {tab:phases} summarises the phases; the C3b/C4 count is from the latest full run in the final session, the others from the phase reports.

::table phases | Phase-wise development summary
::widths 9,55,18,18
| Phase | Deliverable | Gateway tests | Mutations caught |
|---|---|---|---|
| 1 | Core gateway: auth, registry, policy v1, outbox, reconciler | 140 | 10/10 |
| 2 | Flight recorder: CBOR profile, hash chain, chain verifier | 376 | 11/11 |
| 3 | Merkle epochs, bundles, offline verifier, tamper suite | 412 | all |
| 4 | Risk engine v2, adaptive sealing, labelled dataset | 604 | 17/17 |
| 5 | Action-bound approval, Ed25519 decision records | 669 | 17/17 |
| 6 | Anchoring contract, anchorer, CRITICAL gate (Anvil) | 717 | 21/21 |
| 7 | Envelope encryption, selective disclosure, retention | 747 | 20/20 |
| 8 | SDK, LangGraph, MCP adapter, delegation, containment | 813 | 25/25 |
| 9, 9.5 | Console, monitor stream, reconciliation; redesign | 830; 858 | 13/13 |
| 10 | Evaluation harness RQ1-RQ7, ablation flags, hardening | - | - |
| C1 | Coding-agent API, `agw` CLI, coding policy | 1,165 | 11/11 |
| C2 | Connectors, device enrolment, MCP sign-in, `agw init` | 1,240 | 13/13 |
| C3 | GitHub dev-tools, server-side submit, evidence check | 1,265 | 11/11 |
| C3b, C4 | Stored-copy integrity; plain-English console; repo scope | 1,497 | - |

## Database Design

{fig:er} shows the core tables. `actions` holds mutable workflow state; `evidence_events` is append-only, keyed by (tenant, seq), and stores canonical bytes and hashes; ciphertexts and wrapped keys live separately; `epochs` is append-only, with a trigger guaranteeing that epochs tile the sequence range. Two roles separate schema ownership (`agw_migrator`) from runtime access (`agw_app`), with column-level grants.

::figure er | fig4_1_er.png | Simplified entity-relationship diagram of the core tables | 5.77

## Smart Contract and Anchoring Setup

`EpochAnchor.sol` (108 lines) stores, per registered recorder, the next expected epoch and the last root. `anchor()` accepts a root only from the registered submitter, only for the next epoch and only with a back-pointer equal to the stored root, so a second root for an epoch is impossible. The recorder identifier is a salted hash, so no tenant name appears in calldata. Slither (102 detectors) found no issues and 16 Foundry tests pass. Development uses Anvil (chain id 31337) in Docker Compose with persisted state and finality `included` or `confirmations:N`. Base Sepolia (chain 84532) commands are documented but were not run, because no funded key was available.

## AgentGuard Console

The console is a BFF: the session lives in a `__Host-` httpOnly, Secure, SameSite=Strict cookie; every POST needs an HMAC synchronizer token and a same-origin check, which protects against cross-site request forgery (CSRF); the Content Security Policy (CSP) uses a per-request nonce without `unsafe-inline` or `unsafe-eval`; and no dashboard endpoint returns payloads. Phase C4 added a plain-English "Simple" view where it helps most (runs, actions, approvals, events, incidents), while overview and setup pages keep their technical layout. {fig:run} shows a coding session as a structured story whose steps show a command's meaning and reveal the exact command when opened, and {fig:appr} shows a CRITICAL approval request. An Epochs and anchors page lists each sealed epoch with its seal reason and anchor state.

::figure run | fig4_2_console_run.png | AgentGuard Console: a Claude Code session shown as a run story (Simple view) | 5.5

::figure appr | fig4_3_console_approval.png | AgentGuard Console: approval detail for a CRITICAL coding action | 5.5

## MintRail Test Environment

MintRail is a fictional Indian payments company created only to exercise AgentGuard. Its conventions give the coding policy real targets: money is bigint paise (lint-enforced), webhooks carry HMAC signatures, every state change emits an outbox event, and live API keys sign requests. A seeding script files 21 backlog issues on GitHub: 16 labelled `bug`, 4 `feature` and 1 without a type label (an access request), with severities `sev:1` / `sev:2` / `sev:3` of 4 / 11 / 6. Four titles ask for weakening a security or quality control (disabling webhook signature verification in staging, removing a refund-limit test, SSH access to a deploy host, skipping integration tests); this grouping is the author's reading of the public titles, since the repository has no explicit trap label, and the separate answer-key repository was not opened. `agw init` generated `.claude/settings.json` (PreToolUse hooks that block on failure), Cursor `hooks.json` and `mcp.json`, an Antigravity MCP file, `.agentguard.yaml` with sensitive paths, and a managed block in `AGENTS.md`. The repository contains no dev-container definition.

## Experimental Setup

All measurements ran on one machine (Apple M2, 8 cores, 16 GiB RAM, macOS arm64, Python 3.13.2, Docker 29.2.0, `postgres:16`) at commit `dad55bc` with uncommitted changes. One codebase runs under the ablation configurations of {tab:ablation}, selected by `AGW_ABLATION`, which is refused outside development and test. The research-question (RQ) 1 workload calls a LOW-risk no-op tool (`test_echo`) at concurrency 1, 10 and 50, with 5 independent runs per cell, 12 measured requests per agent (at least 120 per run) after 30 warm-up requests, and seed 1. Every request, including fail-closed 503 responses, stays in the percentiles; intervals are 95 % bootstrap intervals over runs (2,000 resamples), and rate limiting was off. Other workloads: a 67-case labelled action dataset (24 routine, 30 adversarial, 7 delegation, 6 volume); a simulated one-hour sealing comparison (Poisson arrivals, 80 % LOW, 15 % MEDIUM, 4 % HIGH, 1 % CRITICAL; 5 seeds); 40 mined anchors; a 13-document injection corpus in two modes; the approval-attack suite; tamper runs on real exports (25 events, 5 epochs); and a 191-case coding-action table. Integration agents are LangGraph graphs with SDK and MCP transports driven by a deterministic mock LLM; no hosted LLM is called.

::table ablation | Ablation configurations C0-C6
::widths 10,90
| Config | Layers enabled |
|---|---|
| C0 | No gateway: in-process call of the same no-op tool |
| C1 | Gateway authentication and policy; no evidence; approvals off |
| C2 | C1 + canonical CBOR event records (no chain) |
| C3 | C2 + hash chain + fixed 100-event Merkle sealing |
| C4 | C3 + fixed-interval anchoring |
| C5 | C4 with risk-adaptive sealing and anchoring |
| C6 | C5 + approvals + CRITICAL pre-action anchoring (production behaviour) |
