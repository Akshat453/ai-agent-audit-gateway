# AI Agent Audit Gateway — Design Documentation

Status: **Phase 0 (design), Phase 1 (core gateway), Phase 2 (flight recorder), Phase 3
(Merkle epochs + offline verifier), Phase 4 (risk engine + risk-adaptive sealing), Phase 5
(action-bound human approval) and Phase 6 (blockchain anchoring, on Anvil; Base Sepolia pending a
funded key) and Phase 7 (encryption, key management, selective disclosure) implemented,
2026-11-16.** Per-phase records: [phases/](phases/).
Phase numbers follow the phase prompts, which differ from [13-roadmap.md](13-roadmap.md) (see
the note there).

The gateway sits on the execution path between AI agents and the tools they call. It has two
separate responsibilities. The documents keep them apart deliberately:

| | Responsibility | Mechanism | Fails how |
|---|---|---|---|
| **A** | **Enforcement**: an unauthorized or unapproved action never reaches a controlled tool | authenticated agents, tool registry, deterministic deny-by-default policy, approvals, outbox-gated dispatch | closed (no side effect) |
| **B** | **Evidence**: tamper-evident records of what was proposed, decided, dispatched and observed, verifiable by a third party | immutable lifecycle events, deterministic CBOR, SHA-256 hash chain, RFC 9162 Merkle epochs, chained epoch roots, on-chain anchors, encrypted payloads | detectably (verifier reports TAMPERED / INCOMPLETE) |

> **Claim boundary.** An anchor proves that a 32-byte commitment existed no later than the
> anchor's inclusion/finality time. It does **not** prove that the committed action was
> truthful, authorized, complete or semantically correct (Paper A §2, §4, §8; Paper B §II-C,
> §VIII-A). Every document repeats this boundary where it matters.

## Reading order

| # | Document | Purpose |
|---|---|---|
| 00 | [00-repository-setup.md](00-repository-setup.md) | Monorepo layout, package boundaries, tooling, CI, branch-per-phase workflow |
| 01 | [01-source-analysis.md](01-source-analysis.md) | What we take from, change in, and reject from Papers A and B (with section citations) |
| 02 | [02-architecture.md](02-architecture.md) | Components, trust boundaries, request flow, evidence pipeline |
| 03 | [03-threat-model.md](03-threat-model.md) | Assets, adversaries, attacks, controls, residual risk |
| 04 | [04-risk-and-policy-design.md](04-risk-and-policy-design.md) | Risk levels, mandatory rules, policy engine, approval binding |
| 05 | [05-event-schema.md](05-event-schema.md) | Lifecycle state machine, event types, record vs payload, CBOR profile fields |
| 06 | [06-cryptographic-specification.md](06-cryptographic-specification.md) | Exact byte layouts: tags, event hash, payload digest, Merkle, epoch root, proofs, test vectors |
| 07 | [07-key-management-and-privacy.md](07-key-management-and-privacy.md) | AES-256-GCM envelope encryption, selective disclosure, crypto-erasure |
| 08 | [08-reliability-and-failure-model.md](08-reliability-and-failure-model.md) | Transactions, outbox, crash points, idempotency, reconciliation, fail-closed |
| 09 | [09-batching-and-anchoring.md](09-batching-and-anchoring.md) | Per-tenant chain, epoch sealing triggers, anchoring states, CRITICAL pre-action gate, contract |
| 10 | [10-verification-and-evaluation.md](10-verification-and-evaluation.md) | Standalone verifier, evidence bundles, experiment and ablation plan |
| 11 | [11-api-and-data-contracts.md](11-api-and-data-contracts.md) | HTTP API, error model, DB contracts |
| 12 | [12-technology-decisions.md](12-technology-decisions.md) | Stack evaluated on its merits, with rejected alternatives |
| 13 | [13-roadmap.md](13-roadmap.md) | Phases 1–10, scope and exit criteria |
| 14 | [14-phase-1-handoff.md](14-phase-1-handoff.md) | **The Phase 1 backlog**: tables, endpoints, demo tools, auth, ordered tasks |
| 15 | [15-glossary.md](15-glossary.md) | One definition per term |
| — | [adr/](adr/README.md) | Architecture Decision Records (locked decisions; change only via a new ADR) |
| — | [phases/](phases/) | One document per implemented phase: what changed, decisions, work done, gaps |

## Sources

Originals are in [papers/](papers/). SHA-256 of the files as stored:

| Ref | Paper | File | SHA-256 |
|---|---|---|---|
| **Paper A** | A. Brömme, *A Black Box for Agentic Processes: Blockchain-Anchored Evidence for AI Agent Communication, Human Oversight, and GRC Audits*, arXiv:2609.04017v1, draft v0.9.1.5, 3 Sep 2026. Position/architecture paper, no experiments. | `papers/2609.04017v1-bromme-black-box-agentic-processes.pdf` | `39534a615e6abbd33cf25d592141dd5306b24206a4de05faf94f9a434c50f763` |
| **Paper B** | L. Bindschaedler, Q. Botha, C. Siebenbrunner, *Agent Flight Recorder: Tamper-Evident Audit Trails with On-Chain Anchoring for Long-Horizon Tool-Using Agents*, arXiv:2609.01931v1, 1 Sep 2026. ~1,500-line prototype, mostly synthetic evaluation. | `papers/2609.01931v1-bindschaedler-agent-flight-recorder.pdf` | `d9563ded707e7d5bf20a2b9d70facf8d151a3dc6c3c1c87c5b9fd48608d3c3a2` |

Citation style in these docs: "Paper A §4", "Paper B §III-C". Paper A's sections are numbered
1–9. Paper B uses Roman numerals with lettered subsections. Paper A's sections are short, so
some citations name a paragraph heading, e.g. "Paper A §3, *Authenticity and authorized anchoring*".

## Conventions used in all documents

- **MUST / MUST NOT / SHOULD / MAY** follow RFC 2119 meaning.
- `||` is byte concatenation. `u16(x)` / `u64(x)` are unsigned big-endian integers of 2 / 8 bytes.
- "Phase N" refers to [13-roadmap.md](13-roadmap.md). A feature tagged *(Phase N)* is specified
  here but MUST NOT be implemented before that phase ("leave interfaces, not features").
- Claims about performance are hypotheses until an experiment in `experiments/` measures them.
