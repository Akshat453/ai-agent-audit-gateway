# 13 — Roadmap

Status: Accepted (Phase 0). One phase per session. Each phase ends with a report and STOP.

> **Numbering note (Phase 5).** The phase prompts implemented so far are: 1 core gateway,
> 2 flight recorder, 3 Merkle epochs, **4 risk engine + adaptive sealing (ADR-0026)**,
> **5 approvals (ADR-0027)**. The table below is the Phase 0 plan (approvals as 4, encryption
> as 5). Reconciling the two is an open owner decision; `probe()`/manual reconcile from row 4
> is not yet implemented.
Features specified for a later phase MUST NOT be implemented early. Earlier phases leave only
interfaces.

| Phase | Name | Scope | Exit criteria (summary) |
|---|---|---|---|
| 0 | Design | These docs + ADRs. Papers in `docs/gateway/papers/`. | Only `docs/` created or changed |
| 1 | Core execution gateway | Skeleton, config, DB (11 tables), auth, registry, policy v1, risk v1, POST/GET endpoints, outbox executor, reconciliation, demo tools and agent | See [14-phase-1-handoff.md](14-phase-1-handoff.md) §10 |
| 2 | Canonical events + hash chain | AGW-CBOR-v1 encoder/validator in `packages/schemas`, `canonical_bytes` NOT NULL, `event_hash`, `prev`, chain head, args digest, tag table | INV-8. Vectors for tags/CBOR/event hash. JSONB derived from bytes. |
| 3 | Merkle epochs | Sealer with all four triggers, `epoch_heads`/`epochs`, `R_t`, inclusion-proof endpoint. **Generate and freeze test vectors** (06 §9). | INV-9. Vectors frozen. Gateway reproduces every byte. |
| 4 | Approvals + reconciliation | Approval binding (04 §5), human auth for approvers, single-use nonces, re-evaluation at dispatch, `probe()` and manual reconcile | INV-11. Change-any-field → approval invalid. |
| 5 | Encryption + payload store (**done as prompt Phase 7**, ADR-0029) | Salted payloads, AES-256-GCM DEK/KEK, `evidence_payloads`/`payload_keys`, MinIO for large blobs, erasure | T18/T19 tests. KEK-down → 503. |
| 6 | Anchoring | Foundry contract + tests, Anvil in compose, anchorer + tracker (submitted/included/finalized, reorg), **CRITICAL gate**, Base Sepolia manual run | INV-10. ANCHOR_TIMEOUT test. Gas measured. |
| 7 | Verifier + bundles | `agw-verify` CLI, bundle export, selective disclosure package, signed operator manifest | Verifier passes all vectors with zero imports from `apps/` |
| 8 | Experiments + monitoring stream | Tamper suite, ablations, benchmarks, risk experiments, `_monitor` tenant | Reproducible results with scripts and raw data |
| 9 | Dashboard | Read-only Next.js investigation UI (timeline, epochs, anchors, verification) | No write endpoints |
| 10 | Multi-agent + hardening | A2A events, delegation tokens, MCP front-end, mTLS/OIDC, signed event records | Per-phase prompt |

Future research (not scheduled): TEE-attested gateway for completeness (Paper B §VIII-A(1),
§VIII-D(2)); threshold signing for anchors (Paper A §3, §8); ZK inclusion for compelled audits
(Paper B §III-E, §VIII-D(1)); gas-adaptive epoch sizing (Paper B §VIII-D(3)); signed operator
manifest via transparency log.
