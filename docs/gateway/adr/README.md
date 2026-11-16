# Architecture Decision Records

Locked decisions. Change one only by adding a new ADR that supersedes it. Then set the old
one's `Status:` to `Superseded by ADR-XXXX` and leave its text unchanged.

Template: Context → Decision → Consequences (+/−) → Alternatives rejected.

| ADR | Title |
|---|---|
| [0001](0001-active-gateway-deny-by-default.md) | Active gateway, registered tools only, deny by default |
| [0002](0002-deterministic-policy-no-llm.md) | Deterministic policy; no LLM in allow/deny |
| [0003](0003-immutable-events-mutable-actions.md) | Immutable lifecycle events; mutable actions table |
| [0004](0004-durable-pre-execution-evidence-outbox.md) | Durable pre-execution evidence via transactional outbox |
| [0005](0005-deterministic-cbor-hash-stored-bytes.md) | Deterministic CBOR profile; hash exact stored bytes |
| [0006](0006-sha256-domain-separation.md) | SHA-256 with length-prefixed domain-separation tags |
| [0007](0007-rfc9162-merkle-no-duplication.md) | RFC 9162 Merkle; reject last-leaf duplication |
| [0008](0008-one-chain-per-tenant-risk-triggered-sealing.md) | One chain per tenant; risk-triggered sealing; separate risk queues rejected |
| [0009](0009-critical-pre-action-anchoring.md) | CRITICAL pre-action anchoring gate |
| [0010](0010-approval-binding.md) | Approval binding, single use |
| [0011](0011-no-auto-retry-outcome-unknown.md) | No auto-retry for non-idempotent tools; OUTCOME_UNKNOWN |
| [0012](0012-envelope-encryption-random-dek.md) | AES-256-GCM random per-event DEK + KEK (reject HKDF hierarchy) |
| [0013](0013-salted-payload-commitments.md) | Salted payload commitments |
| [0014](0014-append-only-onchain-registry.md) | Append-only on-chain registry; Anvil / Base Sepolia; anchor states |
| [0015](0015-phase1-agent-auth-api-key.md) | Phase 1 agent auth: hashed per-agent API key |
| [0016](0016-monorepo-layout-and-tooling.md) | Monorepo layout and tooling |
| [0017](0017-ciphertext-in-postgres.md) | Ciphertext in Postgres; MinIO for large blobs and bundles |
| [0018](0018-seq-allocation-chain-head-lock.md) | Per-tenant seq via chain-head row lock |
| [0019](0019-monitoring-stream-system-tenant.md) | Monitoring stream as a system tenant chain |
| [0020](0020-phase1-dispatch-args-in-outbox.md) | Phase 1 dispatch args in `outbox_jobs.args` (cleared on completion; replaced in Phase 5) |
| [0021](0021-own-agw-cbor-codec.md) | Hand-written AGW-CBOR-v1 codec (cbor2 decoder accepts non-canonical input) |
| [0022](0022-chain-heads-table.md) | Chain head in `chain_heads`, SELECT … FOR UPDATE (supersedes ADR-0018's mechanism) |
| [0023](0023-agw-evt-v1-header-finalized.md) | AGW-EVT v1 / AGW-PAY v1 as implemented in Phase 2 (obs, cg, payload.ref, code.agent) |
| [0024](0024-phase2-payload-store-export-events-api.md) | Phase 2 plaintext payload store, operator-only export, scoped `/v1/events` |
| [0025](0025-phase3-epochs-membership-proofs-receipts.md) | Phase 3: derived epoch membership, on-demand proofs, EPOCH_SEALED receipts, sealer locking, 300 s max-age |
| [0026](0026-phase4-risk-engine-adaptive-sealing.md) | Phase 4: risk policy as data (TOML → digest), risk-v2 factors, policy-v2 (CRITICAL deny unless exception), risk-adaptive sealing, metrics |
| [0027](0027-phase5-action-bound-human-approval.md) | Phase 5: action digest, approvals + single-use nonces, separate human auth, gateway-signed decisions, one-tx revalidation (supersedes parts of 0010) |
| [0028](0028-phase6-blockchain-anchoring.md) | Phase 6: EpochAnchor.sol (recorderId, write-once contiguous epochs, seq tiling), write-ahead anchor worker, CRITICAL pre-action gate, chain-pinned verifier (supersedes parts of 0014 and 09 §7) |
| [0029](0029-phase7-encryption-disclosure.md) | Phase 7: AES-256-GCM per-event DEKs (CBOR AAD), local/Vault KEK providers, MinIO blobs, field classification + redaction, sealed operational args, HPKE disclosure grants, retention/erasure, re-encryption migration, rotation (supersedes parts of 07, 0017) |
| [0030](0030-phase8-delegation-integrations.md) | Phase 8: Ed25519/CBOR delegation tokens (chain intersection, revalidated at use, consumed per link), DELEGATION_CREATED/REVOKED + hash-linked child requests, typed SDK, LangGraph + MCP (2026-07-28) adapters, RFC 8693 exchange for audience-bound MCP tokens, real HTTP/SMTP adapters, containment networks, injection corpus |
