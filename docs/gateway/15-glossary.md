# 15 — Glossary

One definition per term, in alphabetical order. State terms (*captured* … *verified*) are
ordered evidence states. Each implies all earlier ones: **captured → durably stored → chained →
sealed → submitted → included → finalized → exported → verified**.

| Term | Definition |
|---|---|
| **A2A / A2H / A2S / SYS** | Evidence classes: agent–agent, agent–human, agent–system interactions (Paper A §3), and gateway-internal system events (ours). |
| **Ablation** | An experiment configuration that adds integrity layers cumulatively (Paper B §VI-B) to attribute overhead and detection to each layer. |
| **Action** | One proposed tool call by one agent, identified by `action_id`. Its operational row in `actions` is mutable. Its history is the immutable lifecycle events. |
| **Active gateway** | A component on the execution path that can block a call before it reaches a tool, as opposed to a passive recorder. |
| **Adapter** | The registered code that actually invokes a tool. Only the gateway holds adapters and tool credentials. |
| **Anchor** | An on-chain record `(tenantKey, epochNo, R_t, R_{t−1})` in the AnchorRegistry contract. |
| **Anchored** | Shorthand for an epoch whose anchor transaction is at least *included*. Always say which finality level is meant. |
| **Anchor time** | The time a commitment obtains verifiable inclusion and, where applicable, finality (Paper A §4). The commitment existed no later than this time. |
| **ANCHOR_TIMEOUT** | The failure reason when a CRITICAL action's authorization anchor doesn't reach configured finality before its deadline. The action fails with no side effect. |
| **Approval binding** | The tuple (agent, tool+version, args digest, target, policy version, action, expiry, nonce) that a human approval authorizes, and nothing else (ADR-0010). |
| **Args digest** | `H(TAG("AGW/args/v1") ‖ cbor(validated_args))`. |
| **Audit path** | The sibling hashes from a leaf to the Merkle root (RFC 9162 §2.1.3). |
| **Captured** | An event has been constructed by the gateway from authenticated inputs but is not yet committed. Not durable. |
| **Chained** | An event has `canonical_bytes` and a `prev` equal to its predecessor's `event_hash` (Phase 2+). |
| **Canonical bytes** | The unique AGW-CBOR-v1 encoding of an event record, stored once and hashed exactly as stored. |
| **Compromise window** | The period during which recorded but not yet anchored evidence can be rewritten without public detection (Paper B §IV-A, Table III). |
| **Control id** | A GRC control identifier attached to a policy rule and recorded in `POLICY_EVALUATED` (Paper A §3, §5). |
| **CRITICAL gate** | The rule that a CRITICAL action's `ACTION_AUTHORIZED` is sealed into its own epoch and anchored to configured finality before dispatch (ADR-0009). |
| **Crypto-erasure** | Making a payload unrecoverable by destroying its DEK, while the chain stays intact. |
| **DEK** | Data Encryption Key: a random 256-bit AES-GCM key for exactly one payload. |
| **Deny by default** | Absent an explicit ALLOW, and after all system checks pass, the decision is DENY. |
| **Deterministic CBOR** | RFC 8949 §4.2.1 core deterministic encoding, here restricted by the AGW-CBOR-v1 profile (05 §6). |
| **Dispatched** | `ACTION_DISPATCHED` is committed. The adapter call may now happen or may have happened. |
| **Domain separation** | Prefixing every hash input with a type-specific, length-prefixed tag (or the RFC 9162 0x00/0x01 bytes), so different structures can never hash-collide by type. |
| **Durably stored** | The event's transaction has committed in PostgreSQL. It survives a process crash. |
| **Epoch** | A contiguous seq range `[first_seq, last_seq]` of one tenant's chain, sealed into one Merkle tree and one epoch root. |
| **Epoch header** | `{tenant, epoch_no, tree_size, first_seq, last_seq, M_t, R_{t−1}, R_t, sealed_at, seal_reason}`. |
| **Epoch root (`R_t`)** | The chained commitment defined in 06 §7. Binds tenant, epoch number, size, seq range, Merkle root and the previous root. |
| **Equivocation (fork)** | Presenting different histories that share a common prefix to different verifiers (Paper B §II-C). |
| **Event hash** | `H(TAG("AGW/event/v1") ‖ canonical_bytes)`. |
| **Event record** | The non-sensitive, hashed part of an event (05 §4). Contrast with *payload*. |
| **Evidence bundle** | The exported, self-contained set of records, headers, proofs, anchor refs and optional disclosed keys for third-party verification (10 §2). |
| **Exported** | Evidence has been written to a bundle outside the live DB. |
| **Finalized** | The anchor's block is at or below the chain's `finalized` block tag. A reorg can no longer remove it under the chain's finality rules. |
| **Idempotency key** | A client-chosen key making `POST /v1/actions` safe to retry. At most one action per (agent, key). |
| **Idempotent tool** | A tool whose adapter can safely be re-invoked with the same `idempotency_token` after an ambiguous outcome. |
| **Included** | The anchor transaction has a successful receipt in a block on the current canonical chain. A reorg may still remove it. |
| **Inclusion proof** | `{tenant, epoch_no, tree_size, leaf_index, audit_path[]}`, proving an event hash is a leaf of `M_t`. |
| **KEK** | Key Encryption Key: wraps DEKs. Local file in dev, KMS later. |
| **Leaf input / leaf hash** | Leaf input = the event's `event_hash`. Leaf hash = `H(0x00 ‖ leaf_input)`. |
| **Lifecycle event** | An immutable evidence row recording one step of an action (05 §3). |
| **Mandatory rule** | A risk rule that sets a minimum risk level regardless of the numeric score (04 §2.2). |
| **Merkle root (`M_t`)** | RFC 9162 Merkle Tree Hash over an epoch's leaf inputs. |
| **Monitoring evidence stream** | Verification reports appended to the `_monitor` tenant chain (Paper A §5). |
| **Outbox job** | A row in `outbox_jobs`, committed in the same tx as the evidence that justifies it. It is the source of truth for dispatch, sealing and anchoring work. |
| **OUTCOME_UNKNOWN** | The state of an action whose adapter call may or may not have taken effect. Never auto-retried for non-idempotent tools. |
| **Payload** | The sensitive content of an event (args, results, prompts). Salted, encrypted, committed via its digest. |
| **Payload digest** | `H(TAG("AGW/payload/v1") ‖ plaintext_payload_cbor)`. |
| **Policy version** | An immutable `(policy_id, version)` row. Decisions record the exact version used. |
| **Reconciliation** | Resolving an OUTCOME_UNKNOWN action by an adapter probe or a human, recorded as `ACTION_RECONCILED`. |
| **Risk level** | LOW < MEDIUM < HIGH < CRITICAL. Computed deterministically (04 §2). |
| **Safe** | The anchor's block is at or below the chain's `safe` block tag. Weaker than finalized. |
| **Sealed** | An event is a leaf of an epoch whose header and `R_t` are committed in the `epochs` table. |
| **Security domain / tenant** | The unit with exactly one hash chain and one epoch sequence. |
| **Selective disclosure** | Revealing the DEKs of chosen events only. Others stay confidential. |
| **Seq** | A per-tenant, gap-free, commit-ordered sequence number starting at 0. The only ordering source. |
| **Submitted** | The anchor transaction has been broadcast and its hash is known. Not yet in a block. |
| **Tamper-evident** | Modification is detectable by verification. Not the same as tamper-proof. |
| **Tenant key** | `H(TAG("AGW/tenant-key/v1") ‖ u16(len) ‖ tenant)`. The on-chain identifier of a tenant. |
| **Tree size** | The number of leaves in an epoch. Bound into `R_t` because an inclusion proof alone doesn't fix it (06 §6.3). |
| **Unsealed tail** | Committed events after the last sealed epoch. Not yet protected by Merkle or anchor (residual risk R2). |
| **Verified** | The verifier recomputed all applicable checks (10 §3) and every one passed. This means unchanged since anchoring and correctly ordered. It does **not** mean truthful, authorized, complete or correct. |
