# 01 — Source Analysis: Paper A and Paper B

Status: Accepted (Phase 0). This document records only what the papers actually say, with
section citations. Where we go further, it is labelled **Ours**.

## 1. Paper A — Brömme, "A Black Box for Agentic Processes" (arXiv:2609.04017v1)

**Nature.** A position and architecture paper. It states that it "does not present an empirical
performance or security evaluation" (Abstract) and that §7's scenario "does not represent an
implemented evaluation". So it offers design guidance, not measured findings.

| What Paper A says | Where | How we use it |
|---|---|---|
| Hash anchoring supports an *existence and integrity proof*. It does not prove authorship, authorization, truthfulness or correctness. | §2; restated §8 | Adopted verbatim as our claim boundary (README; 03; 10). |
| Threats: log alteration or deletion; incomplete A2A capture; unauthorized channels; spoofed or manipulated tool-call records; unclear HITL approvals; **mismatch between approved and executed action**; loss of intermediate artifacts. | §2 | Each becomes a row in [03-threat-model.md](03-threat-model.md). "Approved ≠ executed" motivates approval binding (ADR-0010). |
| Pipeline Capture → Canonicalize → Hash → Anchor → Certify → Verify. Canonicalization is "security-relevant rather than merely technical". | §3 | Adopted as the evidence pipeline (02 §4). Canonicalization becomes a versioned, test-vectored profile (ADR-0005). |
| JCS (RFC 8785) as an *example* canonical form for JSON. | §3 | **Changed**: we use deterministic CBOR (from Paper B). Paper A presents JCS only as an example and requires "equivalent normative representations" for every type. A single binary profile satisfies that with fewer edge cases (no floats, byte strings native). |
| Minimal event object with `policy_id`, `control_id`, `artifact_hash`, `context_hash`, `approval_ref`, `tool_ref`. | §3 | `policy_id`/`policy_version`/`rule_ids` and `control_ids` are first-class event fields (05). |
| SHA-512 used "illustratively"; SHA-256 explicitly not claimed unsuitable. | §3, footnote 1 | **Changed**: SHA-256 (ADR-0006), consistent with Paper B and RFC 9162. The paper itself says the choice should weigh "intended security lifetime". Revisit via ADR if retention exceeds the SHA-256 lifetime. |
| Three interaction classes: agent–agent, agent–human, agent–system. | §3 | Our `evidence_class` field: `A2A`, `A2H`, `A2S`, plus `SYS` for gateway-internal events (05). The abbreviations are **Ours**. |
| Merkle-batch high-volume events, anchor only the root, keep inclusion proofs off-chain. | §3 | Adopted (06, 09). |
| Data minimization: only hashes/commitments external; sensitive content stays in controlled storage. | §3 | Adopted: only 32-byte roots + minimal metadata on-chain (ADR-0014); payloads encrypted off-chain (07). |
| *Authenticity and authorized anchoring*: a compromised runtime or controller "could suppress the actual communication and anchor a benign substitute record". Bind events to authenticated identities **before** hashing. Make anchoring attributable to authorized components. Suggested controls: signed records, HW keys, role-based anchoring permissions, separation of duties, append-only buffers, independent monitoring. | §3 | Agent identity comes only from the credential (ADR-0015). The anchoring contract restricts submitters per tenant (09 §7). Separation of DB roles (08). Signed records and HW keys are future work (13). |
| Anchor time is when the commitment obtains verifiable inclusion and, where applicable, finality. The digest existed *no later than* that time. On-chain order ≠ workflow order. | §4 | We track `submitted`/`included`/`finalized` separately (ADR-0014). Ordering comes from our `seq`, never from chain order. |
| Stricter reconstruction "should use an evidence controller or audit gateway that assigns sequence numbers, applies policy checks, links events by hash". | §4 | This *is* our system: an active gateway (ADR-0001) with per-tenant `seq` (ADR-0008). |
| GRC mappings (human oversight, policy conformance, tool control, segregation of duties, incident analysis, audit readiness). | §5, Table 1 | Mapped to concrete verifier checks in 10 §3. |
| **Risk-based evidence selection**: routine communication "may be retained locally and included in periodic Merkle batches", while high-impact events "may require immediate or individual anchoring". | §5 | **Adopted with a deliberate interpretation**: risk changes *when* an epoch is sealed and anchored, never *whether* an event enters the chain (ADR-0008). Leaving routine events out of the chain would create gaps the verifier can't detect. |
| **Monitoring evidence stream**: verification reports are themselves hashed and anchored as a separate stream. | §5 | Adopted as a separate system security domain with its own chain (ADR-0019, Phase 8). |
| EU AI Act, NIS2, CRA readiness. The architecture is "not a compliance engine". | §6 | Out of scope for code. We make no compliance claims. |
| Limitations: integrity ≠ truth; value depends on capture completeness; identity, authz, ordering and time are surrounding-system concerns; key management, retention, deletion. | §8 | Each one is addressed or carried as residual risk in 03 §6. |

## 2. Paper B — Bindschaedler, Botha, Siebenbrunner, "Agent Flight Recorder" (arXiv:2609.01931v1)

**Nature.** A ~1,500-line Python prototype and a ~30-line Solidity contract (§V). The primary
evaluation uses **synthetic** workloads. RQ1 is validated on 5 real SWE-agent traces (38
events), and RQ2 gas is measured from 100 Base Sepolia transactions (§VI-B). RQ3/RQ4 are
single deterministic runs (§VIII-C).

| What Paper B says | Where | How we use it |
|---|---|---|
| Adversary compromises the agent host at time `t_c`. Operations: **edit, delete, reorder, equivocation (fork)**. After full compromise, new entries can't be trusted (Schneier–Kelsey boundary). | §II-C | Adopted as attack classes and as the post-compromise boundary (03). |
| Assumptions: on-chain roots available and immutable; verifier keys and watchers not compromised; an off-host copy of the log exists. | §II-C | Carried as explicit assumptions (03 §2). |
| Non-goal: completeness. "Guarantees integrity of recorded events, not that all events reach the recorder." | §III-A | **Ours strengthens part of this**: as an *active* gateway, a controlled tool's credentials are held only by the gateway, so bypass requires breaking enforcement, not just skipping a log call (03 §4). Completeness against side channels remains out of scope. |
| Eight semantic fields: intent, policy evaluation, human approval, execution, effects, context provenance, code provenance, delegation provenance. Intent excludes raw chain-of-thought. | §III-B | Adopted. Mapped onto lifecycle events (05 §4). We also exclude chain-of-thought. |
| Approval field "should carry a cryptographic signature or token binding the approver's identity to the specific action". | §III-B (3) | Adopted as approval binding (ADR-0010). Signatures come in Phase 4+. |
| Deterministic CBOR (RFC 8949 §4.2), with all hashes over the canonical byte sequence. | §III-B | Adopted, plus our rule "hash the exact stored bytes" (ADR-0005). |
| Event payloads (sensitive) vs event records (fixed metadata + payload hash). Integrity structures operate on records. | §III-C | Adopted: the record commits to `payload_digest` (06 §5). |
| Layer 1 hash chain `e_i.prev = H(e_{i-1})`. Single-writer path. Monotonic counter + optional concurrency-group tag. | §III-C, §V | Adopted: per-tenant `seq` and `prev_event_hash`. A row lock on the tenant chain head is the single writer (ADR-0018). |
| Layer 2 Merkle: "When the leaf count is not a power of two, the implementation duplicates the last leaf." | §III-C | **Rejected** (ADR-0007): the root becomes ambiguous (06 §6.4). |
| Epoch root `R_t = H(M_t ∥ R_{t-1})`, `R_0 = H(M_0 ∥ 0^32)`. Only `R_t` goes on-chain. Gap detection via back-pointer. | §III-C | **Adopted and extended**: domain tag, tenant, epoch number, tree size and seq range are bound into `R_t` (06 §7). |
| Verification without disclosure (proof → root → anchor → continuity) and with disclosure (decrypt → check payload hash). Outputs verified / tampered / incomplete. | §III-D, §V | Adopted for the verifier (10). |
| "If two anchors claim the same epoch number under that identity, the earlier-included transaction is canonical." | §III-D | **Changed**: our contract *refuses* a second anchor for the same `(tenant, epoch)` and requires contiguous epochs and a matching back-pointer (09 §7). |
| Data availability of payloads and proofs is separate from and not guaranteed by anchoring. | §III-D, Table I note | Adopted: evidence bundles and MinIO exports (10 §2). Listed as residual risk. |
| HKDF hierarchy `K_t = HKDF(master, epoch_id)`, `k_{t,i} = HKDF(K_t, event_id)`. Limitation: whoever obtains `K_t` derives all event keys of the epoch. Crypto-erasure needs destroying epoch-key material. | §III-E, §VIII-B | **Rejected** in favour of random per-event DEKs wrapped by a KEK (ADR-0012). This allows per-event erasure, and the compromise of one key reveals one event. |
| Anchor stores `R_t` and `H(R_{t-1})`, msg.sender, epoch number, block timestamp. | §IV-A | Adapted: we store `R_{t-1}` itself (no reason to hash a public 32-byte value), plus the tenant key (09 §7). |
| Anchor frequency trades cost for compromise-window width. L2 sequencer risk; force inclusion. | §IV-A | Adopted as a tunable (`max_events`, `max_age`) plus risk-triggered sealing (09). |
| Table II: Full stack median ≈ 48 µs/event, 512 B/event (synthetic, N = 10K, Apple M-series, Python 3.11). | §VI-C | **Not assumed** for our system. We have a DB transaction per event, which will dominate. Experiments re-measure this (10 §5). |
| Gas: mean 91,800 per `anchor()` on Base Sepolia (100 txs). L2 cost $2.30 per 100K events at 100-event epochs (projected at 0.01 gwei, ETH = $2,500). | §VI-D, Table III | Used as an order-of-magnitude prior only. Our contract stores more (tenant key, back-pointer check), so gas will differ, and we will measure it. |
| Tamper detection (Table IV): Chain catches edit/delete 90% (it misses the final event), Merkle 100%, fork detected only with anchoring, using a separate recorder. | §VI-E | Our experiments reproduce the four classes and add more (10 §4). The "unsealed tail" window remains and is stated honestly (03 §6). |
| Limitations: completeness, post-compromise truth, payload recovery, side channels, anchoring availability, **strategic anchoring delay**. | §VIII-A | Each is carried into 03. Strategic delay is mitigated by `max_age` plus the monitoring stream (Phase 8). |
| Threats to validity: synthetic workloads, experimenter-defined queries, "reorg/finality edge cases". | §VIII-C | Our anchoring states model reorgs explicitly (09 §6). |

## 3. Gaps neither paper closes (addressed by Ours)

1. **Enforcement.** Both papers record. Neither *prevents*. Paper A §2 says prevention "still
   depends on secure architecture, access control, ... policy enforcement". We add the active
   gateway, deny-by-default policy and outbox-gated dispatch (ADR-0001, 0002, 0004).
2. **Pre-execution durability.** Neither paper specifies whether the authorization record is
   durable *before* the side effect. We require `ACTION_AUTHORIZED` + outbox job to commit in
   one Postgres transaction before dispatch (ADR-0004). For CRITICAL actions, the authorization
   must also be anchored to the configured finality before dispatch (ADR-0009).
3. **Ambiguous outcomes.** Neither paper handles crashes between dispatch and result. We add
   `ACTION_OUTCOME_UNKNOWN` and reconciliation, with no auto-retry for non-idempotent tools
   (ADR-0011).
4. **Payload-digest hiding.** Paper B commits to `H(payload)`. For low-entropy payloads (e.g.
   `{"record_id": 42}`) that digest can be brute-forced from public or leaked records. We salt
   every payload (ADR-0013).
5. **Tree-size binding.** An RFC 9162 inclusion proof alone does not uniquely determine
   `tree_size`. In our check, the proof for leaf 0 of a 5-leaf tree also verifies when the
   claimed size is 6, 7 or 8. We bind `tree_size`, `first_seq` and `last_seq` into the epoch root (06 §7).
6. **Multi-tenant domain separation.** Neither paper defines tenants. We have one chain per
   tenant, and the tenant is bound into every hash and anchor (ADR-0008).
