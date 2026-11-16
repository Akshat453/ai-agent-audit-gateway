# 03 — Threat Model

Status: Accepted (Phase 0). Sources: Paper A §2, §3 (*Authenticity and authorized anchoring*),
§8; Paper B §II-C, §VIII-A, §VIII-C.

## 1. Assets

| ID | Asset | Property needed |
|---|---|---|
| AS1 | Controlled tools and the systems behind them | Only authorized, approved actions reach them (enforcement) |
| AS2 | Lifecycle evidence (records, chain, epochs) | Integrity, ordering, completeness within the gateway |
| AS3 | Event payloads (tool args, results, approval prompts) | Confidentiality, selective disclosure, erasability |
| AS4 | Agent credentials, approval tokens | Unforgeability, single use |
| AS5 | KEK / DEKs | Confidentiality |
| AS6 | Anchor signer key | Exclusive control (otherwise forged/blocked anchors) |
| AS7 | Policy documents and versions | Integrity, attributable versioning |

## 2. Assumptions

1. The anchoring chain stays available and immutable after finality (Paper B §II-C, assumption 1).
2. The verifier's software and its RPC view of the chain are not compromised (Paper B §II-C, assumption 2). A verifier SHOULD cross-check two independent RPC providers.
3. An off-host copy of the evidence exists (exported bundles / DB replica) for anything that must survive host loss (Paper B §II-C, assumption 3; §VIII-A(3)).
4. Agents have **no** direct network route or credentials to controlled tools. This is a
   deployment control, and the gateway's enforcement claim depends on it.
5. The Postgres superuser and the `agw_migrator` role are operated by people other than the
   people who operate agents (separation of duties, Paper A §3).
6. Wall-clock timestamps are informational. Order comes from `seq`, and time upper bounds come
   from anchors (Paper A §4).

## 3. Adversaries

| ID | Adversary | Capabilities |
|---|---|---|
| ADV1 | Malicious or prompt-injected agent | Arbitrary requests with its own valid credential: unknown tools, malformed args, spoofed `agent_id`, replays, concurrency races |
| ADV2 | External attacker without credentials | Network access to the API |
| ADV3 | Insider with DB write access (app role or DBA) | Edit/delete/reorder evidence rows, forge rows |
| ADV4 | Compromised gateway host from time `t_c` | Everything ADV3 can do, plus suppress capture, write false new entries, withhold or delay anchors, equivocate (Paper B §II-C) |
| ADV5 | Malicious operator in a dispute | Present different histories to different verifiers (fork), delay anchoring strategically (Paper B §VIII-A(6)) |
| ADV6 | Compromised or faulty tool | Wrong results, hangs, partial side effects |
| ADV7 | Chain-level adversity | Reorgs, congestion, sequencer downtime (Paper B §IV-A) |

## 4. Attacks and controls

| # | Attack | Adversary | Control | Where | Verified by |
|---|---|---|---|---|---|
| T1 | Call a tool without valid credential | ADV2 | Bearer key, SHA-256 digest lookup, constant-time compare. 401 with no events except auth-failure counters. | ADR-0015 | Phase 1 test: 401, no ACTION_DISPATCHED |
| T2 | Spoof another agent via body `agent_id` | ADV1 | Identity only from the credential. Mismatch → 403 + `SECURITY_VIOLATION` event. | 11 §3 | Phase 1 test |
| T3 | Call an unregistered tool or a tool outside scope/env | ADV1 | Deny by default. Registry lookup. Scope + environment checks before policy rules. | ADR-0001 | Phase 1 tests + Hypothesis |
| T4 | Malformed / injected args | ADV1 | Pydantic models with `extra="forbid"` and strict types. Failure → DENY, recorded, never executed. | 04 §3 | Phase 1 tests |
| T5 | LLM-manipulable authorization | ADV1 | No LLM in allow/deny. Policy is pure deterministic code. | ADR-0002 | Code review + import-linter (no LLM SDK in `policies`/`risk`) |
| T6 | Duplicate execution via retries or races | ADV1 | Idempotency key unique per agent. Same body → replay. Different body → 409. 20 concurrent → 1 action. | 08 §5 | Phase 1 test |
| T7 | Approval replay / approve one thing, execute another (Paper A §2) | ADV1 | Approval binds the action digest (agent, tool+version, args digest, target, env, policy version + digest, risk, delegation); single-use nonce; expiry by DB time; digest + nonce echo; revalidation in one tx. Any change → new action + new approval. | ADR-0010, ADR-0027 | Phase 5 attack suite A1–A13 (`test_approval_attacks.py`) |
| T8 | Side effect without durable record | ADV4 (crash) | ACTION_AUTHORIZED + outbox in one tx. DISPATCHED committed before the adapter call. | ADR-0004 | Phase 1 crash-hook test |
| T9 | Double side effect after ambiguous crash | ADV6 / crash | No auto-retry for non-idempotent tools → OUTCOME_UNKNOWN → reconciliation | ADR-0011 | Phase 1 test |
| T10 | Edit / delete evidence rows | ADV3 | (a) REVOKE UPDATE/DELETE/TRUNCATE from `agw_app`. (b) Trigger raising on UPDATE/DELETE + statement trigger on TRUNCATE. (c) Phase 2+: hash chain. (d) Phase 3+: Merkle. (e) Phase 6+: anchor. | 08 §2, 06 | Phase 1 DB tests. Phase 8 tamper experiments. |
| T11 | Reorder events | ADV3 | `seq` + `prev_event_hash` chain. Leaves ordered by seq. | 06 §4 | Phase 8 |
| T12 | Delete the newest events (tail truncation) | ADV3/4 | Sealed: the epoch root binds `last_seq` and the anchor commits it. **Unsealed tail: not detectable** until sealed (see R2). | 09 | Phase 8 |
| T13 | Delete a whole epoch | ADV3/4 | `R_t` includes `R_{t-1}`. The contract requires contiguous epoch numbers and a matching back-pointer. | 06 §7, 09 §7 | Phase 8 |
| T14 | Equivocation / fork (Paper B §II-C) | ADV5 | One anchor per `(tenant, epoch)` on-chain, so a second history can't be anchored by the authorized submitter. Verifiers compare against chain state. | 09 §7 | Phase 8 fork experiment |
| T15 | Merkle ambiguity (odd leaf count) | ADV3 | RFC 9162 tree, no duplication. `tree_size` bound in `R_t`. | ADR-0007 | Phase 3 vectors |
| T16 | Cross-type hash confusion (event vs node vs payload) | ADV3 | Length-prefixed domain tags. RFC 9162 0x00/0x01 prefixes. | ADR-0006 | Phase 2/3 tests |
| T17 | Cross-tenant splicing (reuse an event/epoch of tenant X for Y) | ADV3 | Tenant id inside event record, epoch root and on-chain tenant key | 06 | Phase 8 |
| T18 | Guess payload content from its digest | anyone with records | 32-byte random salt in every payload | ADR-0013 | Phase 7: salted payloads + DB-only-attacker dump test (`test_db_only_attacker_cannot_read_payloads`). Residual: the header args digest is unsalted (ADR-0029 Consequences) |
| T19 | Payload ciphertext swap between events | ADV3 | AAD binds tenant, event_id, seq, payload_digest, schema version; the DEK wrap binds the event. Decrypted plaintext must hash to the committed digest. | 07 §3, ADR-0029 | Phase 7: `test_ciphertext_swap_between_events_fails`, `test_grant_for_x_cannot_open_y_in_the_same_epoch` |
| T20 | Anchor forgery by others / spam | anyone on-chain | Contract: only the registered submitter per tenant key can anchor | 09 §7 | Phase 6 forge tests |
| T21 | Strategic anchoring delay (Paper B §VIII-A(6)) | ADV5 | `max_age` seal trigger. CRITICAL dispatch blocked without anchor. Monitoring stream alerts on overdue epochs. | 09 | Phase 8 |
| T22 | Reorg removes an anchor after "inclusion" | ADV7 | Separate included/finalized states. Re-submit on reorg. CRITICAL gate waits for configured finality. | 09 §6 | Phase 6 Anvil reorg test |
| T23 | DB unavailable → bypass | infra | Fail closed: 503, nothing executes, since the executor needs the DB to claim jobs | 08 §6 | Phase 1 test |
| T24 | Secrets or args leak via errors/logs | ADV1/2 | Uniform error model. Args never echoed. Structured logs with an allow-list of fields. Phase 7: secret fields redacted everywhere, unvalidated args not stored. | 11 §2, ADR-0029 | Phase 7 canary test across logs/metrics/errors/headers (`test_canary_never_leaks`) |
| T25 | Compromised runtime anchors a benign substitute (Paper A §3) | ADV4 | **Not prevented.** Partially mitigated: the gateway, not the agent, captures; identity is bound before hashing; DB roles are separated. Future: signed records, TEE attestation (Paper B §VIII-A(1)). | 13 | — |

## 5. Security invariants (numbered, referenced by tests)

- **INV-1** No adapter is invoked for an unauthenticated request.
- **INV-2** No adapter is invoked unless the tool is registered, the args validate, and the decision is ALLOW (or REQUIRE_APPROVAL followed by a valid bound approval, Phase 4).
- **INV-3** An adapter is invoked only after `ACTION_AUTHORIZED` and the DISPATCH outbox row are committed, and after `ACTION_DISPATCHED` is committed.
- **INV-4** `evidence_events` rows can't be updated, deleted or truncated by `agw_app`, and a trigger rejects UPDATE/DELETE/TRUNCATE for every role that doesn't disable triggers.
- **INV-5** For each agent, an idempotency key maps to at most one action.
- **INV-6** A non-idempotent tool is invoked at most once per action.
- **INV-7** The authenticated agent identity is the only identity recorded for an action.
- **INV-8** (Phase 2) For each tenant, `seq` is gap-free and `prev_event_hash(seq) = event_hash(seq-1)`.
- **INV-9** (Phase 3) Every event with `seq < sealed_up_to` belongs to exactly one epoch, and epochs tile the seq range without overlap.
- **INV-10** (Phase 6; implemented, ADR-0028 §5) A CRITICAL action is never dispatched unless the epoch containing its `ACTION_AUTHORIZED` has reached the configured finality. Tests: `test_critical_pre_anchor_released_only_after_finality`, `test_critical_pre_anchor_rpc_down_fails_closed` (adapter calls 0) and `test_gate_release_and_timeout_exactly_one_wins`.
- **INV-11** (Phase 5, ADR-0027) An approval authorizes at most one dispatch, and only for the exact bound action digest.

## 6. Residual risks (accepted, documented)

| ID | Risk | Why accepted / mitigation path |
|---|---|---|
| R1 | Post-compromise entries are untrustworthy (Paper B §II-C). | Fundamental. Anchoring frequency bounds the window. |
| R2 | **Unsealed tail**: events after the last sealed epoch can be truncated or edited by ADV3/4 without detection by a verifier. | Window ≤ `max_age` (default 60 s) or `max_events`. HIGH/CRITICAL events seal immediately. Off-host replica (assumption 3). |
| R3 | Capture completeness beyond the gateway (side channels, Paper B §VIII-A(4); Paper A §8). | Network isolation (assumption 4). TEE attestation is future work. |
| R4 | Data availability of payloads and proofs is not guaranteed by the chain (Paper B §III-D). | Export bundles to MinIO and off-site. Verifier reports INCOMPLETE, not VERIFIED, when material is missing. |
| R5 | Anchor signer key compromise lets the attacker anchor arbitrary roots, or anchor first to block the honest root. | Per-deployment key. Owner can rotate the submitter. Monitoring compares DB roots with chain roots (Phase 8). HSM/KMS later. |
| R6 | L2 sequencer centralization (Paper B §IV-A). | Finality tracked explicitly. L1 force-inclusion is out of scope. |
| R7 | Semantic truth: a correctly recorded tool result can still be false (Paper A §2, §8). | Out of scope by design. Stated in every verifier report. |
| R8 | The DB superuser can disable triggers. | Separation of duties (assumption 5). Hash chain + anchors detect the result for sealed data. |
