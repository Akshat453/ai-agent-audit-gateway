# Phase 5: Action-bound human approval

Status: **Done**, 2026-11-15.

Goal: a REQUIRE_APPROVAL action executes only after a valid, authenticated, single-use, unexpired human decision bound to that exact action.

Decisions are in [ADR-0027](../adr/0027-phase5-action-bound-human-approval.md). It supersedes the binding layout of ADR-0010 and its "policy change invalidates" rule.

> **Claim boundary.** A decision signature is made with a **gateway-held** Ed25519 key. It proves the gateway attested that a session-authenticated approver decided about this exact action digest and nonce. It does **not** prove that a human held a private key; WebAuthn/passkeys are the future option. Approval evidence, like all evidence, says what was decided, not that the decision was wise.

## 1. What changed

| Area | Files |
|---|---|
| Action digest and decision record (pure) | `agw_gateway/approvals/binding.py`:<ul><li>`ActionBinding.digest()` (`AGW/action/v1`);</li><li>`policy_digest()` over the stored policy JSON (`AGW/policy/v1`);</li><li>`target_resource()`;</li><li>`DecisionRecord.digest()` (`AGW/approval-decision/v1`);</li><li>`signing_message()` (`AGW/approval-sig/v1`);</li><li>`render_args()`: sorted keys, ASCII only, so invisible characters show as `\uXXXX`.</li></ul>Added to the purity import contract. |
| Signing key | `approvals/signing.py`: `DecisionSigner` loads a 32-byte hex seed file, `verify_decision`, `generate_key_file` (mode 0600, never overwrites). Admin `gen-signing-key`; `make dev-keys`; `secrets/` is git-ignored. |
| Workflow | `approvals/service.py`:<ul><li>`NewApproval` (created in tx1);</li><li>`ApprovalService.list_approvals / get / decide / authorize / sweep`;</li><li>`record_agent_on_human_endpoint`.</li></ul>Lock order: approval → action → chain head. |
| Human identities | `agw_gateway/humans/`: `AuthenticatedHuman`, roles approver/admin/auditor; `HumanAuthenticator` (Argon2id, `agws_` session tokens stored as digests, `Authorization: Session`); `HumanIdentityProvider` protocol (the OIDC seam). Admin `create-human` (password from env or prompt, never argv). `seed-demo` creates alice and bob (approvers) and audrey (auditor) when `AGW_DEMO_APPROVER_PASSWORD` is set. |
| Request path (tx1) | `execution/service.py`:<ul><li>computes the action digest before tx1 for every valid action;</li><li>stores `action_digest`, `delegation_depth` and `risk_policy_digest`, plus `request_args` while approval is pending;</li><li>creates the approval row;</li><li>APPROVAL_REQUIRED carries `approval{id, binding, exp, req}` and is sealed as ≥ HIGH;</li><li>the response includes `approval{approval_id, required_approvals}`.</li></ul>`policy_store.py` (moved out of `policies/` for purity) returns the stored document together with the model. |
| API | `api/approval_routes.py`: `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/approvals`, `GET /v1/approvals/{id}`, `POST /v1/approvals/{id}/decision`, `GET /v1/approvals-signing-keys`. An agent key on these gets 403 and a recorded violation. `GET /v1/actions/{id}` adds `approval{…}` (never the nonce) and `?wait=N` long-poll. The timeline shows approval fields. New error codes are listed in `api/errors.py`. |
| Evidence | `agw_schemas.events`: the `Approval` map is defined (+ `ApprovalDecisionRef`, `Bytes64`). APPROVAL_GRANTED, APPROVAL_DENIED and APPROVAL_EXPIRED are writable (`MODEL_ONLY_TYPES` is empty). `Violation.kind` gains `AGENT_ON_HUMAN_ENDPOINT`. `evidence/records.py` shares the POLICY_EVALUATED builder. |
| DB | Migration `0005_phase5_approvals.py` adds:<ul><li>`humans` and `human_sessions`;</li><li>`approvals` (column-level UPDATE grant: `state`, `state_reason`, `updated_at` only);</li><li>`approval_decisions`, `approval_uses` and `approval_signing_keys`, all append-only;</li><li>`actions` columns `action_digest`, `request_args`, `delegation_depth`, `risk_policy_digest`, and status `EXPIRED`;</li><li>event types APPROVAL_GRANTED / DENIED / EXPIRED.</li></ul> |
| Worker | `agw_worker/__main__.py` runs the approval sweeper next to the sealer. The in-process runner runs it too. |
| Config | `AGW_APPROVAL_SIGNING_KEY_FILE`, `AGW_APPROVAL_TTL_SECONDS_{MEDIUM,HIGH,CRITICAL}` (900), `AGW_APPROVAL_FOUR_EYES_CRITICAL` (true), `AGW_APPROVAL_SWEEP_SECONDS` (5), `AGW_HUMAN_SESSION_TTL_MINUTES` (480), `AGW_ACTION_LONG_POLL_MAX_SECONDS` (30). `.env.example` updated. |
| Metrics | `agw_approval_decisions_total{decision}`, `agw_approval_authorizations_total{result}`, `agw_approvals_expired_total`. |
| SDK and CLI | `agw_sdk.approve_cli` (`agw-approve list / show / approve / reject`): human session; shows the action; echoes digest and nonce. SDK `wait_for_change` (long-poll), `wait_for_final`, `EXPIRED` status. |
| Demo | `examples/single-agent/approval_demo.py`, called from `run_demo.sh`. The script creates the signing key if missing and a random per-run approver password; neither is printed. |
| Dependencies | `cryptography` 50.0.2 (Ed25519) and `argon2-cffi` 25.1.0. |
| Tests | <ul><li>`tests/unit/test_approval_binding.py` (26);</li><li>`tests/e2e/test_approvals.py` (19, workflow);</li><li>`tests/e2e/test_approval_attacks.py` (18, named attacks + attack table);</li><li>`tests/e2e/test_approve_cli.py` (2);</li><li>`test_fail_closed.py` extended (DB down: decision → 503).</li></ul>`approvalkit.py` holds the helpers. The conftest gives a session-wide signing key and spies for the three Phase 4 mock tools. |
| Experiments | `experiments/approvals/mutation_check.py` (`make approval-mutations`); `results/attack-table.md` (`make approval-attacks`). |

## 2. Decisions

| Decision | Why | Record |
|---|---|---|
| The action digest leaves out `action_id`, expiry and nonce; they live on the approval row and in the signed record | The prompt's field list. A test shows two identical requests share a digest and the replay still fails. | ADR-0027 §1 |
| `target_resource` = `target_field`, else `destination_field` | send_email's "target" is its recipients; no tool metadata change, so no version bump | ADR-0027 §1 |
| `policy_digest` over the **stored** JSON document; `risk_policy_digest` also bound | Stable across model evolution; binds both policies that shaped the decision | ADR-0027 §1 |
| Revalidation: re-evaluate under the current policy, stricter wins (DENY, or a higher level than approved, needs a new approval) | Prompt. Supersedes ADR-0010's "any policy-version change invalidates". | ADR-0027 §7 |
| New approval state `INVALIDATED`; new action status `EXPIRED` | "Approved but refused at revalidation" is not "consumed" | ADR-0027 §2 |
| APPROVAL_REQUESTED stored as the existing APPROVAL_REQUIRED type | The literal is in hashed records since Phase 1 | ADR-0027 §6 |
| `approval` header map defined inside v1 | No record had used it (model-only types) | ADR-0027 §6, 05 note |
| Only signatures under the **configured** key count | `agw_app` can insert into `approval_signing_keys`; a forged key there must not be trusted (attack A9) | ADR-0027 §4 |
| Separate `Session` scheme, `agws_` prefix, separate table; an agent key on human endpoints gets 403 + SECURITY_VIOLATION | Agents can never hold approver credentials, by construction | ADR-0027 §3 |
| Four-eyes on by default for CRITICAL | The prompt's optional four-eyes rule; PK(approval, approver) makes "same person twice" impossible | ADR-0027 §2 |
| `request_args` kept only while pending, cleared when the approval closes | Data minimization; the evidence payload keeps the args | ADR-0027 §1 |
| TOTP not implemented | Optional in the prompt; the `HumanIdentityProvider` seam is ready | ADR-0027 §3 |

## 3. Results

### 3.1 Clean-state acceptance
Stack, volume, `.env` and `.venv` were removed first. `make up && make migrate && make test && make demo` exits 0.
- Migrations 0001 → 0005 applied.
- ruff clean; mypy: no issues in 83 source files; import-linter: 5 contracts kept.
- **669 tests pass** (604 at the end of Phase 4).
- Coverage: 92% overall, 97% on the gated packages (now including `approvals/` and `humans/`), 100% on `risk/`.
- Module coverage:

| Module | Coverage |
|---|---|
| `approvals/binding.py` | 100% |
| `approvals/signing.py` | 100% |
| `approval_routes.py` | 100% |
| `approvals/service.py` | 97% |
| `humans/service.py` | 97% |

`make vectors`, `make verify-isolated` and `make risk-eval` still pass.

### 3.2 Demo (`make demo`, Phase 5 part)
1. The agent calls `send_email` to `partner@example.org`: risk HIGH (score 45), so `PENDING_APPROVAL`.
2. `agw-approve approve --yes` runs in a separate process as alice. It shows the tool, args, target, risk reasons and policy rules, and echoes the digest. The result: `APPROVED`, then `AUTHORIZED`.
3. The agent long-polls and sees `COMPLETED`.
4. The agent sends the same email again with the recipient changed to `attacker@evil.example`. This is a new action, still `PENDING_APPROVAL`, and the digests differ. Every attempt to reuse the first approval fails:

| Attempt | Result |
|---|---|
| Approve the new request while echoing the first approval | 409 `APPROVAL_STALE` |
| Re-use the consumed first approval | 409 `APPROVAL_NOT_PENDING` |
| The agent approves its own request | 403 `AGENT_NOT_PERMITTED` |

5. alice rejects the new request: `DENIED`.
6. Email tool invocations: approved request = 1, altered request = 0. `PHASE 5 DEMO OK`.
7. Every APPROVAL_* event in the exported chain sits in an epoch with seal reason `RISK_HIGH`. This was checked by mapping the export's events to the export's epochs; APPROVAL_DENIED was still pending when the demo printed its timeline and was sealed by the next tick. Offline `agw-verify` passes (event bundle with root: exit 0; without root: exit 4; epochs with events: exit 0).

### 3.3 Attack table (`make approval-attacks`)

| attack | attempts | unauthorized executions | blocked by |
|---|---|---|---|
| A1 approve, then alter args (subject) | 1 | 0 | digest recomputed from stored request |
| A2 approve, then alter target (recipient) | 1 | 0 | digest recomputed from stored request |
| A3 approve, then alter tool version | 1 | 0 | digest recomputed from stored request |
| A3b approve, then alter environment | 1 | 0 | digest recomputed from stored request |
| A3c approve, then lower recorded risk | 1 | 0 | digest recomputed from stored request |
| A4 approve, then resubmit with altered recipient | 2 | 0 | new action → new digest + new approval |
| A5 replay consumed approval for identical request | 5 | 0 | approval bound to action_id; CONSUMED; nonce PK; column grants |
| A6 use an expired approval | 3 | 0 | expires_at checked against DB time |
| A7 20 concurrent dispatch attempts, one approval | 20 | 0 | approval row lock + nonce PK (exactly 1 execution) |
| A8 agent credential on decision/approval endpoints | 6 | 0 | separate human auth scheme; 403 + SECURITY_VIOLATION |
| A9 forged decision (wrong nonce / wrong digest / bad or foreign signature) | 4 | 0 | echo check; Ed25519 under the configured key only |
| A10 approval for tenant A used from tenant B | 3 | 0 | tenant-scoped lookup; tenant check at authorization |
| A11 approve an already executed / rejected / invalidated action | 3 | 0 | state machine: only PENDING is decidable |
| A12 policy tightened between approval and dispatch | 1 | 0 | re-evaluation under current policy; stricter wins |
| A12b scope revoked / agent disabled after approval | 2 | 0 | re-evaluation with current agent row |
| A12c risk rose after approval (stricter wins) | 1 | 0 | level re-check |
| A13 four-eyes CRITICAL: same approver twice | 2 | 0 | PK(approval, approver); distinct valid signatures counted |

**Total: 57 attempts, 0 unauthorized executions.**

Notes on how the attacks were run:
- **Insider attacks (A1–A3c, A5c–e, A9c–d, A10c).** These are direct DB writes, as `agw_app` or `agw_migrator`. An agent has no API that changes a pending action.
- **A12 (policy tightened).** Runs in its own Postgres container, because a new `default` policy version is global.
- **A12c (risk rose).** Wraps the re-evaluation: the default policies have no reachable HIGH → CRITICAL-with-exception path.

### 3.4 Failing-then-passing evidence (`make approval-mutations`)
17 guards, each removed in turn; each time, its named test fails:
- digest recompute; echo check; APPROVED-only authorize; nonce row;
- expiry at decision; expiry at authorize; tenant check; action still pending;
- signature verification; enough signed approvers; re-evaluation DENY; risk increase;
- agent active; four-eyes; approver role; agent-on-human 403 + record; signer required.

Result: **17/17 caught.**

### 3.5 Bug found in an older test
`test_flight_recorder.py::test_delete_middle_event_detected` renumbered events with `UPDATE … SET seq = seq - 1` against the non-deferrable `(tenant_id, seq)` unique key. Postgres does not guarantee row update order, so the test failed whenever seq 4 was visited first; it started failing in this session. The test now renumbers in two steps. This was a test-only fragility, not a product bug.

## 4. Known gaps
- **Signature semantics.** The gateway signs, not the human; WebAuthn is future work. Rotating the key invalidates pending approvals; a list of old public keys is a later change.
- **No TOTP, lockout or login rate limiting.** Approver passwords are the only factor in dev.
- **Revalidation happens at authorization (into the outbox), not inside the executor.** An app-role edit of `outbox_jobs.args` after authorization is not caught online. Verifier V10 (dispatched args digest = approved args digest) is the offline check and is not built yet.
- **Plaintext evidence.** Approver comments and the signed record sit in plaintext evidence payloads until encryption.
- **Approval view.** `GET /v1/approvals/{id}` shows the request-time POLICY_EVALUATED; the dispatch-time re-evaluation is visible in the timeline and evidence.
- **`probe()` / manual reconcile** (roadmap row 4) is not implemented.
- **Agent-declared delegation** is unchanged from Phase 4: unverifiable, can only raise risk.
- **No dashboard.** Out of scope; the CLI is the approver UI.
- **Open owner decisions:** phase numbering vs `13-roadmap.md`; four-eyes default (on for CRITICAL); TTL defaults (900 s at every level).
