# ADR-0027: Phase 5 action-bound human approval
Status: Accepted · Date: 2026-11-15 · Deciders: Phase 5 implementation (pending owner review)

## Context
The Phase 5 prompt asks that REQUIRE_APPROVAL actions execute only after a valid, authenticated,
single-use, unexpired human decision bound to the exact action. It fixes the action digest
fields, an approval object with a 128-bit nonce, separate human identities, gateway-signed
decision records, a digest + nonce echo, APPROVAL_* evidence, and revalidation in one
transaction at dispatch.

The approval spec so far was 04 §5 and ADR-0010, written in Phase 0, when the roadmap still
called this "Phase 4".

**Docs and reality disagreed in three places:**
1. The prompt says to read `07-approval-security.md`. No such file exists: 07 is key management. The approval spec is 04 §5 plus ADR-0010, and I used those.
2. The roadmap (13) numbers approvals as Phase 4 and encryption as Phase 5. The prompts number risk as 4 and approvals as 5. This mismatch has been open since Phase 2 and is left to the owner.
3. ADR-0010 (locked) differs from the prompt in two respects:
   - ADR-0010 puts `action_id`, `expires_at` and `nonce` inside the binding digest. The prompt's action digest leaves them out.
   - Under ADR-0010 any policy-version change invalidates the approval. The prompt re-evaluates under the current policy instead, and the stricter result wins.

   This ADR supersedes ADR-0010 on both points, as described below.

## Decision

### 1. Action digest (computed once, stored, recomputed)
```
action_digest = SHA-256(TAG("AGW/action/v1") || cbor({v:1, tenant, agent_id, tool_id,
    tool_version, canonical_args_digest, target_resource, environment, policy_id,
    policy_version, policy_digest, risk_policy_digest, risk_level, delegation_ref}))
```
- **Fields.** These are the prompt's fields plus `policy_id` and `risk_policy_digest` (stricter).
- **`target_resource`.** It is `args[target_field]`, else `args[destination_field]` (for send_email, the recipients), else null. It is kept as a CBOR value, not flattened to text.
- **`policy_digest`.** It is `SHA-256(TAG("AGW/policy/v1") || cbor(stored JSON document))`. Hashing the stored document keeps the digest stable when the model later gains optional fields.
- **`delegation_ref`.** It is `{depth, declared_by:"agent"}` or null.
- **When it is computed.** At request time, for every action with a known tool and valid args. It is stored in `actions.action_digest`. While the approval is pending, `actions.request_args` keeps the validated args, which are needed to recompute the digest and to dispatch. They are cleared as soon as the approval closes (authorized, rejected, invalidated or expired); the evidence payload keeps them.
- **No `action_id`.** Two identical requests have the same digest. Replay is stopped by the approval row: it is bound to one `action_id` and has a single-use nonce. A test asserts that the digests are equal while the replay still fails.

### 2. Approval object and state machine
- **Table.** `approvals(approval_id, tenant_id, action_id UNIQUE, action_digest, nonce bytea(16) UNIQUE, required_role='approver', required_approvals 1|2, state, state_reason, requested_at, expires_at)`.
- **Clock and TTL.** Both timestamps come from the DB clock. The TTL is configurable per risk level (default 900 s).
- **States.** `PENDING → APPROVED → CONSUMED | INVALIDATED` and `PENDING → REJECTED | EXPIRED`.
  - `INVALIDATED` is an addition to the prompt's five states. It means approved but refused at revalidation, which is different from "used".
- **Action statuses.** `EXPIRED` is a new action status.
- **Column-level grants.** `agw_app` can update only `state`, `state_reason` and `updated_at`. The digest, nonce, expiry, action and required count cannot be rewritten by the runtime role (tested).
- **Four-eyes.** It is on by default for CRITICAL: two distinct approvers are required, with `PK(approval_id, approver_id)` on `approval_decisions`.

### 3. Humans are not agents
- **Separate identity store.** `humans` holds tenant, username, Argon2id hash, roles ⊆ {approver, admin, auditor} and status. `human_sessions` stores only `SHA-256(TAG("AGW/session/v1") || token)`.
- **Token format.** `agws_<16 hex>_<43 b64url>`, presented as `Authorization: Session <token>`.
- **Three independent separations from agents:** the token prefix (`agw_` vs `agws_`), the scheme (`Bearer` vs `Session`) and the lookup table. `agw_app` cannot write `humans`; humans are created with the admin CLI as `agw_migrator`.
- **Agent keys on human endpoints.** An agent key presented on any `/v1/approvals*` endpoint gets 403 `AGENT_NOT_PERMITTED`. A `SECURITY_VIOLATION{kind: AGENT_ON_HUMAN_ENDPOINT, claimed: "<METHOD> <route template>"}` is recorded at HIGH. An agent scope literally named "approver" changes nothing (tested).
- **Login failures.** They are uniform 401s. Unknown users still pay one Argon2 verification.
- **OIDC-ready.** `HumanIdentityProvider` is the seam.
- **Not done:** TOTP (optional in the prompt), lockout and rate limiting (gap).

### 4. Signed decision records (gateway attestation)
```
record = {v:1, tenant, approval_id, action_id, action_digest, nonce, decision, approver_id,
          decided_at (µs, DB clock), reason}
dd     = SHA-256(TAG("AGW/approval-decision/v1") || cbor(record))
sig    = Ed25519(gateway key, TAG("AGW/approval-sig/v1") || dd)
```
- **Why sign the tagged digest.** A verifier can check `sig` from the event header alone. The full record is in the event's payload.
- **The key.** It is a 32-byte seed file (`AGW_APPROVAL_SIGNING_KEY_FILE`, created with `make dev-keys`, git-ignored, mode 0600). Public keys are published in the append-only `approval_signing_keys`.
- **What it proves:** the gateway attested that a session-authenticated approver made this decision about this exact digest and nonce.
- **What it does not prove:** that a human held a private key. **Future, stronger option:** per-approver WebAuthn/passkey signatures over `dd`. The authenticator then signs the digest the approver was shown, and the gateway only verifies.
- **Only the configured key is trusted.** At authorization, only signatures under the gateway's configured key count; rows in `approval_signing_keys` never make a key trusted, because `agw_app` can insert there. Rotating the key therefore invalidates pending approvals (fails closed; gap: a configured list of old public keys).
- **No key, no decision.** With no usable key, decisions return 503 and nothing is recorded. The action stays pending, then expires.

### 5. Decision API (digest + nonce echo)
- **Endpoints.** `GET /v1/approvals?state=` and `GET /v1/approvals/{id}` are for approvers, auditors and admins, within the human's own tenant (404 otherwise). The second shows the exact tool and version, the args rendered as sorted ASCII-only JSON (bidi and zero-width characters become visible `\uXXXX`), the target, risk level, score, rules and reasons, the policy rules, `action_digest` and `nonce`.
- **Decisions.** `POST /v1/approvals/{id}/decision {decision, reason, action_digest, nonce}` is for approvers only. A mismatched echo returns 409 `APPROVAL_STALE`. The body is strict (`extra="forbid"`), so no endpoint accepts new args for an existing action.
- **Public keys.** `GET /v1/approvals-signing-keys` publishes the verification keys.

### 6. Evidence
- **Event names.** The prompt's APPROVAL_REQUESTED is the existing **APPROVAL_REQUIRED** type: that literal has been in hashed records since Phase 1 (same reasoning as ADR-0026 §4 for seal reasons).
- **The `approval` map.** It is defined inside AGW-EVT v1 (the APPROVAL_* types were model-only, so no record used the map):

| Event | Keys in the `approval` map |
|---|---|
| APPROVAL_REQUIRED | `{id, binding (= action_digest), exp (µs), req}` |
| APPROVAL_GRANTED / APPROVAL_DENIED | the above plus `{approver, dec, votes, dd, sig, kid}`; the payload holds the signed record and the comment |
| APPROVAL_EXPIRED | `{id, binding, exp, req, votes}` |
| ACTION_AUTHORIZED | `{id, binding, exp, req, decs: [{approver, dd, sig, kid}]}` |

- **Re-evaluation record.** The authorization tx also writes a second POLICY_EVALUATED: the re-evaluation, recorded whether it allows or denies.
- **Sealing.** All approval events are written with `risk_level ≥ HIGH`, so they seal immediately (Phase 4).

### 7. Authorization in one transaction (dispatch-time revalidation)
Lock order: the approval row, then the action row, then the chain head. The executor never touches approvals, so there is no cycle. Under those locks, all of the following must hold:
1. The approval is `APPROVED` (anything else is a NOOP, so replays and races are absorbed) and unexpired by DB time.
2. The approval and the action are in the same tenant (confused deputy).
3. The action is still `PENDING_APPROVAL`.
4. At least `required_approvals` distinct, still-active approvers of that tenant have valid signatures over the recomputed record.
5. The digest recomputed from the stored request equals **both** `approvals.action_digest` and `actions.action_digest`. The stored request is re-validated args, registry spec at the stored version, environment, stored policy version plus its stored-document digest, risk level and delegation.
6. The agent is active.
7. Re-evaluation under the **current** policy, risk policy, agent scopes and registry is not DENY and is not at a higher risk level than approved (stricter wins).
8. Insert `approval_uses(nonce PK)`.

Then: CONSUMED, POLICY_EVALUATED, ACTION_AUTHORIZED, the outbox DISPATCH job, COMMIT. Any failure gives INVALIDATED, ACTION_DENIED with a reason code, and nothing in the outbox.

**When it runs.** Authorization runs right after the decision that completes the approval, and from the sweeper for APPROVED rows (crash recovery).

**Scope of "at dispatch".** As for ALLOW actions, the check happens when the action is authorized into the outbox, not again inside the executor (gap: an ADV3 edit of `outbox_jobs.args` after authorization is not detected online; verifier V10 is the offline check).

### 8. Expiry and fail closed
- **Sweeper.** It runs in the worker, and in the in-process runner when that mode is used. It expires PENDING and APPROVED rows past `expires_at` (APPROVAL_EXPIRED, action EXPIRED) and retries authorization of unexpired APPROVED rows.
- **Agents.** They poll `GET /v1/actions/{id}`, or long-poll with `?wait=N` (capped at 30 s). The view shows the approval state but never the nonce.
- **Failures.** DB down gives 503, with no decision and no execution. Missing signing key: see §4.

## Consequences
**Gains**
- INV-11 is enforced by four independent layers: the row-lock state machine, the nonce primary key, the digest recomputation and the column grants.
- Every named attack in the prompt has a test. 17 guard mutations are each caught by a named test.
- Approval evidence seals immediately.

**Costs and limits**
- The decision signature is gateway attestation, not human non-repudiation.
- Rotating the key invalidates pending approvals.
- Unchanged from Phase 4: agent-declared delegation is unverifiable, and humans have no rate limiting or lockout.
- While approval is pending, `request_args` (plaintext validated args) sit in the operational `actions` row. They are cleared when the approval closes; the evidence payload stays plaintext until encryption arrives.
