# Methodology

## Overall Architecture

The gateway separates **enforcement**, which keeps unauthorised or unapproved actions away from controlled tools and fails *closed*, from **evidence**, which lets a third party verify what was proposed, decided, dispatched and observed and fails *detectably* (TAMPERED or INCOMPLETE instead of VERIFIED). {fig:arch} shows the three planes: execution (authentication, risk and policy engines, approvals, outbox and executor), evidence (lifecycle events, canonical encoding and hash chain, Merkle sealer, envelope encryption, anchorer) and audit/control (the AgentGuard Console as a backend-for-frontend (BFF), the monitor, disclosure grants, connectors and the GitHub check). Agents are untrusted, tool credentials live only in the gateway, and the verifier trusts only the chain and the mathematics.

::figure arch | fig3_1_architecture.png | AgentGuard architecture: execution, evidence and audit/control planes across trust zones | 4.6

## Request Lifecycle and Immutable Events

An agent's identity comes only from its credential; a mismatching identifier in the request body yields 403 and a SECURITY_VIOLATION event. As {fig:life} shows, the gateway evaluates risk and policy as pure functions and commits ACTION_REQUESTED, POLICY_EVALUATED and the outcome (ACTION_DENIED, APPROVAL_REQUIRED, or ACTION_AUTHORIZED with an outbox job) in one transaction, tx1. The executor commits ACTION_DISPATCHED before calling the adapter, so every side effect is preceded by a durable record that it might have happened (ADR-0004). Evidence rows are immutable through revoked privileges and triggers, and each tenant has one chain with gap-free sequence numbers allocated under a lock on the chain head.

::figure life | fig3_2_lifecycle.png | Action lifecycle and the immutable events recorded at each transition | 3.35

## Risk Engine and Deterministic Policy

Risk and policy contain no input/output and no LLM (ADR-0002), so injected text cannot change a decision and an auditor can re-run it from recorded inputs. The risk engine reads a versioned TOML policy with nine weighted factors (sensitivity, operation, environment, data classification, reversibility, external destination, trust tier, volume, delegation depth); scores of 25, 45 and 75 map to MEDIUM, HIGH and CRITICAL. Mandatory rules run first and can only make the outcome stricter, and a missing attribute counts as its worst value ({tab:risk}). The policy engine takes the most restrictive of the risk-forced effect, the document rules and the per-level default; the policy digest is recorded in every POLICY_EVALUATED event.

::table risk | Risk levels, default effects, sealing urgency and example mandatory rules
::widths 15,26,22,37
| Level | Default effect | Evidence sealing | Example mandatory rules (floor) |
|---|---|---|---|
| LOW | ALLOW | 100 events or 300 s | - |
| MEDIUM | Tool's `medium_effect` | 25 events or 60 s | - |
| HIGH | REQUIRE_APPROVAL | Immediate (next tick) | MR-EXTERNAL-TRANSFER, MR-MISSING-META |
| CRITICAL | DENY; exception rule: two approvers | Immediate; anchored before dispatch | MR-DELETE-PROD, MR-PRIVILEGE, MR-UNTRUSTED-SENSITIVE |

## Human Approval Binding

To prevent "approve one thing, execute another" [@bromme2026], an approval binds an action digest over the agent, tool version, canonical argument digest, target, environment, policy and risk-policy digests, risk level and delegation context, plus a random nonce and an expiry checked against database time. The approver echoes digest and nonce, and the gateway signs the decision with Ed25519 [@josefsson2017]. At authorisation the action is re-evaluated under the current policy and the stricter result wins; a row lock and a primary key on the nonce ensure one dispatch per approval. CRITICAL actions need two distinct approvers by default, each re-authenticated within 300 s, and agent credentials are refused on approval endpoints.

## Evidence Pipeline

{fig:pipe} shows the pipeline. Each record is encoded once as deterministic CBOR under the strict AGW-CBOR-v1 profile; gateway and verifier have separate hand-written codecs, because the off-the-shelf decoder accepted non-canonical input. The event hash is SHA-256 over a length-prefixed domain tag and the *stored* bytes, including the previous hash, and every payload carries a 32-byte salt against digest guessing. The sealer builds an RFC 9162 tree over a contiguous sequence range without leaf duplication [@laurie2021] and computes the epoch root R_t, binding tenant, epoch number, tree size, sequence range, Merkle root and previous root; binding the size matters because an inclusion proof for leaf 0 of a 5-leaf tree also verified under claimed sizes 6 to 8. The append-only contract accepts (R_t, R_t-1) only from the registered submitter, for the next epoch, with a matching back-pointer; anchors move through PENDING, SUBMITTED, INCLUDED and FINALIZED, and a reorg re-broadcasts the same transaction. The verifier `agw-verify` reports the codes in {tab:verify}. Risk changes only *when* an epoch is sealed, never *whether* an event enters the chain.

::figure pipe | fig3_3_evidence_pipeline.png | Evidence pipeline: canonical encoding, hash chain, RFC 9162 epoch sealing, chained epoch root and anchor finality states | 4.62

::table verify | Verifier result codes
::widths 25,8,67
| Result | Exit | Meaning |
|---|---|---|
| VERIFIED | 0 | All checks pass and an external trusted root covers the material |
| TAMPERED | 1 | Non-canonical bytes; hash, link or root mismatch; broken tiling; truncation |
| INCOMPLETE | 2 | Material missing (events, payloads, trusted epoch outside the material) |
| INVALID_PROOF | 3 | Inclusion proof fails or disagrees with the authenticated epoch header |
| UNANCHORED | 4 | Internally consistent but no external trust root |

## Privacy: Envelope Encryption and Selective Disclosure

Each payload has its own random data-encryption key (DEK), used once with AES-256-GCM [@dworkin2007] and wrapped under a key-encryption key (KEK) that never enters the database. The additional authenticated data (AAD) binds the ciphertext to tenant, event and committed digest, so swapped ciphertexts fail to decrypt; secret arguments become salted markers. An administrator can grant an auditor selected events for a limited time, and the gateway seals their DEKs to the auditor's key with HPKE [@barnes2022]; grants and accesses, including refusals, are evidence. Deleting one wrapped DEK erases one payload, after which the chain verifies as INCOMPLETE, not TAMPERED.

## Reliability: Outbox, Outcome-Unknown and Reconciliation

The authorisation and its outbox job commit together, so a crash leaves either no side effect or a durable job, which executors claim with `FOR UPDATE SKIP LOCKED` under a lease. Idempotency keys map retries to one action. A crash after dispatch or an adapter timeout yields ACTION_OUTCOME_UNKNOWN; non-idempotent tools are never retried automatically (ADR-0011), and an administrator records ACTION_RECONCILED. Without the database the gateway returns 503 and nothing executes.

## Coding-Agent Governance

{fig:coding} shows the coding path. Each agent's pre-tool hook runs `agw hook`, a standard-library command-line interface (CLI) that normalises the native payload into the vendor-neutral `agw.coding-action/1` model and calls `POST /v1/coding/decide`. A deterministic coding policy answers allow, deny or ask: shell commands are parsed, never executed, and diffs pass content rules (for example, removing webhook-signature checks, skipping tests, or converting bigint money to a number). The agents' native "ask" is never used, because the developer would answer it for their own agent; a gateway "ask" is an approval routed to `maintainer`, `ledger_lead` or two `security` approvers, and the identical retry consumes it once. Any failure denies, and a post-tool report without an authorised action is a violation. GitHub changes go only through MCP dev-tools: `git_submit_change` re-applies the diff server-side, evaluates the full diff and pushes with a GitHub App token the agent never sees, and the check "AgentGuard evidence" passes only if every commit on the PR was gateway-pushed and verifies. `agw init` writes each repository's configuration and `agw doctor` reports whether each agent is enforced, hooked or MCP-only.

::figure coding | fig3_4_coding_agents.png | Coding-agent governance: local hook path and server-side GitHub submit path | 5.12

## Connectors Framework and Deny-by-Default Classification

Administrators add connectors (GitHub, Slack, e-mail, HTTP APIs, upstream MCP servers, agent clients) from the console. Every new action starts *unclassified* and denied; classification needs a re-authenticated administrator, creates a new version, is recorded as evidence and acts as a risk floor. A repository's `.agentguard.yaml` can only tighten policy, loosening becomes an administrator proposal, credentials are sealed under the KEK, and outbound HTTP is guarded against server-side request forgery (SSRF).

## Threat Model Summary

Seven adversaries are considered: an injected agent, an external attacker, a database insider, a compromised gateway host, a malicious operator, a faulty tool and chain-level adversity. {tab:threat} summarises representative threats.

::table threat | Threat model summary: threat, control and residual risk
::widths 30,42,28
| Threat | Control | Residual risk |
|---|---|---|
| Spoofed identity or unregistered tool | Identity from credential only; registry; deny by default | - |
| Approve one action, execute another | Action digest, nonce, expiry, single use, re-evaluation | Gateway (not human) holds signing key |
| Side effect without durable record | Authorisation + outbox in one transaction | - |
| Insider edits, deletes or reorders evidence | Grants, triggers, chain, epochs, anchors | Unsealed tail until sealed |
| Fork or equivocation | Contract refuses a second root per epoch | Signer key compromise |
| Ciphertext swap or digest guessing | AAD binding; salted digests | Header argument digest unsalted |
| Prompt injection | Deterministic policy; delegation; approvals | Injected *allowed* actions |
| Bypassing the gateway | Credentials and routes only at the gateway | Side channels; killed hooks fail open in some agents |
