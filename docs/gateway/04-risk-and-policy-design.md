# 04 — Risk and Policy Design

Status: Accepted (Phase 0). ADRs: 0001 (deny by default), 0002 (deterministic policy),
0010 (approval binding), **0026 (Phase 4)**, **0027 (Phase 5, approvals)**.

> **Phase 4 (implemented, ADR-0026).** §2's fixed four-factor classifier (`risk-v1`) is replaced
> by `risk-v2`: a versioned TOML risk policy (`agw_gateway/risk/default_risk_policy.toml`) with
> nine weighted factors, thresholds, mandatory rules that can force DENY / REQUIRE_APPROVAL or
> set a floor, missing ⇒ worst value, and control ids; its digest is recorded in every
> POLICY_EVALUATED. §4.3 `CAP-CRITICAL-APPROVAL` is superseded: CRITICAL is **DENY** unless a
> `critical_exception` rule matches (then REQUIRE_APPROVAL). MEDIUM follows the tool's
> `medium_effect`. The policy document is `default` v2. §2 and §4.3 below describe v1 and are
> kept for records written before Phase 4. Sources: Paper A §5 (*Risk-based evidence selection*, Table 1),
Paper B §III-B (policy evaluation field).

> **C1 (implemented, ADR-0034).** Coding-agent actions use a **separate policy family**:
> `coding-mintrail` v1 (`agw_gateway/coding/policies/coding-mintrail-v1.toml` + pure rule
> modules). It is deterministic and has no LLM. It combines deny > ask > allow, max level, and
> mandatory denies (secrets, network/exfiltration commands, diff content rules). Its digest is
> recorded as `risk.cv = coding-policy-v1`. "ask" is a Phase 5 approval routed to a role
> (`security` for CRITICAL, `ledger_lead` for `ledger/**`, else `maintainer`) and bound to the
> coding action digest. The agent's identical retry consumes it once. Summary:
> [coding-agents.md](coding-agents.md) §4.

Risk and policy are **separate pure functions** with different jobs:

| | Risk classifier | Policy engine |
|---|---|---|
| Question | "How dangerous is this call, and how urgently must its evidence be sealed and anchored?" | "Is this call allowed, denied, or does it need human approval?" |
| Output | `RiskAssessment` | `Decision` |
| Affects enforcement? | Only through policy rules that match on `risk_level` and through mandatory caps (§4.3) | Yes, directly |
| Affects evidence? | Yes: seal/anchor urgency (09) | Records `policy_id`, `policy_version`, `matched_rule_ids` |
| I/O, clock, randomness, LLM | **None** | **None** |

Both functions take an explicit `now` and explicit inputs, so a verifier or auditor can
re-run them from the recorded inputs and get the same result.

## 1. Inputs

```python
@dataclass(frozen=True)
class EvaluationInput:
    agent: AuthenticatedAgent        # tenant_id, agent_id, scopes: frozenset[str]
    tool: ToolMetadata | None        # None => unknown tool
    args_valid: bool                 # result of Pydantic validation
    args: Mapping[str, Any] | None   # validated args (None if invalid)
    environment: Environment         # dev | staging | prod (requested target env)
    policy: PolicyDocument           # exact immutable version
    now: datetime                    # Phase 4 (approval expiry); unused by Phase 1 rules
```

`ToolMetadata` (registry, 11 §4): `tool_id`, `version`, `operation_type`
(`read|create|update|delete|execute`), `sensitivity` (`public|internal|confidential|restricted`),
`environments_allowed`, `required_scope`, `base_risk` (`LOW..CRITICAL`), `is_idempotent`,
`external_effect: bool`, `target_field: str | None`, `args_model`, `adapter`.

## 2. Risk levels and classifier (v1)

Levels, totally ordered: `LOW < MEDIUM < HIGH < CRITICAL`.

### 2.1 Score

| Factor | Values → points |
|---|---|
| operation_type | read 0, create 10, update 20, execute 30, delete 40 |
| sensitivity | public 0, internal 10, confidential 25, restricted 40 |
| environment | dev 0, staging 10, prod 30 |
| external_effect | false 0, true 20 |

`score_level`: score < 25 → LOW; < 50 → MEDIUM; < 75 → HIGH; otherwise CRITICAL.

### 2.2 Final level

```
level = max(tool.base_risk, score_level, max(mandatory floors that fired))
```

**Mandatory rules override numeric scores.** They can only *raise* the level:

| Rule id | Condition | Floor |
|---|---|---|
| `MR-DELETE-PROD` | operation_type = delete AND environment = prod | CRITICAL |
| `MR-PRIVILEGE` | tool tagged `privilege_change` or `credential_access` | CRITICAL |
| `MR-RESTRICTED-WRITE` | sensitivity = restricted AND operation_type ≠ read | HIGH |
| `MR-EXTERNAL-TRANSFER` | external_effect AND sensitivity ≥ confidential | HIGH |
| `MR-MISSING-META` | any of operation_type, sensitivity, base_risk missing or unknown | HIGH |
| `MR-POLICY-EXCEPTION` | (Phase 4) action executes under an approved policy exception | HIGH |

**Missing metadata ⇒ higher risk**: a tool that lacks any risk attribute is treated as at least
HIGH (`MR-MISSING-META`). An *unregistered* tool is never risk-scored as callable. It is DENIED
before risk matters, and the event records `risk_level = HIGH` with
`mandatory_rule_ids = [MR-MISSING-META]` so the denial still seals promptly.

### 2.3 Output

```python
RiskAssessment(level: RiskLevel, score: int, factors: tuple[tuple[str, int], ...],
               mandatory_rule_ids: tuple[str, ...], classifier_version: str = "risk-v1")
```

The classifier version is recorded in `POLICY_EVALUATED`. Any change to the weights is a new
version. An ML classifier is explicitly *not* planned (12 §4). If one is ever added, it may only
raise the level, never lower it, and never feed allow/deny directly.

## 3. Pre-policy system checks (not overridable by policy documents)

Evaluated in order. The first failure yields DENY with a system rule id:

| Rule id | Check | Reason code |
|---|---|---|
| `SYS-TOOL-UNKNOWN` | tool id+version not in registry, or disabled | `TOOL_NOT_REGISTERED` |
| `SYS-ARGS-INVALID` | args fail the Pydantic model (`extra="forbid"`, strict) | `ARGS_SCHEMA_INVALID` |
| `SYS-ENV-FORBIDDEN` | environment ∉ tool.environments_allowed | `ENVIRONMENT_NOT_ALLOWED` |
| `SYS-SCOPE-MISSING` | tool.required_scope ∉ agent.scopes | `SCOPE_MISSING` |
| `SYS-AGENT-DISABLED` | agent status ≠ active (checked in auth too) | `AGENT_DISABLED` |

Reason codes are stable enums. Free-text reasons never include arg values.

## 4. Policy engine v1

### 4.1 Document (stored immutable in `policies`, one row per version)

```yaml
policy_id: default
version: 1
default_effect: DENY            # MUST be DENY; documents with ALLOW default are rejected at load
rules:
  - rule_id: allow-low-read
    effect: ALLOW
    match: { operation_types: [read], risk_levels: [LOW], environments: [dev, staging, prod] }
  - rule_id: allow-medium-ticket
    effect: ALLOW
    match: { tools: [create_ticket], risk_levels: [LOW, MEDIUM] }
  - rule_id: approve-high
    effect: REQUIRE_APPROVAL
    match: { risk_levels: [HIGH] }
  - rule_id: deny-delete-record
    effect: DENY
    match: { tools: [delete_record] }
  - rule_id: deny-critical
    effect: DENY
    match: { risk_levels: [CRITICAL] }
```

Match fields (all optional; omitted = wildcard; all present fields must match):
`tools`, `tool_versions`, `operation_types`, `sensitivities`, `environments`, `risk_levels`,
`agent_ids`, `scopes_any`. Unknown match fields → the document fails to load (fail closed).

### 4.2 Combination: deny-overrides

1. Run system checks (§3). Failure → DENY.
2. Collect all matching rules.
3. Any `DENY` → **DENY**. Otherwise any `REQUIRE_APPROVAL` → **REQUIRE_APPROVAL**. Otherwise any
   `ALLOW` → **ALLOW**. Otherwise → **DENY** via `default-deny`.

`matched_rule_ids` lists every matching rule in document order, so auditors see *all*
reasons, not just the winner.

### 4.3 Mandatory caps (code, not document)

- `risk_level = CRITICAL` and the effect would be ALLOW → becomes REQUIRE_APPROVAL
  (`CAP-CRITICAL-APPROVAL`). In Phase 1 there is no approval API, so the action stays
  `PENDING_APPROVAL`.
- `risk_level = HIGH` and the effect would be ALLOW → becomes REQUIRE_APPROVAL unless the policy
  rule has `allow_high_without_approval: true` **and** the tool is `is_idempotent`
  (`CAP-HIGH-APPROVAL`).

### 4.4 Output

```python
Decision(effect: Literal["ALLOW","DENY","REQUIRE_APPROVAL"], policy_id: str, policy_version: int,
         matched_rule_ids: tuple[str, ...], reasons: tuple[ReasonCode, ...],
         risk: RiskAssessment, engine_version: str = "policy-v1")
```

### 4.5 Control mapping (Paper A §5, Table 1)

Each rule MAY carry `control_ids: [HITL-APPROVAL, SOD-REVIEW, ...]`. These are copied into
`POLICY_EVALUATED` so evidence maps to GRC control objectives (Paper A §3 `control_id`). They
are not used for decisions.

## 5. Approval binding (implemented in Phase 5; see ADR-0027)

> **Phase 5 (implemented, ADR-0027) supersedes the layout below.** What an approval binds is
> the **action digest** `SHA-256(TAG("AGW/action/v1") || cbor({tenant, agent_id, tool_id,
> tool_version, canonical_args_digest, target_resource, environment, policy_id,
> policy_version, policy_digest, risk_policy_digest, risk_level, delegation_ref}))`, computed
> once at request time and stored on the action. `action_id`, `expires_at` and the 16-byte
> nonce live on the `approvals` row and in the gateway-signed decision record, not in the
> digest. A policy change does **not** by itself invalidate an approval: at authorization the
> action is re-evaluated under the current policy, and the stricter result wins (DENY, or a
> higher risk level than approved, means a new approval is needed). Approvers authenticate
> with a separate session scheme. The text below is kept as the Phase 0 design record.

An approval is valid for exactly one tuple:

```
approval_binding = {
  agent_id, tenant_id,
  tool_id, tool_version,
  args_digest   = SHA256(TAG("AGW/args/v1") || cbor(validated_args)),   # 06 §3
  target        = args[tool.target_field] canonicalized (or "" if none),
  policy_id, policy_version,
  action_id,
  expires_at    (≤ now + tool.approval_ttl, default 15 min),
  nonce         (16 random bytes, single use)
}
binding_digest = SHA256(TAG("AGW/approval/v1") || cbor(approval_binding))
```

- Dispatch re-evaluates policy **at dispatch time** and checks that the approval's
  `binding_digest` equals a fresh recomputation. Any difference (args, target, tool version,
  policy version, agent) → the approval is unusable, and a new evaluation + new approval is
  required.
- Single use is enforced by a unique constraint on `(nonce)` in a `approval_uses` table,
  inserted in the same tx as the DISPATCH job. That makes double use a constraint violation.
- Expiry is checked against DB time at claim time, not at request time.
- The approver's identity comes from the human's authenticated session, never from the
  request. `APPROVAL_GRANTED` records `approver_id`, `binding_digest` and the prompt digest
  (Paper B §III-B (3)).

## 6. Demo policy outcomes (Phase 1 acceptance)

| Tool | Metadata | Risk (dev) | Decision under default v1 |
|---|---|---|---|
| `public_doc_search` | read, public, base LOW | LOW (score 0) | ALLOW (`allow-low-read`) |
| `create_ticket` | create, internal, base MEDIUM | MEDIUM (score 20 → LOW; base MEDIUM wins) | ALLOW (`allow-medium-ticket`) |
| `delete_record` | delete, confidential, base CRITICAL | CRITICAL | DENY (`deny-delete-record`, `deny-critical`) |
| unknown tool | — | HIGH (`MR-MISSING-META`) | DENY (`SYS-TOOL-UNKNOWN`) |
