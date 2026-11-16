# ADR-0026: Phase 4 risk engine v2 (risk policy as data) and risk-adaptive sealing
Status: Accepted · Date: 2026-11-15 · Deciders: Phase 4 implementation (pending owner review)

## Context
The Phase 4 prompt asks for the following:
- Paper A §5 risk-based evidence selection as **deterministic, versioned policy**: a policy file with weighted factors, thresholds, mandatory rules (evaluated first, able to force DENY / REQUIRE_APPROVAL or set a floor), missing ⇒ worst value, and GRC control ids.
- The policy is stored immutably with its SHA-256 digest, and the digest is recorded in POLICY_EVALUATED.
- Per-level default execution policy.
- Risk-adaptive sealing on the single per-tenant chain.

Phase 0–3 had `risk-v1`: four fixed factors in code (04 §2), CRITICAL capped to REQUIRE_APPROVAL (04 §4.3), and count/age sealing only (ADR-0025).

## Decision

### 1. Risk policy is data
- **Format and storage.** A TOML file is loaded into a strict Pydantic `RiskPolicy`. TOML parsing comes from stdlib `tomllib`, so there is no new parser dependency and no YAML implicit typing. Loading **fails closed**:
  - unknown keys;
  - floats (weights and points are integers, because the canonical profile has no floats);
  - a missing or extra factor, or a missing vocabulary value;
  - points that decrease along a factor's risk order, or bad buckets;
  - empty rule conditions, or rules that do nothing;
  - thresholds that are not ascending, or duplicate rule ids.
- **Identity.** The authoritative form is AGW-CBOR-v1 of the validated model. `digest = SHA-256(TAG("AGW/risk-policy/v1") ‖ canonical)` uses a new tag, added to 06 §2. TOML formatting never changes the digest.
- **Storage table.** `risk_policies(policy_id, version, digest UNIQUE, canonical, document)` is append-only (grants plus the same mutation triggers as evidence).
- **Startup sync.** The configured file (`AGW_RISK_POLICY_FILE`, default: the bundled `default_risk_policy.toml`) is inserted if absent. The same version with different bytes is a startup error.
- **Per request.** The latest version of `AGW_RISK_POLICY_ID` is used, rebuilt from the stored bytes and re-hashed against the stored digest. The digest, id and version go into POLICY_EVALUATED, so old decisions keep referencing old digests.
- **Factors.** There are 9 factors:
  - tool sensitivity, operation (read<create<update<delete<execute), environment;
  - data classification (public<internal<confidential<secret/pii), reversibility;
  - external destination, volume (buckets), delegation depth (buckets), agent trust tier.
- **New inputs.** Tool risk metadata gains `data_classification`, `reversible`, `destination_field`, `volume_field` and `medium_effect` (stored in `tool_registry.risk_attributes`). Agents gain `trust_tier`. Requests may declare `delegation.depth`, which is agent-declared and can only raise risk.
- **Missing ⇒ worst.** A missing or unknown value is scored at the factor's worst value and recorded as `FACTOR_MISSING:<name>`. A rule condition on a missing factor counts as **satisfied**, so a missing value can never let a rule escape. A missing base_risk counts as CRITICAL. Property-tested: blanking any subset of factors never lowers the score, level, forced effect or decision.
- **Destinations.** Destinations are parsed from args: `user@host`, or `scheme://[user@]host[:port]/…`. A host is internal only if it equals one of `internal_domains` or ends with `.` plus one of them. Anything else, including unparseable input, is external.
- **Engine.** `risk.evaluate(ctx, policy) -> RiskResult` is pure, with no I/O, clock, randomness or LLM. The import-linter purity contract now also forbids `prometheus_client`, `risk_store` and `metrics`. `risk/` has 100% statement and branch coverage, enforced by `make test`.

### 2. Decision path (policy-v2)
Risk feeds the policy, which produces the decision. System checks run first and are unchanged. Then three sources each propose an effect, and **the most restrictive wins**:
1. **The risk policy's forced effect.**
2. **The policy document**: deny-overrides, default DENY.
3. **The per-level default:**
   - LOW: allow;
   - MEDIUM: the tool's `medium_effect` (missing means approval);
   - HIGH: approval (the Phase 1 idempotent exemption is kept);
   - CRITICAL: **DENY**, unless a matching rule with `critical_exception: true` exists, and then still REQUIRE_APPROVAL. The loader rejects exception rules whose effect is not REQUIRE_APPROVAL.

This **supersedes 04 §4.3 `CAP-CRITICAL-APPROVAL`**: CRITICAL used to become REQUIRE_APPROVAL when a document allowed it, and is now DENY without an exception. The document `default` v2, seeded by migration 0004, allows LOW and MEDIUM, routes HIGH to approval, declares one exception (`update_iam_role` outside prod for `iam:admin` holders) and keeps the `delete_record` ban. v1 stays stored and loadable.

The pure pipeline `policies.pipeline.decide_action` is shared by the service, the tests and the labeled-dataset regression, so they all exercise the production path.

### 3. Header additions inside AGW-EVT v1
The `risk` map of POLICY_EVALUATED gains optional keys `pid`, `pver`, `pd`, `f`, `reasons` and `forced`:
- `pd` is the risk policy digest.
- `f` is a list of `{n, v, p, w, miss?}` with vocabulary labels only, never raw arg values.

`cv = "risk-v2"` discriminates the shape. Phase 1–3 records (`cv = "risk-v1"`) stay valid. This is an *addition inside an existing map*, the same kind ADR-0023 made within v1. 05 §4's "new fields require v = 2" is read as "new top-level keys", and the verifier's key check is top-level. The `delegation` payload section is now writable: `{depth, declared_by: "agent"}` when declared, explicit null otherwise.

### 4. Risk-adaptive sealing
- **Per-event risk, at insert time.** `evidence_events.risk_level` is written once when the row is inserted: the action's level, `HIGH` for SECURITY_VIOLATION (an incident indicator), NULL for receipts. It is not part of the hashed header and is used only for seal urgency. The trigger is therefore derived from **durable rows** every sealer tick: no in-memory signal, and no SEAL job inserted in tx1. A job inserted in tx1 would have to upsert the single open SEAL job and could deadlock against the sealer, which holds the job row and needs the chain head for its receipt.
- **Pure decision.** `agw_worker.sealing.policy.decide(window, policy)` checks, in order:
  1. Count: pending ≥ T, seal exactly T.
  2. Risk: an urgent (HIGH or CRITICAL) event is pending. Seal up to and including the **latest** urgent event; older events are never skipped. The reason is RISK_CRITICAL if any CRITICAL event is in range, otherwise RISK_HIGH.
  3. Age: the oldest pending event is older than the strictest age among the levels present. Seal everything pending.
  
  Receipts alone never seal.
- **Defaults (hypotheses).** LOW 100 events / 300 s, MEDIUM 25 / 60 s, HIGH and CRITICAL immediate. `AGW_SEAL_ADAPTIVE=false` restores Phase 3 behaviour.
- **Count basis.** The prompt says "max_events of the lowest pending level", which is the default (`AGW_SEAL_COUNT_BASIS=lowest`). The alternative `strictest` is monotone: an extra LOW event can never postpone a MEDIUM batch. But it produced about 2.8× more epochs in the local simulation (`experiments/risk/seal_comparison.py`). MEDIUM stays bounded by its 60 s age rule either way. **Owner decision.**
- **Seal reasons.** The prompt's COUNT and AGE are stored as the existing `MAX_EVENTS` and `MAX_AGE`, which are already in the DB check, the hashed `EpochRef.reason` literal and the Phase 3 records.
- **Anchor priority.** `epochs.anchor_priority` is CRITICAL if any CRITICAL event is in range (the flag for Phase 6 pre-action anchoring), PRIORITY for HIGH, otherwise ROUTINE. It is operational, not part of R_t, and not exported yet.
- **Anti-starvation.**
  - One sealer per tenant, through the three Phase 3 lock layers.
  - Jobs are served FIFO by job id across tenants.
  - A tenant's next job is enqueued only after its previous job finished.
  - `drain()` keeps going after a job that produced no epoch (already sealed, or self-check failed). Before Phase 4 it stopped the whole tick for every tenant; a test now covers this.

### 5. Metrics
Prometheus metrics, with bounded enum labels only (no tenant or agent ids, args or payloads):
- gateway `/metrics`: `agw_risk_decisions_total{level,effect}`;
- worker (`AGW_WORKER_METRICS_PORT`, bound to 127.0.0.1): `agw_sealer_pending_events{level}`, `agw_sealer_oldest_unsealed_age_seconds`, `agw_epochs_sealed_total{seal_reason}`.

## Consequences
**Gains**
- Risk is reproducible from recorded inputs plus the referenced policy digest.
- Changing the policy is a new row, never an edit.
- HIGH and CRITICAL evidence is sealed within a tick (simulated: ≤ 1 s, against up to 300 s for fixed).

**Costs**
- 1.5–2.7× more epochs, so more future anchors (simulated).
- Agent-declared delegation and admin-set trust tiers are inputs the gateway cannot verify; they can only raise risk.
- Every unknown-tool call, missing-scope call or AGENT_ID_MISMATCH is HIGH and seals at once. This is an anchoring amplification vector until rate limiting exists.
- The labels in the regression dataset and the weights have the same author.
