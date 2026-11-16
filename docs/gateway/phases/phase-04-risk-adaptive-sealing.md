# Phase 4: Risk engine + risk-adaptive sealing (Paper A)

Status: **Done**, 2026-11-15.

Goal: implement Paper A §5 risk-based evidence selection as deterministic, versioned policy. That means:
- classify every action before execution;
- enforce mandatory rules;
- let risk drive how urgently epochs are sealed on the single per-tenant chain.

Decisions are in [ADR-0026](../adr/0026-phase4-risk-engine-adaptive-sealing.md).

> **Claim boundary.** Every weight, threshold and seal default is a **hypothesis**. The labeled dataset and the sealing comparison are local, preliminary and partly simulated. Risk changes *when* evidence is sealed and *what* the gateway allows; it never changes which chain an event belongs to or its order.

## 1. What changed

| Area | Files |
|---|---|
| Risk policy as data | `agw_gateway/risk/policy.py`: strict model, TOML loading that fails closed, canonical bytes, `digest = SHA-256(TAG("AGW/risk-policy/v1") ‖ cbor)`. `risk/default_risk_policy.toml`: 9 factors, thresholds, 10 mandatory rules with `AGW-CTRL-*` control ids. |
| Risk engine v2 (pure) | `agw_gateway/risk/engine.py`: `build_context`, `evaluate(ctx, policy) -> RiskResult{level, score, factor_values, matched_rules, reasons, forced_effect, control_ids, policy_digest}`. No I/O, clock or LLM. 100% statement and branch coverage, gated in `make test`. Replaces `risk/classifier.py` (risk-v1). |
| Storage | `agw_gateway/risk_store.py`: startup sync (a version is immutable), and per-request latest version rebuilt from stored bytes with the digest re-checked. Migration `0004_phase4_risk.py` adds:<ul><li>append-only `risk_policies`;</li><li>`tool_registry.risk_attributes` (backfilled for the Phase 1 tools);</li><li>`agents.trust_tier`;</li><li>`evidence_events.risk_level`;</li><li>`epochs.anchor_priority`;</li><li>policy document `default` v2.</li></ul> |
| Decision path | `policies/pipeline.py` `decide_action` (risk → policy → decision, shared by the service, the tests and the dataset). `policies/engine.py` policy-v2: the most restrictive of risk-forced effect, document rules and per-level default. CRITICAL is DENY unless a `critical_exception` rule matches. `policies/default_policy.py` v2. |
| Tools | `tools/metadata.py` adds `data_classification`, `reversible`, `destination_field`, `volume_field` and `medium_effect`. Three mocks in `tools/adapters/phase4_mocks.py` (`send_email`, `export_customer_data`, `update_iam_role`) write only to the sandbox. |
| Request envelope | Optional `delegation: {depth}`. It is agent-declared, can only raise risk, and is recorded in the ACTION_REQUESTED payload. |
| Evidence | POLICY_EVALUATED `risk` gains `pid`, `pver`, `pd` (policy digest), `f` (factor values), `reasons` and `forced` (`agw_schemas.events.Risk`, `cv = "risk-v2"`). Every event row carries `risk_level` (not hashed). The writer inherits it from the action. |
| Sealing | `agw_worker/sealing/policy.py`: pure `decide()` with count / risk / age rules, `anchor_priority()` and `SealPolicy.adaptive|fixed`. `sealer.py`: per-level pending window from durable rows, `anchor_priority` on epochs, metrics. `drain()` no longer stops the tick for all tenants when one job produces no epoch. |
| Metrics | `agw_gateway/metrics.py`. Gateway `GET /metrics`: `agw_risk_decisions_total{level,effect}`. Worker (`AGW_WORKER_METRICS_PORT`): pending events by level, oldest unsealed age, epochs by seal reason. |
| Timeline | `GET /v1/runs/{id}/timeline` adds `risk_level`, `risk{level,score,rules,reasons}`, `matched_rules`, `controls` and `epoch{epoch_no, seal_reason, anchor_priority}` (null means still batched). |
| Demo | `agent.py` has a Phase 4 mixed-risk section. `fetch_bundle.py` bundles a HIGH event. `run_demo.sh` uses the default adaptive sealing (no 1 s override) and prints the risk metrics. SDK gains `delegation_depth`. `seed-demo` refreshes the demo agents' scopes and tier. |
| Experiments | `experiments/risk/`: `labeled_actions.jsonl` (67 cases), `risk_eval.py`, `seal_comparison.py`, `results/`. Make targets: `make risk-eval`, `make seal-compare`. |

## 2. Decisions

| Decision | Why | Record |
|---|---|---|
| TOML (stdlib `tomllib`), integers only, digest over canonical CBOR | No new parser, no YAML implicit typing; formatting-independent identity; the stored bytes are what is hashed | ADR-0026 §1 |
| Missing ⇒ worst value, **and** conditions on a missing factor count as satisfied | Otherwise a missing value could make a rule like `operation = delete` escape. Property-tested monotonicity. | ADR-0026 §1 |
| Missing base_risk ⇒ CRITICAL | Without it, filling in metadata could *raise* the level (found while writing the property test) | ADR-0026 §1 |
| Policy-v2: the most restrictive source wins; CRITICAL is DENY unless an exception rule matches, and even then only approval | Prompt; no source can loosen another. Supersedes 04 §4.3 `CAP-CRITICAL-APPROVAL`. | ADR-0026 §2 |
| `risk` header additions inside v1, discriminated by `cv` | Same approach as ADR-0023; old records stay valid | ADR-0026 §3, 05 §4 note |
| Risk trigger derived each tick from `evidence_events.risk_level`, not a SEAL job inserted in tx1 | As durable as the event. A tx1 upsert of the single open SEAL job could deadlock against the sealer. | ADR-0026 §4 |
| Count threshold basis `lowest` (prompt wording) by default; `strictest` available | Measured: `strictest` gives about 2.8× more epochs. MEDIUM is bounded by 60 s age either way. **Owner decision.** | ADR-0026 §4 |
| Seal reasons stay `MAX_EVENTS` / `MAX_AGE` (the prompt's COUNT / AGE) | Already in the DB check, the hashed receipt literal and Phase 3 records | ADR-0026 §4 |
| SECURITY_VIOLATION recorded as HIGH, so it seals at once | Paper A §5 "incident indicators" | ADR-0026 §4 |
| `MR-UNTRUSTED-SENSITIVE` added after the first dataset run | The engine let an untrusted agent export PII / change IAM with only an approval | experiments/risk/README |

## 3. Results

### 3.1 Clean-state acceptance
Stack, volume, `.env` and `.venv` were removed first. `make up && make migrate && make test && make demo` exits 0.
- Migrations 0001 → 0004 applied.
- ruff clean; mypy: no issues in 72 source files; import-linter: 5 contracts kept.
- **604 tests pass** (412 at the end of Phase 3).
- Coverage: 92% overall, 97% on the gated packages, **100% on `risk/`**.
- Module coverage:

| Module | Coverage |
|---|---|
| `policies/engine.py` | 100% |
| `risk_store.py` | 100% |
| `sealing/policy.py` | 100% |
| `sealer.py` | 94% |
| `writer.py` | 90% |

`make vectors` (all frozen vectors unchanged) and `make verify-isolated` also pass.

### 3.2 Demo (acceptance)
Mixed traffic in one run, read from the run timeline:

| Action | Risk | Decision | Sealing |
|---|---|---|---|
| 3 × search | LOW | ALLOW | **Batched**: still unsealed after 2.5 s (more than 2 sealer ticks) |
| internal email | MEDIUM | ALLOW | Batched |
| PII export (internal bucket) | HIGH, score 50 | REQUIRE_APPROVAL | **Sealed within one worker tick**: epoch `RISK_HIGH` / `PRIORITY`, ending at its APPROVAL_REQUIRED event, carrying the older pending LOW/MEDIUM events (never skipped) |
| IAM change (no `iam:admin`) | CRITICAL (`MR-PRIVILEGE`, `MR-RESTRICTED-WRITE`) | **DENY** (`CAP-CRITICAL-DENY`) | Own epoch `RISK_CRITICAL` / `CRITICAL`: only the previous seal's receipt plus its 3 events |
| search afterwards | LOW | ALLOW | Still pending (batched) |

With the gateway and worker stopped, verification runs offline:
- `agw-verify event` gives VERIFIED (exit 0); without a trust root, exit 4.
- `agw-verify epochs --events` gives VERIFIED.

`/metrics` showed `agw_risk_decisions_total` by level and effect.

### 3.3 Required tests (all passing)

| Requirement | Test |
|---|---|
| Labeled regression + confusion matrix | `test_risk_dataset.py` (67 cases, one test each) |
| Mandatory rule beats score | `test_mandatory_rule_beats_score_prod_delete_without_scope_is_deny`: all weights 0, so score 0 / LOW; the rules still force DENY with a CRITICAL floor; the decision is DENY even under an allow-all document |
| Missing metadata never lower | `test_missing_metadata_never_lowers_risk` (Hypothesis, 800 cases): level, score, forced effect and decision effect |
| Policy change → new version row; old decisions keep the old digest | `test_policy_change_new_version_old_decisions_keep_old_digest` (also: same version with other bytes is refused; UPDATE/DELETE refused for both roles) |
| HIGH seals an epoch ending at its seq within the tick | `test_high_event_seals_an_epoch_ending_at_its_seq_in_one_tick`; `test_high_seal_inside_the_real_background_loop` (real periodic runner) |
| LOW-only traffic seals on count / age | `test_low_only_traffic_seals_on_count`, `test_low_only_traffic_seals_on_age`; MEDIUM sooner: `test_medium_seals_sooner_than_low` |
| Ordering and continuity under mixed load | `test_ordering_and_continuity_under_mixed_concurrent_load`: 4 writers plus a concurrent sealer; gap-free seq, tiling, every RISK epoch ends on an urgent event, offline VERIFIED; 8/8 repeated runs passed |
| Phase 3 tamper suite still passes | `test_tamper_matrix` unchanged and passing |
| Determinism | `test_evaluation_is_deterministic_to_the_byte` (Hypothesis, 500 cases; same canonical bytes, also against a re-parsed policy) |

Additional tests:
- **Risk factors and rules:** every factor and bucket, every mandatory rule fires and does not fire, destination parsing (subdomain, suffix trick, userinfo, port, unparseable).
- **Policy loader:** 22 loader fail-closed cases; tampered stored policy rejected.
- **Upgrade path:** 0003 → 0004 with a pre-existing unknown tool row, which fails sync with `risk_attributes` as the only drift.
- **Operational:** a broken tenant does not stop sealing for others; metrics expose no ids; timeline fields.

### 3.4 Mutation checks (remove the protection; a test must fail)
All 17 were caught on the first run:
- **Risk engine:**
  - a missing factor escapes rules;
  - a missing factor is scored at its best value;
  - a missing base_risk is ignored;
  - rule floors are ignored;
  - the destination suffix match drops the dot;
  - a declared delegation depth is ignored.
- **Policy engine:**
  - the risk-forced effect is ignored;
  - the CRITICAL default becomes approval;
  - the least restrictive effect wins.
- **Policy identity and storage:**
  - the digest is computed without its tag;
  - the store accepts a changed version;
  - the stored digest is not re-checked.
- **Evidence:** executor events do not inherit the action's risk.
- **Sealing:**
  - risk triggers are ignored;
  - a HIGH seal stops at the first urgent event;
  - anchor priority is always ROUTINE;
  - MEDIUM uses LOW's age.

A separate regression test exists for the drain bug fixed this phase. It fails on the old code and passes on the new.

### 3.5 Labeled dataset (start of RQ/E4): local, preliminary
67 actions across the 6 tools plus unknown tools: 24 routine, 30 adversarial, 7 delegation, 6 volume.

**First run, before any adjustment:** level 64/67, decision 65/67.

| Level: label \ engine | LOW | MEDIUM | HIGH | CRITICAL |
|---|---|---|---|---|
| LOW | 5 | 1 | 0 | 0 |
| MEDIUM | 0 | 12 | 0 | 0 |
| HIGH | 0 | 0 | 29 | 1 |
| CRITICAL | 0 | 0 | 1 | 18 |

| Decision: label \ engine | ALLOW | REQUIRE_APPROVAL | DENY |
|---|---|---|---|
| ALLOW | 16 | 0 | 0 |
| REQUIRE_APPROVAL | 0 | 23 | 0 |
| DENY | 0 | 2 | 26 |

How the 4 disagreements were resolved:
- **Policy fixed (2 cases):** both engine errors were too permissive (L50, L61: untrusted agent touching PII or IAM). The new rule `MR-UNTRUSTED-SENSITIVE` covers them.
- **Relabeled (2 cases), each with a written rationale:** L04 (level only; same decision) and L54 (an invalid-args case where the label had not applied missing ⇒ worst).

**Final:** 67/67 and 67/67. Inputs that reproduce the first run are in `experiments/risk/results/`. Labels and weights share an author, so this measures consistency, not validity.

### 3.6 Fixed 100-event vs adaptive sealing: local, preliminary, **simulated**
`seal_comparison.py`: production `decide()`, 1 s tick, receipts appended. The workload is synthetic: Poisson arrivals with a mix of LOW 80% / MEDIUM 15% / HIGH 4% / CRITICAL 1%; 5 seeds × 1 h.

| Actions/s | Policy | Epochs/h | Max unsealed s, HIGH+CRIT | p95 s, HIGH+CRIT | Mean s, all events |
|---|---|---|---|---|---|
| 0.05 | fixed-100 | 12 | 300.8 | 283.5 | 157.7 |
| 0.05 | adaptive (default) | 32 | 1.0 | 0.9 | 72.5 |
| 0.5 | fixed-100 | 89 | 300.6 | 48.7 | 22.2 |
| 0.5 | adaptive (default) | 135 | 1.0 | 0.9 | 17.2 |
| 5.0 | fixed-100 | 887 | 299.0* | 5.0 | 2.6 |
| 5.0 | adaptive (default) | 1293 | 1.0 | 1.0 | 2.2 |
| 5.0 | adaptive (`strictest`) | 3669 | 1.0 | 1.0 | 1.3 |

\* Fixed-100's maximum is set by the end-of-run partial batch waiting for the 300 s age rule; its p95 is the more representative number.

**Reading.** Adaptive sealing bounds HIGH and CRITICAL unsealed time to one tick, against up to 300 s for fixed. The cost is 1.5–2.7× more epochs, which means more future anchors. No DB, network or concurrency effects are modelled.

## 4. Known limits and gaps
- **Unverifiable inputs.** Delegation depth is agent-declared and the trust tier is admin-set; the gateway cannot verify either, so both can only raise risk. Delegation provenance is a later phase.
- **Anchoring amplification.** Unknown-tool calls, missing-scope calls and AGENT_ID_MISMATCH are HIGH and seal at once. A misbehaving agent can force many small epochs. There is no rate limiting yet.
- **Approvals.** HIGH and CRITICAL-exception actions stay `PENDING_APPROVAL`. The approval API and UI are Phase 5.
- **CRITICAL-authorization epoch.** The separate `[s, s]` epoch for a CRITICAL authorization (09 §2) needs approvals and anchoring, so it is not built. `anchor_priority = CRITICAL` is the hook.
- **Anchor priority.** `anchor_priority` is not in the `agw-epochs/v1` export or the epoch API yet (operational only; Phase 6 consumes it).
- **Policy loading.** The active risk policy is the latest stored version of `AGW_RISK_POLICY_ID`. Storing a new version takes effect on the next request without a restart. No admin command to load a policy file exists yet (startup sync or `store_risk_policy`).
- **Metrics.** Worker metrics have no tenant label, which is a deliberate cardinality and privacy choice. Gateway `/metrics` is unauthenticated and must be restricted at the network layer.
- **Experiments.** The comparison is a simulation; the workload mix and every threshold are hypotheses.
- **Coverage.** `phase4_mocks.py` adapters are 84% covered: the export and IAM adapters are never dispatched, because policy never allows them yet.
- **Numbering.** The phase numbers in the prompts still differ from `13-roadmap.md`. This was flagged in Phases 2 and 3 and is still open.

## 5. Ready for the next phase
- **Approvals.** HIGH and CRITICAL-exception actions already stop in `PENDING_APPROVAL` with `APPROVAL_REQUIRED` evidence. POLICY_EVALUATED records the risk-policy digest and the document version that an approval binding must include (04 §5).
- **Anchoring.** `epochs.anchor_priority` (ROUTINE / PRIORITY / CRITICAL) and the RISK_* seal reasons are what the anchoring phase needs to order and gate submissions.
