# 14 — Phase 1 Handoff (Core Execution Gateway)

Status: Ready (Phase 0 output, 2026-11-15). **This document is the Phase 1 backlog. Follow §9
in order.** Read first: README, 02, 04, 05, 08, 11, this file, all ADRs.

Phase 1 **out of scope**: CBOR, hashing of events, Merkle, anchoring, encryption, approval API,
dashboard, MCP. Leave interfaces (e.g. `canonical_bytes` column, `outbox_jobs.kind`), not features.

## 0. Repository bootstrap (Phase 0 could not do this: docs-only)

1. `git init`. Create `README.md` (one-paragraph purpose + link to `docs/gateway/README.md`) and
   `.gitignore` (Python, uv, `.env`, `.sandbox/`, `secrets/`, Node, Foundry `out/` `cache/`).
2. Work on branch `phase/1-core-gateway` (00 §10). Commit only if the Phase 1 prompt says so.
   (The prompt's acceptance asks for `git diff --stat`, which needs the repo initialized.)

## 1. Demo tools

| tool_id | version | operation | sensitivity | base_risk | env allowed | idempotent | external | target_field | Args model (strict, `extra="forbid"`) | Adapter behaviour | Default decision |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `public_doc_search` | 1.0.0 | read | public | **LOW** | dev, staging, prod | yes | no | — | `query: str (1..256)`, `limit: int (1..20) = 5` | Searches a fixed in-repo corpus (`examples/single-agent/corpus/`, read-only). Returns ids + titles. | **ALLOW** |
| `create_ticket` | 1.0.0 | create | internal | **MEDIUM** | dev, staging | **no** | no | — | `title: str (1..120)`, `body: str (0..4000)`, `priority: Literal["low","normal","high"] = "normal"` | Inserts into `demo.tickets` (local table) with `created_by_action = action_id` | **ALLOW** |
| `delete_record` | 1.0.0 | delete | confidential | **CRITICAL** | dev | no | no | `record_id` | `record_id: UUID` | Would delete from `demo.records`. **Unreachable under the default policy.** | **DENY** (`deny-delete-record`, `deny-critical`) |

Scopes: demo agent `demo-agent` gets `tools:public_doc_search`, `tools:create_ticket`,
`tools:delete_record`. It *has* the delete scope on purpose, so the DENY demonstrably comes
from policy and not from a missing scope. A second agent `demo-readonly` gets only
`tools:public_doc_search` (for missing-scope tests).

Sandboxing: adapters touch only `AGW_DEMO_SANDBOX_DIR` and the `demo` schema. No network.

## 2. Agent authentication (Phase 1 mechanism; ADR-0015)

Per-agent API key, sent as `Authorization: Bearer agw_<key_id>_<secret>`. Stored only as
`H(TAG("AGW/apikey/v1") ‖ token)` (SHA-256), compared in constant time. Identity comes only
from the credential. Full contract in [11 §3](11-api-and-data-contracts.md). Keys are created
by `python -m agw_gateway.admin create-agent-key --tenant demo --agent demo-agent`, which prints
the token once. mTLS/OIDC come later (Phase 10).

## 3. Exact Phase 1 table list

The Phase 1 prompt names 8 tables. This list is a **superset of 11**, with reasons: `tenants`
is required for the per-tenant chain and seq (ADR-0008/0018), and the two `demo.*` tables are
required by the demo tools ("writes to a local table").

| # | Table | Kind | Key columns (types) | Constraints / notes |
|---|---|---|---|---|
| 1 | `tenants` | operational | `tenant_id text PK` (05 §4 regex), `display_name text`, `next_seq bigint NOT NULL DEFAULT 0`, `created_at timestamptz` | `agw_app`: SELECT + column UPDATE(`next_seq`). Phase 2 adds `head_event_hash bytea`. |
| 2 | `agents` | operational | `agent_id uuid PK`, `tenant_id FK`, `name text`, `scopes text[]`, `status text CHECK (active,disabled)`, `created_at` | UNIQUE(`tenant_id`,`name`) |
| 3 | `agent_credentials` | operational | `credential_id uuid PK`, `agent_id FK`, `key_id text UNIQUE`, `key_digest bytea CHECK (octet_length=32)`, `created_at`, `expires_at NULL`, `revoked_at NULL` | No plaintext column, ever |
| 4 | `tool_registry` | reference | PK(`tool_id`,`version`), `operation_type`, `sensitivity`, `base_risk`, `environments_allowed text[]`, `required_scope`, `is_idempotent bool`, `external_effect bool`, `target_field NULL`, `tags text[]`, `args_schema jsonb`, `adapter text`, `enabled bool`, `registered_at` | Synced from code at startup (11 §4) |
| 5 | `policies` | **evidence (append-only)** | PK(`policy_id`,`version int`), `document jsonb`, `created_at`, `created_by text` | Same grants and triggers as `evidence_events`. Active = highest version. Loader rejects `default_effect ≠ DENY`. |
| 6 | `actions` | operational (mutable) | `action_id uuid PK` (UUIDv7), `tenant_id`, `agent_id FK`, `run_id uuid`, `tool_id`, `tool_version`, `environment`, `status text CHECK (…)`, `decision text`, `risk_level text`, `policy_id`, `policy_version`, `idempotency_key text`, `result_public jsonb NULL`, `error_code text NULL`, `created_at`, `updated_at`, `version int` | Index (`agent_id`,`run_id`). Status set: DENIED, PENDING_APPROVAL, AUTHORIZED, DISPATCHED, COMPLETED, FAILED, OUTCOME_UNKNOWN. |
| 7 | `evidence_events` | **evidence (append-only)** | `event_id uuid PK` (UUIDv7), `tenant_id FK`, `seq bigint NOT NULL`, `event_type text CHECK (…)`, `schema_version smallint NOT NULL DEFAULT 1`, `action_id uuid NULL`, `run_id uuid NULL`, `agent_id uuid NULL`, `occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()`, `body jsonb NOT NULL`, `canonical_bytes bytea NULL` | UNIQUE(`tenant_id`,`seq`). Index (`action_id`,`seq`), (`run_id`,`seq`). `REVOKE UPDATE, DELETE, TRUNCATE`. Row trigger BEFORE UPDATE OR DELETE + statement trigger BEFORE TRUNCATE → raise. **No hash columns in Phase 1.** |
| 8 | `outbox_jobs` | operational | `job_id bigserial PK`, `kind text CHECK (DISPATCH)` (Phase 3 adds SEAL, ANCHOR), `tenant_id`, `action_id uuid NULL`, `status text CHECK (PENDING,CLAIMED,DONE,FAILED)`, `available_at`, `attempts int`, `claimed_by text NULL`, `lease_expires_at NULL`, `last_error_code NULL`, `args jsonb NULL` ([ADR-0020](adr/0020-phase1-dispatch-args-in-outbox.md)), `created_at` | Partial UNIQUE(`action_id`) WHERE kind='DISPATCH'. Index (`status`,`available_at`). |
| 9 | `idempotency_keys` | operational | PK(`agent_id`,`key`), `fingerprint bytea`, `fingerprint_alg text`, `action_id uuid`, `response_status int`, `response_body jsonb`, `created_at`, `expires_at` | Inserted first in tx1 (08 §5) |
| 10 | `demo.tickets` | demo | `ticket_id uuid PK`, `title`, `body`, `priority`, `created_by_action uuid UNIQUE`, `created_at` | Schema `demo`. Not evidence. |
| 11 | `demo.records` | demo | `record_id uuid PK`, `content text`, `created_at` | Seeded with 3 rows |

DB roles (created by `infra/docker/postgres/init/*.sql`): `agw_migrator` (owner, runs Alembic)
and `agw_app` (runtime, least privilege). Passwords come from `.env`, with placeholders only in
`.env.example`.

## 4. Event types used in Phase 1

`ACTION_REQUESTED`, `POLICY_EVALUATED`, `ACTION_DENIED`, `APPROVAL_REQUIRED`,
`ACTION_AUTHORIZED`, `ACTION_DISPATCHED`, `ACTION_COMPLETED`, `ACTION_FAILED`,
`ACTION_OUTCOME_UNKNOWN`, `SECURITY_VIOLATION`. `body` uses the 05 §4 key names. Events are
appended via a single `EvidenceWriter.append(session, tenant_id, events: list[...])` that
allocates seq with the `tenants` row lock (08 §3). Phase 2 swaps the encoding inside this one
function.

## 5. Endpoints

`POST /v1/actions`, `GET /v1/actions/{id}`, `GET /v1/tools`, `GET /v1/runs/{id}/timeline`,
`GET /v1/health`, `GET /v1/ready`. Exact contracts: [11 §5](11-api-and-data-contracts.md).
Error model: 11 §2.

## 6. Policy and risk

Risk v1 (04 §2) and policy v1 (04 §3–4) are pure functions in `agw_gateway.risk` and
`agw_gateway.policies`. The default policy document is 04 §4.1, seeded as `default` v1.
REQUIRE_APPROVAL leaves the action in `PENDING_APPROVAL` with an `APPROVAL_REQUIRED` event (no
approval API).

## 7. Request flow

As in 02 §3 and 08 §1/§4. In-process executor reading from `outbox_jobs`. Reconciler for
lease-expired DISPATCHED (08 §7). Crash hooks: a test-only `CrashPoints` injectable
(`after_tx1_commit`, `after_claim`, `after_dispatch_commit`, `after_adapter_return`) raising
`SimulatedCrash`. It is disabled unless `AGW_ENV=test`.

## 8. Forward-compatibility rule for Phase 2

Phase 1 events have `canonical_bytes = NULL`, and they can't be backfilled because the table is
append-only. Phase 2's migration MUST refuse to run while `evidence_events` holds rows with
NULL `canonical_bytes`. The only exception is `AGW_ALLOW_DEV_EVIDENCE_RESET=1` in `dev`/`test`,
which drops and recreates the dev evidence. Phase 1 data is dev-only by definition. Genesis
(`seq = 0`, `prev = ZERO32`) is then the first Phase 2 event of each tenant.

## 9. Ordered backlog

Tests first for every invariant (write the test, see it fail, then implement).

| # | Task | Invariants / tests |
|---|---|---|
| 1 | §0 bootstrap. uv workspace (`apps/gateway`, `apps/worker` stub, `packages/gateway-sdk`, `packages/schemas` stub, `packages/verifier` stub). ruff, mypy strict on `agw_gateway`, pytest, import-linter contracts. Makefile `up test lint migrate demo down`. | `make lint` green on empty packages |
| 2 | `config.py` with pydantic-settings (00 §7). `.env.example`. | Missing `AGW_DATABASE_URL` → startup error naming the variable, not echoing values |
| 3 | `docker-compose.yml` (Postgres 16 with healthcheck) + role init SQL | `make up` waits healthy |
| 4 | Alembic migration: 11 tables, grants, triggers | **INV-4**: UPDATE/DELETE/TRUNCATE as `agw_app` → 42501. As `agw_migrator` → trigger error. Same for `policies`. |
| 5 | Auth (11 §3) + admin CLI | **INV-1**, **INV-7**: no header / bad token / revoked / unknown id → 401 and no `ACTION_DISPATCHED` anywhere. Spoofed body `agent_id` → 403 + `SECURITY_VIOLATION` row. |
| 6 | Tool registry + 3 demo adapters + spy adapter for tests | Unknown tool → DENY. Bad args → DENY. Forbidden env → DENY. Missing scope → DENY. Spy adapter fails the test if invoked. |
| 7 | Risk v1 + Policy v1 (pure) | Unit tests per rule. Demo table 04 §6. Policy loader rejects ALLOW default and unknown match keys. |
| 8 | `EvidenceWriter` + action service tx1 + idempotency | Ordering REQUESTED < EVALUATED < AUTHORIZED. Replay → same body + `Idempotent-Replayed`. Different body → 409. **INV-5**: 20 concurrent → 1 action. |
| 9 | Executor (outbox claim, DISPATCHED, adapter, result) + reconciler + crash hooks | **INV-3**: crash at `after_tx1_commit` → adapter not called and AUTHORIZED row committed. Full ALLOW ordering through COMPLETED. **INV-6**: crash after DISPATCHED → OUTCOME_UNKNOWN, call count unchanged. |
| 10 | Endpoints + error model + log allow-list | Canary arg never appears in logs or error bodies (T24). `GET /v1/tools` filtered by scope. Timeline only for own runs. Other agent's action → 404. |
| 11 | Fail closed | DB stopped (Testcontainers `stop()`) → `POST /v1/actions` 503, `/v1/ready` 503, adapter never called (**T23**) |
| 12 | Hypothesis property | **INV-2**: random tool names and arg dicts never reach an adapter unless registered **and** valid **and** allowed |
| 13 | SDK (`agw_sdk.Client`) + `examples/single-agent` scripted agent + optional LLM agent behind `--llm` flag (off by default, needs an API key env var, not run in CI) | `make demo` shows: search ALLOW→COMPLETED. Unknown tool DENIED. `delete_record` DENIED. Bad args DENIED. |
| 14 | Coverage ≥ 85% on `policies`, `auth`, `tools`, `execution`. ruff + mypy clean. `git diff --stat` shows only layout paths. | Phase 1 acceptance |

## 10. Acceptance (from the Phase 1 prompt, restated)

`make up && make migrate && make test && make demo` succeed from a clean checkout. Coverage ≥ 85%
on policy, auth, registry and action flow. ruff and mypy clean. No files outside the 00 §2
layout. The report lists files built, commands with their output, the test list with pass
status, any deviations (with ADR), known gaps, and readiness for Phase 2. Then STOP.
