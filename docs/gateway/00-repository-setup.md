# 00 — Repository Setup

Status: Accepted (Phase 0). Related ADR: [ADR-0016](adr/0016-monorepo-layout-and-tooling.md).

## 1. What exists today (inspected 2026-11-15)

The repository `ai-agent-audit-gateway` is greenfield. At Phase 0 start it contained only:

```
ai-agent-audit-gateway/
  docs/gateway/papers/2609.01931v1-bindschaedler-agent-flight-recorder.pdf
  docs/gateway/papers/2609.04017v1-bromme-black-box-agentic-processes.pdf
```

There was **no** root `README.md`, **no** `.gitignore`, and the directory was **not** a git
repository. Phase 0 may only create files under `docs/`. These three items are therefore the
first tasks of Phase 1 (see [14-phase-1-handoff.md](14-phase-1-handoff.md) §0):
`git init`, root `README.md`, root `.gitignore`.

## 2. Monorepo layout

This is the layout from the Phase 0 addendum (item E), refined only where a reason is given.
Phase 1 acceptance requires "no files outside this layout".

```
ai-agent-audit-gateway/
├── apps/
│   ├── gateway/                    # FastAPI service — the enforcement point
│   │   ├── pyproject.toml          # package: agw-gateway, import: agw_gateway
│   │   ├── alembic.ini
│   │   ├── migrations/             # Alembic env + versions   (refinement: Alembic needs a home)
│   │   ├── src/agw_gateway/
│   │   │   ├── api/                # routers, error model, request-id middleware
│   │   │   ├── auth/               # API-key auth (Phase 1); mTLS/OIDC later
│   │   │   ├── tools/              # registry, tool metadata, adapters/ (demo tools)
│   │   │   ├── policies/           # pure policy engine + policy document models
│   │   │   ├── risk/               # pure risk classifier
│   │   │   ├── approvals/          # (Phase 4) approval binding + API
│   │   │   ├── execution/          # action service, executor, reconciliation
│   │   │   ├── evidence/           # lifecycle event writer, seq allocation
│   │   │   ├── crypto/             # (Phase 2/5) tags, hashing, AES-GCM envelope
│   │   │   ├── merkle/             # (Phase 3) RFC 9162 tree + proofs
│   │   │   ├── anchoring/          # (Phase 6) anchor client interface
│   │   │   ├── db/                 # SQLAlchemy models, session, roles
│   │   │   └── config.py           # pydantic-settings
│   │   └── tests/{unit,integration,property,e2e}/
│   ├── worker/                     # long-running jobs: outbox, sealing, anchoring, monitoring
│   │   ├── pyproject.toml          # package: agw-worker, import: agw_worker
│   │   ├── src/agw_worker/{outbox,sealing,anchoring,monitoring}/
│   │   └── tests/
│   └── dashboard/                  # (Phase 9) Next.js + TypeScript + Tailwind
├── packages/
│   ├── gateway-sdk/                # thin Python agent client (import: agw_sdk)
│   ├── verifier/                   # standalone verifier CLI (import: agw_verifier) — NO imports from apps/
│   └── schemas/                    # versioned event schemas, CBOR profile, test-vectors/
│       └── test-vectors/           # frozen in Phase 3 (see 06 §9)
├── contracts/                      # (Phase 6) Solidity + Foundry: src/, test/, script/, foundry.toml
├── examples/
│   ├── single-agent/               # Phase 1 scripted + optional LLM agent
│   └── multi-agent/                # (Phase 10)
├── experiments/
│   ├── benchmarks/  tampering/  risk/  ablations/
├── infra/
│   ├── docker/                     # Dockerfiles, Postgres init SQL (roles), MinIO bootstrap
│   └── grafana/                    # (later) dashboards
├── docs/gateway/                   # all specs + adr/ + papers/
├── docker-compose.yml
├── pyproject.toml                  # uv workspace root (no code)
├── uv.lock
├── Makefile
├── .env.example
├── .gitignore  README.md           # Phase 1 step 0
└── .github/workflows/ci.yml        # refinement: CI must live here for GitHub Actions
```

Refinements to the addendum layout, with reasons:

| Refinement | Reason |
|---|---|
| `apps/gateway/migrations/` | Alembic needs a script directory. It belongs to the service that owns the schema. |
| `src/` layout in every Python package | Tests can't accidentally import the working tree instead of the installed package. It also makes the import-boundary checks meaningful. |
| `.github/workflows/` | GitHub Actions only reads workflows from this path. |
| `apps/*/tests/` instead of a top-level `tests/` | Tests sit next to the package they verify. Cross-package end-to-end tests live in `apps/gateway/tests/e2e/`, because the gateway is the system under test. |

## 3. Package boundaries

```mermaid
flowchart LR
  schemas[packages/schemas]
  verifier[packages/verifier] --> schemas
  sdk[packages/gateway-sdk]
  gateway[apps/gateway] --> schemas
  worker[apps/worker] --> gateway
  worker --> schemas
  examples --> sdk
  experiments --> sdk
  experiments --> verifier
```

| Package | May import | MUST NOT import | Why |
|---|---|---|---|
| `packages/schemas` | stdlib, `cbor2` | anything internal | The leaf of the graph. It holds the normative CBOR profile and the test vectors. |
| `packages/verifier` | `packages/schemas`, stdlib, `cryptography`, `web3` (read-only RPC) | `apps/*`, `packages/gateway-sdk` | A third party must be able to verify without trusting or running our live system. The verifier re-implements the hashing and Merkle code from the spec (06) and does not reuse gateway code, so a bug in the gateway can't hide in shared code. |
| `packages/gateway-sdk` | `httpx`, `pydantic` | `apps/*` | Agents get a small dependency footprint with no server internals. |
| `apps/gateway` | `packages/schemas` | `apps/worker`, `packages/verifier` | |
| `apps/worker` | `apps/gateway` (domain + db modules), `packages/schemas` | `packages/verifier` | The worker runs in the same trust domain and on the same DB as the gateway. Sharing the models avoids two copies of the state machine. |

Enforcement: these rules are enforced in CI with `import-linter` contracts (added in Phase 1),
not by convention. The verifier contract is the critical one.

## 4. Python tooling

| Concern | Choice | Notes |
|---|---|---|
| Interpreter | CPython 3.12 (min). CI tests 3.12 and 3.13. | `requires-python = ">=3.12"` |
| Env + lock | **uv** workspace. Root `pyproject.toml` lists members `apps/*`, `packages/*`. One `uv.lock` is committed. | Gives exact pins for reproducible `make test` from a clean checkout. Rejected pip-tools: it doesn't manage workspaces natively, which would mean per-package lockfiles and drift. |
| Lint + format | **ruff** (`ruff check`, `ruff format`). Rule sets: E, F, W, I, B, UP, S (bandit), SIM, PL, RUF. | `S` catches `assert` in prod code, hard-coded secrets and `pickle`. |
| Types | **mypy**: `strict = true` for `agw_gateway`, `agw_verifier` and `agw_schemas`. Non-strict but checked for the worker, SDK and examples. | The verifier is security-critical too. |
| Tests | **pytest**, **pytest-cov**, **Hypothesis**, **Testcontainers** (`postgres:16`). | |
| Import rules | **import-linter** | See §3. |

## 5. Node tooling (Phase 9 only)

Node LTS pinned via `apps/dashboard/.nvmrc`, **pnpm** with a committed `pnpm-lock.yaml`,
ESLint + Prettier, `tsc --noEmit` in CI. No Node tooling is introduced before Phase 9.

## 6. Test layout and categories

| Directory | Contents | Runs against |
|---|---|---|
| `tests/unit/` | Pure functions: policy, risk, CBOR profile, hashing, Merkle | nothing external |
| `tests/property/` | Hypothesis properties (e.g. "unregistered or invalid calls never reach an adapter"; "Merkle proof verifies iff leaf is in tree") | nothing external |
| `tests/integration/` | DB triggers, role grants, outbox, idempotency races | Testcontainers Postgres 16 |
| `tests/e2e/` | HTTP → DB → adapter, crash-hook injection | Testcontainers + in-process app |
| `packages/schemas/test-vectors/` | Frozen JSON vectors (Phase 3) | consumed by gateway **and** verifier tests |
| `experiments/*` | Benchmarks and tamper/ablation runs. Not part of `make test`. | docker-compose stack |

Each security invariant gets a test that was seen to fail before the code that makes it pass
(Master Context, rule 4). PR descriptions show the failing run.

Pytest markers: `unit`, `property`, `integration`, `e2e`, `slow`. `make test` runs all except
`slow`.

## 7. Environment-variable conventions

- Every setting has the prefix `AGW_` and is read only through `pydantic-settings` in `config.py`.
- Required settings have no default. A missing one fails startup with the setting's *name*,
  never its value.
- Secrets can be supplied either as `AGW_<NAME>` or as `AGW_<NAME>_FILE` (a path, for Docker
  secrets). Secret values are typed `SecretStr` and never logged.
- `.env.example` lists every variable with a placeholder (`change-me`, `postgresql://agw_app:change-me@localhost:5432/agw`). Real `.env` is git-ignored.

| Variable | Phase | Required | Example placeholder |
|---|---|---|---|
| `AGW_ENV` | 1 | yes | `dev` (`dev`/`test`/`staging`/`prod`) |
| `AGW_DATABASE_URL` | 1 | yes | `postgresql+psycopg://agw_app:change-me@localhost:5432/agw` |
| `AGW_MIGRATOR_DATABASE_URL` | 1 | for `make migrate` | `postgresql+psycopg://agw_migrator:change-me@localhost:5432/agw` |
| `AGW_LOG_LEVEL` | 1 | no (`INFO`) | |
| `AGW_EXECUTOR_MODE` | 1 | no (`inprocess`) | `inprocess` / `worker` |
| `AGW_DEMO_SANDBOX_DIR` | 1 | demo only | `./.sandbox` |
| `AGW_DEMO_CORPUS_DIR` | 1 | demo only | `./examples/single-agent/corpus` (read-only corpus for `public_doc_search`) |
| `AGW_PG_HOST_PORT` | 1 | compose only | `54329` (host port of the compose Postgres; 5432 is often taken locally) |
| `AGW_KEK_FILE` | 5 | yes in Phase 5+ | `./secrets/dev-kek.bin` |
| `AGW_S3_ENDPOINT`, `AGW_S3_ACCESS_KEY`, `AGW_S3_SECRET_KEY` | 5 | Phase 5+ | |
| `AGW_CHAIN_RPC_URL`, `AGW_CHAIN_ID`, `AGW_ANCHOR_CONTRACT`, `AGW_ANCHOR_SIGNER_KEY_FILE` | 6 | Phase 6+ | `84532` for Base Sepolia, `31337` for Anvil |
| `AGW_EPOCH_MAX_EVENTS`, `AGW_EPOCH_MAX_AGE_SECONDS`, `AGW_ANCHOR_FINALITY`, `AGW_CRITICAL_ANCHOR_TIMEOUT_SECONDS` | 3/6 | no (defaults in 09) | |

## 8. Make targets

| Target | Phase | Does |
|---|---|---|
| `make up` | 1 | `docker compose up -d --wait` (Postgres 16; MinIO from Phase 5; Anvil from Phase 6) |
| `make migrate` | 1 | `alembic upgrade head` as `agw_migrator` |
| `make test` | 1 | ruff + mypy + pytest (non-slow) with coverage gates |
| `make lint` | 1 | `ruff check`, `ruff format --check`, `mypy`, `lint-imports` |
| `make demo` | 1 | seed demo tenant/agent/tools/policy, run `examples/single-agent` scripted agent |
| `make down` | 1 | `docker compose down -v` |
| `make vectors` | 3 | regenerate test vectors into a temp dir and **diff** against the frozen ones (never overwrite) |
| `make contracts` | 6 | `forge build && forge test` |

## 9. CI plan (GitHub Actions)

One workflow, `ci.yml`, triggered on every PR and on pushes to `main`:

| Job | Steps | Blocks merge |
|---|---|---|
| `lint` | uv sync --frozen, ruff check, ruff format --check, mypy, lint-imports | yes |
| `unit` | pytest -m "unit or property" with coverage | yes |
| `integration` | pytest -m "integration or e2e" (Docker is available on `ubuntu-latest` runners for Testcontainers) | yes |
| `coverage-gate` | ≥ 85% line coverage on `policies`, `auth`, `tools`, `execution` (Phase 1 acceptance) | yes |
| `vectors` (Phase 3+) | gateway **and** verifier both reproduce every frozen vector | yes |
| `contracts` (Phase 6+) | foundry toolchain, forge test | yes |
| `secrets-scan` | gitleaks over the diff | yes |

CI never holds testnet keys. Base Sepolia runs are manual, local experiments (Phase 6/8).

## 10. Branch-per-phase workflow

- `main` holds only accepted phases. Each phase works on `phase/<n>-<slug>`, e.g.
  `phase/1-core-gateway`.
- A phase is accepted when its acceptance checklist passes. Then it is merged to `main` via PR
  and tagged `phase-<n>-accepted`.
- Agents working on a phase MUST NOT pull, rebase, reset, switch branches, force-push or
  discard changes, and commit only if the phase prompt says so (Master Context, rule 2). The
  human owner does branch housekeeping.
- Locked decisions change only through a new ADR in `docs/gateway/adr/` that supersedes the old
  one. Old ADRs are never edited except for their `Status:` line.
- Phase 0 itself has not been committed. The directory is not yet a git repository (§1).
