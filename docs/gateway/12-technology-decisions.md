# 12 — Technology Decisions

Status: Accepted (Phase 0). The stack is evaluated on its merits for a greenfield project.
Exact versions are pinned in `uv.lock` / `foundry.toml` / `pnpm-lock.yaml` when each phase
introduces them, not here. Re-evaluate any row only when its "revisit when" condition is
measured.

## 1. Chosen stack

| Concern | Choice | Why | Rejected alternatives | Revisit when |
|---|---|---|---|---|
| Language | Python ≥ 3.12 | `hashlib`, `cryptography` and web3.py are mature. One language for gateway, worker, verifier, experiments. | Go/Rust (faster, but the hot path is a DB tx, not CPU) | Phase 8 shows CPU-bound p99 |
| HTTP | FastAPI + Pydantic v2 | Typed request models, strict validation (`extra="forbid"`, `strict=True`), JSON Schema export for `GET /v1/tools` | Flask (no typed validation), Django (too much ORM magic) | — |
| Config | pydantic-settings | Typed, fail-fast on missing required settings, `SecretStr` | dynaconf | — |
| DB | PostgreSQL 16 | Transactions for the outbox pattern, `FOR UPDATE SKIP LOCKED`, row/statement triggers, column-level grants, JSONB for derived views | MySQL (weaker trigger/grant story), SQLite (no concurrent writers) | — |
| ORM / migrations | SQLAlchemy 2 (**sync**, psycopg 3) + Alembic | Explicit transaction control. Sync keeps the crash-hook tests deterministic. FastAPI runs sync endpoints in a threadpool. | async SQLAlchemy (harder to reason about lock scopes in tests) | Phase 8 throughput limited by threadpool |
| Queue | Postgres transactional outbox + Python worker | The job is atomic with its evidence (ADR-0004). No second system to keep consistent. | Celery/Redis, Kafka: dual-write problem, more ops | Measured > ~1K jobs/s/tenant sustained need |
| Encoding | Deterministic CBOR via `cbor2`, wrapped by our AGW-CBOR-v1 profile validator | Paper B §III-B. Binary-safe. No float/key-order pitfalls of JSON (RFC 8785 needs number canonicalization). | JCS (Paper A §3 example), protobuf (not canonical by spec) | `cbor2` fails a profile vector → write a ~300-line profile encoder in `packages/schemas` (allowed by ADR-0005) |
| Hash | `hashlib.sha256` | Standard, constant across all hash types (ADR-0006) | SHA-512 (Paper A fn. 1), BLAKE3 (not FIPS) | Retention horizon or policy demands it → new tag version |
| AEAD | `cryptography` AESGCM | Audited, AES-NI | libsodium XChaCha20 (fine, but adds a dependency) | — |
| Object store | MinIO (S3 API) | Local S3 for bundles and large blobs. Same code works against S3 later. | Filesystem (no S3 parity) | — |
| Contracts | Solidity + Foundry (forge, anvil) | Fast tests, Anvil for local chains incl. reorg simulation | Hardhat (JS toolchain) | — |
| Chain client | web3.py | Python, async optional, receipts and block tags | ethers via Node (second runtime) | — |
| Testnet | Base Sepolia (84532) | EVM L2, low fees. Paper B §VI-D measured there (comparable gas). | Ethereum Sepolia (slower, pricier), multiple chains (no need) | — |
| Tests | pytest, Hypothesis, Testcontainers | Real Postgres for trigger/grant/lock tests. Property tests for INV-2 and Merkle. | Mocked DB (can't test triggers or locks) | — |
| Lint / types | ruff, mypy (strict), import-linter | Fast. Strict typing for security code. Enforced package boundaries. | flake8+black+isort (slower, more tools) | — |
| Env / deps | uv workspace + `uv.lock` | Reproducible clean-checkout builds | pip-tools, poetry | — |
| Dashboard | Next.js + TypeScript + Tailwind (Phase 9) | Standard. Read-only UI. | — | — |
| CI | GitHub Actions | Docker available for Testcontainers | — | — |
| Local orchestration | Docker Compose | Postgres, MinIO, Anvil, gateway, worker | Kubernetes (no need) | Multi-node deployment requirement |

## 2. Verification tasks the stack depends on

| Claim | How it will be checked | Phase |
|---|---|---|
| `cbor2` canonical output matches RFC 8949 §4.2.1 for our profile | `cbor-profile.json` vectors, including RFC 8949 Appendix A cases within the profile, round-trip + must-reject cases | 2 |
| Text-key ordering = bytewise lexicographic of encoded keys | dedicated vectors with keys of lengths 1, 23, 24, 255, 256 | 2 |
| `FOR UPDATE SKIP LOCKED` claim never double-dispatches | 20 concurrent executors, 1,000 jobs, count adapter calls | 1/2 |
| Postgres blocks the concurrent unique insert until commit (idempotency) | 20 concurrent identical POSTs | 1 |
| Anvil can simulate reorgs for anchor-state tests | `anvil_reorg` / snapshot-revert based test | 6 |

## 3. Not used (and why)

| Tech | Why not now | What would change that |
|---|---|---|
| Redis | No caching or locking need. Postgres holds all state transactionally. | Measured auth-lookup latency issue |
| Celery | Outbox + worker suffices. Celery adds broker dual-write. | — |
| Kafka | No fan-out consumers. Ordering is per tenant in Postgres. | External SIEM streaming requirement |
| Kubernetes | Single-node dev/test target | Production deployment |
| Multiple chains | One registry is enough for evidence. More chains multiply finality semantics. | A customer requires a specific chain |
| ML risk classifier | Authorization must be deterministic (ADR-0002). Rules are auditable. | Never for allow/deny. At most a raise-only advisory signal via ADR. |
| LLM in policy | Prompt-injectable (T5) | Never (ADR-0002) |
