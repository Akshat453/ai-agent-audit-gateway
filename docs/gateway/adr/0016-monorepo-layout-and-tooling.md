# ADR-0016: Monorepo layout and tooling
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Decision
Layout per 00 §2: `apps/{gateway,worker,dashboard}`, `packages/{gateway-sdk,verifier,schemas}`, `contracts/`, `examples/`, `experiments/`, `infra/`, `docs/gateway/`, plus root `pyproject.toml` (uv workspace), `uv.lock`, `Makefile`, `docker-compose.yml`, `.env.example`. Refinements: `apps/gateway/migrations/`, `src/` layout, `.github/workflows/`, per-package `tests/`. Tooling: uv, ruff, mypy (strict for gateway, verifier, schemas), pytest, Hypothesis, Testcontainers, import-linter. `packages/verifier` MUST NOT import `apps/*`.
## Consequences
+ The verifier's independence is machine-checked. + Reproducible clean-checkout builds.
− A single lockfile couples dependency upgrades across packages (acceptable at this size).
