# ai-agent-audit-gateway

An active gateway that sits on the execution path between AI agents and the tools they call.
It **enforces** (authenticated agents, registered tools only, deterministic deny-by-default
policy, outbox-gated dispatch) and it records **evidence** (append-only lifecycle events, made
tamper-evident in later phases with deterministic CBOR, hash chains, Merkle epochs and on-chain
anchors). Design, threat model and roadmap: [docs/gateway/README.md](docs/gateway/README.md).

## Quick start (Phase 1)

```sh
make up        # Postgres 16 via docker compose (creates .env from .env.example if missing)
make migrate   # alembic upgrade head as agw_migrator
make test      # ruff + mypy + import-linter + pytest (Testcontainers) with coverage gate
make demo      # seed demo tenant/agents, start gateway, run the scripted agent
make down      # stop and remove the stack
```
