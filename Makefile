# Phase 1 targets (docs/gateway/00 §8).
SHELL := /bin/bash
UV ?= uv
COV_PKGS := */agw_gateway/policies/*,*/agw_gateway/auth/*,*/agw_gateway/tools/*,*/agw_gateway/execution/*,*/agw_gateway/approvals/*,*/agw_gateway/humans/*,*/agw_gateway/anchoring/*,*/agw_worker/anchoring/*,*/agw_gateway/privacy/*,*/agw_gateway/keys/*,*/agw_gateway/delegation/*,*/agw_gateway/auth/*,*/agw_sdk/*,*/agw_langgraph/*,*/agw_mcp/*

.PHONY: backfill-targets dashboard-unit console-inventory start stop rebuild c2-mutations c3-mutations coding-policy coding-cli coding-mutations device-key up down migrate test lint demo sync vectors verify-isolated bench tamper risk-eval seal-compare dev-keys approval-attacks approval-mutations contracts-test contracts-check contracts-gas contracts-slither anchor-deploy-anvil anchor-gas anchor-mutations dev-kek privacy-mutations containment injection-corpus delegation-mutations dev-delegation-key integration-latency dashboard-api dashboard-check dashboard-e2e ui-up ui-screenshots monitoring-mutations rq1 rq2 rq3 rq4 rq5 rq6 rq7 experiments plots hardening hardening-ci

.env:
	cp .env.example .env

sync:
	$(UV) sync --frozen

up: .env
	docker compose up -d --wait

# DELETES every AgentGuard container AND data volume (database, local chain, files). Asks first;
# scripts/CI skip the question with `make down CONFIRM=yes`. To pause and keep data: make stop.
down:
	@if [ "$(CONFIRM)" != "yes" ]; then \
	  echo "make down DELETES all AgentGuard data: the database (accounts, runs, approvals, evidence),"; \
	  echo "the local blockchain and stored files. It cannot be undone. To pause and keep data: make stop"; \
	  printf "Type DELETE to continue: "; read ans || ans=""; \
	  if [ "$$ans" != "DELETE" ]; then echo "Cancelled. Nothing was deleted."; exit 1; fi; \
	fi
	docker compose --profile ui --profile monitoring down -v

migrate: .env sync
	set -a; . ./.env; set +a; cd apps/gateway && $(UV) run alembic upgrade head

lint: sync
	$(UV) run ruff check .
	$(UV) run ruff format --check .
	$(UV) run mypy apps/gateway/src apps/worker/src packages/gateway-sdk/src packages/schemas/src packages/verifier/src integrations/langgraph/src integrations/mcp/src packages/agw-cli/src
	$(UV) run lint-imports

test: lint
	$(UV) run pytest --cov --cov-report=term
	$(UV) run coverage report --include='$(COV_PKGS)' --fail-under=85
	$(UV) run coverage report --include='*/agw_gateway/risk/*' --fail-under=100

demo: .env sync
	./examples/single-agent/run_demo.sh

# Phase 5: dev Ed25519 approval-decision signing key (git-ignored secrets/; never overwritten).
dev-keys: sync
	@test -f secrets/approval-signing.key || $(UV) run python -m agw_gateway.admin gen-signing-key --out secrets/approval-signing.key

# Regenerate the frozen vectors in memory and fail on any difference (never overwrites).
vectors: sync
	$(UV) run --with cbor2 python packages/schemas/test-vectors/generate_phase2.py --check
	$(UV) run python packages/schemas/test-vectors/generate_phase3.py --check

# Install ONLY packages/verifier into a throwaway venv and run its CLI (independence check).
VERIFIER_VENV ?= $(shell python3 -c "import tempfile,os;print(os.path.join(tempfile.gettempdir(),'agw-verifier-venv'))")
verify-isolated:
	$(UV) venv -q --clear $(VERIFIER_VENV) --python 3.12
	$(UV) pip install -q --python $(VERIFIER_VENV)/bin/python ./packages/verifier
	$(UV) pip list --python $(VERIFIER_VENV)/bin/python
	$(VERIFIER_VENV)/bin/python -c "import importlib.util as u; bad=[m for m in ('agw_gateway','agw_schemas','pydantic','sqlalchemy') if u.find_spec(m)]; assert not bad, bad; print('isolated: no gateway/schemas/pydantic/sqlalchemy')"
	$(VERIFIER_VENV)/bin/agw-verify --help >/dev/null && echo "agw-verify runs from the isolated venv"
	@# Phase 7: the [disclosure] extra adds ONLY cryptography (HPKE/AES-GCM to open disclosures).
	$(UV) venv -q --clear $(VERIFIER_VENV)-disclosure --python 3.12
	$(UV) pip install -q --python $(VERIFIER_VENV)-disclosure/bin/python "./packages/verifier[disclosure]"
	$(VERIFIER_VENV)-disclosure/bin/python -c "import importlib.util as u; bad=[m for m in ('agw_gateway','agw_schemas','pydantic','sqlalchemy') if u.find_spec(m)]; assert not bad, bad; assert u.find_spec('cryptography'); print('isolated [disclosure]: verifier + cryptography only')"

bench: .env sync
	set -a; . ./.env; set +a; $(UV) run python experiments/benchmarks/phase2_event_latency.py

# Tamper matrix over real exports: make tamper EVENTS=events.jsonl EPOCHS=epochs.jsonl
tamper: sync
	$(UV) run python experiments/tampering/run_tamper_suite.py --events $(EVENTS) --epochs $(EPOCHS)

# Phase 4: labeled-action regression (confusion matrices) and fixed vs adaptive sealing (simulated).
risk-eval: sync
	$(UV) run python experiments/risk/risk_eval.py --strict

seal-compare: sync
	$(UV) run python experiments/risk/seal_comparison.py

# Phase 5: named approval attacks -> attack table (attempts, unauthorized executions).
approval-attacks: sync
	AGW_ATTACK_TABLE_OUT=experiments/approvals/results/attack-table.md $(UV) run pytest -q apps/gateway/tests/e2e/test_approval_attacks.py
	cat experiments/approvals/results/attack-table.md

# Phase 5: remove each approval guard in turn; its named test must fail.
approval-mutations: sync
	$(UV) run python experiments/approvals/mutation_check.py

# Phase 6 (ADR-0028): contracts run in the pinned Foundry image; nothing is installed on the host.
FOUNDRY_IMAGE := ghcr.io/foundry-rs/foundry:v1.3.5
FORGE := docker run --rm -v "$(CURDIR)/contracts":/work -w /work --entrypoint forge $(FOUNDRY_IMAGE)

contracts-test:
	$(FORGE) test -vv

# The committed artifact (ABI + bytecode) must equal a fresh build.
contracts-check:
	$(FORGE) build >/dev/null
	python3 contracts/tools/export_artifact.py --check

contracts-gas:
	$(FORGE) test --gas-report | sed -n '/EpochAnchor Contract/,/╰/p' | tee experiments/anchoring/results/forge-gas-report.txt

# Slither on an isolated copy of the source (it would otherwise call forge on the host).
contracts-slither:
	./contracts/tools/slither.sh

# Deploy to the compose Anvil via the Foundry script; writes contracts/deployments/anvil-31337.json.
anchor-deploy-anvil: sync
	./contracts/deploy-anvil.sh

# >= 30 real anchor transactions on a throwaway Anvil -> experiments/anchoring/results/gas-anvil-31337.*
anchor-gas: sync
	$(UV) run python experiments/anchoring/measure_gas.py --n 40

# Phase 6: remove each anchoring guard (worker, gate, verifier, contract); its named test must fail.
anchor-mutations: sync
	$(UV) run python experiments/anchoring/mutation_check.py

# Phase 7: dev KEK keyring OUTSIDE the repo (AGW_KEK_DIR, default ~/.agw/kek); never overwritten.
dev-kek: .env sync
	set -a; . ./.env; set +a; $(UV) run python -m agw_gateway.admin gen-kek --if-missing

# Phase 7: remove each encryption / minimization / disclosure guard; its named test must fail.
privacy-mutations: sync
	$(UV) run python experiments/privacy/mutation_check.py

# Phase 8 (ADR-0030): dev delegation-token signing key (git-ignored secrets/; never overwritten).
dev-delegation-key: sync
	$(UV) run python -m agw_gateway.admin gen-delegation-key --out secrets/delegation-signing.key --if-missing

# Phase 8: agent container whose ONLY route is the gateway; probes run inside it.
containment:
	bash examples/containment/run.sh

# Phase 8: prompt-injection corpus (>= 10 docs x 2 modes) -> results table, 0 unauthorized executions.
injection-corpus: sync
	AGW_INJECTION_TABLE_OUT=experiments/injection/results/injection-table.md $(UV) run pytest -q apps/gateway/tests/e2e/test_prompt_injection.py
	cat experiments/injection/results/injection-table.md

# Phase 8: remove each delegation / integration guard in turn; its named test must fail.
delegation-mutations: sync
	$(UV) run python experiments/delegation/mutation_check.py

# Phase 8: added latency per tool call (direct adapter vs SDK vs LangGraph vs MCP) + adapter LOC.
integration-latency: sync
	$(UV) run python experiments/integrations/measure.py

# Phase 9 (ADR-0031): dashboard. The typed client is generated from the gateway's OpenAPI.
dashboard-api: sync
	$(UV) run python -m agw_gateway.openapi --out apps/dashboard/openapi.json
	cd apps/dashboard && npm run gen:api

# Fails if the committed OpenAPI / generated types drifted from the code, or TS does not check.
DRIFT := $(shell python3 -c "import tempfile;print(tempfile.gettempdir())")/agw-openapi-check
dashboard-check: sync
	cd apps/dashboard && npm ci --no-audit --no-fund >/dev/null
	mkdir -p $(DRIFT)
	$(UV) run python -m agw_gateway.openapi --out $(DRIFT)/openapi.json
	diff -q $(DRIFT)/openapi.json apps/dashboard/openapi.json
	cd apps/dashboard && npx openapi-typescript openapi.json -o $(DRIFT)/schema.d.ts >/dev/null
	diff -q $(DRIFT)/schema.d.ts apps/dashboard/lib/api/schema.d.ts
	cd apps/dashboard && npm run typecheck
	cd apps/dashboard && npm run test:unit

# Plain-English console (ADR-0039): vocabulary unit tests + the field inventory from the code.
dashboard-unit:
	cd apps/dashboard && npm run test:unit
console-inventory:
	cd apps/dashboard && node scripts/inventory.mjs

# Playwright against a real gateway + seeded tenant + the production dashboard build.
dashboard-e2e: .env sync
	cd apps/dashboard && npm ci --no-audit --no-fund >/dev/null && npx playwright install chromium >/dev/null
	bash apps/dashboard/e2e/run.sh

# Whole stack in containers + Phase 8 demo data + dashboard on http://localhost:3000.
ui-up: .env
	docker compose --profile ui up -d --build

# One command each: start the whole stack (infra + gateway + worker + MCP + demo data +
# dashboard) and stop it. `stop` KEEPS the data volumes; `make down` deletes them.
# `start` reuses the built images (compose builds them only if they do not exist yet);
# after changing code, run `make rebuild` once.
start: .env
	docker compose --profile ui up -d
	@echo "Dashboard: http://localhost:3000  (new account: /signup; demo users when AGW_UI_SEED_DEMO=1)"
	@echo "Gateway:   http://localhost:8088  (agw login --url http://localhost:8088; MCP: /mcp)"

rebuild: .env
	docker compose --profile ui up -d --build
	@echo "Dashboard: http://localhost:3000  (new account: /signup; demo users when AGW_UI_SEED_DEMO=1)"
	@echo "Gateway:   http://localhost:8088  (agw login --url http://localhost:8088; MCP: /mcp)"

# ADR-0041: show the commands/paths of coding actions recorded before migration 0015 (once;
# idempotent; redacted like new actions; evidence is only read).
backfill-targets:
	docker compose --profile ui exec -T ui-gateway bash -c '. /app/infra/docker/ui/env.sh && python -m agw_gateway.admin backfill-coding-targets'

stop:
	docker compose --profile ui --profile monitoring stop

ui-screenshots:
	cd apps/dashboard && AGW_SHOT_PASSWORD="$$(grep '^AGW_UI_DEMO_PASSWORD=' ../../.env | cut -d= -f2-)" node scripts/screenshots.mjs

# Phase 9: remove each dashboard-API / step-up / reconcile / monitor / tracing guard in turn.
monitoring-mutations: sync
	$(UV) run python experiments/monitoring/mutation_check.py

# Phase 10 (ADR-0032): one command per experiment. Config: experiments/<rq>/config.toml
# (fixed seeds); raw CSV + env.json -> experiments/<rq>/results/. Needs Docker.
rq1: sync
	$(UV) run python -m experiments.rq1_latency.run
rq2: sync
	$(UV) run python -m experiments.rq2_batching.run
rq3: sync
	$(UV) run python -m experiments.rq3_tamper.run
rq4: sync
	$(UV) run python -m experiments.rq4_authz.run
rq5: sync
	$(UV) run python -m experiments.rq5_faults.run
rq6: sync
	$(UV) run python -m experiments.rq6_agents.run
rq7: sync
	$(UV) run python -m experiments.rq7_audit.run
# rq6 before rq2: rq2 replays the agent trace that rq6 records.
experiments: rq1 rq3 rq4 rq5 rq6 rq2 rq7

# Figures for results.md, generated ONLY from the raw CSVs.
plots: sync
	$(UV) run python -m experiments.plots

# Phase 10 hardening: scanners (network + Docker), DB least-privilege review, backup drill.
hardening: sync
	$(UV) run python -m experiments.hardening.run scans
	$(UV) run python -m experiments.hardening.run grants
	$(UV) run python -m experiments.hardening.run backup
hardening-ci: sync
	$(UV) run python -m experiments.hardening.run ci

# C1 (ADR-0034): coding-agent integration.
# The labeled coding-policy table (>= 100 actions incl. every MintRail trap) must pass 100 %.
coding-policy: sync
	$(UV) run pytest -q apps/gateway/tests/unit/test_coding_policy.py
# Every `agw hook` adapter + fail-closed behaviour (no gateway needed).
coding-cli: sync
	$(UV) run pytest -q packages/agw-cli/tests
# Remove each coding-security guard in turn; its named test must fail.
coding-mutations: sync
	$(UV) run python apps/gateway/tests/coding_mutation_check.py
# Issue a coding device key (printed once): make device-key TENANT=demo DEVELOPER=alice LABEL=laptop
device-key: .env sync
	set -a; . ./.env; set +a; $(UV) run python -m agw_gateway.admin create-device-key --tenant $(TENANT) --developer $(DEVELOPER) --label $(LABEL)

# C2 (ADR-0035): remove each connector / identity / repo-policy / CLI guard; its test must fail.
c2-mutations: sync
	$(UV) run python apps/gateway/tests/c2_mutation_check.py

# C3 (ADR-0036): remove each GitHub connector / evidence-check guard; its test must fail.
c3-mutations: sync
	$(UV) run python apps/gateway/tests/c3_mutation_check.py
