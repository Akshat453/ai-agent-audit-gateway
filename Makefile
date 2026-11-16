# Phase 1 targets (docs/gateway/00 §8).
SHELL := /bin/bash
UV ?= uv
COV_PKGS := */agw_gateway/policies/*,*/agw_gateway/auth/*,*/agw_gateway/tools/*,*/agw_gateway/execution/*,*/agw_gateway/approvals/*,*/agw_gateway/humans/*,*/agw_gateway/anchoring/*,*/agw_worker/anchoring/*,*/agw_gateway/privacy/*,*/agw_gateway/keys/*

.PHONY: up down migrate test lint demo sync vectors verify-isolated bench tamper risk-eval seal-compare dev-keys approval-attacks approval-mutations contracts-test contracts-check contracts-gas contracts-slither anchor-deploy-anvil anchor-gas anchor-mutations dev-kek privacy-mutations

.env:
	cp .env.example .env

sync:
	$(UV) sync --frozen

up: .env
	docker compose up -d --wait

down:
	docker compose down -v

migrate: .env sync
	set -a; . ./.env; set +a; cd apps/gateway && $(UV) run alembic upgrade head

lint: sync
	$(UV) run ruff check .
	$(UV) run ruff format --check .
	$(UV) run mypy apps/gateway/src apps/worker/src packages/gateway-sdk/src packages/schemas/src packages/verifier/src
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
