# Phase 1 targets (docs/gateway/00 §8).
SHELL := /bin/bash
UV ?= uv
COV_PKGS := */agw_gateway/policies/*,*/agw_gateway/auth/*,*/agw_gateway/tools/*,*/agw_gateway/execution/*

.PHONY: up down migrate test lint demo sync vectors verify-isolated bench

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

demo: .env sync
	./examples/single-agent/run_demo.sh

# Regenerate the frozen vectors in memory and fail on any difference (never overwrites).
vectors: sync
	$(UV) run --with cbor2 python packages/schemas/test-vectors/generate_phase2.py --check

# Install ONLY packages/verifier into a throwaway venv and run its CLI (independence check).
VERIFIER_VENV ?= $(shell python3 -c "import tempfile,os;print(os.path.join(tempfile.gettempdir(),'agw-verifier-venv'))")
verify-isolated:
	$(UV) venv -q --clear $(VERIFIER_VENV) --python 3.12
	$(UV) pip install -q --python $(VERIFIER_VENV)/bin/python ./packages/verifier
	$(UV) pip list --python $(VERIFIER_VENV)/bin/python
	$(VERIFIER_VENV)/bin/python -c "import importlib.util as u; bad=[m for m in ('agw_gateway','agw_schemas','pydantic','sqlalchemy') if u.find_spec(m)]; assert not bad, bad; print('isolated: no gateway/schemas/pydantic/sqlalchemy')"
	$(VERIFIER_VENV)/bin/agw-verify --help >/dev/null && echo "agw-verify runs from the isolated venv"

bench: .env sync
	set -a; . ./.env; set +a; $(UV) run python experiments/benchmarks/phase2_event_latency.py
