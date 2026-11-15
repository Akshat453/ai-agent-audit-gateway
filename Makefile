# Phase 1 targets (docs/gateway/00 §8).
SHELL := /bin/bash
UV ?= uv
COV_PKGS := */agw_gateway/policies/*,*/agw_gateway/auth/*,*/agw_gateway/tools/*,*/agw_gateway/execution/*

.PHONY: up down migrate test lint demo sync

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
