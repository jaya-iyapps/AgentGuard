PYTHON ?= python3
VENV := .venv/bin/python
NPM := npm --prefix apps/dashboard

.PHONY: setup setup-python setup-frontend env dev backend gateway frontend test lint format build check contracts contracts-check smoke docker-up docker-down pdp-init test-pdp opa opa-test db-up db-migrate db-seed test-db

setup: setup-python setup-frontend env

setup-python:
	$(PYTHON) -m venv .venv
	$(VENV) -m pip install -e '.[dev]'

setup-frontend:
	$(NPM) install

env:
	$(PYTHON) scripts/init_env.py

dev:
	$(VENV) scripts/dev.py

backend:
	$(VENV) -m uvicorn agentguard_backend.app:create_app --factory --reload --host 127.0.0.1 --port 8000

gateway:
	$(VENV) -m uvicorn agentguard_gateway.app:create_app --factory --reload --host 127.0.0.1 --port 8001

frontend:
	$(NPM) run dev

test:
	$(VENV) -m pytest
	$(NPM) test

lint:
	$(VENV) -m ruff check .
	$(VENV) -m ruff format --check .
	$(NPM) run lint
	$(NPM) run typecheck
	$(NPM) run format:check

format:
	$(VENV) -m ruff check --fix .
	$(VENV) -m ruff format .
	$(NPM) run format

build:
	$(NPM) run build

contracts:
	$(VENV) scripts/contracts.py

contracts-check:
	$(VENV) scripts/contracts.py --check

check: contracts-check lint test build

smoke:
	$(VENV) scripts/smoke.py

docker-up:
	docker compose up --build

docker-down:
	docker compose down

pdp-init:
	$(VENV) services/policy-engine/scripts/init_context.py

test-pdp:
	$(VENV) -m pytest services/policy-engine/tests

opa:
	opa run --server --addr=127.0.0.1:8181 services/policy-engine/policies/authorize.rego

opa-test:
	opa test services/policy-engine/policies --verbose

db-up:
	docker compose --profile database up -d postgres

db-migrate:
	$(VENV) -m alembic -c services/policy-engine/alembic.ini upgrade head

db-seed:
	$(VENV) services/policy-engine/scripts/seed_database.py

test-db:
	$(VENV) -m pytest services/policy-engine/tests/test_database.py services/policy-engine/tests/test_migrations.py
