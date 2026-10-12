PYTHON ?= python3
VENV := .venv/bin/python
NPM := npm --prefix apps/dashboard

.PHONY: setup setup-python setup-frontend env dev backend gateway frontend test lint format build check contracts contracts-check smoke docker-up docker-down

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
