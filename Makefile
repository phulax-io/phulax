# Phulax — the six-verb contract (build plan §6).
# Every phase assumes these verbs work from a clean clone.
# "Works on my machine" is banned by construction.

.DEFAULT_GOAL := help
SHELL := /bin/bash

# Load .env when present (local overrides); CI and clean clones use defaults.
UV := uv run $(if $(wildcard .env),--env-file .env,)
SRC := PYTHONPATH=apps/api/src:apps/gateway/src:packages/policy/src

.PHONY: help bootstrap dev down migrate seed test demo

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

bootstrap: ## Create venv, install locked dependencies, git hooks, local policy keys
	uv sync --all-packages
	@# macOS/iCloud can set the UF_HIDDEN flag inside .venv; CPython 3.13+
	@# skips hidden .pth files, which silently breaks editable installs.
	@command -v chflags >/dev/null 2>&1 && find .venv -name '*.pth' -exec chflags nohidden {} + || true
	uv run pre-commit install
	@test -f .env || (cp .env.example .env && echo "bootstrap: created .env from .env.example")
	@$(SRC) uv run --no-sync python scripts/generate_policy_keys.py
	@echo "bootstrap: done. Review .env, then 'make dev'."

dev: ## Start local services: postgres, redis, api, gateway
	docker compose up -d --build --wait postgres redis api gateway
	docker compose ps

down: ## Stop local services
	docker compose down

migrate: ## Apply database schema (alembic upgrade head)
	$(SRC) $(UV) --no-sync alembic -c apps/api/alembic.ini upgrade head

seed: ## Seed demo org, owner, agent, tools, canonical policy bundle via the API
	$(SRC) $(UV) --no-sync python scripts/seed.py

test: ## Run unit + integration tests (integration needs 'make dev')
	$(UV) pytest

demo: ## Demo 2: read allowed, external send denied, duplicate refund protected
	$(SRC) $(UV) --no-sync python scripts/demo.py
