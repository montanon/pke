.DEFAULT_GOAL := help

.PHONY: help install lint fmt typecheck test ci db serve clean ios-test ios-lint

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install all dependencies
	uv sync --dev --all-packages
	uv run pre-commit install

lint: ## Run linter
	uv run ruff check src/backend

fmt: ## Format code
	uv run ruff format src/backend
	uv run ruff check --fix src/backend

typecheck: ## Run type checker
	uv run mypy src/backend/src

test: ## Run tests
	@uv run pytest --tb=short -q; rc=$$?; [ $$rc -eq 5 ] || exit $$rc

ci: lint typecheck test ## Run full CI checks locally

db: ## Start local PostgreSQL
	docker compose up -d postgres

serve: ## Run backend dev server
	uv run uvicorn pke_backend.main:app --reload --port 8000

clean: ## Remove caches and build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .mypy_cache .ruff_cache .pytest_cache htmlcov dist build

ios-test: ## Run iOS Swift tests
	cd src/ios && swift test

ios-lint: ## Run SwiftLint on iOS sources
	cd src/ios && swiftlint --config .swiftlint.yml --strict
