SHELL := /bin/bash

.DEFAULT_GOAL := help

PYTHON_FILES := $(shell git ls-files "*.py")

.PHONY: help
help:
	@echo "Usage:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  %-20s%s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: format
format: ## Format Python files
	@echo "Formatting Python files..."
	black $(PYTHON_FILES)

.PHONY: ruff
ruff: ## Run Ruff linter
	@echo "Running Ruff linter..."
	ruff check --ignore E501,F401 $(PYTHON_FILES)

.PHONY: ruff-fix
ruff-fix: ## Run Ruff linter with auto-fixes
	@echo "Running Ruff linter with auto-fixes..."
	ruff check --fix --ignore E501,F401 $(PYTHON_FILES)
