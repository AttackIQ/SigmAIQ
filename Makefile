SHELL := /bin/bash

.DEFAULT_GOAL := help

SRC_DIRS := sigmaiq/llm/tools examples
PYTHON_FILES := $(shell find $(SRC_DIRS) -type f -name "*.py")

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
	ruff check $(PYTHON_FILES)