SHELL := /bin/bash

.DEFAULT_GOAL := help

PYTHON_FILES := $(shell git ls-files "*.py")

.PHONY: help
help: ## Show this help message
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_\/-]+:.*?## / {printf "  %-25s%s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

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

# New targets for building and publishing

.PHONY: clean
clean: ## Clean up build artifacts
	@echo "Cleaning up build artifacts..."
	rm -rf dist/ build/ .pytest_cache/ .coverage htmlcov/ *.egg-info/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

.PHONY: test
test: install-dev ## Run tests
	@echo "Running tests..."
	pytest

.PHONY: build
build: clean ## Build the package
	@echo "Building package..."
	poetry build

.PHONY: token-check
token-check: ## Check if PyPI token is configured
	@echo "Checking PyPI token configuration..."
	@# First check using poetry config, but suppress error messages
	@if poetry config pypi-token.pypi 2>/dev/null | grep -q "."; then \
		echo "✓ PyPI token found"; \
	else \
		if python -c "import keyring; keyring.get_password('pypi-token', 'pypi') and print('Token found')" 2>/dev/null | grep -q "Token found"; then \
			echo "✓ PyPI token found (in keyring)"; \
		else \
			echo "PyPI token not configured. Please run:"; \
			echo "make token-set TOKEN=your-token-here"; \
			echo ""; \
			echo "If you encounter keyring errors, install keyrings.alt:"; \
			echo "pip install keyrings.alt"; \
			exit 1; \
		fi \
	fi

.PHONY: token-set
token-set: ## Set PyPI token (Usage: make token-set TOKEN=your-token-here)
	@if [ -z "$(TOKEN)" ]; then \
		echo "Error: TOKEN is required. Usage: make token-set TOKEN=your-token-here"; \
		exit 1; \
	fi
	@echo "Setting PyPI token..."
	@poetry config pypi-token.pypi "$(TOKEN)"
	@# Try to store in keyring but don't fail if it doesn't work
	@python -c "import keyring; keyring.set_password('pypi-token', 'pypi', '$(TOKEN)')" 2>/dev/null || echo "Note: Token stored in poetry config only (keyring backend not available)"
	@echo "Token configured successfully"

.PHONY: token-remove
token-remove: ## Remove PyPI token configuration
	@echo "Removing PyPI token..."
	@poetry config --unset pypi-token.pypi 2>/dev/null || true
	@# Try to remove from keyring but don't fail if it doesn't work
	@python -c "import keyring; keyring.delete_password('pypi-token', 'pypi')" 2>/dev/null || echo "Note: Keyring backend not available, token removed from poetry config only"
	@rm -f ~/.config/pypoetry/auth.toml 2>/dev/null || true
	@echo "Token removed successfully"

.PHONY: publish
publish: token-check clean ## Publish to PyPI using twine
	@echo "Building package for PyPI..."
	python -m build
	@echo "Checking package with twine..."
	twine check dist/*
	@echo "Publishing to PyPI..."
	@# Get latest version from pyproject.toml
	@VERSION=$$(poetry version -s) && \
	echo "Publishing version $$VERSION" && \
	TOKEN=$$(python -c "import keyring; print(keyring.get_password('pypi-token', 'pypi'))") && \
	if [ -n "$$TOKEN" ]; then \
		echo "Using token from keyring"; \
		twine upload dist/* --username __token__ --password "$$TOKEN"; \
	else \
		echo "Token not found in keyring, prompting for manual entry"; \
		twine upload dist/*; \
	fi

.PHONY: test-publish
test-publish: token-check clean ## Publish to TestPyPI
	@echo "Building package for TestPyPI..."
	python -m build
	@echo "Checking package with twine..."
	twine check dist/*
	@echo "Publishing to TestPyPI..."
	@# Get latest version from pyproject.toml
	@VERSION=$$(poetry version -s) && \
	echo "Publishing version $$VERSION to TestPyPI" && \
	TOKEN=$$(python -c "import keyring; print(keyring.get_password('pypi-token', 'pypi'))") && \
	if [ -n "$$TOKEN" ]; then \
		echo "Using token from keyring"; \
		twine upload --repository-url https://test.pypi.org/legacy/ dist/* --username __token__ --password "$$TOKEN"; \
	else \
		echo "Token not found in keyring, prompting for manual entry"; \
		twine upload --repository-url https://test.pypi.org/legacy/ dist/*; \
	fi

.PHONY: version
version: ## Display current version
	@poetry version

.PHONY: version-patch
version-patch: ## Bump patch version (0.0.X)
	@poetry version patch
	@$(MAKE) _sync-version

.PHONY: version-minor
version-minor: ## Bump minor version (0.X.0)
	@poetry version minor
	@$(MAKE) _sync-version

.PHONY: version-major
version-major: ## Bump major version (X.0.0)
	@poetry version major
	@$(MAKE) _sync-version

.PHONY: _sync-version
_sync-version:
	@echo "Syncing versions..."
	@VERSION=$$(poetry version -s) && \
	echo "New version: $$VERSION" && \
	sed -i.bak "s/__version__ = .*/__version__ = \"$$VERSION\"/" sigmaiq/__init__.py && \
	rm -f sigmaiq/__init__.py.bak

.PHONY: _lock
_lock:
	@echo "Updating poetry.lock file..."
	poetry lock

.PHONY: install-dev
install-dev: _lock ## Install development dependencies
	@echo "Installing development dependencies..."
	poetry install --with dev
	poetry add --group dev twine keyring keyrings.alt build

.PHONY: update
update: ## Update dependencies to their latest versions
	@echo "Updating dependencies..."
	poetry update
