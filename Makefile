SHELL := /bin/bash

.DEFAULT_GOAL := help

# ENSURE POETRY ENV
# This block is similar to the one in DetectIQ/Makefile for consistency
.PHONY: ensure-poetry-env
ensure-poetry-env: ## Ensure Poetry environment is properly set up
	@echo -e "\033[1;34m[i] Ensuring Poetry environment is available...\033[0m"
	@if ! poetry env info -p >/dev/null 2>&1; then \
		echo -e "\033[1;33m[*] Creating virtual environment...\033[0m"; \
		poetry env use python3; \
	fi
	@echo -e "\033[1;32m[✓] Poetry environment: $$(poetry env info -p)\033[0m"

.PHONY: help
help: ## Show this help message
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_\/-]+:.*?## / {printf "  %-25s%s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

.PHONY: format
format: ensure-poetry-env ## Format Python files with Black
	@echo "Formatting Python files with Black..."
	poetry run ruff check . --fix
	poetry run isort --profile black .
	poetry run black .
	@echo "Formatting completed"

# CLEAN TARGETS
.PHONY: clean/poetry-env
clean/poetry-env: ## Clean Poetry virtual environment
	@echo -e "\033[1;33m[*] Cleaning Poetry virtual environment for SigmAIQ...\033[0m"
	@if poetry env info -p >/dev/null 2>&1; then \
		echo "Removing Poetry virtual environment for SigmAIQ..."; \
		poetry env remove $$(poetry env info -p) 2>/dev/null || true; \
	else \
		echo "No Poetry environment found for this project."; \
	fi
	@echo -e "\033[1;32m[✓] Poetry environment cleaned\033[0m"

.PHONY: clean
clean: clean/poetry-env ## Clean up build artifacts and Poetry virtual environment
	@echo -e "\033[1;33m[*] Cleaning SigmAIQ build artifacts...\033[0m"
	rm -rf dist/ build/ .pytest_cache/ .coverage htmlcov/ *.egg-info/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo -e "\033[1;32m[✓] SigmAIQ build artifacts cleaned\033[0m"
	@echo -e "\033[1;33m[*] Deep cleaning project (artifacts & poetry env)\033[0m"
	@echo -e "\033[1;32m[✓] SigmAIQ project cleaned\033[0m"

.PHONY: test
test: install ## Run tests (depends on the renamed 'install' target)
	@echo "Running tests..."
	pytest

.PHONY: build
build: ensure-poetry-env clean ## Build the package
	@echo "Building package..."
	poetry build

.PHONY: token-check
token-check: ensure-poetry-env ## Check if PyPI token is configured
	@echo "Checking PyPI token configuration..."
	@# First check using poetry config, but suppress error messages
	@if poetry config pypi-token.pypi 2>/dev/null | grep -q "."; then \
		echo "✓ PyPI token found"; \
	else \
		if poetry run python -c "import keyring; keyring.get_password('pypi-token', 'pypi') and print('Token found')" 2>/dev/null | grep -q "Token found"; then \
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
token-set: ensure-poetry-env ## Set PyPI token (Usage: make token-set TOKEN=your-token-here)
	@if [ -z "$(TOKEN)" ]; then \
		echo "Error: TOKEN is required. Usage: make token-set TOKEN=your-token-here"; \
		exit 1; \
	fi
	@echo "Setting PyPI token..."
	@poetry config pypi-token.pypi "$(TOKEN)"
	@# Try to store in keyring but don't fail if it doesn't work
	@poetry run python -c "import keyring; keyring.set_password('pypi-token', 'pypi', '$(TOKEN)')" 2>/dev/null || echo "Note: Token stored in poetry config only (keyring backend not available)"
	@echo "Token configured successfully"

.PHONY: token-remove
token-remove: ensure-poetry-env ## Remove PyPI token configuration
	@echo "Removing PyPI token..."
	@poetry config --unset pypi-token.pypi 2>/dev/null || true
	@# Try to remove from keyring but don't fail if it doesn't work
	@poetry run python -c "import keyring; keyring.delete_password('pypi-token', 'pypi')" 2>/dev/null || echo "Note: Keyring backend not available, token removed from poetry config only"
	@rm -f ~/.config/pypoetry/auth.toml 2>/dev/null || true
	@echo "Token removed successfully"

.PHONY: publish
publish: ensure-poetry-env token-check build ## Publish package to PyPI
	@echo -e "\033[1;33m[*] Publishing SigmAIQ to PyPI\033[0m"
	@# Verify keyring is installed, as poetry publish might use it
	@if ! poetry run pip show keyring >/dev/null 2>&1; then \
		echo -e "\033[1;33m[*] Installing keyring as it might be needed by poetry publish...\033[0m"; \
		poetry run pip install keyring keyrings.alt; \
	fi
	poetry publish
	@echo -e "\033[1;32m[✓] Published to PyPI successfully\033[0m"

.PHONY: show-package-contents
show-package-contents: ensure-poetry-env build ## Show contents of the built package files
	@echo -e "\033[1;33m[*] Showing contents of built packages in dist/ for SigmAIQ\033[0m"
	@if [ -z "$$(ls -A dist/*.tar.gz 2>/dev/null)" ] || [ -z "$$(ls -A dist/*.whl 2>/dev/null)" ]; then \
		echo -e "\033[1;31m[!] No built packages found in dist/. Run 'make build' first.\033[0m"; \
		exit 1; \
	fi
	@echo "\n--- Contents of .tar.gz file ---"
	@for tarball in dist/*.tar.gz; do \
		if [ -f "$$tarball" ]; then \
			echo "Contents of $$tarball:"; \
			tar tzf "$$tarball"; \
			echo ""; \
		fi; \
	done
	@echo "\n--- Contents of .whl file (archive listing) ---"
	@for wheel in dist/*.whl; do \
		if [ -f "$$wheel" ]; then \
			echo "Contents of $$wheel:"; \
			unzip -l "$$wheel"; \
			echo ""; \
		fi; \
	done
	@echo -e "\033[1;32m[✓] Finished showing package contents\033[0m"

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
_lock: # No ensure-poetry-env here as it might be called before env exists for lock
	@echo "Updating poetry.lock file..."
	poetry lock

.PHONY: install # Renamed from install-dev
install: ensure-poetry-env _lock ## Install development dependencies
	@echo -e "\033[1;33m[*] Installing SigmAIQ dependencies (including dev)\033[0m"
	poetry install --with dev
	@echo -e "\033[1;32m[✓] SigmAIQ dependencies installed\033[0m"
	@# The following lines were removed as dependencies should ideally be in pyproject.toml:
	@# poetry add --group dev twine keyring keyrings.alt build

.PHONY: update
update: ensure-poetry-env ## Update dependencies to their latest versions
	@echo -e "\033[1;33m[*] Updating SigmAIQ dependencies\033[0m"
	poetry update
	@echo -e "\033[1;32m[✓] SigmAIQ dependencies updated\033[0m"
