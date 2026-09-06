.PHONY: verify lint typecheck deadcode test docs clean

# Run all verification checks (default target)
verify: lint typecheck deadcode test docs
	@echo "==> All Checks Passed Successfully"

# Check style and lint errors
lint:
	@echo "==> Running Ruff Format & Lint..."
	uv run ruff format
	uv run ruff check --fix

# Run static type checking
typecheck:
	@echo "==> Running Pyright Type Check..."
	uv run pyright

# Run dead code analysis
deadcode:
	@echo "==> Running Vulture Dead Code Analysis..."
	uv run vulture

# Run the test suite with coverage
test:
	@echo "==> Running Pytest Suite & Coverage..."
	uv run pytest --cov=scanner

# Build Sphinx documentation
docs:
	@echo "==> Building Sphinx Documentation..."
	uv run sphinx-build -b html docs/source docs/build/html

# Clean up generated build/cache artifacts
clean:
	@echo "==> Cleaning caches and build files..."
	rm -rf .ruff_cache .pytest_cache docs/build .coverage

