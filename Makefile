# Tenuo Makefile
# Mirrors CI pipeline for local pre-commit and development workflows
#
# Usage:
#   make check      - Full pre-commit checks (local mode, auto-fixes)
#   make check-ci   - CI mode (fails on issues, no auto-fix)
#   make test       - Just run tests
#   make fmt        - Just format code
#   make help       - Show all targets
#
# Run `make check` before every commit to avoid CI surprises.

.PHONY: help check check-ci fmt lint test test-rust test-python test-explorer \
        build audit clean vectors docker benchmark

# Default target
help:
	@echo "Tenuo Development Commands"
	@echo ""
	@echo "Primary targets:"
	@echo "  make check       Full pre-commit checks (like CI, with auto-fix)"
	@echo "  make check-ci    CI mode checks (fails on unformatted code)"
	@echo ""
	@echo "Individual targets:"
	@echo "  make fmt         Format all code (Rust + Python)"
	@echo "  make lint        Run linters (Clippy + ruff + mypy)"
	@echo "  make test        Run all tests"
	@echo "  make test-rust   Run Rust tests only"
	@echo "  make test-python Run Python tests only"
	@echo "  make test-explorer Run Explorer tests only"
	@echo "  make vectors     Regenerate test vectors"
	@echo "  make audit       Security audit (cargo-audit)"
	@echo "  make docker      Build Docker images"
	@echo "  make benchmark   Run benchmarks"
	@echo "  make clean       Clean build artifacts"

# ============================================================================
# PRIMARY TARGETS
# ============================================================================

# Full pre-commit check with auto-fix (matches CI but fixes locally)
check:
	./scripts/check.sh

# CI mode - fails on issues, no auto-fix (exact CI behavior)
check-ci:
	./scripts/check.sh --check

# ============================================================================
# FORMATTING
# ============================================================================

fmt: fmt-rust fmt-python

fmt-rust:
	cd tenuo-core && cargo fmt --all
	cd tenuo-python && cargo fmt --all

fmt-python:
	@if [ -d ".venv" ]; then \
		source .venv/bin/activate && cd tenuo-python && ruff check . --fix; \
	else \
		echo "Skipping Python format (no .venv)"; \
	fi

# ============================================================================
# LINTING
# ============================================================================

lint: lint-rust lint-python

lint-rust:
	cd tenuo-core && cargo clippy --all-targets --all-features -- -D warnings

lint-python:
	@if [ -d ".venv" ]; then \
		source .venv/bin/activate && cd tenuo-python && ruff check . && mypy .; \
	else \
		echo "Skipping Python lint (no .venv)"; \
	fi

# ============================================================================
# TESTING
# ============================================================================

test: test-rust test-python test-explorer

test-rust:
	cd tenuo-core && cargo test --all-features

test-python:
	@if [ -d ".venv" ]; then \
		source .venv/bin/activate && cd tenuo-python && maturin develop && pytest -v; \
	else \
		echo "Skipping Python tests (no .venv)"; \
	fi

test-explorer:
	@if [ -d "tenuo-explorer/node_modules" ]; then \
		cd tenuo-explorer && npm test -- --run; \
	else \
		echo "Skipping Explorer tests (no node_modules)"; \
	fi

# Security-specific tests (matches security.yml)
test-security:
	cd tenuo-core && cargo test --test red_team -- --nocapture
	@if [ -d ".venv" ]; then \
		source .venv/bin/activate && cd tenuo-python && pytest tests/security/ -v; \
	else \
		echo "Skipping Python security tests (no .venv)"; \
	fi

# ============================================================================
# TEST VECTORS
# ============================================================================

vectors:
	cd tenuo-core && cargo run --bin generate_test_vectors > ../docs/spec/test-vectors.md
	@echo "✓ test-vectors.md regenerated"

vectors-check:
	@cd tenuo-core && \
	GENERATED=$$(cargo run --bin generate_test_vectors 2>/dev/null) && \
	COMMITTED=$$(cat ../docs/spec/test-vectors.md) && \
	if ! diff -b <(echo "$$GENERATED") <(echo "$$COMMITTED") > /dev/null 2>&1; then \
		echo "❌ test-vectors.md out of sync - run: make vectors"; \
		exit 1; \
	fi
	@echo "✓ test-vectors.md in sync"

# ============================================================================
# SECURITY AUDIT
# ============================================================================

audit:
	@command -v cargo-audit >/dev/null || cargo install cargo-audit --locked
	cd tenuo-core && cargo audit
	cd tenuo-python && cargo audit

# ============================================================================
# DOCKER
# ============================================================================

docker: docker-control docker-authorizer

docker-control:
	docker build -t tenuo/control:local -f tenuo-core/deploy/docker/Dockerfile.control tenuo-core

docker-authorizer:
	docker build -t tenuo/authorizer:local -f tenuo-core/deploy/docker/Dockerfile.authorizer tenuo-core

# ============================================================================
# BENCHMARKS
# ============================================================================

benchmark:
	cd tenuo-core && cargo bench --bench warrant_benchmarks -- --noplot

# ============================================================================
# BUILD
# ============================================================================

build: build-rust build-python build-wasm

build-rust:
	cd tenuo-core && cargo build --release

build-python:
	@if [ -d ".venv" ]; then \
		source .venv/bin/activate && cd tenuo-python && maturin build --release; \
	else \
		echo "Skipping Python build (no .venv)"; \
	fi

build-wasm:
	cd tenuo-wasm && wasm-pack build --target web --out-dir ../tenuo-explorer/src/wasm

build-explorer:
	@if [ -d "tenuo-explorer/node_modules" ]; then \
		cd tenuo-explorer && npm run build; \
	else \
		echo "Skipping Explorer build (no node_modules)"; \
	fi

# ============================================================================
# CLEAN
# ============================================================================

clean:
	cd tenuo-core && cargo clean
	cd tenuo-python && cargo clean
	cd tenuo-wasm && cargo clean
	rm -rf tenuo-explorer/dist

# ============================================================================
# VERSION SYNC CHECK
# ============================================================================

version-check:
	@PYPROJECT=$$(grep '^version = ' tenuo-python/pyproject.toml | head -1 | sed 's/version = "\(.*\)"/\1/' | sed 's/a/-alpha./' | sed 's/b/-beta./'); \
	PYTHON_CARGO=$$(grep '^version = ' tenuo-python/Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/'); \
	CORE_CARGO=$$(grep '^version = ' tenuo-core/Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/'); \
	WASM_CARGO=$$(grep '^version = ' tenuo-wasm/Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/'); \
	if [ "$$PYPROJECT" != "$$PYTHON_CARGO" ] || [ "$$PYPROJECT" != "$$CORE_CARGO" ] || [ "$$PYPROJECT" != "$$WASM_CARGO" ]; then \
		echo "❌ Version mismatch:"; \
		echo "  pyproject.toml: $$PYPROJECT"; \
		echo "  tenuo-python/Cargo.toml: $$PYTHON_CARGO"; \
		echo "  tenuo-core/Cargo.toml: $$CORE_CARGO"; \
		echo "  tenuo-wasm/Cargo.toml: $$WASM_CARGO"; \
		exit 1; \
	fi
	@echo "✓ All versions in sync: $$PYPROJECT"

# ============================================================================
# EXPLORER SYNC CHECK
# ============================================================================

explorer-sync:
	@if [ -d "tenuo-explorer/node_modules" ] && [ -f "docs/explorer/index.html" ]; then \
		cd tenuo-explorer && npm run build > /dev/null 2>&1; \
		DIST_HASH=$$(cat dist/index.html | shasum -a 256 | cut -d' ' -f1); \
		DOCS_HASH=$$(cat ../docs/explorer/index.html | shasum -a 256 | cut -d' ' -f1); \
		if [ "$$DIST_HASH" != "$$DOCS_HASH" ]; then \
			echo "❌ docs/explorer out of sync - run:"; \
			echo "  rm -rf docs/explorer && cp -r tenuo-explorer/dist docs/explorer"; \
			exit 1; \
		fi; \
		echo "✓ docs/explorer in sync"; \
	else \
		echo "Skipping explorer sync check"; \
	fi
