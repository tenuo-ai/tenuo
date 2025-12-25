#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Parse arguments
CHECK_MODE=0
for arg in "$@"; do
    case $arg in
        --check)
            CHECK_MODE=1
            shift
            ;;
    esac
done

echo "[INFO] Starting Pre-commit Checks..."

# 0. Cargo.lock Sync Check
echo -e "\n${GREEN}[0/6] Checking Cargo.lock sync...${NC}"
cd tenuo-core
if ! cargo check --locked 2>/dev/null; then
    echo -e "${RED}  → Cargo.lock out of sync! Regenerating...${NC}"
    cargo generate-lockfile
    echo -e "${YELLOW}  → Cargo.lock updated. Will be included in commit.${NC}"
fi
cd ../tenuo-python
if ! cargo check --locked 2>/dev/null; then
    echo -e "${RED}  → Cargo.lock out of sync! Regenerating...${NC}"
    cargo generate-lockfile
    echo -e "${YELLOW}  → Cargo.lock updated. Will be included in commit.${NC}"
fi
cd ..
echo "  → Cargo.lock files in sync"

# 1. Rust Formatting
echo -e "\n${GREEN}[1/6] Formatting Rust Code...${NC}"
if [ "$CHECK_MODE" = "1" ]; then
    # CI mode: fail if not formatted
    echo "  → Checking format (CI mode)..."
    cd tenuo-core
    cargo fmt --all -- --check
    cd ../tenuo-python
    cargo fmt --all -- --check
    cd ..
    echo "  → Format check passed"
else
    # Local mode: auto-format
    cd tenuo-core
    cargo fmt --all
    cd ../tenuo-python
    cargo fmt --all
    cd ..
    echo "  → Rust code formatted"
fi

# 2. Rust Linting (Clippy)
echo -e "\n${GREEN}[2/6] Running Clippy...${NC}"
cd tenuo-core
cargo clippy --all-targets --all-features -- -D warnings
cd ..

# 3. Rust Tests (all tests including integration tests)
echo -e "\n${GREEN}[3/6] Running Rust Tests...${NC}"
cd tenuo-core
echo "  → Running unit tests..."
cargo test --lib
echo "  → Running integration tests..."
cargo test --test invariants
cargo test --test integration
cargo test --test security
cargo test --test cel_stdlib
cargo test --test revocation
cargo test --test parental_revocation
cargo test --test test_object_extraction
cargo test --test red_team
# Note: enrollment_flow requires network access, skipped locally
cd ..

# 4. Security Audit (optional - skip with SKIP_AUDIT=1)
if [ "${SKIP_AUDIT:-0}" = "1" ]; then
    echo -e "\n${GREEN}[4/6] Skipping Security Audit (SKIP_AUDIT=1)${NC}"
else
    echo -e "\n${GREEN}[4/6] Running Security Audit...${NC}"
    cd tenuo-core
    if ! command -v cargo-audit &> /dev/null; then
        echo "Installing cargo-audit..."
        cargo install cargo-audit --locked
    fi
    cargo audit || echo "  → Audit warnings (non-blocking)"
    cd ..
fi

# 5. Python Checks (if venv exists)
if [ -d ".venv" ]; then
    echo -e "\n${GREEN}[5/6] Running Python Checks...${NC}"
    source .venv/bin/activate
    cd tenuo-python
    
    echo "  → Building and installing Rust extension..."
    maturin develop
    
    # Ensure the Python wrapper is importable (maturin develop doesn't always create .pth file)
    echo "$(pwd)" > ../.venv/lib/python3.9/site-packages/tenuo.pth
    
    echo "  → Linting with ruff..."
    ruff check .
    
    echo "  → Type checking with mypy..."
    mypy  # Uses mypy.ini config (files = tenuo/)
    
    echo "  → Running tests with pytest (isolated)..."
    # Run tests in isolation to avoid pollution on Python 3.9
    for test_file in tests/test_*.py tests/security/test_*.py; do
        [ -e "$test_file" ] || continue
        echo "Testing $test_file..."
        python -m pytest "$test_file"
    done
    
    cd ..
else
    echo -e "\n${RED}[5/6] Skipping Python checks (no .venv found)${NC}"
    echo "To enable Python checks:"
    echo "  1. python3 -m venv .venv"
    echo "  2. source .venv/bin/activate"
    echo "  3. pip install maturin pytest ruff mypy langchain langchain-core langchain-openai fastapi uvicorn pydantic PyYAML types-PyYAML types-requests"
    echo "  4. cd tenuo-python && maturin develop"
fi

# 6. Version Sync Check
echo -e "\n${GREEN}[6/6] Checking version sync...${NC}"

# Extract versions (normalize Python alpha format to match Rust)
PYPROJECT_VER=$(grep '^version = ' tenuo-python/pyproject.toml | head -1 | sed 's/version = "\(.*\)"/\1/' | sed 's/a/-alpha./')
PYTHON_CARGO_VER=$(grep '^version = ' tenuo-python/Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
CORE_CARGO_VER=$(grep '^version = ' tenuo-core/Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
WASM_CARGO_VER=$(grep '^version = ' tenuo-wasm/Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')

VERSION_MISMATCH=0
if [ "$PYPROJECT_VER" != "$PYTHON_CARGO_VER" ]; then
    echo -e "${RED}  ✗ Version mismatch: pyproject.toml ($PYPROJECT_VER) vs tenuo-python/Cargo.toml ($PYTHON_CARGO_VER)${NC}"
    VERSION_MISMATCH=1
fi
if [ "$PYPROJECT_VER" != "$CORE_CARGO_VER" ]; then
    echo -e "${RED}  ✗ Version mismatch: pyproject.toml ($PYPROJECT_VER) vs tenuo-core/Cargo.toml ($CORE_CARGO_VER)${NC}"
    VERSION_MISMATCH=1
fi
if [ "$PYPROJECT_VER" != "$WASM_CARGO_VER" ]; then
    echo -e "${RED}  ✗ Version mismatch: pyproject.toml ($PYPROJECT_VER) vs tenuo-wasm/Cargo.toml ($WASM_CARGO_VER)${NC}"
    VERSION_MISMATCH=1
fi

if [ "$VERSION_MISMATCH" = "1" ]; then
    echo -e "${RED}  → Fix version mismatches before committing!${NC}"
    exit 1
fi
echo "  → All versions in sync: $PYPROJECT_VER"

echo -e "\n${GREEN}[OK] All checks passed! You are ready to commit.${NC}"

# Usage hint
if [ "$CHECK_MODE" = "0" ]; then
    echo -e "${YELLOW}Tip: Use './scripts/check.sh --check' for CI mode (fails on unformatted code)${NC}"
fi
