#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "[INFO] Starting Pre-commit Checks..."

# 1. Rust Formatting (auto-fix)
echo -e "\n${GREEN}[1/5] Formatting Rust Code...${NC}"
cd tenuo-core
cargo fmt --all
cd ../tenuo-python
cargo fmt --all
cd ..
echo "  → Rust code formatted"

# 2. Rust Linting (Clippy)
echo -e "\n${GREEN}[2/5] Running Clippy...${NC}"
cd tenuo-core
cargo clippy --all-targets --all-features -- -D warnings
cd ..

# 3. Rust Tests (all tests including integration tests)
echo -e "\n${GREEN}[3/5] Running Rust Tests...${NC}"
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
cargo test --test repro_object_extraction
cargo test --test red_team
# Note: enrollment_flow requires network access, skipped locally
cd ..

# 4. Security Audit (optional - skip with SKIP_AUDIT=1)
if [ "${SKIP_AUDIT:-0}" = "1" ]; then
    echo -e "\n${GREEN}[4/5] Skipping Security Audit (SKIP_AUDIT=1)${NC}"
else
    echo -e "\n${GREEN}[4/5] Running Security Audit...${NC}"
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
    echo -e "\n${GREEN}[5/5] Running Python Checks...${NC}"
    source .venv/bin/activate
    cd tenuo-python
    
    echo "  → Building and installing Rust extension..."
    maturin develop
    
    # Ensure the Python wrapper is importable (maturin develop doesn't always create .pth file)
    echo "$(pwd)" > ../.venv/lib/python3.9/site-packages/tenuo.pth
    
    echo "  → Linting with ruff..."
    ruff check .
    
    echo "  → Type checking with mypy..."
    mypy .
    
    echo "  → Running tests with pytest..."
    pytest
    
    cd ..
else
    echo -e "\n${RED}[5/5] Skipping Python checks (no .venv found)${NC}"
    echo "To enable Python checks:"
    echo "  1. python3 -m venv .venv"
    echo "  2. source .venv/bin/activate"
    echo "  3. pip install maturin pytest ruff mypy langchain langchain-core langchain-openai fastapi uvicorn pydantic PyYAML types-PyYAML types-requests"
    echo "  4. cd tenuo-python && maturin develop"
fi

echo -e "\n${GREEN}[OK] All checks passed! You are ready to commit.${NC}"
