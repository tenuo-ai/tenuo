#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "[INFO] Starting Pre-commit Checks..."

# 1. Rust Formatting
echo -e "\n${GREEN}[1/4] Checking Rust Formatting...${NC}"
cd tenuo-core
cargo fmt --all -- --check
cd ../tenuo-python
cargo fmt --all -- --check
cd ..

# 2. Rust Linting (Clippy)
echo -e "\n${GREEN}[2/4] Running Clippy...${NC}"
cd tenuo-core
cargo clippy --all-targets --all-features -- -D warnings
cd ..

# 3. Rust Tests
echo -e "\n${GREEN}[3/4] Running Rust Tests...${NC}"
cd tenuo-core
cargo test
cd ..

# 4. Python Checks (if venv exists)
if [ -d ".venv" ]; then
    echo -e "\n${GREEN}[4/4] Running Python Checks...${NC}"
    source .venv/bin/activate
    cd tenuo-python
    
    echo "  → Building and installing Rust extension..."
    maturin develop
    
    echo "  → Linting with ruff..."
    ruff check .
    
    echo "  → Type checking with mypy..."
    mypy .
    
    echo "  → Running tests with pytest..."
    pytest
    
    cd ..
else
    echo -e "\n${RED}[4/4] Skipping Python checks (no .venv found)${NC}"
    echo "To enable Python checks:"
    echo "  1. python3 -m venv .venv"
    echo "  2. source .venv/bin/activate"
    echo "  3. pip install maturin pytest ruff mypy langchain langchain-core langchain-openai fastapi uvicorn pydantic PyYAML types-PyYAML types-requests"
    echo "  4. cd tenuo-python && maturin develop"
fi

echo -e "\n${GREEN}[OK] All checks passed! You are ready to commit.${NC}"
