#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "🔍 Starting Pre-commit Checks..."

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
cargo clippy --all-features -- -D warnings
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
    maturin develop
    ruff check .
    mypy .
    pytest
    cd ..
else
    echo -e "\n${RED}[4/4] Skipping Python checks (no .venv found)${NC}"
fi

echo -e "\n${GREEN}✅ All checks passed! You are ready to commit.${NC}"
