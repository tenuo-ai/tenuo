#!/bin/bash
# Validate that docs/spec/test-vectors.md matches the generator output
#
# This ensures the spec documentation stays in sync with the implementation.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SPEC_FILE="$ROOT_DIR/docs/spec/test-vectors.md"

echo "Generating test vectors..."
cd "$ROOT_DIR/tenuo-core"
GENERATED=$(cargo run --bin generate_test_vectors 2>/dev/null)

echo "Comparing with $SPEC_FILE..."

# Read the committed file, skipping the first line if it differs only in generation date clarification
COMMITTED=$(cat "$SPEC_FILE")

# Compare (ignoring trailing whitespace)
if diff -b <(echo "$GENERATED") <(echo "$COMMITTED") > /dev/null 2>&1; then
    echo "OK: test-vectors.md is up to date"
    exit 0
else
    echo "MISMATCH: test-vectors.md needs regeneration"
    echo ""
    echo "To fix, run:"
    echo "  cd tenuo-core && cargo run --bin generate_test_vectors > ../docs/spec/test-vectors.md"
    echo ""
    echo "Diff:"
    diff -u <(echo "$COMMITTED") <(echo "$GENERATED") | head -50
    exit 1
fi

