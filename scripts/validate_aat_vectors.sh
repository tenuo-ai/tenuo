#!/bin/bash
# Validate that tests/vectors/aat-jws-vectors.json and ietf/vectors/aat-jws-vectors.md
# match the generator output.
#
# Regenerates into a temporary directory and diffs against the committed files. Same contract as validate_test_vectors.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
VEC_DIR="$ROOT_DIR/ietf/vectors"
PY="${PYTHON:-python3}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Generating AAT JWS vectors..."
"$PY" "$VEC_DIR/gen_vectors.py" --json-out "$TMP/aat-jws-vectors.json" --md-out "$TMP/aat-jws-vectors.md" > "$TMP/gen.log" 2>&1 || {
    echo "Generator failed:"
    cat "$TMP/gen.log"
    exit 1
}

status=0
check() {  # check <generated> <committed>
    if diff -q "$1" "$2" > /dev/null; then
        echo "OK: ${2#"$ROOT_DIR"/} is up to date"
    else
        echo "MISMATCH: ${2#"$ROOT_DIR"/} needs regeneration"
        status=1
    fi
}
check "$TMP/aat-jws-vectors.json" "$ROOT_DIR/tests/vectors/aat-jws-vectors.json"
check "$TMP/aat-jws-vectors.md" "$VEC_DIR/aat-jws-vectors.md"

if [ $status -ne 0 ]; then
    echo ""
    echo "To fix, run:"
    echo "  $PY ietf/vectors/gen_vectors.py"
fi
exit $status
