#!/bin/bash
# Validate that tests/vectors/aat-jws-vectors.json and ietf/vectors/aat-jws-vectors.md
# match the generator output, and that every check of the generator's verifier
# is pinned by some vector (gen_vectors.py --mutation-check).
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
gen_status=0
"$PY" "$VEC_DIR/gen_vectors.py" --mutation-check --json-out "$TMP/aat-jws-vectors.json" \
    --md-out "$TMP/aat-jws-vectors.md" > "$TMP/gen.log" 2>&1 || gen_status=$?
if [ ! -s "$TMP/aat-jws-vectors.json" ] || [ ! -s "$TMP/aat-jws-vectors.md" ]; then
    echo "Generator failed:"
    cat "$TMP/gen.log"
    exit 1
fi

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

if [ $gen_status -ne 0 ]; then
    echo "MUTATION CHECK FAILED:"
    grep -E '^(!!|mutation check:)' "$TMP/gen.log" || tail -n 20 "$TMP/gen.log"
    status=1
else
    echo "OK: $(grep '^mutation check:' "$TMP/gen.log")"
fi

if [ $status -ne 0 ]; then
    echo ""
    echo "To fix, run:"
    echo "  $PY ietf/vectors/gen_vectors.py"
    echo "  $PY ietf/vectors/gen_vectors.py --mutation-check   # lists the checks no vector depends on"
fi
exit $status
