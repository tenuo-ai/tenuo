#!/bin/bash
# Validate that ietf/vectors/aat-jws-vectors.{json,md} match the generator output.
#
# Regenerates into a temporary directory (the generator writes next to itself)
# and diffs against the committed files. Same contract as validate_test_vectors.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
VEC_DIR="$ROOT_DIR/ietf/vectors"
PY="${PYTHON:-python3}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cp "$VEC_DIR/gen_vectors.py" "$TMP/gen_vectors.py"
echo "Generating AAT JWS vectors..."
"$PY" "$TMP/gen_vectors.py" > "$TMP/gen.log" 2>&1 || {
    echo "Generator failed:"
    cat "$TMP/gen.log"
    exit 1
}

status=0
for f in aat-jws-vectors.json aat-jws-vectors.md; do
    if diff -q "$TMP/$f" "$VEC_DIR/$f" > /dev/null; then
        echo "OK: $f is up to date"
    else
        echo "MISMATCH: $f needs regeneration"
        status=1
    fi
done

if [ $status -ne 0 ]; then
    echo ""
    echo "To fix, run:"
    echo "  $PY ietf/vectors/gen_vectors.py"
fi
exit $status
