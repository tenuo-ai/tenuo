#!/usr/bin/env bash
# End-to-end test: Envoy HTTP ext_authz -> Tenuo authorizer -> httpbin.
#
# Usage (from any directory):
#   docs/quickstart/envoy/e2e-test.sh              # published image (tenuo/authorizer:0.3.1)
#   E2E_BUILD=1 docs/quickstart/envoy/e2e-test.sh  # build the authorizer from this checkout
#   TENUO_AUTHORIZER_IMAGE=tenuo-authorizer:e2e docs/quickstart/envoy/e2e-test.sh
#
# Needs docker compose, curl, and either uv or a python3 with `tenuo` installed
# (set DEMO_PY="python3" in that case).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

export ENVOY_PORT="${ENVOY_PORT:-18080}"
BASE="http://127.0.0.1:${ENVOY_PORT}"
DEMO_PY="${DEMO_PY:-uv run -q}"
export TENUO_DEMO_DIR
TENUO_DEMO_DIR="$(mktemp -d)"
WORK="$(mktemp -d)"

COMPOSE=(docker compose -p tenuo-envoy-e2e -f docker-compose.yaml)
if [[ "${E2E_BUILD:-0}" == "1" ]]; then
  COMPOSE+=(-f docker-compose.build.yaml)
fi

demo() { $DEMO_PY "$HERE/demo_warrant.py" "$@"; }

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    echo "--- authorizer logs ---"; "${COMPOSE[@]}" logs --no-color --tail=60 tenuo-authorizer || true
    echo "--- envoy logs ---"; "${COMPOSE[@]}" logs --no-color --tail=40 envoy || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$TENUO_DEMO_DIR" "$WORK"
  exit $status
}
trap cleanup EXIT

TENUO_TRUSTED_KEYS="$(demo init)"
export TENUO_TRUSTED_KEYS

UP_ARGS=(-d)
[[ "${E2E_BUILD:-0}" == "1" ]] && UP_ARGS+=(--build)
"${COMPOSE[@]}" up "${UP_ARGS[@]}"
"${COMPOSE[@]}" images tenuo-authorizer

# Wait until Envoy answers (any HTTP status means listener + authorizer are up).
for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/get" || true)"
  [[ "$code" != "000" && "$code" != "503" ]] && break
  sleep 1
done

PASS=0
FAIL=0

# check NAME EXPECTED_STATUS EXPECTED_DENY_REASON_SUBSTRING|- curl-args...
check() {
  local name="$1" want_status="$2" want_reason="$3"
  shift 3
  local hdrs="$WORK/h" body="$WORK/b" status reason
  status="$(curl -s -D "$hdrs" -o "$body" -w '%{http_code}' "$@")"
  reason="$(grep -i '^x-tenuo-deny-reason:' "$hdrs" | head -n1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//' || true)"
  local ok=1
  [[ "$status" == "$want_status" ]] || ok=0
  if [[ "$want_reason" != "-" && "$reason" != *"$want_reason"* ]]; then ok=0; fi
  if [[ $ok -eq 1 ]]; then
    PASS=$((PASS + 1))
    printf 'PASS  %-58s %s %s\n' "$name" "$status" "${reason:+[x-tenuo-deny-reason: $reason]}"
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL  %-58s got %s [%s], want %s [%s]\n' "$name" "$status" "$reason" "$want_status" "$want_reason"
    head -c 400 "$body"; echo
  fi
}

WARRANT="$(demo mint)"
READ_ONLY="$(demo mint --read-only)"
UNTRUSTED="$(demo mint --untrusted)"
TAMPERED="$(demo tamper "$WARRANT")"
pop() { demo pop --warrant "$1" "${@:2}"; }

check "no warrant -> 401 missing_warrant" 401 missing_warrant \
  "$BASE/get"
check "valid warrant + PoP, GET /get -> 200 from httpbin" 200 - \
  -H "X-Tenuo-Warrant: $WARRANT" -H "X-Tenuo-PoP: $(pop "$WARRANT" httpbin_read endpoint=get)" "$BASE/get"
grep -q '"url"' "$WORK/b" || { echo "FAIL  200 body is not from httpbin"; FAIL=$((FAIL + 1)); }
check "valid warrant, no PoP -> 403" 403 - \
  -H "X-Tenuo-Warrant: $WARRANT" "$BASE/get"
check "PoP signed for other args -> 403" 403 - \
  -H "X-Tenuo-Warrant: $WARRANT" -H "X-Tenuo-PoP: $(pop "$WARRANT" httpbin_read endpoint=headers)" "$BASE/get"
check "out-of-scope path GET /headers -> 403 constraint" 403 constraint \
  -H "X-Tenuo-Warrant: $WARRANT" -H "X-Tenuo-PoP: $(pop "$WARRANT" httpbin_read endpoint=headers)" "$BASE/headers"
check "unrouted method DELETE /get -> 404 no_route" 404 no_route \
  -X DELETE -H "X-Tenuo-Warrant: $WARRANT" "$BASE/get"
check "POST /post body in scope -> 200" 200 - \
  -X POST -H 'content-type: application/json' -d '{"message":"hello world"}' \
  -H "X-Tenuo-Warrant: $WARRANT" -H "X-Tenuo-PoP: $(pop "$WARRANT" httpbin_write 'message=hello world')" "$BASE/post"
check "POST /post body out of scope -> 403" 403 constraint \
  -X POST -H 'content-type: application/json' -d '{"message":"drop tables"}' \
  -H "X-Tenuo-Warrant: $WARRANT" -H "X-Tenuo-PoP: $(pop "$WARRANT" httpbin_write 'message=drop tables')" "$BASE/post"
check "read-only warrant, POST /post -> 403 tool" 403 tool \
  -X POST -H 'content-type: application/json' -d '{"message":"hello"}' \
  -H "X-Tenuo-Warrant: $READ_ONLY" -H "X-Tenuo-PoP: $(pop "$READ_ONLY" httpbin_write message=hello)" "$BASE/post"
check "untrusted root warrant -> 403" 403 - \
  -H "X-Tenuo-Warrant: $UNTRUSTED" -H "X-Tenuo-PoP: $(pop "$UNTRUSTED" httpbin_read endpoint=get)" "$BASE/get"
# Warrant signatures are verified while decoding, so tampering is a 400.
check "tampered warrant signature -> 400 invalid_warrant" 400 invalid_warrant \
  -H "X-Tenuo-Warrant: $TAMPERED" -H "X-Tenuo-PoP: $(pop "$WARRANT" httpbin_read endpoint=get)" "$BASE/get"
check "garbage warrant -> 400 invalid_warrant" 400 invalid_warrant \
  -H "X-Tenuo-Warrant: not-a-warrant" "$BASE/get"
for p in /health /healthz /ready /status; do
  check "authorizer $p is not reachable through Envoy -> 401" 401 missing_warrant "$BASE$p"
done

# Fail closed when the authorizer is unavailable.
"${COMPOSE[@]}" stop tenuo-authorizer >/dev/null 2>&1
check "authorizer down, valid request -> 403 (fail closed)" 403 - \
  -H "X-Tenuo-Warrant: $WARRANT" -H "X-Tenuo-PoP: $(pop "$WARRANT" httpbin_read endpoint=get)" "$BASE/get"

echo
echo "passed: $PASS  failed: $FAIL"
[[ $FAIL -eq 0 ]]
