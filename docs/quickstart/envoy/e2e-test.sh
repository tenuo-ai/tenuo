#!/usr/bin/env bash
# End-to-end test: Envoy HTTP ext_authz -> Tenuo authorizer -> httpbin.
#
# Usage (from any directory):
#   docs/quickstart/envoy/e2e-test.sh              # published image (tenuo/authorizer:0.3.2)
#   E2E_BUILD=1 docs/quickstart/envoy/e2e-test.sh  # build the authorizer from this checkout
#   TENUO_AUTHORIZER_IMAGE=tenuo-authorizer:e2e docs/quickstart/envoy/e2e-test.sh
#
# Needs docker compose, curl, and either uv or a python3 with `tenuo` installed
# (set DEMO_PY="python3" in that case). Host ports, all on 127.0.0.1:
# ENVOY_PORT (18080), NOPREFIX_PORT (18081), HEALTH_PORT (19091).
#
# Images before 0.3.2 predate two behaviors this test checks: the
# x-tenuo-deny-reason header on early 401/400/404 denials, and health routes
# on a separate port (older images answer /health etc. with 200 on the
# ext_authz port, so the no-path_prefix Envoy would let them through). Set
# NEW_AUTHORIZER=0 to skip those checks against such an image.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

export ENVOY_PORT="${ENVOY_PORT:-18080}"
BASE="http://127.0.0.1:${ENVOY_PORT}"
# A second Envoy with path_prefix removed proves the authorizer itself never
# answers its health routes on the ext_authz port.
NOPREFIX_PORT="${NOPREFIX_PORT:-18081}"
NOPREFIX="http://127.0.0.1:${NOPREFIX_PORT}"
# The authorizer's health listener, published to the host for a direct check.
HEALTH_PORT="${HEALTH_PORT:-19091}"
HEALTH="http://127.0.0.1:${HEALTH_PORT}"
DEMO_PY="${DEMO_PY:-uv run -q}"
export TENUO_DEMO_DIR
TENUO_DEMO_DIR="$(mktemp -d)"
WORK="$(mktemp -d)"
# Generated compose override and Envoy config live next to this script, not in
# $TMPDIR: Docker Desktop and Colima only share the home directory by default.
GEN="$(mktemp -d "$HERE/.e2e-gen.XXXXXX")"

# envoy.yaml without path_prefix: the check request path is the raw client path.
grep -v 'path_prefix:' envoy.yaml >"$GEN/envoy-noprefix.yaml"
ENVOY_IMAGE="$(awk '/image: envoyproxy\/envoy:/ {print $2; exit}' docker-compose.yaml)"
cat >"$GEN/docker-compose.e2e.yaml" <<YAML
services:
  tenuo-authorizer:
    ports:
      - "127.0.0.1:${HEALTH_PORT}:9091"
  envoy-noprefix:
    image: ${ENVOY_IMAGE}
    command: ["envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "warn"]
    volumes:
      - ${GEN}/envoy-noprefix.yaml:/etc/envoy/envoy.yaml:ro
    ports:
      - "127.0.0.1:${NOPREFIX_PORT}:8080"
    depends_on:
      - tenuo-authorizer
      - httpbin
YAML

COMPOSE=(docker compose -p tenuo-envoy-e2e -f docker-compose.yaml)
NEW_AUTHORIZER="${NEW_AUTHORIZER:-1}"
if [[ "${E2E_BUILD:-0}" == "1" ]]; then
  COMPOSE+=(-f docker-compose.build.yaml)
fi
COMPOSE+=(-f "$GEN/docker-compose.e2e.yaml")

demo() { $DEMO_PY "$HERE/demo_warrant.py" "$@"; }

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    echo "--- authorizer logs ---"; "${COMPOSE[@]}" logs --no-color --tail=60 tenuo-authorizer || true
    echo "--- envoy logs ---"; "${COMPOSE[@]}" logs --no-color --tail=40 envoy envoy-noprefix || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$TENUO_DEMO_DIR" "$WORK" "$GEN"
  exit $status
}
trap cleanup EXIT

if ! grep -q 'path_prefix: /ext_authz' envoy.yaml || grep -q 'path_prefix' "$GEN/envoy-noprefix.yaml"; then
  echo "expected envoy.yaml to set path_prefix and the generated copy to drop it" >&2
  exit 1
fi

TENUO_TRUSTED_KEYS="$(demo init)"
export TENUO_TRUSTED_KEYS

UP_ARGS=(-d)
[[ "${E2E_BUILD:-0}" == "1" ]] && UP_ARGS+=(--build)
"${COMPOSE[@]}" up "${UP_ARGS[@]}"
"${COMPOSE[@]}" images tenuo-authorizer

# Wait until each Envoy gets the authorizer's answer for a request without a
# warrant: 401 missing_warrant through the prefixed Envoy, 404 no_route through
# the unprefixed one (gateway.yaml routes all start with /ext_authz). Envoy
# answers 403 while the authorizer is still unreachable, so any other status
# means "not ready yet".
wait_for() {
  local url="$1" want="$2" code=""
  for _ in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$url" || true)"
    [[ "$code" == "$want" ]] && return 0
    sleep 1
  done
  echo "FAIL  $url not ready after 60s (want $want, last status: $code)"
  exit 1
}
wait_for "$BASE/get" 401
wait_for "$NOPREFIX/get" 404

PASS=0
FAIL=0

# Expected x-tenuo-deny-reason for an early (non-403) denial: the reason when
# the authorizer sets it, otherwise "-" (not checked).
early() { if [[ "$NEW_AUTHORIZER" == "1" ]]; then echo "$1"; else echo -; fi; }

# check NAME EXPECTED_STATUS EXPECTED_DENY_REASON_SUBSTRING|- curl-args...
check() {
  local name="$1" want_status="$2" want_reason="$3"
  shift 3
  local hdrs="$WORK/h" body="$WORK/b" status reason
  : >"$hdrs"; : >"$body"
  # A connection failure is a FAIL (status 000), not an abort.
  status="$(curl -s -D "$hdrs" -o "$body" -w '%{http_code}' "$@" || true)"
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

check "no warrant -> 401 missing_warrant" 401 "$(early missing_warrant)" \
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
check "unrouted method DELETE /get -> 404 no_route" 404 "$(early no_route)" \
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
check "tampered warrant signature -> 400 invalid_warrant" 400 "$(early invalid_warrant)" \
  -H "X-Tenuo-Warrant: $TAMPERED" -H "X-Tenuo-PoP: $(pop "$WARRANT" httpbin_read endpoint=get)" "$BASE/get"
check "garbage warrant -> 400 invalid_warrant" 400 "$(early invalid_warrant)" \
  -H "X-Tenuo-Warrant: not-a-warrant" "$BASE/get"
for p in /health /healthz /ready /status; do
  check "authorizer $p is not reachable through Envoy -> 401" 401 "$(early missing_warrant)" "$BASE$p"
done

if [[ "$NEW_AUTHORIZER" == "1" ]]; then
  # Without path_prefix the authorizer sees the raw client path. It does not
  # serve health routes on the ext_authz port, so these go through route matching
  # (gateway.yaml has no such route) and are denied: never a 200, never ALLOW.
  for p in /health /healthz /ready /status; do
    check "no path_prefix: $p through Envoy -> 404 no_route" 404 no_route "$NOPREFIX$p"
  done
  check "no path_prefix: valid warrant, unprefixed route -> 404 no_route" 404 no_route \
    -H "X-Tenuo-Warrant: $WARRANT" -H "X-Tenuo-PoP: $(pop "$WARRANT" httpbin_read endpoint=get)" "$NOPREFIX/get"

  # The health listener answers directly, outside Envoy.
  for p in /health /healthz /ready /status; do
    check "health port $p -> 200" 200 - "$HEALTH$p"
  done
  grep -q '"cp"' "$WORK/b" || { echo "FAIL  /status body is not the authorizer status"; FAIL=$((FAIL + 1)); }
  check "health port does not authorize: GET /ext_authz/get -> 404" 404 - "$HEALTH/ext_authz/get"
else
  echo "SKIP  no-path_prefix and health-port checks (NEW_AUTHORIZER=0)"
fi

# Fail closed when the authorizer is unavailable.
"${COMPOSE[@]}" stop tenuo-authorizer >/dev/null 2>&1
check "authorizer down, valid request -> 403 (fail closed)" 403 - \
  -H "X-Tenuo-Warrant: $WARRANT" -H "X-Tenuo-PoP: $(pop "$WARRANT" httpbin_read endpoint=get)" "$BASE/get"

echo
echo "passed: $PASS  failed: $FAIL"
[[ $FAIL -eq 0 ]]
