---
title: Envoy Quickstart
description: Deploy Tenuo with Envoy and get your first denied request in under five minutes.
permalink: /quickstart/envoy/
---

# Envoy Quickstart

Put Tenuo in front of a backend with Envoy's **HTTP** external authorization
(`ext_authz`) filter, then send one allowed and a few denied requests.

> [!NOTE]
> The Tenuo authorizer implements Envoy's **HTTP** ext_authz protocol
> (`http_service`). gRPC ext_authz (`grpc_service`, Istio `envoyExtAuthzGrpc`)
> is not supported yet. A `grpc_service` config fails every request at the
> authorization call.

## How it works

```
Client --> Envoy --(check: same method, /ext_authz + path, Tenuo headers, body)--> Tenuo authorizer
             |                                                                        |
             |<------------------- 200 allow, or 401/403/404 deny --------------------+
             |
             +--> httpbin (only after a 200)
```

1. The client sends `X-Tenuo-Warrant` (the warrant, base64) and `X-Tenuo-PoP`
   (a proof-of-possession signature made with the warrant holder's key).
2. Envoy's ext_authz filter sends a check request to the authorizer with the
   original method, the original path prefixed with `/ext_authz`, the Tenuo
   headers, and the request body.
3. The authorizer matches the path against the routes in
   [`gateway.yaml`](gateway.yaml), extracts the tool arguments (path segments,
   query, headers, JSON body), and verifies the warrant chain, trusted root,
   expiry, PoP, tool and constraints. It answers 200 to allow, anything else to
   deny.
4. On a deny, Envoy returns the authorizer's status and body to the client,
   plus the `x-tenuo-deny-reason` header when `debug_mode` is on.

The demo routes:

| Request | Tool | Arguments |
|---------|------|-----------|
| `GET /<endpoint>` | `httpbin_read` | `endpoint=<endpoint>` |
| `POST /post` with JSON `{"message": ...}` | `httpbin_write` | `message=<message>` |
| anything else | none | 404 `no_route`, denied |

Keep the `/ext_authz` prefix. The authorizer serves its own `/health`,
`/healthz`, `/ready` and `/status` (200 without a warrant) only on a separate
health port, 9091, so on the ext_authz port 9090 those paths are authorized
like any other request. Older authorizers, or one started with
`--legacy-health-on-main-port`, answer them on 9090 too; without a
`path_prefix`, Envoy would treat that 200 as ALLOW and pass the request to
your backend unauthenticated. The prefix is defense in depth against that.
Kubernetes probes and health checks go to port 9091.

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (or Python 3.9+ with `pip install tenuo==0.3.1`)
- Docker with Compose, **or** a Kubernetes cluster (kind, minikube, cloud) with kubectl
- curl

## 1. Create demo keys

[`demo_warrant.py`](demo_warrant.py) uses the Tenuo Python SDK to make keys,
mint warrants and sign PoP. It keeps its keys in `./.tenuo-demo/`.

```bash
curl -fsSLO https://raw.githubusercontent.com/tenuo-ai/tenuo/main/docs/quickstart/envoy/demo_warrant.py
uv run demo_warrant.py init   # prints the demo root public key (hex)
```

`init` creates three keys:

- `root`: the issuer the authorizer trusts (stands in for your control plane)
- `agent`: the warrant holder, which signs PoP for each request
- `untrusted-root`: an issuer the authorizer does not trust, for negative tests

> [!WARNING]
> These keys are for this demo only. They sit unencrypted on disk. Do not reuse
> them, the demo root public key, or `debug_mode: true` anywhere else.

## 2a. Run with Docker Compose

```bash
git clone https://github.com/tenuo-ai/tenuo && cd tenuo/docs/quickstart/envoy
uv run demo_warrant.py init
export TENUO_TRUSTED_KEYS="$(uv run demo_warrant.py root-pubkey)"
docker compose up -d
```

Envoy listens on `localhost:8080`. Skip to [step 3](#3-send-requests).

## 2b. Run on Kubernetes

```bash
kubectl apply -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/docs/quickstart/envoy/all-in-one.yaml

# The authorizer reads the trusted root from this ConfigMap and waits for it.
kubectl -n tenuo-system create configmap tenuo-demo-root \
  --from-literal=TENUO_TRUSTED_KEYS="$(uv run demo_warrant.py root-pubkey)"

kubectl -n tenuo-system wait --for=condition=available deploy --all --timeout=180s
kubectl -n tenuo-system port-forward svc/envoy 8080:8080 &
```

This creates the `tenuo-system` namespace with the Tenuo authorizer
(`tenuo/authorizer:0.3.1`), Envoy (`envoyproxy/envoy:v1.39.1`) and httpbin.
The embedded `gateway.yaml` and `envoy.yaml` are the same files used by Docker
Compose.

## 3. Send requests

### No warrant: denied

```bash
curl -i http://localhost:8080/get
```

```
HTTP/1.1 401 Unauthorized
content-type: application/json

{"error":"missing_warrant","message":"Missing X-Tenuo-Warrant header",...}
```

### Valid warrant and PoP: allowed

Mint a warrant (valid for one hour) that allows `httpbin_read` with
`endpoint=get` and `httpbin_write` with a `message` matching `hello*`:

```bash
WARRANT="$(uv run demo_warrant.py mint)"
```

A PoP signature covers the tool, the arguments and a 30 second time window, so
sign right before each request, with the arguments the gateway will extract:

```bash
curl -i http://localhost:8080/get \
  -H "X-Tenuo-Warrant: $WARRANT" \
  -H "X-Tenuo-PoP: $(uv run demo_warrant.py pop httpbin_read endpoint=get --warrant "$WARRANT")"
```

```
HTTP/1.1 200 OK
...
  "url": "http://localhost:8080/get"
```

A POST whose JSON body is in scope (the authorizer reads `message` from the body):

```bash
curl -i -X POST http://localhost:8080/post \
  -H 'content-type: application/json' -d '{"message":"hello world"}' \
  -H "X-Tenuo-Warrant: $WARRANT" \
  -H "X-Tenuo-PoP: $(uv run demo_warrant.py pop httpbin_write 'message=hello world' --warrant "$WARRANT")"
# HTTP/1.1 200 OK
```

### Out of scope: denied

Path outside the warrant (`endpoint` must be `get`):

```bash
curl -i http://localhost:8080/headers \
  -H "X-Tenuo-Warrant: $WARRANT" \
  -H "X-Tenuo-PoP: $(uv run demo_warrant.py pop httpbin_read endpoint=headers --warrant "$WARRANT")"
```

```
HTTP/1.1 403 Forbidden
x-tenuo-deny-reason: constraint_violation: endpoint="headers" exceeds value does not match constraint
```

Other denials you can try:

| Request | Result |
|---------|--------|
| Warrant without `X-Tenuo-PoP` | 403, `missing_pop` |
| PoP signed for different arguments | 403, `signature_invalid` |
| `POST /post` with `{"message":"drop tables"}` | 403, `constraint_violation` |
| `POST /post` with `WARRANT="$(uv run demo_warrant.py mint --read-only)"` | 403, `tool_not_allowed` |
| Warrant from `uv run demo_warrant.py mint --untrusted` | 403, `untrusted_root` |
| Warrant from `uv run demo_warrant.py tamper "$WARRANT"` | 400, `invalid_warrant` |
| `DELETE /get` (no route for that method) | 404, `no_route` |
| `GET /ready` without a warrant | 401, `missing_warrant` (not the authorizer's health check) |
| Authorizer stopped | 403 from Envoy (`failure_mode_allow: false`) |

Status codes: 401 when the warrant header is missing, 400 when it cannot be
decoded or verified, 404 when no route matches, 403 for every authorization
failure. Envoy treats any non-200 as a deny. The JSON body always carries the
`error` code. The `x-tenuo-deny-reason` header is only sent with
`debug_mode: true`; authorizer releases after 0.3.1 also send it on the 401,
400 and 404 responses.

## Envoy config essentials

The full file is [`envoy.yaml`](envoy.yaml). The parts that matter:

```yaml
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    failure_mode_allow: false          # fail closed
    with_request_body:                 # needed for `from: body` extraction
      max_request_bytes: 65536
      allow_partial_message: false
    allowed_headers:                   # headers copied into the check request
      patterns:
      - exact: x-tenuo-warrant
      - exact: x-tenuo-pop
      - exact: x-tenuo-approvals
      - exact: content-type
    http_service:
      server_uri:
        uri: http://tenuo-authorizer:9090
        cluster: tenuo-authorizer
        timeout: 1s
      path_prefix: /ext_authz          # must match the route patterns in gateway.yaml
      authorization_response:
        allowed_client_headers:        # returned to the client on deny
          patterns:
          - exact: x-tenuo-deny-reason
          - exact: content-type
```

Also set `normalize_path: true` and `merge_slashes: true` on the
`HttpConnectionManager` so the authorizer and the backend see the same path.

## Test it end to end

[`e2e-test.sh`](e2e-test.sh) brings up the Compose stack, runs every request
above and asserts the status codes and deny reasons:

```bash
docs/quickstart/envoy/e2e-test.sh              # published tenuo/authorizer:0.3.1
E2E_BUILD=1 docs/quickstart/envoy/e2e-test.sh  # authorizer built from this checkout
```

The test also starts a second Envoy with `path_prefix` removed and checks that
`/health`, `/healthz`, `/ready` and `/status` are still denied through it, and
that the health port (published on `127.0.0.1:${HEALTH_PORT:-19091}`) answers
200. Those checks need an authorizer with the separate health port, so they
run only with `E2E_BUILD=1` or a custom `TENUO_AUTHORIZER_IMAGE` (override with
`NEW_AUTHORIZER=0|1`); against the published 0.3.1 image they are skipped.

## Multi-hop delegation chains

`X-Tenuo-Warrant` accepts a single warrant or a full delegation chain (a CBOR
array of warrants, base64url-encoded as one value). The authorizer verifies
every link from the trusted root to the leaf, offline. The PoP must be signed
by the leaf warrant's holder.

```python
import base64, time
from tenuo import Exact, encode_warrant_stack

# parent: minted by the trusted root, held by agent_key
child = (parent.grant_builder()
         .capability("httpbin_read", endpoint=Exact("get"))
         .holder(worker_key.public_key)
         .ttl(300)
         .grant(agent_key))

args = {"endpoint": "get"}
pop = child.sign(worker_key, "httpbin_read", args, int(time.time()))
headers = {
    "X-Tenuo-Warrant": encode_warrant_stack([parent, child]),
    "X-Tenuo-PoP": base64.b64encode(bytes(pop)).decode(),
}
```

Sending only the child warrant fails with `untrusted_root`: the authorizer
needs the whole chain back to a trusted root.

## Troubleshooting

```bash
# Compose
docker compose logs tenuo-authorizer envoy
# Kubernetes
kubectl -n tenuo-system logs deploy/tenuo-authorizer --tail=20
kubectl -n tenuo-system logs deploy/envoy --tail=20
```

- Every request returns 403 with no body: the authorizer is unreachable (check
  the cluster address and that it is not configured as `grpc_service`).
- `no_route` for a path you expect to match: route patterns in `gateway.yaml`
  must include the `/ext_authz` prefix.
- `missing_warrant` although you sent one: add the header to `allowed_headers`.
- `signature_invalid` on PoP: the PoP arguments must match what the gateway
  extracts, and a PoP is only accepted within about 60 seconds of signing.

## Clean up

```bash
docker compose down
# or
kubectl delete -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/docs/quickstart/envoy/all-in-one.yaml
rm -rf .tenuo-demo
```

## Next steps

- [Istio Quickstart](../istio/): the same authorizer behind an Istio sidecar
- [Kubernetes Guide](../../kubernetes): production patterns
- [Proxy Configurations](../../enforcement#proxy-configurations): Envoy, Istio and nginx reference
