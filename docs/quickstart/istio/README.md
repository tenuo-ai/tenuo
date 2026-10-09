# Istio Quickstart

Enforce Tenuo warrants on a workload in an Istio mesh, using an Istio
`CUSTOM` AuthorizationPolicy backed by the Tenuo authorizer.

> [!NOTE]
> The Tenuo authorizer implements Envoy's **HTTP** ext_authz protocol, so the
> Istio extension provider is `envoyExtAuthzHttp`. `envoyExtAuthzGrpc` is not
> supported yet.

This guide uses sidecar mode. In ambient mode, `CUSTOM` policies are enforced
by a waypoint proxy instead; the provider config is the same.

## Prerequisites

- A Kubernetes cluster and kubectl
- [istioctl](https://istio.io/latest/docs/setup/getting-started/#download)
- [uv](https://docs.astral.sh/uv/) (or Python 3.9+ with `pip install tenuo==0.3.2`)

## Steps

### 1. Create demo keys

```bash
curl -fsSLO https://raw.githubusercontent.com/tenuo-ai/tenuo/main/docs/quickstart/envoy/demo_warrant.py
uv run demo_warrant.py init   # prints the demo root public key (hex)
```

> [!WARNING]
> Demo keys only, stored unencrypted in `./.tenuo-demo/`. Never reuse them.

### 2. Register Tenuo as an Istio extension provider

On a demo cluster:

```bash
istioctl install -y -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/docs/quickstart/istio/mesh-config.yaml
```

[`mesh-config.yaml`](mesh-config.yaml) adds this provider to `meshConfig`. On
an existing mesh, add the entry to your current `extensionProviders` (Helm:
istiod `meshConfig` values) instead of replacing the list:

```yaml
extensionProviders:
- name: tenuo-ext-authz
  envoyExtAuthzHttp:
    service: tenuo-authorizer.tenuo-system.svc.cluster.local
    port: 9090
    timeout: 1s
    failOpen: false
    pathPrefix: /ext_authz              # must match the routes in gateway.yaml
    includeRequestHeadersInCheck: [x-tenuo-warrant, x-tenuo-pop, x-tenuo-approvals, content-type]
    includeRequestBodyInCheck:          # needed for `from: body` extraction
      maxRequestBytes: 65536
      allowPartialMessage: false
    headersToDownstreamOnDeny: [x-tenuo-deny-reason, content-type]
```

Keep `pathPrefix`. The authorizer's own `/health`, `/ready` and `/status`
endpoints answer 200 without a warrant, but only on its separate health port
(9091, used by the pod probes), never on the ext_authz port 9090. Older
authorizers, or one started with `--legacy-health-on-main-port`, also answer
them on 9090, and without a prefix those request paths would be allowed
through to your workload. The prefix is defense in depth against that.

### 3. Deploy the Tenuo authorizer

```bash
kubectl apply -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/docs/quickstart/istio/tenuo.yaml

# The authorizer reads the trusted root from this ConfigMap and waits for it.
kubectl -n tenuo-system create configmap tenuo-demo-root \
  --from-literal=TENUO_TRUSTED_KEYS="$(uv run demo_warrant.py root-pubkey)"
```

The gateway config is the same as the [Envoy quickstart](../envoy/)'s:

| Request | Tool | Arguments |
|---------|------|-----------|
| `GET /<endpoint>` | `httpbin_read` | `endpoint=<endpoint>` |
| `POST /post` with JSON `{"message": ...}` | `httpbin_write` | `message=<message>` |

### 4. Deploy the test app

```bash
kubectl apply -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/docs/quickstart/istio/httpbin.yaml
kubectl -n tenuo-demo wait --for=condition=available deploy --all --timeout=180s
```

This creates the `tenuo-demo` namespace (sidecar injection on) with httpbin, an
in-mesh `curl` client, and an AuthorizationPolicy that sends every request to
httpbin through Tenuo.

### 5. Send requests from inside the mesh

Test from the `curl` pod. `kubectl port-forward` connects straight to the pod
and skips the sidecar, so it bypasses ext_authz and is not a valid test.

```bash
mesh_curl() { kubectl -n tenuo-demo exec deploy/curl -c curl -- curl -s -i "$@"; }
```

No warrant:

```bash
mesh_curl http://httpbin:8080/get
# HTTP/1.1 401 Unauthorized
# {"error":"missing_warrant","message":"Missing X-Tenuo-Warrant header",...}
```

Valid warrant and PoP:

```bash
WARRANT="$(uv run demo_warrant.py mint)"
mesh_curl http://httpbin:8080/get \
  -H "X-Tenuo-Warrant: $WARRANT" \
  -H "X-Tenuo-PoP: $(uv run demo_warrant.py pop httpbin_read endpoint=get --warrant "$WARRANT")"
# HTTP/1.1 200 OK
```

Out of scope:

```bash
mesh_curl http://httpbin:8080/headers \
  -H "X-Tenuo-Warrant: $WARRANT" \
  -H "X-Tenuo-PoP: $(uv run demo_warrant.py pop httpbin_read endpoint=headers --warrant "$WARRANT")"
# HTTP/1.1 403 Forbidden
# x-tenuo-deny-reason: constraint_violation: endpoint="headers" exceeds value does not match constraint
```

See the [Envoy quickstart](../envoy/#out-of-scope-denied) for the other denial
cases; they behave the same here.

## Troubleshooting

```bash
kubectl -n tenuo-demo get authorizationpolicy
kubectl -n tenuo-system logs deploy/tenuo-authorizer --tail=20
kubectl -n tenuo-demo logs deploy/httpbin -c istio-proxy --tail=20
kubectl -n istio-system get configmap istio -o yaml | grep -A15 extensionProviders
```

- 200 without a warrant: the request did not pass through httpbin's sidecar
  (port-forward, or the namespace is not injected; pods should show `2/2`).
- 403 with an empty body on every request: the authorizer is unreachable or the
  provider is configured as `envoyExtAuthzGrpc`.
- `no_route`: the provider needs `pathPrefix: /ext_authz` to match `gateway.yaml`.

## Envoy vs Istio

| Aspect | Envoy | Istio |
|--------|-------|-------|
| Setup | ext_authz filter in Envoy config | Extension provider + `CUSTOM` AuthorizationPolicy |
| Granularity | Per listener or route | Per workload, per path |
| Dependencies | Just Envoy | Service mesh |
| Best for | Edge or standalone proxy | Existing Istio users |

## Multi-hop delegation chains

`X-Tenuo-Warrant` accepts a single warrant or a full delegation chain. The
sidecar forwards the header to Tenuo, which verifies every link from the trusted
root to the leaf offline. See the [Envoy quickstart](../envoy/#multi-hop-delegation-chains)
for an example.

## Clean up

```bash
kubectl delete -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/docs/quickstart/istio/httpbin.yaml
kubectl delete -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/docs/quickstart/istio/tenuo.yaml
rm -rf .tenuo-demo
```

## Next steps

- [Envoy Quickstart](../envoy/): standalone proxy, with a local Docker Compose version
- [Kubernetes Guide](../../kubernetes): production patterns
- [Proxy Configurations](../../enforcement#proxy-configurations): full config reference
