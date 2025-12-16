# Istio Quickstart

Get your first 403 in under 5 minutes with Istio service mesh.

## Prerequisites

- Kubernetes cluster with Istio installed
- kubectl configured
- istioctl (optional, for debugging)

Verify Istio is running:
```bash
kubectl get pods -n istio-system
```

## Steps

### 1. Deploy Tenuo Authorizer

```bash
kubectl apply -f https://raw.githubusercontent.com/horkosdev/tenuo/main/docs/quickstart/istio/tenuo.yaml
```

### 2. Configure Istio ExtensionProvider

```bash
kubectl patch configmap istio -n istio-system --type merge \
  --patch-file https://raw.githubusercontent.com/horkosdev/tenuo/main/docs/quickstart/istio/mesh-config.yaml
kubectl rollout restart deployment/istiod -n istio-system
```

### 3. Deploy Test App

```bash
kubectl apply -f https://raw.githubusercontent.com/horkosdev/tenuo/main/docs/quickstart/istio/httpbin.yaml
```

This deploys httpbin with an AuthorizationPolicy that routes requests to Tenuo.

### 4. Wait for Pods

```bash
kubectl wait --for=condition=ready pod -l app=httpbin --timeout=60s
```

### 5. Port Forward

```bash
kubectl port-forward svc/httpbin 8080:8000 &
```

### 6. Test Without Warrant

```bash
curl -i http://localhost:8080/get
```

Expected:
```
HTTP/1.1 403 Forbidden
x-tenuo-deny-reason: missing_warrant
```

### 7. Test With Warrant

For demo purposes, the authorizer accepts a test warrant. In production, warrants come from your control plane.

```bash
# Demo warrant (pre-signed)
WARRANT="eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9..."

curl -i -H "X-Tenuo-Warrant: $WARRANT" http://localhost:8080/get
```

See the [Kubernetes Guide](../../kubernetes) for issuing real warrants.

## Architecture

```
Client --> Istio Sidecar --> Tenuo Authorizer --> httpbin
                 |                |
                 |    (verify)    |
                 |<---------------+
                 |
                 +--> (forward if 200)
```

1. Request arrives at httpbin's Istio sidecar
2. AuthorizationPolicy triggers external auth to Tenuo
3. Tenuo verifies warrant
4. Sidecar forwards to httpbin only if authorized

## AuthorizationPolicy

The policy applies Tenuo auth to specific paths:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: tenuo-authz
spec:
  selector:
    matchLabels:
      app: httpbin
  action: CUSTOM
  provider:
    name: tenuo-ext-authz
  rules:
  - to:
    - operation:
        paths: ["/api/*", "/get", "/post"]
```

## Troubleshooting

Check AuthorizationPolicy:
```bash
kubectl get authorizationpolicy
istioctl x authz check deploy/httpbin
```

Check authorizer logs:
```bash
kubectl logs -n tenuo-system -l app=tenuo-authorizer --tail=20
```

Check Istio sidecar logs:
```bash
kubectl logs -l app=httpbin -c istio-proxy --tail=20
```

Verify ExtensionProvider:
```bash
kubectl get configmap istio -n istio-system -o yaml | grep -A10 extensionProviders
```

## Envoy vs Istio

| Aspect | Envoy | Istio |
|--------|-------|-------|
| Setup | Direct Envoy config | ExtensionProvider + AuthorizationPolicy |
| Granularity | Per-listener | Per-workload, per-path |
| Dependencies | Just Envoy | Full service mesh |
| Best for | Simple proxy | Existing Istio users |

## Next Steps

- [Envoy Quickstart](../envoy/) - Standalone proxy alternative
- [Kubernetes Guide](../../kubernetes) - Production patterns
- [Proxy Configs](../../proxy-configs) - Full Istio config reference

## Clean Up

```bash
kubectl delete -f https://raw.githubusercontent.com/horkosdev/tenuo/main/docs/quickstart/istio/httpbin.yaml
kubectl delete -f https://raw.githubusercontent.com/horkosdev/tenuo/main/docs/quickstart/istio/tenuo.yaml
```
