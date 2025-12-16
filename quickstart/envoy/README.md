# Envoy Quickstart

Get your first 403 in under 5 minutes.

## Prerequisites

- Kubernetes cluster (minikube, kind, or cloud)
- kubectl configured
- curl

## Steps

### 1. Deploy Everything

```bash
kubectl apply -f https://raw.githubusercontent.com/horkosdev/tenuo/main/quickstart/envoy/all-in-one.yaml
```

This creates the `tenuo-system` namespace with:
- Tenuo authorizer (verifies warrants)
- Envoy proxy (ext_authz filter)
- httpbin (test backend)

### 2. Wait for Pods

```bash
kubectl wait --for=condition=ready pod -l app=envoy -n tenuo-system --timeout=60s
```

### 3. Port Forward

```bash
kubectl port-forward -n tenuo-system svc/envoy 8080:8080 &
```

### 4. Test Without Warrant

```bash
curl -i http://localhost:8080/get
```

Expected:
```
HTTP/1.1 403 Forbidden
x-tenuo-deny-reason: missing_warrant
```

### 5. Test With Warrant

For demo purposes, the authorizer accepts a test warrant. In production, warrants come from your control plane.

```bash
# Demo warrant (pre-signed, expires in 24h)
WARRANT="eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9..."

curl -i -H "X-Tenuo-Warrant: $WARRANT" http://localhost:8080/get
```

See the [Kubernetes Guide](../../docs/kubernetes.md) for issuing real warrants.

## Architecture

```
Client --> Envoy --> Tenuo Authorizer --> httpbin
              |            |
              |   (verify) |
              |<-----------+
              |
              +--> (forward if 200)
```

1. Request arrives at Envoy with `X-Tenuo-Warrant` header
2. Envoy's ext_authz filter calls Tenuo authorizer
3. Tenuo verifies signature, expiry, and constraints
4. Envoy forwards to backend only if Tenuo returns 200

## Troubleshooting

Check authorizer logs:
```bash
kubectl logs -n tenuo-system -l app=tenuo-authorizer --tail=20
```

Check Envoy logs:
```bash
kubectl logs -n tenuo-system -l app=envoy --tail=20
```

List pods:
```bash
kubectl get pods -n tenuo-system
```

## Next Steps

- [Istio Quickstart](../istio/README.md) - Service mesh alternative
- [Kubernetes Guide](../../docs/kubernetes.md) - Production patterns
- [Proxy Configs](../../docs/proxy-configs.md) - Full Envoy config reference

## Clean Up

```bash
kubectl delete -f https://raw.githubusercontent.com/horkosdev/tenuo/main/quickstart/envoy/all-in-one.yaml
```
