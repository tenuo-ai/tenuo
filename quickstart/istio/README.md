# Istio Quickstart (5 minutes)

Get from zero to your first 403 in 5 minutes with Tenuo and Istio.

## Prerequisites

- Kubernetes cluster with Istio installed
- `kubectl` configured to access your cluster
- Istio injection enabled in the `default` namespace

## Quick Start

### 1. Deploy Tenuo Authorizer

```bash
kubectl apply -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/quickstart/istio/authorizer.yaml
```

This creates:
- `tenuo-system` namespace
- Tenuo authorizer deployment (2 replicas)
- Service exposing the authorizer on port 9090

### 2. Configure Istio Extension Provider

```bash
kubectl patch configmap istio -n istio-system --type merge -p "$(cat extension-provider.yaml)"
```

Or manually add to your Istio mesh config:

```yaml
extensionProviders:
- name: tenuo-authorizer
  envoyExtAuthzGrpc:
    service: tenuo-authorizer.tenuo-system.svc.cluster.local
    port: 9090
```

**Restart Istio control plane** to pick up the config:

```bash
kubectl rollout restart deployment/istiod -n istio-system
```

### 3. Deploy Test Application

```bash
kubectl apply -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/quickstart/istio/httpbin.yaml
```

### 4. Apply Authorization Policy

```bash
kubectl apply -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/quickstart/istio/authz-policy.yaml
```

This enforces Tenuo authorization on all requests to httpbin.

### 5. Test: Time to First 403! 🎉

```bash
# No warrant → 403 Forbidden
kubectl exec -it deploy/sleep -n default -- curl -i http://httpbin.default:8000/get
```

**Expected output:**
```
HTTP/1.1 403 Forbidden
```

### 6. Test with Valid Warrant

First, generate a warrant from your control plane:

```bash
# Get a warrant (replace with your control plane endpoint)
WARRANT=$(curl -s http://tenuo-control.tenuo-system:8080/v1/warrants \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "http_request",
    "constraints": {"path": "/get"},
    "ttl_seconds": 300
  }' | jq -r '.warrant_base64')

# Generate PoP signature (using tenuo CLI)
POP=$(tenuo sign --warrant "$WARRANT")

# Make request with warrant and PoP
kubectl exec -it deploy/sleep -n default -- \
  curl -i \
  -H "X-Tenuo-Warrant: $WARRANT" \
  -H "X-Tenuo-PoP: $POP" \
  http://httpbin.default:8000/get
```

**Expected output:**
```
HTTP/1.1 200 OK
```

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ 1. Request
       ▼
┌─────────────────────┐
│  Istio Ingress      │
│  (Envoy Proxy)      │
└──────┬──────────────┘
       │ 2. Check Authorization
       ▼
┌─────────────────────┐
│ Tenuo Authorizer    │◄─── Trusted Issuer Keys
│ (External AuthZ)    │
└──────┬──────────────┘
       │ 3. Allow/Deny
       ▼
┌─────────────────────┐
│   httpbin Service   │
└─────────────────────┘
```

## How It Works

1. **Request arrives** at Istio ingress gateway
2. **Envoy calls** Tenuo authorizer via gRPC (ExtAuthz)
3. **Tenuo validates**:
   - Warrant signature (from trusted issuer)
   - Warrant expiration
   - Proof of Possession (PoP)
   - Constraint matching
4. **Envoy forwards** request if authorized, or returns 403

## Configuration

### Trusted Issuer Keys

Update the `TENUO_TRUSTED_KEYS` in `authorizer.yaml`:

```yaml
data:
  TENUO_TRUSTED_KEYS: "your-control-plane-public-key-hex"
```

Get your control plane's public key:

```bash
curl http://tenuo-control:8080/v1/public-key | jq -r '.public_key_hex'
```

### Authorization Policy Scope

By default, the policy applies to `httpbin`. To protect other services:

```yaml
spec:
  selector:
    matchLabels:
      app: your-service  # Change this
```

Or apply globally to the entire namespace:

```yaml
spec:
  # No selector = applies to all workloads in namespace
  action: CUSTOM
  provider:
    name: tenuo-authorizer
```

## Troubleshooting

### Check authorizer logs

```bash
kubectl logs -n tenuo-system -l app=tenuo-authorizer --tail=50
```

### Verify Istio config

```bash
istioctl proxy-config all deploy/httpbin -n default | grep tenuo
```

### Test authorizer directly

```bash
kubectl port-forward -n tenuo-system svc/tenuo-authorizer 9090:9090

# Send a test gRPC request (requires grpcurl)
grpcurl -plaintext localhost:9090 list
```

## Next Steps

- [Kubernetes Integration Guide](../../docs/kubernetes-integration.md)
- [Gateway Configuration](../../docs/gateway-config.md)
- [Control Plane Setup](../../tenuo-core/deploy/kubernetes/control-plane.yaml)

## Clean Up

```bash
kubectl delete -f authz-policy.yaml
kubectl delete -f httpbin.yaml
kubectl delete -f authorizer.yaml
```
