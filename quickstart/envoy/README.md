# Envoy Quickstart (5 minutes)

Get from zero to your first 403 in 5 minutes with Tenuo and standalone Envoy.

## Prerequisites

- Kubernetes cluster
- `kubectl` configured to access your cluster

## Quick Start

### 1. Deploy Tenuo Authorizer

```bash
kubectl apply -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/quickstart/envoy/authorizer.yaml
```

This creates:
- `tenuo-system` namespace
- Tenuo authorizer deployment (2 replicas)
- Service exposing the authorizer on port 9090

### 2. Deploy Envoy Proxy

```bash
kubectl apply -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/quickstart/envoy/envoy.yaml
```

This deploys Envoy configured with ext_authz filter pointing to Tenuo.

### 3. Deploy Test Application

```bash
kubectl apply -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/quickstart/envoy/httpbin.yaml
```

### 4. Test: Time to First 403! 🎉

```bash
# Port-forward to Envoy
kubectl port-forward -n default svc/envoy 8080:8080

# No warrant → 403 Forbidden
curl -i http://localhost:8080/get
```

**Expected output:**
```
HTTP/1.1 403 Forbidden
```

### 5. Test with Valid Warrant

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
curl -i \
  -H "X-Tenuo-Warrant: $WARRANT" \
  -H "X-Tenuo-PoP: $POP" \
  http://localhost:8080/get
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
│  Envoy Proxy        │
│  (ext_authz filter) │
└──────┬──────────────┘
       │ 2. Check Authorization
       ▼
┌─────────────────────┐
│ Tenuo Authorizer    │◄─── Trusted Issuer Keys
│ (gRPC ExtAuthz)     │
└──────┬──────────────┘
       │ 3. Allow/Deny
       ▼
┌─────────────────────┐
│   httpbin Service   │
└─────────────────────┘
```

## How It Works

1. **Request arrives** at Envoy proxy
2. **Envoy ext_authz filter** calls Tenuo authorizer via gRPC
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

### Envoy Filter Configuration

The Envoy config uses the `envoy.filters.http.ext_authz` filter:

```yaml
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    grpc_service:
      envoy_grpc:
        cluster_name: tenuo-authorizer
      timeout: 1s
    include_peer_certificate: true
```

## Troubleshooting

### Check authorizer logs

```bash
kubectl logs -n tenuo-system -l app=tenuo-authorizer --tail=50
```

### Check Envoy logs

```bash
kubectl logs -n default -l app=envoy --tail=50
```

### Test authorizer directly

```bash
kubectl port-forward -n tenuo-system svc/tenuo-authorizer 9090:9090

# Send a test gRPC request (requires grpcurl)
grpcurl -plaintext localhost:9090 list
```

## Envoy vs Istio

| Feature | Standalone Envoy | Istio |
|---------|------------------|-------|
| **Setup** | Direct Envoy config | ExtensionProvider + AuthorizationPolicy |
| **Complexity** | Lower | Higher (service mesh) |
| **Control** | Full Envoy control | Istio abstractions |
| **Use Case** | Simple proxy needs | Full service mesh features |

**Choose Envoy if:**
- You want a simple, standalone proxy
- You don't need full service mesh features
- You want direct control over Envoy configuration

**Choose Istio if:**
- You already have Istio deployed
- You need service mesh features (mTLS, traffic management, etc.)
- You prefer declarative policies over Envoy config

## Next Steps

- [Istio Quickstart](../istio/README.md) - Alternative with Istio service mesh
- [Kubernetes Integration Guide](../../docs/kubernetes.md)
- [Gateway Configuration](../../docs/gateway-config.md)
- [Helm Chart](../../charts/tenuo-authorizer/README.md)

## Clean Up

```bash
kubectl delete -f envoy.yaml
kubectl delete -f httpbin.yaml
kubectl delete -f authorizer.yaml
```
