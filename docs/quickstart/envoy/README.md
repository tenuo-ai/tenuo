# Envoy Quickstart

Get your first 403 in under 5 minutes.

## Prerequisites

- Kubernetes cluster (minikube, kind, or cloud)
- kubectl configured
- curl

## Steps

### 1. Deploy Everything

```bash
kubectl apply -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/docs/quickstart/envoy/all-in-one.yaml
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

See the [Kubernetes Guide](../../kubernetes) for issuing real warrants.

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

## Multi-hop Delegation Chains

`X-Tenuo-Warrant` accepts both a single warrant and a full delegation chain. The authorizer automatically distinguishes between the two: a chain is a CBOR array of warrants base64url-encoded as a single value; a single warrant is a CBOR-encoded warrant base64url-encoded directly.

For service-to-service calls in a mesh, each service that needs to delegate to a downstream service should:

1. Receive the chain in `X-Tenuo-Warrant`
2. Derive a narrower warrant from its own leaf token
3. Append the derived token to the chain and re-encode it
4. Forward the updated chain to the downstream service in `X-Tenuo-Warrant`

```python
# Example: attenuate and forward the chain (Python SDK)
from tenuo import current_warrant, attenuate, encode_chain

# Attenuate the current warrant for the downstream call
child = attenuate(current_warrant(), tool="read_file", path="/data/reports/*")

# Encode the updated chain (parent + child) and forward it
chain_b64 = encode_chain([*current_chain(), child])
requests.post("http://downstream/api", headers={"X-Tenuo-Warrant": chain_b64})
```

The downstream authorizer verifies the full chain — every link from root to leaf — offline, with no network calls.

## Next Steps

- [Istio Quickstart](../istio/) - Service mesh alternative
- [Kubernetes Guide](../../kubernetes) - Production patterns
- [Proxy Configurations](../../enforcement#proxy-configurations) - Full Envoy config reference

## Clean Up

```bash
kubectl delete -f https://raw.githubusercontent.com/tenuo-ai/tenuo/main/docs/quickstart/envoy/all-in-one.yaml
```
