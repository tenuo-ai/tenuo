---
title: Kubernetes Integration
description: Deployment patterns for Kubernetes
---

# Kubernetes Integration

Tenuo provides primitives. You build the integration that fits your setup.

---

## Primitives

```python
from tenuo import Warrant, Keypair, set_warrant_context, set_keypair_context

# Load warrant from any source
warrant = Warrant.from_base64(data)

# Load keypair (required for PoP)
keypair = Keypair.from_pem(pem_string)

# Set in context
with set_warrant_context(warrant), set_keypair_context(keypair):
    await agent.invoke(...)
```

---

## Pattern: Environment Variable

Warrant and keypair loaded at pod startup from K8s Secret.

```yaml
# kubernetes/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: tenuo-credentials
type: Opaque
stringData:
  WARRANT_BASE64: <base64-encoded-warrant>
  KEYPAIR_PEM: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
```

```yaml
# kubernetes/deployment.yaml
env:
- name: TENUO_WARRANT_BASE64
  valueFrom:
    secretKeyRef:
      name: tenuo-credentials
      key: WARRANT_BASE64
- name: TENUO_KEYPAIR_PEM
  valueFrom:
    secretKeyRef:
      name: tenuo-credentials
      key: KEYPAIR_PEM
```

```python
import os
from tenuo import Warrant, Keypair, set_warrant_context, set_keypair_context

warrant = Warrant.from_base64(os.getenv("TENUO_WARRANT_BASE64"))
keypair = Keypair.from_pem(os.getenv("TENUO_KEYPAIR_PEM"))

with set_warrant_context(warrant), set_keypair_context(keypair):
    result = agent.invoke({"input": prompt})
```

---

## Pattern: Request Header

Warrant passed per-request, keypair loaded at startup.

```python
from fastapi import FastAPI, Request
from tenuo import Warrant, Keypair, set_warrant_context, set_keypair_context
import os

app = FastAPI()
keypair = Keypair.from_pem(os.getenv("TENUO_KEYPAIR_PEM"))

@app.middleware("http")
async def tenuo_middleware(request: Request, call_next):
    if header := request.headers.get("X-Tenuo-Warrant"):
        warrant = Warrant.from_base64(header)
        with set_warrant_context(warrant), set_keypair_context(keypair):
            return await call_next(request)
    return await call_next(request)
```

---

## Pattern: Control Plane (Per-Request)

Fetch warrant from control plane for each task.

```python
import httpx
from tenuo import Warrant

async def get_warrant(tools: list, constraints: dict, ttl: int = 60) -> Warrant:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "http://control-plane.tenuo.svc.cluster.local:8080/v1/warrants",
            json={
                "tools": tools,
                "constraints": constraints,
                "ttl_seconds": ttl,
                "holder": keypair.public_key.to_bytes().hex(),
            }
        )
        return Warrant.from_base64(resp.json()["warrant"])

# Usage
warrant = await get_warrant(
    tools=["read_file"],
    constraints={"path": "/data/reports/*"},
)
```

---

## Pattern: Hybrid

Default warrant from environment, override per-request.

```python
import os
from tenuo import Warrant

class WarrantManager:
    def __init__(self):
        base64 = os.getenv("TENUO_WARRANT_BASE64")
        self.default = Warrant.from_base64(base64) if base64 else None
    
    def for_request(self, headers: dict) -> Warrant:
        if h := headers.get("X-Tenuo-Warrant"):
            return Warrant.from_base64(h)
        return self.default

# Usage
manager = WarrantManager()

@app.middleware("http")
async def tenuo_middleware(request: Request, call_next):
    warrant = manager.for_request(dict(request.headers))
    if warrant:
        with set_warrant_context(warrant), set_keypair_context(keypair):
            return await call_next(request)
    return await call_next(request)
```

---

## Pattern: Init Container

Fetch warrant during pod initialization.

```yaml
spec:
  initContainers:
  - name: fetch-warrant
    image: curlimages/curl:latest
    command:
    - sh
    - -c
    - |
      curl -s http://control-plane:8080/v1/warrants \
        -d '{"agent_id": "'$HOSTNAME'"}' \
        -o /tenuo/warrant.b64
    volumeMounts:
    - name: tenuo
      mountPath: /tenuo
  containers:
  - name: agent
    volumeMounts:
    - name: tenuo
      mountPath: /tenuo
      readOnly: true
  volumes:
  - name: tenuo
    emptyDir: {}
```

```python
# Read warrant from init container output
with open("/tenuo/warrant.b64") as f:
    warrant = Warrant.from_base64(f.read().strip())
```

---

## Security Notes

| Practice | Why |
|----------|-----|
| Use K8s Secrets, not ConfigMaps | Secrets are base64 encoded and can be encrypted at rest |
| Keypair per pod | Compromise of one pod doesn't affect others |
| Short TTLs | Limits blast radius of stolen warrants |
| Network policies | Restrict which pods can reach control plane |

---

## Troubleshooting

```python
import os

# Check if warrant is loaded
warrant_b64 = os.getenv("TENUO_WARRANT_BASE64")
if not warrant_b64:
    raise RuntimeError("TENUO_WARRANT_BASE64 not set")

warrant = Warrant.from_base64(warrant_b64)

# Check if expired
if warrant.is_expired():
    raise RuntimeError(f"Warrant expired at {warrant.expires_at}")

# Check tools
print(f"Authorized tools: {warrant.tools}")
```

---

## See Also

- [LangChain Integration](./langchain.md)
- [API Reference](./api-reference.md)
- [Protocol](./protocol.md)
