---
title: FastAPI Integration
description: Zero-boilerplate API protection for FastAPI
---

# Tenuo FastAPI Integration

---

## When to Use This

You have internal APIs that AI agents call. Different agents do different tasks at different times.

```
                                   ┌─────────────────┐
                                   │    Agent A      │
                    warrant A      │  "Research Q3"  │────┐
                  ┌───────────────▶│                 │    │
┌─────────────────┐                └─────────────────┘    │
│   Orchestrator  │                                       │  HTTP + PoP
│                 │                ┌─────────────────┐    │
│  Issues scoped  │                │    Agent B      │    │   ┌─────────────────┐
│  warrants per   │  warrant B     │  "Email CFO"    │────┼──▶│   Your API      │
│  task           │───────────────▶│                 │    │   │   (FastAPI)     │
└─────────────────┘                └─────────────────┘    │   │                 │
                                                          │   │  TenuoGuard     │
                                   ┌─────────────────┐    │   │  verifies each  │
                    warrant C      │    Agent C      │────┘   │  request        │
                  ┌───────────────▶│  (idle - no     │        └─────────────────┘
                  │                │   warrant)      │
                  │                └─────────────────┘
```

**Concrete scenario:**

| Time | Agent | Task | Warrant | API Call | Result |
|------|-------|------|---------|----------|--------|
| 9:00 | A | "Research Q3 for Acme" | `search`, query=`"acme *"`, TTL=10min | `/search?query=acme+earnings` | Pass |
| 9:00 | B | "Draft email to CFO" | `send_email`, to=`*@acme.com`, TTL=5min | `/email` to `cfo@acme.com` | Pass |
| 9:02 | A | Same task | Same warrant | `/search?query=competitor+salaries` | DENIED: Pattern mismatch |
| 9:02 | B | Same task | Same warrant | `/email` to `leak@gmail.com` | DENIED: Pattern mismatch |
| 9:06 | B | (idle) | Warrant expired | `/email` to `cfo@acme.com` | DENIED: Expired |
| 9:08 | A | Same task | Still valid | `/search?query=acme+q3` | Pass |
| 9:15 | A | (idle) | Warrant expired | `/search?query=anything` | DENIED: Expired |

**What Tenuo solves:**

| Problem | How Tenuo Handles It |
|---------|---------------------|
| **Temporal mismatch**  -- Agent was authorized 10 min ago, is it still? | Warrants have TTL. Expired = denied. |
| **Context mismatch**  -- Agent was authorized for Task A, now doing Task B | Each task gets its own warrant with specific constraints. |
| **Provenance**  -- Who authorized this agent? Can we trace the chain? | Warrant is signed. Chain of custody is cryptographically verifiable. |
| **Prompt injection**  -- Agent is tricked into doing something malicious | Doesn't matter. Warrant only allows what the task intended. |

Your API verifies the warrant. The proof is in the token.

---

## Quick Start

### Option 1: `SecureAPIRouter` (Recommended)

Drop-in replacement for `APIRouter` with automatic protection:

```python
from fastapi import FastAPI
from tenuo.fastapi import SecureAPIRouter, configure_tenuo

app = FastAPI()
configure_tenuo(app, trusted_issuers=[issuer_pubkey])

# Drop-in replacement for APIRouter
router = SecureAPIRouter(tool_prefix="api")

@router.get("/users/{user_id}")  # Auto-protected as "api_users_user_id_read"
async def get_user(user_id: str):
    return {"user_id": user_id}

@router.post("/users", tool="create_user")  # Explicit tool name
async def create_user(name: str):
    return {"name": name}

@router.delete("/users/{user_id}")  # Auto: "api_users_user_id_delete"
async def delete_user(user_id: str):
    return {"deleted": user_id}

app.include_router(router)
```

**Tool Name Inference:**

The tool name is automatically inferred from the path and HTTP method:

| Path | Method | Inferred Tool |
|------|--------|---------------|
| `/users/{user_id}` | GET | `api_users_user_id_read` |
| `/users` | POST | `api_users_create` |
| `/users/{user_id}` | PUT | `api_users_user_id_update` |
| `/users/{user_id}` | PATCH | `api_users_user_id_update` |
| `/users/{user_id}` | DELETE | `api_users_user_id_delete` |

### Option 2: `TenuoGuard` Dependency (Fine Control)

For explicit tool naming per route:

```python
from fastapi import FastAPI, Depends
from tenuo.fastapi import TenuoGuard, SecurityContext, configure_tenuo

app = FastAPI()
configure_tenuo(app, trusted_issuers=[issuer_pubkey])

@app.get("/search")
async def search(
    query: str,
    ctx: SecurityContext = Depends(TenuoGuard("search"))
):
    # ctx.warrant is verified, ctx.args contains extracted arguments
    return {"results": [...]}
```

---

## Installation

```bash
uv pip install "tenuo[fastapi]"
```

---

## API Reference

### `configure_tenuo()`

Configure Tenuo at app startup:

```python
from tenuo.fastapi import configure_tenuo

configure_tenuo(
    app,
    trusted_issuers=[issuer_pubkey],  # Required in production
    strict=False,                      # Reserved — not yet enforced
    error_handler=None,                # Reserved — not yet enforced
    expose_error_details=False,        # Don't leak constraint info
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `app` | `FastAPI` | *required* | FastAPI application instance |
| `trusted_issuers` | `List[PublicKey]` | `None` | Trusted warrant issuers (**required in production**) |
| `strict` | `bool` | `False` | Reserved — not yet enforced |
| `error_handler` | `Callable` | `None` | Reserved — not yet enforced |
| `expose_error_details` | `bool` | `False` | Include detailed errors in response |

### `TenuoGuard`

Dependency that extracts and verifies warrants:

```python
from fastapi import Depends
from tenuo.fastapi import TenuoGuard, SecurityContext

@app.post("/files/{path:path}")
async def read_file(
    path: str,
    ctx: SecurityContext = Depends(TenuoGuard("read_file"))
):
    # path automatically extracted from route
    # ctx.warrant is verified
    # ctx.args = {"path": path}
    return {"content": "..."}
```

**Argument extraction (default):**
- Path parameters: Extracted from URL
- Query parameters: Extracted from query string

> **Note:** JSON body fields are **not** extracted by default. To include body fields, provide a custom `extract_args` function to `TenuoGuard`.

### `SecurityContext`

Context object injected into route handlers:

| Property | Type | Description |
|----------|------|-------------|
| `tool` | `str` | The tool name that was matched |
| `warrant` | `Warrant` | The verified warrant |
| `args` | `dict` | Extracted arguments used for authorization |

```python
from fastapi import Depends
from tenuo.fastapi import TenuoGuard, SecurityContext

@app.get("/api/data")
async def get_data(ctx: SecurityContext = Depends(TenuoGuard("get_data"))):
    print(f"Tool: {ctx.tool}")
    print(f"Warrant ID: {ctx.warrant.id}")
    print(f"Tools: {ctx.warrant.tools}")
    print(f"Args: {ctx.args}")
```

### `SecureAPIRouter`

Drop-in replacement for FastAPI's `APIRouter` with automatic Tenuo protection:

```python
from tenuo.fastapi import SecureAPIRouter

router = SecureAPIRouter(
    tool_prefix="api",    # Optional prefix for tool names
    require_pop=True,     # Require PoP signatures (default: True)
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tool_prefix` | `str` | `None` | Prefix for auto-generated tool names |
| `require_pop` | `bool` | `True` | Require Proof-of-Possession signatures |

**Methods:**

All standard `APIRouter` methods are supported, with an additional `tool` parameter:

```python
@router.get("/path", tool="custom_tool_name")
@router.post("/path")  # Auto-inferred tool name
@router.put("/path")
@router.delete("/path")
@router.patch("/path")
```

---

## Headers

Tenuo expects these HTTP headers:

| Header | Description |
|--------|-------------|
| `X-Tenuo-Warrant` | Base64-encoded warrant (or warrant stack) |
| `X-Tenuo-PoP` | Base64-encoded Proof-of-Possession signature |
| `X-Tenuo-Approvals` | Base64-encoded signed approvals (optional) |

**Example request:**

```bash
curl -X GET "https://api.example.com/search?query=test" \
  -H "X-Tenuo-Warrant: eyJ3YXJyYW50IjoiLi4uIn0=" \
  -H "X-Tenuo-PoP: SGVsbG8gV29ybGQ="
```

---

## Error Handling

### Error Responses

Tenuo returns structured errors with canonical wire codes:

```json
{
  "error": "constraint-violation",
  "error_code": 1501,
  "message": "Constraint violation: field 'amount' exceeded maximum value",
  "details": {}
}
```

**Wire Code Support:**

The FastAPI integration automatically includes canonical error codes (1000-2199) that map to HTTP status codes. This enables:

- **Machine-readable errors**: Clients can programmatically handle specific error types
- **Cross-protocol consistency**: Same error codes used across HTTP, JSON-RPC, and gRPC
- **Precise debugging**: Error codes pinpoint the exact failure reason

Common error codes:

| Wire Code | Name | HTTP Status | Meaning |
|-----------|------|-------------|---------|
| 1100 | `signature-invalid` | 401 | Invalid cryptographic signature |
| 1300 | `warrant-expired` | 401 | Warrant TTL exceeded |
| 1500 | `tool-not-authorized` | 403 | Tool not in warrant's allowed list |
| 1501 | `constraint-violation` | 403 | Argument violates constraint |
| 1600 | `pop-signature-mismatch` | 403 | PoP verification failed |
| 1800 | `warrant-revoked` | 401 | Warrant revoked by issuer |

See [wire format specification](/docs/spec/wire-format-v1#appendix-a-error-codes) for the complete list.

### Status Codes

| Code | Meaning |
|------|---------|
| `400 Bad Request` | Malformed request (invalid base64, missing fields) |
| `401 Unauthorized` | Authentication failed (expired, revoked, bad signature) |
| `403 Forbidden` | Authorization failed (tool/constraints not satisfied) |
| `413 Payload Too Large` | Warrant or request exceeds size limits |

### Custom Error Handling

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from tenuo.exceptions import TenuoError

app = FastAPI()

@app.exception_handler(TenuoError)
async def tenuo_error_handler(request: Request, exc: TenuoError):
    """Custom handler with wire codes."""
    return JSONResponse(
        status_code=exc.get_http_status(),
        content={
            "error": exc.get_wire_name(),       # kebab-case name
            "error_code": exc.get_wire_code(),  # numeric wire code
            "message": str(exc),
            "details": exc.details if hasattr(exc, 'details') else {},
        }
    )
```

**Note**: The FastAPI integration registers a global exception handler automatically when you call `configure_tenuo()`, so custom handlers are optional.

---

## Patterns

### Multiple Tools per Route

```python
from fastapi import Depends
from tenuo.fastapi import TenuoGuard, SecurityContext

@app.post("/files/{path:path}")
async def file_operation(
    path: str,
    action: str,
    ctx: SecurityContext = Depends(TenuoGuard("file_operation"))
):
    # Single tool per endpoint - specify the most restrictive
    pass
```

### Body Parameter Extraction

Since JSON body fields are not extracted by default, provide a custom `extract_args`:

```python
from fastapi import Request
from pydantic import BaseModel
from tenuo.fastapi import TenuoGuard, SecurityContext

class TransferRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float

async def extract_transfer_args(request: Request) -> dict:
    body = await request.json()
    return {**request.path_params, **dict(request.query_params), **body}

@app.post("/transfer")
async def transfer(
    body: TransferRequest,
    ctx: SecurityContext = Depends(TenuoGuard("transfer", extract_args=extract_transfer_args))
):
    # ctx.args = {"from_account": "...", "to_account": "...", "amount": ...}
    pass
```

---

## Full Example

```python
from fastapi import FastAPI, Depends
from tenuo import SigningKey, Warrant, Subpath
from tenuo.fastapi import TenuoGuard, SecurityContext, configure_tenuo

app = FastAPI()

# Generate issuer key (in production, load from secure storage)
issuer_key = SigningKey.generate()

# Configure Tenuo
configure_tenuo(app, trusted_issuers=[issuer_key.public_key])

@app.get("/search")
async def search(
    query: str,
    ctx: SecurityContext = Depends(TenuoGuard("search"))
):
    return {"results": [f"Result for: {query}"]}

@app.get("/files/{path:path}")
async def read_file(
    path: str,
    ctx: SecurityContext = Depends(TenuoGuard("read_file"))
):
    return {"path": path, "content": "..."}

# Issue a warrant for testing
@app.post("/admin/issue-warrant")
async def issue_warrant():
    warrant = (Warrant.mint_builder()
        .tool("search")  # No constraints
        .capability("read_file", path=Subpath("/data"))  # With constraint
        .holder(issuer_key.public_key)
        .ttl(3600)
        .mint(issuer_key))
    
    return {"warrant": warrant.to_base64()}
```

---

## Security Notes

### Error Details

By default, authorization errors don't reveal constraint details:

```python
# Client sees:
# {"error": "authorization_denied", "message": "Authorization denied", "request_id": "abc123"}

# Server logs:
# [abc123] Tool 'read_file' denied: path=/etc/passwd, expected=Pattern(/data/*)
```

Enable detailed errors only for development:

```python
configure_tenuo(app, expose_error_details=True)  # Development only!
```

### Replay Protection

For sensitive operations (e.g., payments), use `dedup_key` to prevent replay attacks during the PoP window:

```python
from tenuo.fastapi import TenuoGuard, SecurityContext
import redis

r = redis.Redis()

@app.post("/payments/transfer")
async def transfer(
    ctx: SecurityContext = Depends(TenuoGuard("transfer"))
):
    # Generate unique ID for this specific request
    req_id = ctx.warrant.dedup_key("transfer", ctx.args)
    
    # Check if seen in last 2 minutes
    if r.exists(f"seen:{req_id}"):
        raise HTTPException(400, "Replay detected")
    
    # Mark as seen (expires after PoP window)
    r.setex(f"seen:{req_id}", 120, "1")
    
    process_payment()
```

> [!NOTE]
> **Performance & Responsibility**: You are responsible for provisioning and maintaining the storage backend (e.g., Redis). Tenuo provides the deterministic key but does not manage the statestore. The latency and availability of this check depend entirely on your storage infrastructure.

### Warrant Scope

Each route should specify the minimum tool(s) required:

```python
# Good: specific tool
@app.get("/users")
async def get_users(ctx: SecurityContext = Depends(TenuoGuard("list_users"))):
    ...

# Bad: overly permissive
@app.get("/users")
async def get_users(ctx: SecurityContext = Depends(TenuoGuard("admin_users"))):
    # Each endpoint should have one specific tool
```

---

## Delegation Chains (WarrantStack)

When an orchestrator delegates a subset of its authority to a worker, the full chain of warrants must be sent together. `TenuoGuard` automatically detects a `WarrantStack` and validates the chain end-to-end.

```python
from tenuo import SigningKey, Warrant, encode_warrant_stack
from tenuo.fastapi import configure_tenuo, TenuoGuard, SecurityContext

issuer = SigningKey.generate()
orchestrator = SigningKey.generate()
worker = SigningKey.generate()

root = (Warrant.mint_builder()
    .capability("search").capability("delete_file")
    .holder(orchestrator.public_key).ttl(3600).mint(issuer))

child = (root.grant_builder()
    .capability("search")
    .holder(worker.public_key).ttl(1800).grant(orchestrator))

# Client sends the full chain as a single X-Tenuo-Warrant header
stack_b64 = encode_warrant_stack([root, child])
# Server-side: configure_tenuo(app, trusted_issuers=[issuer.public_key])
# TenuoGuard automatically detects WarrantStack and uses check_chain
```

> **Important:** Orphaned child warrants (sent without the parent chain) are rejected. Always send the complete chain from root to leaf.

---

## See Also

- [Quickstart](./quickstart)  -- Get running in 5 minutes
- [Security](./security)  -- Threat model, best practices
- [API Reference](./api-reference)  -- Full Python API documentation
- [LangChain](./langchain)  -- Tool protection for LangChain

