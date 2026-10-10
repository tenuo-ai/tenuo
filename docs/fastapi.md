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

`trusted_issuers` holds your **root** issuer keys. Delegated warrants are accepted when the client sends the full chain (see [Delegation Chains](#delegation-chains-warrantstack)); never add an intermediate agent's key here to make a bare delegated warrant pass. If no roots are configured here, the guard falls back to a bound `Runtime` and then to `tenuo.configure(trusted_roots=...)`; with none of them it denies every request.

### Calling a protected route

The client signs the exact arguments the route will authorize and sends the warrant and PoP as headers:

```python
import httpx
from tenuo import Pattern, Range, Warrant

warrant = (Warrant.mint_builder()
    .capability("search", query=Pattern("acme *"), limit=Range(max=20))
    .holder(agent_key.public_key)
    .ttl(600)
    .mint(issuer_key))

bound = warrant.bind(agent_key)
args = {"query": "acme earnings", "limit": 5}
headers = bound.headers("search", args, trusted_roots=[issuer_key.public_key])
httpx.get("https://api.example.com/search", params=args, headers=headers)
```

`bound.headers()` checks the call locally first and raises if the warrant would deny it.

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
    expose_error_details=False,        # Don't leak constraint info
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `app` | `FastAPI` | *required* | FastAPI application instance |
| `trusted_issuers` | `List[PublicKey]` | `None` | Trusted root issuer keys (**required in production**) |
| `runtime` | `Runtime` | `None` | Holder runtime; supplies roots, revocation list and receipt outbox when `trusted_issuers` is omitted |
| `expose_error_details` | `bool` | `False` | Include the denial reason and arguments in 403 responses |

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
- Values are typed from the endpoint signature: with `limit: int`, `?limit=5` is authorized as the integer `5` (so `Range` and other numeric constraints work). Parameters the endpoint doesn't declare stay strings. Clients must sign the same typed values, e.g. `bound.headers("list_items", {"limit": 5})`, not `{"limit": "5"}`. Custom `extract_args` results are used as-is.

> **Note:** JSON body fields are **not** extracted by default, so they are covered by neither the PoP signature nor the constraints. To authorize body fields, pass an `extract_args` function to `TenuoGuard` (see [Body Parameter Extraction](#body-parameter-extraction)). It can be a plain function or an `async def`.

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
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tool_prefix` | `str` | `None` | Prefix for auto-generated tool names |
| `require_pop` | `bool` | `True` | Accepted for compatibility; has no effect. Protected routes always require PoP |

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
| `X-Tenuo-Warrant` | Base64-encoded warrant, or a WarrantStack (root → leaf) for delegated warrants |
| `X-Tenuo-PoP` | Standard base64-encoded Proof-of-Possession signature |
| `X-Tenuo-Approvals` | Base64-encoded JSON array of base64 CBOR `SignedApproval` blobs (optional, for retry) |

**Example request (with approval retry):**

```bash
# approvals_b64 = base64(json.dumps([base64(cbor_signed_approval), ...]))
curl -X GET "https://api.example.com/search?query=test" \
  -H "X-Tenuo-Warrant: eyJ3YXJyYW50IjoiLi4uIn0=" \
  -H "X-Tenuo-PoP: SGVsbG8gV29ybGQ=" \
  -H "X-Tenuo-Approvals: W3siLi4uIn1d"
```

On **409** with `"error": "approval_required"`, read `detail.request_hash` from the body, sign, and re-submit with `X-Tenuo-Approvals`. See [Human Approvals](approvals.md#wire-format-retry-payloads).

---

## Error Handling

### Error Responses

`TenuoGuard` rejects a request with an `HTTPException`, so FastAPI wraps the body in `detail`:

```json
{
  "detail": {
    "error": "authorization_denied",
    "message": "Authorization denied",
    "request_id": "f777a1b7"
  }
}
```

| Status | `detail.error` | When |
|--------|----------------|------|
| `400` | (string detail) | `X-Tenuo-Warrant` is not a valid warrant or WarrantStack |
| `400` | `invalid_pop` | `X-Tenuo-PoP` is not valid base64 |
| `400` | `invalid_approval` | `X-Tenuo-Approvals` cannot be decoded |
| `401` | `missing_warrant` | No `X-Tenuo-Warrant` header |
| `401` | `missing_pop` | No `X-Tenuo-PoP` header |
| `401` | `warrant_expired` | Warrant TTL exceeded |
| `403` | `authorization_denied` | Any other denial: tool not in warrant, constraint violation, bad PoP, untrusted root, missing chain, revoked |
| `403` | `configuration_error` | No trusted roots configured anywhere |
| `409` | `approval_required` | Approval gate fired (`request_hash`, `min_approvals` in `detail`) |
| `409` | `insufficient_approvals` | Multi-sig threshold not met (`got` / `need` in `detail`) |
| `500` | `configuration_error` | A sync `extract_args` returned an awaitable |

Every 403 carries a `request_id`; the server logs the denial reason under the same ID. With `expose_error_details=True`, the 403 `detail` also includes the reason, `tool` and `args`.

Approval retries use **409 Conflict** (not 403) so clients can branch separately from scope denials. Re-submit with `X-Tenuo-Approvals`. See [Human Approvals](approvals.md#signals-by-integration).

`configure_tenuo()` also registers a handler for `TenuoError` exceptions that escape your own route code. That handler returns a flat body with a canonical wire code:

```json
{"error": "constraint-violation", "error_code": 1501, "message": "...", "details": {}}
```

See [wire format specification](./spec/wire-format-v1#appendix-a-error-code-reference) for the wire code list.

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

**Note**: `configure_tenuo()` registers this `TenuoError` handler automatically, so a custom one is optional. Denials from `TenuoGuard` are `HTTPException`s and are not routed through it.

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
from tenuo.fastapi import TenuoGuard, SecurityContext, extract_body_args

class TransferRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float

async def extract_transfer_args(request: Request) -> dict:
    body = await extract_body_args(request)  # {} if the body isn't JSON
    return {**request.path_params, **dict(request.query_params), **body}

@app.post("/transfer")
async def transfer(
    body: TransferRequest,
    ctx: SecurityContext = Depends(TenuoGuard("transfer", extract_args=extract_transfer_args))
):
    # ctx.args = {"from_account": "...", "to_account": "...", "amount": ...}
    pass
```

Custom `extract_args` results are used as-is, so the client signs the same JSON values it sends: `bound.headers("transfer", body)` with `json=body`.

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
# Client sees (403):
# {"detail": {"error": "authorization_denied", "message": "Authorization denied", "request_id": "abc123"}}

# Server logs (warning):
# [abc123] Authorization denied for tool 'read_file' with args {'path': '/etc/passwd'}. Reason: ... Warrant ID: tnu_wrt_...
```

The server log line includes argument values; treat it as sensitive. Enable detailed client errors only for development:

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

When an orchestrator delegates a subset of its authority to a worker, the full chain of warrants must be sent together. The server only trusts the root issuer, so it can verify the worker's warrant only when the parents arrive with it. `TenuoGuard` detects a `WarrantStack` in `X-Tenuo-Warrant` and verifies the chain end-to-end.

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

# Server-side: configure_tenuo(app, trusted_issuers=[issuer.public_key])  # root only

# Client: the worker signs PoP; warrant_chain lists the parents, root first
args = {"query": "acme q3"}
headers = child.bind(worker).headers(
    "search", args,
    trusted_roots=[issuer.public_key],
    warrant_chain=[root],
)
# headers["X-Tenuo-Warrant"] is the WarrantStack [root, child]

# Or build the header yourself:
stack_b64 = encode_warrant_stack([root, child])
```

> **Important:** A child warrant sent without its parents is rejected with 403, because its issuer (the orchestrator) is not a trusted root. Always send the complete chain from root to leaf.

---

## Observe Mode

To learn what policy your agents need before enforcing it, run in observe mode:

```python
from tenuo import configure

configure(trusted_roots=[issuer_key.public_key], mode="observe")
# or: TENUO_MODE=observe  ("audit" and "permissive" are accepted aliases)
```

`TenuoGuard` still runs full verification, but a request it would deny is let through: the route runs and the server logs `OBSERVE: would deny <tool>: <reason>` at warning level. This applies to every denial the guard makes after the headers are parsed, including PoP and chain failures, so use observe mode only while discovering policy. Missing headers, an expired warrant and malformed headers are still rejected.

---

## See Also

- [Quickstart](./quickstart)  -- Get running in 5 minutes
- [Security](./security)  -- Threat model, best practices
- [API Reference](./api-reference)  -- Full Python API documentation
- [LangChain](./langchain)  -- Tool protection for LangChain

