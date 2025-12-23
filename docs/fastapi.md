---
title: FastAPI Integration
description: Zero-boilerplate API protection for FastAPI
---

# Tenuo FastAPI Integration

> **Status**: ✅ Implemented (v0.1)

---

## Quick Start

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
pip install tenuo[fastapi]
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
| `trusted_issuers` | `List[PublicKey]` | `None` | Trusted warrant issuers (**required in production**) |
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

**Argument extraction:**
- Path parameters: Extracted from URL
- Query parameters: Extracted from query string
- Body: Extracted from JSON body (POST/PUT/PATCH)

### `SecurityContext`

Context object injected into route handlers:

| Property | Type | Description |
|----------|------|-------------|
| `warrant` | `Warrant` | The verified warrant |
| `args` | `dict` | Extracted arguments used for authorization |

```python
@app.get("/api/data")
async def get_data(ctx: SecurityContext = Depends(TenuoGuard("get_data"))):
    print(f"Warrant ID: {ctx.warrant.id}")
    print(f"Tools: {ctx.warrant.tools}")
    print(f"Args: {ctx.args}")
```

---

## Headers

Tenuo expects these HTTP headers:

| Header | Description |
|--------|-------------|
| `Authorization` | `TenuoWarrant <base64-encoded-warrant>` |
| `X-Tenuo-Pop` | Base64-encoded Proof-of-Possession signature |

**Example request:**

```bash
curl -X GET "https://api.example.com/search?query=test" \
  -H "Authorization: TenuoWarrant eyJ3YXJyYW50IjoiLi4uIn0=" \
  -H "X-Tenuo-Pop: SGVsbG8gV29ybGQ="
```

---

## Error Handling

### Error Responses

Tenuo returns opaque errors by default to prevent information leakage:

```json
{
  "error": "authorization_denied",
  "message": "Authorization denied",
  "request_id": "abc123"
}
```

Use the `request_id` to correlate with server logs.

### Status Codes

| Code | Meaning |
|------|---------|
| `401 Unauthorized` | Missing or invalid warrant, bad PoP signature |
| `403 Forbidden` | Valid warrant, but tool/args not authorized |

### Custom Error Handling

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from tenuo.fastapi import TenuoError

app = FastAPI()

@app.exception_handler(TenuoError)
async def tenuo_error_handler(request: Request, exc: TenuoError):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error_code,
            "message": exc.message,
            "request_id": exc.request_id,
        }
    )
```

---

## Patterns

### Multiple Tools per Route

```python
@app.post("/files/{path:path}")
async def file_operation(
    path: str,
    action: str,
    ctx: SecurityContext = Depends(TenuoGuard(["read_file", "write_file"]))
):
    # Warrant must include at least one of the listed tools
    pass
```

### Body Parameter Extraction

```python
from pydantic import BaseModel

class TransferRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float

@app.post("/transfer")
async def transfer(
    body: TransferRequest,
    ctx: SecurityContext = Depends(TenuoGuard("transfer"))
):
    # ctx.args = {"from_account": "...", "to_account": "...", "amount": ...}
    pass
```

### Optional Authorization

```python
from tenuo.fastapi import TenuoGuard

@app.get("/public-or-private")
async def flexible(
    ctx: Optional[SecurityContext] = Depends(TenuoGuard("read", required=False))
):
    if ctx:
        # Authorized access
        return {"data": "private"}
    else:
        # Public access
        return {"data": "public"}
```

---

## Full Example

```python
from fastapi import FastAPI, Depends
from tenuo import SigningKey, Warrant, Pattern
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
    warrant = (Warrant.builder()
        .tool("search")
        .tool("read_file")
        .capability("read_file", {"path": Pattern("/data/*")})
        .holder(issuer_key.public_key)
        .ttl(3600)
        .issue(issuer_key))
    
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

### Warrant Scope

Each route should specify the minimum tool(s) required:

```python
# ✅ Good: specific tool
@app.get("/users")
async def get_users(ctx: SecurityContext = Depends(TenuoGuard("list_users"))):
    ...

# ❌ Bad: overly permissive
@app.get("/users")
async def get_users(ctx: SecurityContext = Depends(TenuoGuard(["list_users", "delete_users"]))):
    ...
```

---

## See Also

- [Quickstart](./quickstart) — Get running in 5 minutes
- [Security](./security) — Threat model, best practices
- [API Reference](./api-reference) — Full Python API documentation
- [LangChain](./langchain) — Tool protection for LangChain

