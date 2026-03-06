## MCP Integration

Tenuo provides full Model Context Protocol (MCP) integration with cryptographic authorization — both **client-side** (protecting outgoing tool calls) and **server-side** (verifying warrants inside tool handlers).

**Full Stack**: Connect to MCP servers → Discover tools → Auto-protect with warrants → Execute securely → Verify on the server.

---

## Prerequisites

```bash
uv pip install "tenuo[mcp]"       # MCP client + server (Python ≥3.10)
```

For the full LangChain + MCP example:
```bash
uv pip install "tenuo[langchain,mcp]"
```

---

## Why MCP + Tenuo?

**MCP** exposes powerful capabilities (filesystem, database, code execution) to AI agents.  
**Tenuo** ensures those capabilities are constrained with cryptographic warrants.

| Without Tenuo | With Tenuo |
|---------------|------------|
| Agent has full MCP server access | Warrant constrains what MCP tools can do |
| No audit trail | Cryptographic proof of who authorized each action |
| Ambient authority | Task-scoped, time-limited permissions |

### Where Tenuo Fits in MCP

MCP's native auth (OAuth) answers: **WHO is calling?**  
Tenuo answers: **WHAT can they do right now?**

```
┌──────────────────────────────────────────────────────────────────┐
│                         MCP STACK                                 │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│   Host App ──► MCP Client ──► [Tenuo Guard] ──► MCP Server       │
│                                     │                             │
│                              ┌──────┴──────┐                      │
│                              │   Warrant   │                      │
│                              │ • tools     │                      │
│                              │ • constraints│                     │
│                              │ • TTL       │                      │
│                              └─────────────┘                      │
└──────────────────────────────────────────────────────────────────┘
```

**OAuth vs Warrants Comparison:**

| Aspect | OAuth Token | Tenuo Warrant |
|--------|-------------|---------------|
| **Scope granularity** | Coarse (`files:read`) | Fine (`read_file(path=/data/x/*)`) |
| **Proof-of-Possession** | Optional (DPoP) | Mandatory |
| **Delegation** | No native chaining | Cryptographic attenuation chains |
| **Verification** | Requires introspection/JWKS | Stateless, self-contained |

OAuth tells you *who* is authenticated. Warrants constrain *what* they can do *with which arguments*. Even if an LLM is prompt-injected mid-task, it can only use what the warrant allows.

---

## Quick Start

Tenuo supports three integration patterns for MCP:

1. **`SecureMCPClient`** (Built-in): Full client with automatic discovery and protection.
2. **`MCPVerifier`** (Built-in): Server-side warrant verification inside tool handlers.
3. **`langchain-mcp-adapters`** (Official): Secure the official LangChain MCP client.

### Pattern 1: SecureMCPClient (Recommended)

**Prerequisite**: Python 3.10+ (required by MCP SDK)

```python
from tenuo.mcp import SecureMCPClient
from tenuo import configure, mint, Capability, Subpath, SigningKey

key = SigningKey.generate()
configure(issuer_key=key)

# Stdio (local subprocess)
async with SecureMCPClient("python", ["server.py"], register_config=True) as client:
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

### Pattern 2: MCPVerifier (Server-Side)

Verify warrants inside MCP tool handlers. Works with any server framework.

```python
from tenuo import Authorizer, PublicKey, CompiledMcpConfig, McpConfig
from tenuo.mcp import MCPVerifier

authorizer = Authorizer(trusted_roots=[PublicKey.from_bytes(root_pub)])
config = CompiledMcpConfig.compile(McpConfig.from_file("mcp-config.yaml"))
verifier = MCPVerifier(authorizer=authorizer, config=config)

# fastmcp example
@mcp.tool()
async def read_file(path: str, **kwargs) -> str:
    clean = verifier.verify_or_raise("read_file", {"path": path, **kwargs})
    return open(clean["path"]).read()
```

The verifier extracts `_tenuo` from arguments, verifies the warrant + PoP signature, checks constraints, and returns clean arguments (with `_tenuo` stripped).

### Pattern 3: Securing LangChain Adapters

If you are already using `langchain-mcp-adapters`, you can protect its tools using `guard()`:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from tenuo.langchain import guard_tools

# 1. Connect via official client
client = MultiServerMCPClient({...})
mcp_tools = await client.get_tools()

# 2. Wrap with Tenuo protection
secure_tools = guard(mcp_tools, bound)

# ... use secure_tools in your agent
```

### Advanced: Manual Configuration

For fine-grained control or Python < 3.10, you can manually define constraints and authorize calls.

#### 1. Create MCP Configuration

Define how to extract constraints from MCP tool calls:

```yaml
# mcp-config.yaml
version: "1"

tools:
  filesystem_read:
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
        default: 1048576  # 1 MB
```

#### 2. Authorize MCP Calls (Manual)

If you are not using `SecureMCPClient`, you must manually authorize extracted arguments.

```python
from tenuo import McpConfig, CompiledMcpConfig, Authorizer, SigningKey, Warrant, Constraints, Pattern, Range

# 1. Load MCP configuration
config = McpConfig.from_file("mcp-config.yaml")
compiled = CompiledMcpConfig.compile(config)

# 2. Create warrant (usually done by control plane)
control_key = SigningKey.generate()  # In production: SigningKey.from_env("MY_KEY")
warrant = (Warrant.mint_builder()
    .capability("filesystem_read",
        path=Subpath("/var/log"),
        max_size=Range.max_value(1024 * 1024))
    .holder(control_key.public_key)
    .ttl(3600)
    .mint(control_key))

# 3. Handle MCP tool call
# (Simulated MCP arguments)
mcp_arguments = {
    "path": "/var/log/app.log",
    "maxSize": 512 * 1024
}

# 4. Extract constraints based on config
result = compiled.extract_constraints("filesystem_read", mcp_arguments)

# 5. Authorize with PoP signature
pop_sig = warrant.sign(control_key, "filesystem_read", dict(result.constraints))
authorizer = Authorizer(trusted_roots=[control_key.public_key])
authorizer.check(warrant, "filesystem_read", dict(result.constraints), bytes(pop_sig))

# ✓ Authorized - proceed to execute tool
```

---

## LangChain + MCP Integration

Tenuo integrates seamlessly with [`langchain-mcp-adapters`](https://github.com/langchain-ai/langchainjs/tree/main/libs/langchain-mcp-adapters/).

**Pattern**: LangChain `MultiServerMCPClient` → Tenuo Authorization → MCP Server

### Secure Adapter Pattern

The most robust way to use MCP with LangChain is to wrap the official client tools with Tenuo authorization:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from tenuo.mcp import SecureMCPClient # Wrapper for official client

# 1. Connect via official client
client = MultiServerMCPClient({
    "math": {
        "transport": "stdio",
        "command": "python",
        "args": ["math_server.py"]
    }
})

# 2. Get protected tools (Tenuo auto-wraps them)
tools = await client.get_tools()
# ... use tools in LangChain agent
```

### Python Example

```python
from tenuo import McpConfig, CompiledMcpConfig, Authorizer, SigningKey, Warrant, Pattern, Capability
from tenuo import guard, configure, mint_sync

# 1. Configure Tenuo
control_key = SigningKey.generate()  # In production: SigningKey.from_env("MY_KEY")
configure(issuer_key=control_key)

# 2. Load MCP configuration
config = McpConfig.from_file("mcp-config.yaml")
compiled = CompiledMcpConfig.compile(config)

# 3. Define MCP tool wrapper
@guard(tool="filesystem_read")
def filesystem_read(path: str, maxSize: int = 1048576):
    """Read file from filesystem (MCP tool)"""
    # In production: Call actual MCP server
    with open(path, 'r') as f:
        content = f.read(maxSize)
    return content

# 4. Use with task scoping
with mint_sync(Capability("filesystem_read", path="/var/log/*")):
    # Agent calls MCP tool - Tenuo authorizes
    content = filesystem_read("/var/log/app.log", maxSize=512 * 1024)
    print(content)
```

### End-to-End Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  LangChain  │────▶│    Tenuo    │────▶│ MCP Server  │
│   Agent     │     │  Authorizer │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
      │                    │                    │
      │ 1. Call tool       │                    │
      │───────────────────▶│                    │
      │                    │ 2. Extract         │
      │                    │    constraints     │
      │                    │ 3. Check warrant   │
      │                    │ 4. Authorize       │
      │                    │◀───────────────────│
      │                    │ 5. Execute         │
      │◀───────────────────│───────────────────▶│
      │ 6. Return result   │                    │
```

---

## MCP Configuration

Define how to extract constraints from MCP tool call arguments.

> Remember: This configuration defines extraction, not policy. It tells Tenuo where to find the arguments in the JSON-RPC call. The actual limits (e.g., which paths are allowed) are defined in the Warrant. See [Argument Extraction](./argument-extraction) for a deep dive.

### Extraction Sources

MCP tool calls provide an `arguments` JSON object. Use:

- **`from: body`** - Extract from arguments (recommended)
- **`from: literal`** - Use default value

❌ **Don't use**: `from: path`, `from: query`, `from: header` (HTTP-only)

### Example: Filesystem Tool

```yaml
tools:
  filesystem_read:
    description: "Read files from the filesystem"
    constraints:
      path:
        from: body
        path: "path"
        description: "File path to read"
        required: true
      
      max_size:
        from: body
        path: "maxSize"
        description: "Maximum file size in bytes"
        type: integer
        default: 1048576
      
      allowed_paths:
        from: body
        path: "allowedPaths"
        description: "List of allowed path prefixes"
```

### Example: Database Tool

```yaml
tools:
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

---

## Constraint Extraction

### Automatic Extraction

Tenuo extracts constraints from MCP arguments using YAML config.

When using `SecureMCPClient(config_path="...", register_config=True)`, extraction happens automatically during tool calls.

### Warrant Propagation (Mesh)

To enable end-to-end authorization where the server verifies the warrant, set `inject_warrant=True`:

```python
async with SecureMCPClient(..., inject_warrant=True) as client:
    # Warrants now travel in arguments._tenuo
    await client.tools["read_file"](path="/tmp/test.txt")
```

### ⚠️ Interoperability Risk: Strict Schemas

When `inject_warrant=True`, Tenuo injects a `_tenuo` field into the tool arguments:

```python
# Tenuo modifies the call payload:
{
  "path": "/data/file.txt",
  "_tenuo": {
    "warrant": "<base64>",
    "signature": "<base64>",
    "approvals": ["<base64>", ...]  # optional, for approval-gate-protected tools
  }
}
```

If the destination MCP server uses a **strict JSON Schema** validator (e.g., explicit `additionalProperties: false`), the call will fail because `_tenuo` is not in the server's known input schema.

**Mitigation**:
1. **Configure Server**: Ensure your MCP servers are configured to allow unknown properties (this is the default in most Pydantic/Zod setups unless explicitly strict).
2. **Update Schema**: If strict validation is required, add `_tenuo` (type: object, optional) to your tool schemas.
```

### Manual Extraction

If not using `SecureMCPClient`, you can extract constraints manually:

```python
# Extract constraints
result = compiled.extract_constraints("filesystem_read", arguments)

# Result contains:
# result.constraints: { "path": "/var/log/app.log", "max_size": 524288 }
# result.warrant_base64: "..."
```

### Nested Paths

Use dot notation for nested fields:

```yaml
constraints:
  table:
    from: body
    path: "query.table"  # Extracts arguments.query.table
```

### Wildcard Extraction

Extract lists with wildcards:

```yaml
constraints:
  item_ids:
    from: body
    path: "items.*.id"  # Extracts all item IDs
```

**Note**: Wildcard extraction returns a list. Use compatible constraints:
- `OneOf` / `NotOneOf` - Membership checks
- `CEL` - Complex list operations

---

## Authorization Patterns

### Pattern 1: Decorator-Based

```python
from tenuo import guard, mint_sync

@guard(tool="filesystem_read")
def filesystem_read(path: str, maxSize: int):
    # MCP server call
    return read_file_from_mcp_server(path, maxSize)

with mint_sync(Capability("filesystem_read", path="/var/log/*")):
    content = filesystem_read("/var/log/app.log", 1024)
```

### Pattern 2: Explicit Authorization

```python
from tenuo import Authorizer, Warrant

# Create warrant
warrant = (Warrant.mint_builder()
    .capability("filesystem_read", path=Subpath("/var/log"))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key)
)

# Extract constraints from MCP call
result = compiled.extract_constraints("filesystem_read", arguments)

# Authorize
pop_sig = warrant.sign(key, "filesystem_read", dict(result.constraints))
authorizer.check(warrant, "filesystem_read", dict(result.constraints), bytes(pop_sig))
```

### Pattern 3: Multi-Agent Delegation

```python
# Control plane issues root warrant
root_warrant = (Warrant.mint_builder()
    .capability("filesystem_read", path=Subpath("/data"))
    .capability("database_query", path=Subpath("/data"))
    .holder(orchestrator_key.public_key)
    .ttl(3600)
    .mint(control_key))

# Orchestrator attenuates for worker
worker_warrant = (root_warrant.grant_builder()
    .capability("filesystem_read", path=Subpath("/data/reports"))
    .holder(worker_key.public_key)
    .grant(orchestrator_key))  # Orchestrator signs (they hold the parent)

# Worker uses attenuated warrant
# (narrower permissions, cryptographic proof of delegation)
```

---

## Security Best Practices

### 1. Validate Configuration

```python
compiled = CompiledMcpConfig.compile(config)
warnings = compiled.validate()
for warning in warnings:
    print(warning)
```

Warns about incompatible extraction sources (path, query, header).

### 2. Use Trusted Roots

```python
# Load control plane public key
control_plane_key = PublicKey.from_bytes(key_bytes)

# Create authorizer with trusted root
authorizer = Authorizer(trusted_roots=[control_plane_key])
```

Without trusted roots, chain verification only checks internal consistency.

### 3. Proof-of-Possession

Always require PoP signatures for MCP tool calls:

```python
# Create PoP signature
pop_sig = warrant.sign(keypair, tool, args)

# Authorize with signature
authorizer.check(warrant, tool, args, bytes(pop_sig))
```

Prevents warrant theft and replay attacks.

### 4. Constraint Narrowing

Use specific constraints, not wildcards:

```python
# Too broad
constraints = {"path": Wildcard()}

# Specific
constraints = {"path": Subpath("/var/log")}
```

### 5. Short TTLs

MCP tools are often high-risk (filesystem, database). Use short TTLs:

```python
warrant = (Warrant.mint_builder()
    .tool("filesystem_write")
    .holder(key.public_key)
    .ttl(300)  # 5 minutes
    .mint(key)
)
```

---

## Approval Gate Flow

Warrants can embed **approval gates** that require human approval before a tool call proceeds. When an approval gate triggers, the MCP integration returns a structured error so clients can collect approvals and retry.

### Server-Side (MCPVerifier)

```python
result = verifier.verify("transfer", arguments)
if result.is_approval_required:
    # Return JSON-RPC error -32002 with approval_request details
    return {"jsonrpc": "2.0", "id": req_id, "error": result.to_jsonrpc_error()}

result.raise_if_denied()
execute_tool(result.clean_arguments)
```

### Client-Side (Retry with Approvals)

```python
try:
    result = await client.call_tool("transfer", amount=5000, recipient="acme")
except Exception as e:
    if is_approval_required(e):  # JSON-RPC code -32002
        approval = collect_human_approval(e)  # app-specific UI flow
        result = await client.call_tool(
            "transfer",
            amount=5000,
            recipient="acme",
            _approvals=[approval],  # re-submit with SignedApproval
        )
```

### JSON-RPC Error Codes

| Code | Meaning | Action |
|------|---------|--------|
| `-32602` | Invalid params (missing required extraction field) | Fix arguments |
| `-32001` | Access denied (constraint violation, expired, bad signature) | Request new warrant |
| `-32002` | Approval required (approval gate triggered) | Collect approvals and re-submit |

---

## Common MCP Tools

### Filesystem

```yaml
filesystem_read:
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

filesystem_write:
  constraints:
    path:
      from: body
      path: "path"
      required: true
    content:
      from: body
      path: "content"
      required: true
    max_size:
      from: body
      path: "maxSize"
      type: integer
      default: 1048576
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
    max_memory:
      from: body
      path: "code.maxMemory"
      type: integer
      default: 512
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
    max_response_size:
      from: body
      path: "request.maxResponseSize"
      type: integer
      default: 10485760  # 10 MB
```

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
    result = await client.call_protected_tool("read_file", {"path": "/etc/passwd"})
except ConstraintViolation as e:
    print(f"Constraint failed: {e}")
    print(f"Wire code: {e.get_wire_code()}")  # 1501
    print(f"Wire name: {e.get_wire_name()}")  # "constraint-violation"
except ConfigurationError as e:
    print(f"Config error: {e}")
    print(f"Wire code: {e.get_wire_code()}")  # 1201
except TenuoError as e:
    # Catch-all for any Tenuo error
    print(f"Authorization failed: {e.to_dict()}")
```

### Common Errors

| Error | Wire Code | Cause | Fix |
|-------|-----------|-------|-----|
| `ConfigurationError` | 1201 | Not connected to MCP server | Use `async with` or call `connect()` |
| `ToolNotAuthorized` | 1500 | Tool not in warrant | Add tool to warrant |
| `ConstraintViolation` | 1501 | Argument violates constraint | Request within bounds |
| `ConfigurationError` | 1201 | Extraction failed | Check `extraction_config` |
| `ExpiredError` | 1300 | TTL exceeded | Request fresh warrant |

See [wire format specification](/docs/spec/wire-format-v1#appendix-a-error-codes) for the complete list.

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
# Warrant:
constraints = {"path": Subpath("/var/log")}

# MCP call:
arguments = {"path": "/etc/passwd"}  # ❌ Not under /var/log

# Fix: Narrow MCP call or broaden warrant
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

## Scope & Boundaries

### Tenuo Provides
- **Secure Client** (`SecureMCPClient`): Wraps the MCP SDK with warrant injection and constraint enforcement. Supports stdio, SSE, and StreamableHTTP transports.
- **Server Verification** (`MCPVerifier`): Framework-agnostic warrant verification for MCP server tool handlers. Works with `fastmcp`, the raw MCP SDK, or any custom server.
- **Tool discovery**: Automatic wrapping of discovered tools with `@guard`.
- **Warrant propagation**: Injecting warrants (+ approvals) into `_tenuo` field for end-to-end verification.
- **Constraint extraction**: Config-driven extraction from MCP arguments.
- **Approval gate flow**: Structured JSON-RPC errors (`-32002`) for approval-gate-protected tools with retry support.

### Tenuo Does NOT Provide
- MCP Server Framework: Use [`fastmcp`](https://github.com/jlowin/fastmcp) or the official SDK to build servers. Tenuo's `MCPVerifier` plugs into any framework.
- MCP Transport: Tenuo relies on standard transports (stdio, SSE, StreamableHTTP).
- Prompt Injection Detection: Tenuo assumes injection will happen and makes unauthorized actions impossible.

---

## Examples

- [`tenuo-python/examples/mcp/`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/mcp) — Client demos, LangChain/CrewAI/A2A integrations
- [`tenuo-python/examples/mcp_client.py`](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-python/examples/mcp_client.py) — Multi-transport client patterns
- [`tenuo-python/examples/mcp_server.py`](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-python/examples/mcp_server.py) — Server-side MCPVerifier patterns

---

## See Also

- [API Reference → MCP Integration](./api-reference#mcp)
- [Argument Extraction](./argument-extraction)
- [Constraints Guide](./constraints)
- [Security Best Practices](./security)
