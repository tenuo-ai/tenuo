# MCP Integration

Tenuo provides full [Model Context Protocol (MCP)](https://modelcontextprotocol.io) client integration with cryptographic authorization.

**Full Stack**: Connect to MCP servers → Discover tools → Auto-protect with warrants → Execute securely.

> **New in v0.1**: `SecureMCPClient` provides end-to-end MCP integration. Requires Python ≥3.10 (MCP SDK limitation).

---

## Prerequisites

```bash
pip install tenuo
```

For the full LangChain + MCP example:
```bash
pip install tenuo[langchain]
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

---

## Quick Start

### 1. Install

```bash
pip install tenuo
```

### 2. Create MCP Configuration

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

### 3. Authorize MCP Calls

```python
from tenuo import McpConfig, CompiledMcpConfig, Authorizer, SigningKey, Warrant, Pattern, Range

# Load MCP configuration
config = McpConfig.from_file("mcp-config.yaml")
compiled = CompiledMcpConfig.compile(config)

# Create warrant for filesystem operations
control_keypair = SigningKey.generate()
warrant = Warrant.issue(
    tools="filesystem_read",
    constraints={
        "path": Pattern("/var/log/*"),
        "max_size": Range.max_value(1024 * 1024)
    },
    ttl_seconds=3600,
    keypair=control_keypair,
    holder=control_keypair.public_key
)

# MCP tool call arrives
mcp_arguments = {
    "path": "/var/log/app.log",
    "maxSize": 512 * 1024
}

# Extract constraints
result = compiled.extract_constraints("filesystem_read", mcp_arguments)

# Authorize with PoP signature
pop_sig = warrant.create_pop_signature(control_keypair, "filesystem_read", dict(result.constraints))
authorizer = Authorizer(trusted_roots=[control_keypair.public_key])
authorizer.check(warrant, "filesystem_read", dict(result.constraints), bytes(pop_sig))

# ✓ Authorized - execute the tool
```

---

## LangChain + MCP Integration

> **Note**: LangChain's MCP support is currently JavaScript-only (`@langchain/mcp-adapters`). This example shows the **authorization pattern** using simulated MCP tools. When LangChain Python adds MCP support, the same Tenuo authorization will work seamlessly.

**Pattern**: LangChain extracts tools → Tenuo authorizes calls → MCP executes

### Python Example

```python
from tenuo import McpConfig, CompiledMcpConfig, Authorizer, SigningKey, Warrant, Pattern
from tenuo import lockdown, configure, root_task_sync

# 1. Configure Tenuo
control_keypair = SigningKey.generate()
configure(issuer_key=control_keypair)

# 2. Load MCP configuration
config = McpConfig.from_file("mcp-config.yaml")
compiled = CompiledMcpConfig.compile(config)

# 3. Define MCP tool wrapper
@lockdown(tool="filesystem_read")
def filesystem_read(path: str, maxSize: int = 1048576):
    """Read file from filesystem (MCP tool)"""
    # In production: Call actual MCP server
    with open(path, 'r') as f:
        content = f.read(maxSize)
    return content

# 4. Use with task scoping
with root_task_sync(tools=["filesystem_read"], path="/var/log/*"):
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

Tenuo extracts constraints from MCP arguments using YAML config:

```python
# MCP tool call
arguments = {
    "path": "/var/log/app.log",
    "maxSize": 512 * 1024
}

# Extract constraints
result = compiled.extract_constraints("filesystem_read", arguments)

# Result:
# {
#   "path": "/var/log/app.log",
#   "max_size": 524288
# }
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
from tenuo import lockdown, root_task_sync

@lockdown(tool="filesystem_read")
def filesystem_read(path: str, maxSize: int):
    # MCP server call
    return read_file_from_mcp_server(path, maxSize)

with root_task_sync(tools=["filesystem_read"], path="/var/log/*"):
    content = filesystem_read("/var/log/app.log", 1024)
```

### Pattern 2: Explicit Authorization

```python
from tenuo import Authorizer, Warrant

# Create warrant
warrant = Warrant.issue(
    tools="filesystem_read",
    constraints={"path": Pattern("/var/log/*")},
    ttl_seconds=3600,
    keypair=keypair,
    holder=keypair.public_key
)

# Extract constraints from MCP call
result = compiled.extract_constraints("filesystem_read", arguments)

# Authorize
pop_sig = warrant.create_pop_signature(keypair, "filesystem_read", dict(result.constraints))
authorizer.check(warrant, "filesystem_read", dict(result.constraints), bytes(pop_sig))
```

### Pattern 3: Multi-Agent Delegation

```python
# Control plane issues root warrant
root_warrant = Warrant.issue(
    tools=["filesystem_read", "database_query"],
    constraints={"path": Pattern("/data/*")},
    ttl_seconds=3600,
    keypair=control_keypair,
    holder=orchestrator_keypair.public_key
)

# Orchestrator attenuates for worker
worker_warrant = root_warrant.attenuate_builder() \
    .with_tool("filesystem_read") \
    .with_constraint("path", Pattern("/data/reports/*")) \
    .with_holder(worker_keypair.public_key) \
    .delegate_to(orchestrator_keypair, control_keypair)

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
    print(f"⚠️  {warning}")
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
pop_sig = warrant.create_pop_signature(keypair, tool, args)

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
constraints = {"path": Pattern("/var/log/*")}
```

### 5. Short TTLs

MCP tools are often high-risk (filesystem, database). Use short TTLs:

```python
warrant = Warrant.issue(
    tools="filesystem_write",
    ttl_seconds=300,  # 5 minutes
    ...
)
```

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

**Problem**: `AuthorizationDenied: path does not match pattern`

**Solution**: Check warrant constraints match extracted values:

```python
# Warrant:
constraints = {"path": Pattern("/var/log/*")}

# MCP call:
arguments = {"path": "/etc/passwd"}  # ❌ Doesn't match

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

## Examples

See [`tenuo-python/examples/mcp_integration.py`](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-python/examples/mcp_integration.py) for a complete working example.

---

## See Also

- [API Reference → MCP Integration](./api-reference#mcp-integration)
- [Argument Extraction](./argument-extraction)
- [Constraints Guide](./constraints)
- [Security Best Practices](./security)
