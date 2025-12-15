---
title: API Reference
description: Complete Python SDK documentation
---

# Tenuo Python SDK API Reference

Complete API documentation for the Tenuo Python SDK.

## Table of Contents

- [Constants](#constants)
- [Core Types](#core-types)
  - [Keypair](#keypair)
  - [PublicKey](#publickey)
  - [Signature](#signature)
  - [Warrant](#warrant)
  - [Authorizer](#authorizer)
- [Constraints](#constraints)
- [Task Scoping](#task-scoping)
- [Tool Protection](#tool-protection)
- [MCP Integration](#mcp-integration)
- [Decorators & Context](#decorators--context)
- [LangChain Integration](#langchain-integration)
- [LangGraph Integration](#langgraph-integration)
- [Exceptions](#exceptions)
- [Audit Logging](#audit-logging)

---

## Constants

Protocol-level constants exported from the SDK:

```python
from tenuo import MAX_DELEGATION_DEPTH, MAX_ISSUER_CHAIN_LENGTH, MAX_WARRANT_SIZE
```

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_DELEGATION_DEPTH` | 64 | Maximum warrant delegation depth |
| `MAX_ISSUER_CHAIN_LENGTH` | 8 | Maximum chain links in a warrant (DoS protection) |
| `MAX_WARRANT_SIZE` | 1,048,576 | Maximum serialized warrant size in bytes (1 MB) |

**Security Note**: `MAX_ISSUER_CHAIN_LENGTH` limits the embedded issuer chain to prevent stack overflow attacks during verification. Chains longer than 8 levels indicate a design smell and should be reconsidered.

---

## Core Types

### Keypair

Ed25519 keypair for signing and verification.

```python
from tenuo import Keypair
```

#### Class Methods

| Method | Description |
|--------|-------------|
| `Keypair.generate()` | Generate a new random keypair |
| `Keypair.from_bytes(secret_key: bytes)` | Reconstruct keypair from 32-byte secret key |
| `Keypair.from_pem(pem: str)` | Create a keypair from a PEM string |

#### Instance Methods

| Property/Method | Returns | Description |
|-----------------|---------|-------------|
| `public_key` | `PublicKey` | Get the public key (property) |
| `public_key_bytes()` | `bytes` | Get public key as bytes (32 bytes) |
| `secret_key_bytes()` | `bytes` | Get secret key as bytes (32 bytes) ⚠️ |
| `sign(message: bytes)` | `Signature` | Sign a message |
| `to_pem()` | `str` | Convert the keypair to a PEM string |

⚠️ **Security Warning**: `secret_key_bytes()` copies secret material to Python memory. Minimize use.

---

### PublicKey

Ed25519 public key for verification.

```python
from tenuo import PublicKey
```

#### Class Methods

| Method | Description |
|--------|-------------|
| `PublicKey.from_bytes(data: bytes)` | Create from 32-byte public key |
| `PublicKey.from_pem(pem: str)` | Create a public key from a PEM string |

#### Instance Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `to_bytes()` | `bytes` | Get as 32-byte array |
| `verify(message: bytes, signature: Signature)` | `bool` | Verify a signature |
| `to_pem()` | `str` | Convert the public key to a PEM string |

---

### Signature

Ed25519 signature.

```python
from tenuo import Signature
```

#### Class Methods

| Method | Description |
|--------|-------------|
| `Signature.from_bytes(data: bytes)` | Create from 64-byte signature |

#### Instance Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `to_bytes()` | `bytes` | Get as 64-byte array |

---

### Warrant

Capability token with constraints and cryptographic provenance.

```python
from tenuo import Warrant
```

#### Class Methods

| Method | Description |
|--------|-------------|
| `Warrant.from_base64(s: str)` | Deserialize from base64 |
| `Warrant.issue(...)` | Issue a new warrant (see parameters below) |

#### `Warrant.issue()` Parameters

```python
Warrant.issue(
    tools: Union[str, List[str]],
    constraints: dict,
    ttl_seconds: int,
    keypair: Keypair,
    holder: Optional[PublicKey] = None,
    session_id: Optional[str] = None
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `tools` | `str \| List[str]` | Tool name(s) to authorize |
| `constraints` | `dict` | Constraint dictionary |
| `ttl_seconds` | `int` | Time-to-live in seconds |
| `keypair` | `Keypair` | Issuer's keypair |
| `holder` | `PublicKey` | Optional holder (defaults to issuer) |
| `session_id` | `str` | Optional session ID |

#### Instance Properties

| Property | Type | Description |
|----------|------|-------------|
| `id` | `str` | Unique warrant ID |
| `tools` | `List[str]` | Authorized tools |
| `depth` | `int` | Delegation depth (0 = root) |
| `session_id` | `str \| None` | Session identifier |
| `authorized_holder` | `PublicKey \| None` | Bound holder's public key |
| `expires_at` | `str` | Expiration time (RFC3339) |
| `delegation_receipt` | `DelegationReceipt \| None` | Receipt if created via delegation |

#### Instance Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `attenuate(constraints, keypair, ttl_seconds=None, holder=None)` | `Warrant` | Create narrower child warrant |
| `attenuate_builder()` | `AttenuationBuilder` | Create builder for attenuation with diff preview |
| `authorize(tool, args, signature?)` | `bool` | Check if action is authorized |
| `verify(public_key)` | `bool` | Verify signature against issuer |
| `create_pop_signature(keypair, tool, args)` | `list[int]` | Create PoP signature |
| `to_base64()` | `str` | Serialize to base64 |
| `is_expired()` | `bool` | Check if warrant has expired |

⚠️ **Replay Window:** PoP signatures are valid for ~2 minutes to handle clock skew.

---

### Authorizer

Centralized authorization with chain verification.

```python
from tenuo import Authorizer
```

#### Constructor

```python
Authorizer(
    trusted_roots: Optional[List[PublicKey]] = None,
    clock_tolerance_secs: int = 30,
    pop_window_secs: int = 30,
    pop_max_windows: int = 4,
)
```

**Note:** For production use, always provide `trusted_roots` to validate the root issuer. Without it, chain verification only checks internal consistency.

#### Instance Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `verify(warrant)` | `None` | Verify warrant (raises on failure) |
| `authorize(warrant, tool, args, signature=None)` | `None` | Authorize action (raises on failure) |
| `check(warrant, tool, args, signature=None)` | `None` | Verify + authorize in one call |
| `verify_chain(chain)` | `ChainVerificationResult` | Verify complete delegation chain |
| `check_chain(chain, tool, args, signature=None)` | `ChainVerificationResult` | Verify chain + authorize |

---

## Constraints

All constraint types for fine-grained authorization.

```python
from tenuo import (
    Pattern,    # Glob patterns: "staging-*"
    Exact,      # Exact match: "production"
    Range,      # Numeric ranges: Range(min=0, max=100)
    OneOf,      # Allowlist: OneOf(["read", "write"])
    NotOneOf,   # Denylist: NotOneOf(["admin"])
    Regex,      # Regular expressions: Regex("^[a-z]+$")
    Wildcard,   # Match anything (use sparingly)
    Contains,   # List contains: Contains(["admin"])
    Subset,     # List subset: Subset(["read", "write"])
    All,        # AND logic: All([constraint1, constraint2])
    AnyOf,      # OR logic: AnyOf([constraint1, constraint2])
    Not,        # Negation: Not(constraint)
    CEL,        # CEL expressions: CEL('value > 0')
)
```

### Pattern

Glob-style pattern matching.

```python
Pattern("staging-*")      # Matches staging-web, staging-db
Pattern("/tmp/**")        # Recursive: matches /tmp/foo/bar/file.txt
Pattern("*-safe")         # Suffix: matches image-safe
```

### Exact

Exact string match.

```python
Exact("production")       # Only matches "production"
```

### Range

Numeric range constraints.

```python
Range(min=0, max=100)     # 0 <= value <= 100
Range.min_value(10)       # value >= 10
Range.max_value(1000)     # value <= 1000
```

### OneOf / NotOneOf

Set membership.

```python
OneOf(["read", "write", "delete"])   # Must be one of these
NotOneOf(["admin", "root"])          # Anything except these
```

### Regex

Regular expression matching.

```python
Regex("^[a-z0-9_]+$")     # Matches lowercase alphanumeric with underscores
Regex(".*\\.pdf$")        # Matches files ending in .pdf
```

### Wildcard

Matches any value. Use sparingly—prefer explicit constraints.

```python
Wildcard()                # Matches anything
```

### Contains / Subset

List constraints.

```python
Contains(["admin"])                   # List must include "admin"
Subset(["read", "write", "admin"])   # Only these values allowed
```

### All / AnyOf / Not

Composite logic.

```python
All([Range.min_value(0), Range.max_value(100)])   # AND
AnyOf([Exact("admin"), Exact("superuser")])       # OR
Not(Exact("blocked"))                              # Negation
```

### CEL

Common Expression Language for complex logic.

```python
from tenuo import CEL

CEL('value.startsWith("staging") && size(value) < 20')
CEL('value > 0 && value <= 1000')
```

---

## Task Scoping

Context managers for scoping authority to tasks.

### `root_task`

Create root authority for a task. **Async version.**

```python
from tenuo import root_task

async with root_task(tools=["read_file"], path="/data/*") as warrant:
    result = await agent.invoke(prompt)
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tools` | `List[str]` | Yes | Allowed tools |
| `ttl` | `int` | No | TTL in seconds (default from `configure()`) |
| `holder_key` | `Keypair` | No | Explicit holder (default: issuer) |
| `**constraints` | `Any` | No | Constraint key-value pairs |

#### Requirements

- Must call `configure(issuer_key=...)` first
- At least one tool required

### `root_task_sync`

Synchronous version of `root_task`.

```python
from tenuo import root_task_sync

with root_task_sync(tools=["read_file"], path="/data/*") as warrant:
    result = protected_read_file(path="/data/report.csv")
```

Same parameters as `root_task`.

### `scoped_task`

Attenuate within an existing task scope.

```python
from tenuo import scoped_task

async with root_task(tools=["read_file", "write_file"], path="/data/*"):
    async with scoped_task(tools=["read_file"], path="/data/reports/*"):
        # Narrower scope here
        result = await agent.invoke(prompt)
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tools` | `List[str]` | No | Subset of parent's tools (None = inherit all) |
| `ttl` | `int` | No | Shorter TTL (None = inherit remaining) |
| `**constraints` | `Any` | No | Tighter constraints (must be contained in parent's) |

#### Requirements

- **Must be called within `root_task` or another `scoped_task`**
- Constraints must be monotonically attenuated (tighter than parent)

#### Preview Changes

```python
scope = scoped_task(path="/data/reports/*")
scope.preview().print()  # See diff before entering
async with scope:
    ...
```

---

## Tool Protection

### `protect_tools`

Wrap tools to enforce warrant authorization.

```python
from tenuo import protect_tools
```

#### Signature

```python
protect_tools(
    tools: List[Any],
    *,
    inplace: bool = True,
    strict: bool = False,
    schemas: Optional[Dict[str, ToolSchema]] = None,
) -> List[Any]
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tools` | `List[Any]` | — | List of LangChain/callable tools |
| `inplace` | `bool` | `True` | Mutate original list (False = return new list) |
| `strict` | `bool` | `False` | Fail on tools missing required constraints |
| `schemas` | `Dict[str, ToolSchema]` | `None` | Custom tool schemas |

#### Example

```python
from tenuo import protect_tools, root_task

# Define your tools
tools = [read_file, send_email, query_db]

# Wrap them (mutates in place by default)
protect_tools(tools)

# Use with scoped authority
async with root_task(tools=["read_file"], path="/data/*"):
    result = await tools[0](path="/data/report.csv")
```

#### Non-mutating variant

```python
original = [read_file, send_email]
protected = protect_tools(original, inplace=False)
# original unchanged, protected has wrapped tools
```

---

## MCP Integration

Native support for [Model Context Protocol](https://modelcontextprotocol.io).

```python
from tenuo import McpConfig, CompiledMcpConfig
```

### McpConfig

Load MCP configuration from YAML.

```python
config = McpConfig.from_file("mcp-config.yaml")
```

### CompiledMcpConfig

Compiled configuration for fast constraint extraction.

```python
compiled = CompiledMcpConfig.compile(config)
result = compiled.extract_constraints("filesystem_read", {"path": "/var/log/app.log"})
```

See `examples/mcp_integration.py` for a complete example.

---

## Decorators & Context

### `@lockdown`

Decorator for function-level authorization.

```python
from tenuo import lockdown
```

#### Signature

```python
@lockdown(
    warrant_or_tool=None,  # Warrant instance OR tool name string
    tool=None,             # Tool name (if not passed as first arg)
    keypair=None,          # Keypair for PoP (or use context)
    mapping=None,          # Arg name → constraint name mapping
)
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `warrant_or_tool` | `Warrant \| str` | No | Warrant instance or tool name as first positional arg |
| `tool` | `str` | Yes* | Tool name for authorization (*not needed if tool passed as first arg) |
| `keypair` | `Keypair` | No | Keypair for PoP (or use context) |
| `mapping` | `dict[str, str]` | No | Arg name → constraint name mapping |

#### Patterns

**Context-based (recommended):**

```python
@lockdown(tool="read_file")
def read_file(path: str) -> str:
    return open(path).read()

# Use with task scoping
async with root_task(tools=["read_file"], path="/data/*"):
    read_file("/data/test.txt")
```

**Explicit warrant (positional):**

```python
@lockdown(warrant, tool="read_file", keypair=agent_kp)
def read_file(path: str) -> str:
    return open(path).read()
```

**Tool as first arg:**

```python
@lockdown("read_file")  # tool name as positional arg
def read_file(path: str) -> str:
    return open(path).read()
```

### Context Functions

```python
from tenuo import (
    set_warrant_context,
    get_warrant_context,
    set_keypair_context,
    get_keypair_context,
)
```

| Function | Returns | Description |
|----------|---------|-------------|
| `set_warrant_context(warrant)` | Context manager | Set warrant in async-safe context |
| `set_keypair_context(keypair)` | Context manager | Set keypair in async-safe context |
| `get_warrant_context()` | `Warrant \| None` | Get current warrant |
| `get_keypair_context()` | `Keypair \| None` | Get current keypair |

---

## LangChain Integration

See [LangChain Integration Guide](./langchain) for full documentation.

### Quick Example

```python
from tenuo import configure, root_task, protect_tools, Keypair
from langchain_community.tools import DuckDuckGoSearchRun

# Setup
kp = Keypair.generate()
configure(issuer_key=kp)

# Protect tools
tools = [DuckDuckGoSearchRun()]
protect_tools(tools)

# Use with scoped authority
async with root_task(tools=["duckduckgo_search"], query="*"):
    result = await tools[0].ainvoke({"query": "AI news"})
```

---

## LangGraph Integration

See [LangGraph Integration Guide](./langgraph) for full documentation.

### Two-Layer Model

| Layer | Decorator | Purpose |
|-------|-----------|---------|
| **Scoping** | `@tenuo_node` | Narrows what's allowed in this node |
| **Enforcement** | `@lockdown` | Checks warrant at tool invocation |

**Both layers are required for security.**

### `@tenuo_node`

Scope authority for a LangGraph node.

```python
from tenuo.langgraph import tenuo_node

@tenuo_node(tools=["search"], query="*public*")
async def researcher(state):
    results = await search_tool(query=state["query"])
    return {"results": results}
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `tools` | `List[str]` | Tools this node is allowed to use |
| `ttl` | `int` | Optional TTL override (seconds) |
| `**constraints` | `Any` | Constraint key-value pairs |

### `@require_warrant`

Require a warrant in context without scoping.

```python
from tenuo.langgraph import require_warrant

@require_warrant
async def sensitive_node(state):
    ...
```

---

## Exceptions

```python
from tenuo import TenuoError, AuthorizationError, WarrantError
```

### Exception Hierarchy

```
TenuoError (base)
├── AuthorizationError    # Authorization failed
├── WarrantError          # Warrant creation/validation failed
├── ConstraintError       # Invalid constraint definition
└── ConfigurationError    # Invalid configuration
```

---

## Audit Logging

```python
from tenuo import audit_logger, AuditEventType
```

### Methods

| Method | Description |
|--------|-------------|
| `audit_logger.configure(service_name, output_file=None)` | Configure the logger |
| `audit_logger.log_authorization_success(...)` | Log success event |
| `audit_logger.log_authorization_failure(...)` | Log failure event |

### Example

```python
audit_logger.configure(service_name="payment-service")

audit_logger.log_authorization_success(
    warrant_id="wrt_123",
    tool="process_payment",
    constraints={"amount": 100.0}
)
```

---

## See Also

- [CLI Reference](./cli) — Command-line interface
- [Constraints Guide](./constraints) — Detailed constraint usage
- [Security](./security) — Threat model and protections
- [Examples](https://github.com/horkosdev/tenuo/tree/main/tenuo-python/examples) — Python usage examples
