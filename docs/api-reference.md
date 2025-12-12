# Tenuo Python SDK API Reference

Complete API documentation for the Tenuo Python SDK.

> **Note**: This reference documents the current Python SDK. For removed features (GatewayConfig, RevocationManager, SecureGraph, etc.), see the Git history or Rust API documentation.

## Table of Contents

- [Core Types](#core-types)
  - [Keypair](#keypair)
  - [PublicKey](#publickey)
  - [Signature](#signature)
  - [Warrant](#warrant)
  - [Authorizer](#authorizer)
- [Constraints](#constraints)
- [MCP Integration](#mcp-integration)
- [Decorators & Context](#decorators--context)
- [Exceptions](#exceptions)

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

#### Instance Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `public_key()` | `PublicKey` | Get the public key |
| `public_key_bytes()` | `bytes` | Get public key as bytes (32 bytes) |
| `secret_key_bytes()` | `bytes` | Get secret key as bytes (32 bytes) ⚠️ |
| `sign(message: bytes)` | `Signature` | Sign a message |

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

#### Instance Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `to_bytes()` | `bytes` | Get as 32-byte array |
| `verify(message: bytes, signature: Signature)` | `bool` | Verify a signature |

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
| `Warrant.create(...)` | Create a new root warrant |
| `Warrant.from_base64(s: str)` | Deserialize from base64 |

#### `Warrant.create()` Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `tool` | `str` | Yes | - | Tool name (or `"*"` for wildcard) |
| `constraints` | `dict[str, Constraint]` | No | `None` | Constraint mappings |
| `ttl_seconds` | `int` | No | `3600` | Time-to-live in seconds |
| `keypair` | `Keypair` | Yes | - | Signing keypair |
| `session_id` | `str` | No | `None` | Session/trace identifier |

#### Instance Properties

| Property | Type | Description |
|----------|------|-------------|
| `id` | `str` | Unique warrant ID |
| `tool` | `str` | Tool this warrant authorizes |
| `depth` | `int` | Delegation depth (0 = root) |
| `session_id` | `str \| None` | Session identifier |
| `authorized_holder` | `PublicKey \| None` | Bound holder's public key |
| `expires_at` | `str` | Expiration time (RFC3339) |

#### Instance Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `attenuate(...)` | `Warrant` | Create narrower child warrant |
| `authorize(tool, args, signature?)` | `bool` | Check if action is authorized |
| `verify(public_key)` | `bool` | Verify signature against issuer |
| `create_pop_signature(keypair, tool, args)` | `Signature` | Create PoP signature |
| `to_base64()` | `str` | Serialize to base64 |

#### Example

```python
from tenuo import Warrant, Keypair, Pattern, Exact

# Create root warrant
root_kp = Keypair.generate()
agent_kp = Keypair.generate()

root = Warrant.create(
    tool="manage_infrastructure",
    constraints={
        "cluster": Pattern("staging-*"),
    },
    ttl_seconds=3600,
    keypair=root_kp,
)

# Attenuate for sub-agent
child = root.attenuate(
    constraints={"cluster": Exact("staging-web")},
    keypair=agent_kp,
)

# Authorize with PoP
pop_sig = child.create_pop_signature(
    agent_kp, 
    "manage_infrastructure", 
    {"cluster": "staging-web"}
)
result = child.authorize(
    "manage_infrastructure",
    {"cluster": "staging-web"},
    signature=pop_sig
)
```

---

### Authorizer

Centralized authorization with chain verification.

```python
from tenuo import Authorizer
```

#### Class Methods

| Method | Description |
|--------|-------------|
| `Authorizer.new(trusted_key: PublicKey)` | Create with trusted root public key |

#### Instance Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `authorize(warrant, tool, args, signature?, approvals?)` | `None` | Authorize (raises on failure) |
| `verify_chain(warrants: list)` | `ChainVerificationResult` | Verify delegation chain |
| `check_chain(warrants, tool, args, signature?, approvals?)` | `ChainVerificationResult` | Verify chain + authorize |

#### Example

```python
from tenuo import Authorizer, Keypair

cp_kp = Keypair.generate()
authorizer = Authorizer.new(cp_kp.public_key())

# Verify full delegation chain
result = authorizer.verify_chain([root_warrant, child_warrant])
print(f"Chain depth: {result.leaf_depth}")

# Authorize with chain verification
authorizer.check_chain(
    [root_warrant, child_warrant],
    "read_file",
    {"path": "/tmp/test.txt"},
    signature=pop_sig
)
```

---

## Constraints

All constraint types for fine-grained authorization.

```python
from tenuo import (
    Pattern,    # Glob patterns: "staging-*"
    Exact,      # Exact match: "production"
    Range,      # Numeric ranges: Range(0, 100)
    OneOf,      # Allowlist: OneOf(["read", "write"])
    NotOneOf,   # Denylist: NotOneOf(["admin"])
    Contains,   # List contains: Contains(["admin"])
    Subset,     # List subset: Subset(["read", "write"])
    All,        # AND logic: All([constraint1, constraint2])
    AnyOf,      # OR logic: AnyOf([constraint1, constraint2])
    Not,        # Negation: Not(constraint)
    Cel,        # CEL expressions: Cel('value > 0')
)
```

### Pattern

Glob-style pattern matching.

```python
Pattern("staging-*")     # Matches staging-web, staging-db
Pattern("/tmp/**")       # Matches /tmp/foo, /tmp/foo/bar
```

### Exact

Exact string match.

```python
Exact("production")      # Only matches "production"
```

### Range

Numeric range constraints.

```python
Range(min=0, max=100)    # 0 <= value <= 100
Range.min_value(10)      # value >= 10
Range.max_value(1000)    # value <= 1000
```

### OneOf / NotOneOf

Set membership.

```python
OneOf(["read", "write", "delete"])  # Must be one of these
NotOneOf(["admin", "root"])         # Anything except these
```

⚠️ **Security**: Always start with positive allowlist, use NotOneOf sparingly.

### Contains / Subset

List constraints.

```python
Contains(["admin"])                      # List must include "admin"
Subset(["read", "write", "admin"])      # Only these values allowed
```

### All / AnyOf / Not

Composite logic.

```python
All([Range.min_value(0), Range.max_value(100)])  # AND
AnyOf([Exact("admin"), Exact("superuser")])      # OR
Not(Exact("blocked"))                             # Negation
```

### Cel

Common Expression Language for complex logic.

```python
Cel('value.startsWith("staging") && size(value) < 20')
Cel('value > 0 && value <= 1000')
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
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `extract_constraints(tool, arguments)` | `ExtractionResult` | Extract constraints from MCP tool call |

#### Example

```python
from tenuo import McpConfig, CompiledMcpConfig, Warrant

# Load MCP configuration
config = McpConfig.from_file("mcp-config.yaml")
compiled = CompiledMcpConfig.compile(config)

# Extract constraints from MCP tool call
arguments = {"path": "/var/log/app.log", "maxSize": 1024}
result = compiled.extract_constraints("filesystem_read", arguments)

# Authorize
warrant = Warrant.from_base64(warrant_base64)
pop_sig = warrant.create_pop_signature(keypair, "filesystem_read", result.constraints)
authorized = warrant.authorize("filesystem_read", result.constraints, pop_sig)
```

See `examples/mcp_integration.py` for a complete example.

---

## Decorators & Context

### lockdown

Decorator for function-level authorization.

```python
from tenuo import lockdown
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tool` | `str` | Yes | Tool name for authorization |
| `warrant` | `Warrant` | No* | Explicit warrant |
| `keypair` | `Keypair` | No* | Keypair for PoP |
| `mapping` | `dict[str, str]` | No | Arg name → constraint name mapping |
| `extract_args` | `Callable` | No | Custom arg extraction function |

*If not provided, uses context.

#### Patterns

**Explicit warrant:**
```python
@lockdown(warrant=warrant, tool="read_file", keypair=agent_kp)
def read_file(path: str) -> str:
    return open(path).read()
```

**Context-based (recommended for LangChain/FastAPI):**
```python
@lockdown(tool="read_file")
def read_file(path: str) -> str:
    return open(path).read()

# Use with context
with set_warrant_context(warrant):
    read_file("/tmp/test.txt")
```

### Context Functions

```python
from tenuo import (
    set_warrant_context,
    get_warrant_context,
    WarrantContext,
)
```

| Function | Returns | Description |
|----------|---------|-------------|
| `set_warrant_context(warrant)` | Context manager | Set warrant in async-safe context |
| `get_warrant_context()` | `Warrant \| None` | Get current warrant |

#### Example

```python
with set_warrant_context(warrant), set_keypair_context(keypair):
    # All @lockdown functions use this warrant and keypair
    result = protected_function(arg1, arg2)
```

---

## Exceptions

Pythonic exceptions for error handling.

```python
from tenuo import TenuoError, AuthorizationError, WarrantError
```

### Exception Hierarchy

```
TenuoError (base)
├── AuthorizationError    # Authorization failed
└── WarrantError          # Warrant creation/validation failed
```

### Example

```python
try:
    warrant.authorize("tool", args, signature)
except AuthorizationError as e:
    print(f"Authorization failed: {e}")
except WarrantError as e:
    print(f"Warrant error: {e}")
```

---

## See Also

- **[CLI Specification](cli-spec.md)**: Complete CLI reference
- **[Rust API](https://docs.rs/tenuo-core)**: Full Rust API documentation
- **[Examples](../tenuo-python/examples/)**: Python usage examples
- **[Website](https://tenuo.github.io/tenuo/)**: Landing page and guides

---

**Last Updated**: 2025-12-11  
**SDK Version**: 0.1.x
