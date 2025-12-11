# Tenuo Python SDK API Reference

Complete API documentation for the Tenuo Python SDK.

## Table of Contents

- [Core Types](#core-types)
  - [Keypair](#keypair)
  - [PublicKey](#publickey)
  - [Signature](#signature)
  - [Warrant](#warrant)
  - [Authorizer](#authorizer)
  - [Approval](#approval)
- [Constraints](#constraints)
  - [Basic Constraints](#basic-constraints)
  - [List Constraints](#list-constraints)
  - [Composite Constraints](#composite-constraints)
- [Revocation](#revocation)
  - [RevocationManager](#revocationmanager)
  - [SignedRevocationList](#signedrevocationlist)
  - [SrlBuilder](#srlbuilder)
- [Gateway / MCP](#gateway--mcp)
  - [GatewayConfig](#gatewayconfig)
  - [CompiledGatewayConfig](#compiledgatewayconfig)
- [Decorators & Context](#decorators--context)
  - [lockdown](#lockdown)
  - [Context Functions](#context-functions)
- [Audit Logging](#audit-logging)
  - [AuditLogger](#auditlogger)
  - [AuditEvent](#auditevent)
  - [AuditEventType](#auditeventtype)
- [Exceptions](#exceptions)
- [Constants](#constants)

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

#### Example

```python
# Generate keypair
kp = Keypair.generate()

# Get public key for sharing
pub = kp.public_key()
pub_bytes = kp.public_key_bytes()

# Sign a message
sig = kp.sign(b"hello world")

# Reconstruct from bytes (for key storage/recovery)
secret = kp.secret_key_bytes()
restored = Keypair.from_bytes(secret)
```

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

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tool` | `str` | Yes | Tool name (or `"*"` for wildcard) |
| `constraints` | `dict[str, Constraint]` | Yes | Constraint mappings |
| `ttl_seconds` | `int` | Yes | Time-to-live in seconds |
| `keypair` | `Keypair` | Yes | Signing keypair |
| `session_id` | `str` | No | Session/trace identifier |
| `authorized_holder` | `PublicKey` | No | PoP binding (recommended!) |
| `required_approvers` | `list[PublicKey]` | No | M-of-N approval keys |
| `min_approvals` | `int` | No | Minimum approvals needed |

#### Instance Properties

| Property | Type | Description |
|----------|------|-------------|
| `id` | `str` | Unique warrant ID |
| `tool` | `str` | Tool this warrant authorizes |
| `depth` | `int` | Delegation depth (0 = root) |
| `session_id` | `str` | Session identifier |
| `requires_pop` | `bool` | Whether PoP is required |
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

#### `attenuate()` Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `constraints` | `dict[str, Constraint]` | Yes | Narrower constraints |
| `keypair` | `Keypair` | Yes | Signing keypair |
| `tool` | `str` | No | New tool (if parent is `"*"`) |
| `ttl_seconds` | `int` | No | Shorter TTL |
| `authorized_holder` | `PublicKey` | No | PoP binding for child |
| `add_approvers` | `list[PublicKey]` | No | Additional approvers |
| `raise_min_approvals` | `int` | No | Higher approval threshold |

#### Example

```python
from tenuo import Warrant, Keypair, Pattern, Exact, Range

# Create root warrant
root_kp = Keypair.generate()
agent_kp = Keypair.generate()

root = Warrant.create(
    tool="manage_infrastructure",
    constraints={
        "cluster": Pattern("staging-*"),
        "budget": Range.max_value(10000.0),
    },
    ttl_seconds=3600,
    keypair=root_kp,
    authorized_holder=agent_kp.public_key(),  # PoP binding
)

# Attenuate for sub-agent
child = root.attenuate(
    constraints={
        "cluster": Exact("staging-web"),
        "budget": Range.max_value(1000.0),
    },
    keypair=agent_kp,
    ttl_seconds=300,
)

# Authorize with PoP
pop_sig = child.create_pop_signature(
    agent_kp, 
    "manage_infrastructure", 
    {"cluster": "staging-web", "budget": 500.0}
)
result = child.authorize(
    "manage_infrastructure",
    {"cluster": "staging-web", "budget": 500.0},
    signature=pop_sig
)
print(f"Authorized: {result}")  # True

# Serialize for transmission
b64 = child.to_base64()
restored = Warrant.from_base64(b64)
```

---

### Authorizer

Centralized authorization with revocation support.

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
| `set_revocation_list(srl, expected_issuer)` | `None` | Load revocation list |

#### Example

```python
from tenuo import Authorizer, Keypair, Warrant

cp_kp = Keypair.generate()
authorizer = Authorizer.new(cp_kp.public_key())

# With revocation
authorizer.set_revocation_list(srl, cp_kp.public_key())

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

### Approval

Multi-signature approval for M-of-N authorization.

```python
from tenuo import Approval
```

#### Class Methods

| Method | Description |
|--------|-------------|
| `Approval.create(...)` | Create a signed approval |

#### `Approval.create()` Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `warrant_id` | `str` | Yes | ID of warrant being approved |
| `tool` | `str` | Yes | Tool being authorized |
| `args` | `dict` | Yes | Arguments being approved |
| `approver_key` | `Keypair` | Yes | Approver's keypair |
| `external_id` | `str` | Yes | External identity (e.g., email) |
| `provider` | `str` | Yes | Identity provider (e.g., "okta") |
| `ttl_seconds` | `int` | Yes | Approval validity period |
| `reason` | `str` | No | Approval reason |
| `authorized_holder` | `PublicKey` | No | PoP binding |

#### Example

```python
from tenuo import Approval, Keypair

admin_kp = Keypair.generate()

approval = Approval.create(
    warrant_id=warrant.id,
    tool="delete_database",
    args={"db_name": "production"},
    approver_key=admin_kp,
    external_id="admin@company.com",
    provider="okta",
    ttl_seconds=300,
    reason="Approved for maintenance"
)

# Use with authorizer
authorizer.authorize(
    warrant, "delete_database", args,
    signature=pop_sig,
    approvals=[approval]
)
```

---

## Constraints

### Basic Constraints

#### Wildcard

Matches any value. Universal superset for attenuation.

```python
from tenuo import Wildcard

Wildcard()  # Matches everything
```

#### Pattern

Glob-style pattern matching.

```python
from tenuo import Pattern

Pattern("staging-*")     # Matches staging-web, staging-db, etc.
Pattern("/tmp/**")       # Matches /tmp/foo, /tmp/foo/bar, etc.
Pattern("user-?")        # Matches user-1, user-a, etc.
```

#### Regex

Regular expression matching.

```python
from tenuo import Regex

Regex(r"^prod-[a-z]+$")  # Matches prod-web, prod-api
Regex(r"\d{4}-\d{2}")    # Matches 2024-01, etc.
```

#### Exact

Exact string match.

```python
from tenuo import Exact

Exact("production")      # Only matches "production"
```

#### OneOf

Value must be in allowed set.

```python
from tenuo import OneOf

OneOf(["read", "write", "delete"])  # Must be one of these
```

#### NotOneOf

Value must NOT be in excluded set. Use for "carving holes".

```python
from tenuo import NotOneOf

NotOneOf(["admin", "root"])  # Anything except these
```

⚠️ **Security**: Never start with negation. Use positive allowlist first.

#### Range

Numeric range constraints.

```python
from tenuo import Range

Range(min=0, max=100)    # 0 <= value <= 100
Range.min_value(10)      # value >= 10
Range.max_value(1000)    # value <= 1000
```

#### CEL

Common Expression Language for complex logic.

```python
from tenuo import CEL

CEL('value.startsWith("staging") && size(value) < 20')
CEL('value > 0 && value <= 1000')
```

---

### List Constraints

#### Contains

List must contain all required values.

```python
from tenuo import Contains

Contains(["admin"])  # List must include "admin"
```

#### Subset

List must be subset of allowed values.

```python
from tenuo import Subset

Subset(["read", "write", "admin"])  # Only these values allowed
```

---

### Composite Constraints

#### All

All nested constraints must match (AND).

```python
from tenuo import All, Range

All([Range.min_value(0), Range.max_value(100)])  # 0 <= x <= 100
```

#### AnyOf

At least one constraint must match (OR).

```python
from tenuo import AnyOf, Exact

AnyOf([Exact("admin"), Exact("superuser")])  # Either one
```

#### Not

Negation of a constraint.

```python
from tenuo import Not, Exact

Not(Exact("blocked"))  # Anything except "blocked"
```

⚠️ **Security**: Prefer `NotOneOf` over `Not`. Be careful with negation.

---

## Revocation

### RevocationManager

Manages warrant revocation requests and SRL generation.

```python
from tenuo import RevocationManager
```

#### Methods

| Method | Description |
|--------|-------------|
| `submit_request(...)` | Submit a revocation request |
| `pending_ids()` | Get list of pending warrant IDs |
| `generate_srl(keypair, version)` | Generate signed revocation list |

#### Example

```python
from tenuo import RevocationManager, Keypair
import datetime

manager = RevocationManager()

# Submit revocation
expires_at = (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat() + "Z"
manager.submit_request(
    warrant_id=warrant.id,
    reason="Key compromise",
    warrant_issuer=issuer_kp.public_key(),
    warrant_expires_at=expires_at,
    control_plane_key=cp_kp.public_key(),
    revocation_keypair=issuer_kp,
    warrant_holder=None
)

# Generate SRL
srl = manager.generate_srl(cp_kp, version=1)
```

---

### SignedRevocationList

Signed list of revoked warrant IDs.

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `version` | `int` | SRL version number |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `revoked_ids()` | `list[str]` | List of revoked warrant IDs |

---

### SrlBuilder

Build revocation lists manually.

```python
from tenuo import SrlBuilder

builder = SrlBuilder()
builder.add_warrant_id("wrt_123")
builder.add_warrant_id("wrt_456")
srl = builder.build(cp_keypair, version=1)
```

---

## Gateway / MCP

### GatewayConfig

Load gateway configuration from YAML.

```python
from tenuo import GatewayConfig

config = GatewayConfig.from_yaml(yaml_string)
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `version` | `str` | Config version |

---

### CompiledGatewayConfig

Compiled configuration for fast route matching.

```python
from tenuo import CompiledGatewayConfig

compiled = CompiledGatewayConfig.compile(config)
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `extract(method, path, headers, query, body)` | `tuple[str, dict] \| None` | Extract tool and constraints |

#### Example

```python
yaml_config = """
version: "1.0"
routes:
  - pattern: "/api/v1/users/{user_id}"
    method: ["GET"]
    tool: "read_user"
    extra_constraints:
      user_id:
        from: "path"
        path: "user_id"
"""

config = GatewayConfig.from_yaml(yaml_config)
compiled = CompiledGatewayConfig.compile(config)

result = compiled.extract("GET", "/api/v1/users/alice", {}, {}, None)
if result:
    tool, constraints = result
    print(f"Tool: {tool}")  # "read_user"
    print(f"Constraints: {constraints}")  # {"user_id": "alice"}
```

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
| `warrant` | `Warrant` | No* | Explicit warrant |
| `tool` | `str` | Yes | Tool name for authorization |
| `keypair` | `Keypair` | No | Keypair for PoP |
| `mapping` | `dict[str, str]` | No | Arg name → constraint name mapping |
| `extract_args` | `Callable` | No | Custom arg extraction function |

*If no warrant provided, uses context.

#### Patterns

**Explicit warrant:**
```python
@lockdown(warrant, tool="read_file", keypair=agent_kp)
def read_file(path: str) -> str:
    return open(path).read()
```

**Context-based:**
```python
@lockdown(tool="read_file")
def read_file(path: str) -> str:
    return open(path).read()

# Use with context
with set_warrant_context(warrant), set_keypair_context(keypair):
    read_file("/tmp/test.txt")
```

**With argument mapping:**
```python
@lockdown(warrant, tool="manage", mapping={"target_env": "cluster"})
def deploy(target_env: str):  # target_env maps to "cluster" constraint
    ...
```

---

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
| `get_warrant_context()` | `Warrant \| None` | Get current warrant |
| `set_keypair_context(keypair)` | Context manager | Set keypair for PoP |
| `get_keypair_context()` | `Keypair \| None` | Get current keypair |

#### Example

```python
with set_warrant_context(warrant), set_keypair_context(keypair):
    # All @lockdown functions use this warrant and keypair
    result = protected_function(arg1, arg2)
```

---

## Audit Logging

### AuditLogger

Global logger for security events.

```python
from tenuo import audit_logger
```

#### Methods

| Method | Description |
|--------|-------------|
| `configure(...)` | Configure logging settings |
| `log(event: AuditEvent)` | Log an event |
| `authorization_success(...)` | Log successful auth |
| `authorization_failure(...)` | Log failed auth |

#### `configure()` Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | `bool` | `True` | Enable/disable logging |
| `service_name` | `str` | `"tenuo-python"` | Service name in events |
| `handler` | `Callable` | None | Custom event handler |
| `use_python_logging` | `bool` | `False` | Use Python's logging module |
| `logger_name` | `str` | `"tenuo.audit"` | Logger name |

---

### AuditEvent

Structured audit event.

```python
from tenuo import AuditEvent, AuditEventType
```

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | `AuditEventType` | Type of event |
| `id` | `str` | Auto-generated event ID |
| `severity` | `AuditSeverity` | Auto-inferred severity |
| `timestamp` | `str` | ISO8601 timestamp |
| `service` | `str` | Service name |
| `trace_id` | `str` | Correlation ID |
| `warrant_id` | `str` | Related warrant |
| `tool` | `str` | Tool name |
| `action` | `str` | Action performed |
| `constraints` | `dict` | Constraints checked |
| `actor` | `str` | Actor identifier |
| `details` | `str` | Human-readable details |
| `error_code` | `str` | Error code (failures) |

---

### AuditEventType

```python
from tenuo import AuditEventType
```

| Event Type | Severity | Description |
|------------|----------|-------------|
| `AUTHORIZATION_SUCCESS` | INFO | Authorization granted |
| `AUTHORIZATION_FAILURE` | ERROR | Authorization denied |
| `WARRANT_CREATED` | INFO | New warrant issued |
| `WARRANT_ATTENUATED` | INFO | Warrant narrowed |
| `WARRANT_VERIFIED` | INFO | Signature verified |
| `WARRANT_EXPIRED` | WARNING | Warrant expired |
| `CONTEXT_SET` | INFO | Context activated |
| `CONTEXT_CLEARED` | INFO | Context deactivated |
| `POP_VERIFIED` | INFO | PoP signature valid |
| `POP_FAILED` | ERROR | PoP signature invalid |
| `ENROLLMENT_SUCCESS` | INFO | Agent enrolled |
| `ENROLLMENT_FAILURE` | ERROR | Enrollment failed |

---

## Exceptions

```python
from tenuo import (
    TenuoError,           # Base exception
    WarrantError,         # Warrant operations failed
    AuthorizationError,   # Authorization check failed
    ConstraintError,      # Constraint validation failed
    ConfigurationError,   # Invalid configuration
)
```

All exceptions inherit from `TenuoError`.

---

## Constants

```python
from tenuo import (
    MAX_DELEGATION_DEPTH,  # Maximum delegation chain depth (64)
    MAX_CONSTRAINT_DEPTH,  # Maximum constraint nesting depth
    WIRE_VERSION,          # Wire protocol version
    WARRANT_HEADER,        # HTTP header name ("X-Tenuo-Warrant")
)
```

---

## LangChain / LangGraph Extensions

See also:
- `tenuo.langchain.protect_tools()` - Wrap tools for single-agent
- `tenuo.langchain.protect_tool()` - Wrap single tool
- `tenuo.langgraph.SecureGraph` - Multi-agent warrant management

Refer to [examples/](../examples/README.md) for complete usage patterns.
