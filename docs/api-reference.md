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
- [Audit Logging](#audit-logging)

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

| Method | Returns | Description |
|--------|---------|-------------|
| `public_key()` | `PublicKey` | Get the public key |
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
| `Warrant.issue(tool: str, constraints: dict, ttl_seconds: int, keypair: Keypair, holder: Optional[PublicKey] = None, session_id: Optional[str] = None)` | Issue a new warrant |


#### `Warrant.issue()` Parameters

- `tool`: The tool name to authorize (or comma-separated list like "search,read_file").
- `constraints`: A dictionary of constraints.
- `ttl_seconds`: Time-to-live in seconds.
- `keypair`: The issuer's keypair.
- `holder`: (Optional) The public key of the authorized holder. If not provided, defaults to the issuer (self-signed).
- `session_id`: (Optional) Session ID to bind to.

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
| `attenuate(constraints, keypair, ttl_seconds=None, holder=None)` | `Warrant` | Create narrower child warrant |
| `attenuate_builder()` | `AttenuationBuilder` | Create builder for attenuation with diff preview |
| `authorize(tool, args, signature?)` | `bool` | Check if action is authorized |
| `verify(public_key)` | `bool` | Verify signature against issuer |
| `create_pop_signature(keypair, tool, args)` | `list[int]` | Create PoP signature (bytes as list of ints). **⚠️ Replay Window:** PoP signatures are valid for ~2 minutes to handle clock skew. Implement request deduplication for high-security operations. |
| `to_base64()` | `str` | Serialize to base64 |
| `is_expired()` | `bool` | Check if warrant has expired |
| `expires_at()` | `str` | Get expiration time (RFC3339) |
| `tool` | `str` | **Property**: The tool(s) authorized by this warrant |
| `session_id` | `str \| None` | **Property**: The session ID |
| `delegation_receipt` | `DelegationReceipt \| None` | **Property**: Get delegation receipt if this warrant was created via delegation |

#### Example

```python
from tenuo import Warrant, Keypair, Pattern, Exact

# Issue a new warrant
issuer_keypair = Keypair.generate()
worker_public_key = Keypair.generate().public_key()
root = Warrant.issue(
    tool="manage_infrastructure",
    constraints={"cluster": Pattern("staging-*")},
    ttl_seconds=3600,
    keypair=issuer_keypair,
    holder=worker_public_key
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
    signature=bytes(pop_sig)
)
```

---

## Delegation Diff & Audit

Types and methods for tracking warrant delegation changes and generating audit receipts.

### AttenuationBuilder

Fluent builder for creating attenuated warrants with diff preview.

```python
from tenuo import Warrant

builder = warrant.attenuate_builder()
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `with_constraint(field, constraint)` | `AttenuationBuilder` | Add or override a constraint |
| `with_ttl(seconds)` | `AttenuationBuilder` | Set TTL in seconds |
| `with_holder(public_key)` | `AttenuationBuilder` | Set authorized holder |
| `with_trust_level(level)` | `AttenuationBuilder` | Set trust level |
| `with_intent(intent)` | `AttenuationBuilder` | Set human-readable intent for audit |
| `diff()` | `str` | Get human-readable diff preview |
| `diff_structured()` | `DelegationDiff` | Get structured diff for programmatic use |
| `delegate_to(keypair, parent_keypair)` | `Warrant` | Build and sign the attenuated warrant |

#### Example

```python
builder = parent_warrant.attenuate_builder()
builder.with_constraint("path", Exact("/data/q3.pdf"))
builder.with_ttl(60)
builder.with_holder(worker_key)
builder.with_intent("Read Q3 report for analysis")

# Preview changes
print(builder.diff())

# Create child warrant
child = builder.delegate_to(orchestrator_kp, control_kp)

# Access receipt
receipt = child.delegation_receipt
```

### DelegationDiff

Structured representation of changes between parent and child warrants.

```python
from tenuo import DelegationDiff
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `parent_warrant_id` | `str` | Parent warrant ID |
| `child_warrant_id` | `str \| None` | Child warrant ID (None if not yet built) |
| `timestamp` | `str` | RFC3339 timestamp |
| `tools` | `ToolsDiff` | Tools changes |
| `constraints` | `dict[str, ConstraintDiff]` | Constraint changes by field |
| `ttl` | `TtlDiff` | TTL changes |
| `trust` | `TrustDiff` | Trust level changes |
| `depth` | `DepthDiff` | Depth changes |
| `intent` | `str \| None` | Human-readable intent |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `to_human()` | `str` | Human-readable diff output |
| `to_json()` | `str` | JSON serialization |
| `to_siem_json()` | `str` | SIEM-compatible JSON format |

### DelegationReceipt

Audit receipt for warrant delegation, extends `DelegationDiff` with additional metadata.

```python
from tenuo import DelegationReceipt
```

#### Properties

Includes all `DelegationDiff` properties plus:

| Property | Type | Description |
|----------|------|-------------|
| `delegator_fingerprint` | `str` | Fingerprint of delegator's key |
| `delegatee_fingerprint` | `str` | Fingerprint of delegatee's key |
| `used_pass_through` | `bool` | Whether pass-through was used |
| `pass_through_reason` | `str \| None` | Reason for pass-through (if used) |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `to_json()` | `str` | JSON serialization |
| `to_siem_json()` | `str` | SIEM-compatible JSON format |

#### Example

```python
# Receipt is automatically attached after delegation
child = builder.delegate_to(keypair, parent_keypair)
receipt = child.delegation_receipt

if receipt:
    print(f"Delegator: {receipt.delegator_fingerprint}")
    print(f"Delegatee: {receipt.delegatee_fingerprint}")
    print(f"Intent: {receipt.intent}")
    
    # Export for SIEM/audit logging
    siem_json = receipt.to_siem_json()
    audit_logger.log(siem_json)
```

---

### Authorizer

Centralized authorization with chain verification.

```python
from tenuo import Authorizer
```

#### Constructor

```python
Authorizer(
    trusted_roots: List[PublicKey],  # At least one required
    clock_tolerance_secs: int = 30,
    pop_window_secs: int = 30,
    pop_max_windows: int = 4,
)
```

#### Instance Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `verify(warrant)` | `None` | Verify warrant (signature, expiration, revocation) - raises on failure |
| `authorize(warrant, tool, args, signature=None)` | `None` | Authorize action (raises on failure) |
| `check(warrant, tool, args, signature=None)` | `None` | Verify warrant and authorize in one call (raises on failure) |
| `verify_chain(chain)` | `ChainVerificationResult` | Verify complete delegation chain from root to leaf |
| `check_chain(chain, tool, args, signature=None)` | `ChainVerificationResult` | Verify chain and authorize action against leaf warrant |

#### Example

```python
from tenuo import Authorizer, Keypair

cp_kp = Keypair.generate()
authorizer = Authorizer(trusted_roots=[cp_kp.public_key()])

# Verify root warrant
authorizer.verify(root_warrant)

# Verify and authorize in one call
pop_sig = warrant.create_pop_signature(keypair, "read_file", {"path": "/tmp/test.txt"})
authorizer.check(
    warrant,
    "read_file",
    {"path": "/tmp/test.txt"},
    signature=bytes(pop_sig)
)

# Verify a delegation chain
chain = [root_warrant, child_warrant, leaf_warrant]
result = authorizer.verify_chain(chain)
print(f"Chain verified: {result.chain_length} warrants, depth {result.leaf_depth}")

# Verify chain and authorize action
result = authorizer.check_chain(
    chain=chain,
    tool="read_file",
    args={"path": "/tmp/data.txt"},
    signature=None
)
```

---

## Chain Verification

Types and methods for verifying complete delegation chains.

### ChainVerificationResult

Result of a successful chain verification.

```python
from tenuo import ChainVerificationResult
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `root_issuer` | `bytes \| None` | Public key of root issuer (32 bytes), or None |
| `chain_length` | `int` | Total number of warrants in the verified chain |
| `leaf_depth` | `int` | Delegation depth of the leaf warrant |
| `verified_steps` | `List[ChainStep]` | Details of each verified step in the chain |

#### Example

```python
result = authorizer.verify_chain([root_warrant, child_warrant, leaf_warrant])
print(f"Chain length: {result.chain_length}")
print(f"Leaf depth: {result.leaf_depth}")
for step in result.verified_steps:
    print(f"  Step {step.depth}: {step.warrant_id[:16]}...")
```

### ChainStep

A single step in a verified delegation chain.

```python
from tenuo import ChainStep
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `warrant_id` | `str` | The warrant ID at this step |
| `depth` | `int` | Delegation depth at this step |
| `issuer` | `bytes` | Public key of the issuer at this step (32 bytes) |

#### Example

```python
result = authorizer.verify_chain(chain)
for step in result.verified_steps:
    print(f"Warrant {step.warrant_id[:16]}... at depth {step.depth}")
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
# Prefix patterns
Pattern("staging-*")     # Matches staging-web, staging-db, staging-api
Pattern("public/*")      # Matches public/file.txt, public/data.json
                          # Does NOT match public/subdir/file.txt (use ** for recursive)

# Recursive patterns (crosses path separators)
Pattern("/tmp/**")        # Matches /tmp/foo, /tmp/foo/bar, /tmp/a/b/c/file.txt
Pattern("public/**")      # Matches public/file.txt, public/subdir/file.txt, public/a/b/c/file.txt

# Suffix patterns
Pattern("*-safe")         # Matches image-safe, container-safe

# URL patterns
Pattern("https://public.*")  # Matches https://public.example.com, https://public.api.io
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

### CEL (CelConstraint)

Common Expression Language for complex logic.

**Note:** The type is `CelConstraint` in Rust, but Python exports it as `CEL` for convenience.

```python
from tenuo import CEL

CEL('value.startsWith("staging") && size(value) < 20')
CEL('value > 0 && value <= 1000')
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
with set_warrant_context(warrant), set_keypair_context(keypair):
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
| `set_keypair_context(keypair)` | Context manager | Set keypair in async-safe context |
| `get_warrant_context()` | `Warrant \| None` | Get current warrant |
| `get_keypair_context()` | `Keypair \| None` | Get current keypair |

#### Example

```python
with set_warrant_context(warrant), set_keypair_context(keypair):
    # All @lockdown functions use this warrant and keypair
    result = protected_function(arg1, arg2)
```

---

## LangChain Integration

### `protect_tools(tools: List[BaseTool], warrant: Warrant, keypair: Keypair, config: Optional[Union[str, dict, LangChainConfig]] = None) -> List[BaseTool]`

Wrap a list of LangChain tools with Tenuo protection.

- `tools`: List of tools to protect.
- `warrant`: Root warrant to enforce.
- `keypair`: Keypair for PoP (Mandatory).
- `config`: Optional configuration for per-tool constraints.

Returns a new list of protected tools.

```python
from tenuo.langchain import protect_tools
from langchain_community.tools import DuckDuckGoSearchRun

protected = protect_tools(
    tools=[DuckDuckGoSearchRun()],
    warrant=warrant,
    keypair=keypair
)
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
├── WarrantError          # Warrant creation/validation failed
├── ConstraintError       # Invalid constraint definition
└── ConfigurationError    # Invalid configuration (MCP/Gateway)
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

## Audit Logging

Structured audit logging for authorization events.

```python
from tenuo import audit_logger, AuditEventType, AuditEvent
```

### `audit_logger`

Singleton logger instance.

#### Methods

| Method | Description |
|--------|-------------|
| `configure(service_name: str, output_file: Optional[str] = None)` | Configure the logger |
| `log(event: AuditEvent)` | Log a raw audit event |
| `log_authorization_success(warrant_id, tool, constraints, ...)` | Log success event |
| `log_authorization_failure(warrant_id, tool, constraints, error_code, ...)` | Log failure event |

### `AuditEventType`

Enum for event types:
- `AUTHORIZATION_SUCCESS`
- `AUTHORIZATION_FAILURE`
- `WARRANT_CREATED`
- `WARRANT_ATTENUATED`
- `WARRANT_EXPIRED`
- `POP_FAILED`

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

- **[CLI Specification](cli-spec.md)**: Complete CLI reference
- **[Rust API](https://docs.rs/tenuo-core)**: Full Rust API documentation
- **[Examples](../tenuo-python/examples/)**: Python usage examples
- **[Website](https://tenuo.github.io/tenuo/)**: Landing page and guides

---

**Last Updated**: 2025-12-11  
**SDK Version**: 0.1.x
