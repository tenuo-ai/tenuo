---
title: API Reference
description: Complete Python SDK documentation
---

# Tenuo Python SDK API Reference

Complete API documentation for the Tenuo Python SDK. For wire format details, see [Protocol Specification](protocol).

## Table of Contents

- [Configuration](#configuration)
- [Constants](#constants)
- [Core Types](#core-types)
  - [SigningKey](#keypair)
  - [PublicKey](#publickey)
  - [Signature](#signature)
  - [Warrant](#warrant)
  - [BoundWarrant](#boundwarrant)
  - [Authorizer](#authorizer)
- [Constraints](#constraints)
- [Task Scoping](#task-scoping)
- [Tool Protection](#tool-protection)
- [MCP Integration](#mcp-integration)
- [Decorators & Context](#decorators--context)
- [LangChain Integration](#langchain-integration)
- [LangGraph Integration](#langgraph-integration)
- [Testing Utilities](#testing-utilities)
- [Exceptions](#exceptions)
- [Audit Logging](#audit-logging)
- [Type Protocols](#type-protocols)

---

## Constants

Protocol-level constants exported from the SDK:

```python
from tenuo import MAX_DELEGATION_DEPTH, MAX_WARRANT_SIZE, MAX_WARRANT_TTL_SECS, DEFAULT_WARRANT_TTL_SECS
```

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_DELEGATION_DEPTH` | 16 | Maximum warrant delegation depth |
| `MAX_WARRANT_TTL_SECS` | 7,776,000 | Maximum TTL in seconds (90 days) |
| `DEFAULT_WARRANT_TTL_SECS` | 300 | Default TTL if not specified (5 minutes) |
| `MAX_WARRANT_SIZE` | 65,536 | Maximum serialized warrant size in bytes (64 KB) |

**Notes**:
- 16 levels of delegation is sufficient for even complex hierarchies (typical chains are 3-5 levels)
- 90 days is the protocol ceiling; deployments can (and should) configure stricter TTL limits
- Default TTL is intentionally short (5 minutes) - expand only as needed

---

## Configuration

### `configure()`

Initialize Tenuo globally. **Call once at application startup** before using `root_task()` or `scoped_task()`.

```python
from tenuo import configure, SigningKey

# Development (self-signed warrants)
kp = SigningKey.generate()
configure(
    issuer_key=kp,
    dev_mode=True,
    allow_self_signed=True,
)

# Production (trusted roots required)
configure(
    issuer_key=my_keypair,
    trusted_roots=[control_plane_pubkey],
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `issuer_key` | `SigningKey` | None | SigningKey for signing warrants (required for `root_task`) |
| `trusted_roots` | `List[PublicKey]` | None | Public keys to trust as warrant issuers (**required in production**) |
| `default_ttl` | `int` | 300 | Default warrant TTL in seconds |
| `clock_tolerance` | `int` | 30 | Clock tolerance for expiration checks |
| `pop_window_secs` | `int` | 30 | PoP window size in seconds |
| `pop_max_windows` | `int` | 4 | Number of PoP windows to accept (~2 min total) |
| `dev_mode` | `bool` | False | Enable development mode (relaxed security) |
| `allow_passthrough` | `bool` | False | Allow tool calls without warrants (requires `dev_mode`) |
| `allow_self_signed` | `bool` | False | Trust self-signed warrants (requires `dev_mode`) |

#### Modes

**Production Mode** (default):
- `trusted_roots` required
- All warrants must chain to a trusted root
- PoP mandatory
- Missing warrants → `Unauthorized` error

**Development Mode** (`dev_mode=True`):
- `trusted_roots` optional
- `allow_self_signed=True` enables single-keypair testing
- `allow_passthrough=True` skips authorization entirely (dangerous)

**Strict Mode** (`strict_mode=True`):
- Missing warrant → `RuntimeError` (panic/crash)
- Catches integration bugs (missing decorators, forgotten context)
- **Recommended for CI/CD**

**Warning Mode** (`warn_on_missing_warrant=True`):
- Missing warrant → Python warning + audit log
- Surfaces integration issues without breaking tests
- **Recommended for development/staging**

**Tripwire** (`max_missing_warrant_warnings=N`):
- Auto-flip to strict mode after N warnings
- Prevents "warn fatigue" in production
- `0` = disabled (default)

See [Integration Safety](./security#integration-safety) for detailed guide.

#### Errors

| Error | Cause |
|-------|-------|
| `ConfigurationError: trusted_roots required` | Production mode without trusted roots |
| `ConfigurationError: allow_passthrough requires dev_mode` | Passthrough without dev mode |
| `ConfigurationError: allow_self_signed requires dev_mode` | Self-signed without dev mode |

### `get_config()`

Get the current configuration.

```python
from tenuo import get_config

config = get_config()
print(f"TTL: {config.default_ttl}")
print(f"Dev mode: {config.dev_mode}")
```

---

## Core Types

### SigningKey

Ed25519 keypair for signing and verification.

```python
from tenuo import SigningKey
```

#### Class Methods

| Method | Description |
|--------|-------------|
| `SigningKey.generate()` | Generate a new random keypair |
| `SigningKey.from_bytes(secret_key: bytes)` | Reconstruct keypair from 32-byte secret key |
| `SigningKey.from_pem(pem: str)` | Create a keypair from a PEM string |

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
| `Warrant.issue(...)` | Issue a new execution warrant |
| `Warrant.issue_issuer(...)` | Issue a new issuer warrant |

#### `Warrant.issue()` Parameters (Execution Warrants)

```python
from tenuo import Warrant, Constraints, Pattern

Warrant.issue(
    capabilities: dict,  # Constraints.for_tool("name", {...}) or {tool: constraints}
    keypair: SigningKey,
    holder: PublicKey,
    ttl_seconds: int = 3600,
    session_id: Optional[str] = None
)

# Example
warrant = Warrant.issue(
    capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
    keypair=my_keypair,
    holder=my_keypair.public_key,
    ttl_seconds=3600,
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `capabilities` | `dict` | Tool→constraint mapping (use `Constraints.for_tool()` helper) |
| `keypair` | `SigningKey` | Issuer's keypair |
| `holder` | `PublicKey` | Holder's public key |
| `ttl_seconds` | `int` | Time-to-live in seconds |
| `session_id` | `str` | Optional session ID |

#### `Warrant.issue_issuer()` Parameters (Issuer Warrants)

```python
Warrant.issue_issuer(
    issuable_tools: List[str],
    keypair: SigningKey,
    constraint_bounds: Optional[dict] = None,
    max_issue_depth: Optional[int] = None,
    ttl_seconds: int = 3600,
    holder: Optional[PublicKey] = None,
    session_id: Optional[str] = None,
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `issuable_tools` | `List[str]` | Tools this warrant can issue |
| `keypair` | `SigningKey` | Issuer's keypair |
| `constraint_bounds` | `dict` | Optional constraint bounds |
| `max_issue_depth` | `int` | Max depth for issued warrants |
| `ttl_seconds` | `int` | Time-to-live in seconds |
| `holder` | `PublicKey` | Optional holder (defaults to issuer) |

#### `Warrant.builder()` - Fluent API

For improved DX, use the fluent builder pattern:

```python
from tenuo import Warrant, Pattern, Range, Clearance

# Execution warrant with builder
warrant = (Warrant.builder()
    .capability("read_file", {
        "path": Pattern("/data/*"),
        "max_size": Range(0, 1000000),
    })
    .ttl(3600)
    .holder(keypair.public_key)
    .issue(keypair))

# Issuer warrant with builder
issuer = (Warrant.builder()
    .issuer()  # Switch to issuer mode
    .issuable_tools(["read_file", "write_file"])
    .clearance(Clearance.INTERNAL)  # Optional
    .constraint_bound("path", Pattern("/data/*"))
    .max_issue_depth(3)
    .issue(keypair))
```

| Method | Description |
|--------|-------------|
| `.capability(tool, constraints)` | Add a capability (tool + constraints) — **recommended** |
| `.tool(str)` | Set single tool (legacy, for single-tool warrants) |
| `.constraint(field, value)` | Add a constraint (legacy, applies to current tool) |
| `.ttl(seconds)` | Set time-to-live |
| `.holder(pubkey)` | Set authorized holder |
| `.session_id(str)` | Set session identifier |
| `.clearance(level)` | Set clearance level |
| `.issuer()` | Switch to issuer warrant mode |
| `.issuable_tools(list)` | Tools this issuer can delegate |
| `.constraint_bound(field, value)` | Add constraint bound |
| `.max_issue_depth(n)` | Max delegation depth |
| `.preview()` | Preview configuration before building |
| `.issue(keypair)` | Issue and sign the warrant |

#### Instance Properties

| Property | Type | Description |
|----------|------|-------------|
| `id` | `str` | Unique warrant ID |
| `tools` | `List[str]` | Authorized tools |
| `depth` | `int` | Delegation depth (0 = root) |
| `session_id` | `str \| None` | Session identifier |
| `authorized_holder` | `PublicKey \| None` | Bound holder's public key |
| `ttl_remaining` | `timedelta` | Time remaining until expiration |
| `ttl` | `timedelta` | Alias for `ttl_remaining` |
| `expires_at` | `datetime` | Expiration time as datetime object |
| `is_expired` | `bool` | Whether warrant has expired |
| `is_terminal` | `bool` | Whether warrant cannot delegate further (depth=0) |
| `capabilities` | `dict` | Human-readable constraint summary |
| `delegation_receipt` | `DelegationReceipt \| None` | Receipt if created via delegation |

```python
# Property examples
warrant.ttl_remaining       # timedelta(seconds=299, ...)
warrant.expires_at          # datetime(2025, 12, 22, 21, 30, ...)
warrant.is_expired          # False
warrant.is_terminal         # False  
warrant.capabilities        # {'tools': ['read_file'], 'path': '/data/*', 'max_size': 1000000}
```

#### Instance Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `attenuate(constraints, keypair, ttl_seconds=None, holder=None)` | `Warrant` | Create narrower child warrant |
| `attenuate()` | `AttenuationBuilder` | Create builder for attenuation with diff preview |
| `issue_execution()` | `IssuanceBuilder` | Create execution warrant from issuer warrant |
| `delegate(holder, tools=None, **constraints)` | `Warrant` | Convenience method to delegate (requires context) |
| `authorize(tool, args, signature?)` | `bool` | Check if action is authorized |
| `verify(public_key)` | `bool` | Verify signature against issuer |
| `create_pop_signature(keypair, tool, args)` | `list[int]` | Create PoP signature |
| `to_base64()` | `str` | Serialize to base64 |
| `preview_can(tool, **args)` | `PreviewResult` | Check if action would be allowed (UX only) |
| `why_denied(tool, **args)` | `WhyDenied` | Get structured denial reason |
| `auth_headers(keypair, tool, args)` | `dict` | Generate HTTP authorization headers |

#### Preview & Debugging Methods

```python
from tenuo import Warrant, PreviewResult, WhyDenied, DenyCode

# Preview (UX-only, not security-enforced)
result = warrant.preview_can("read_file", path="/data/report.txt")
if result.allowed:
    print("Would be allowed")
else:
    print(f"Would be denied: {result.reason}")

# Why denied (for debugging)
reason = warrant.why_denied("write_file", path="/etc/passwd")
# WhyDenied(deny_code=DenyCode.TOOL_NOT_ALLOWED, tool='write_file', ...)

if reason.deny_code == DenyCode.TOOL_NOT_ALLOWED:
    print("Tool not in warrant")

# Generate HTTP headers
headers = warrant.auth_headers(keypair, "read_file", {"path": "/data/x.txt"})
# {'Authorization': 'TenuoWarrant ...', 'X-Tenuo-Pop': '...'}
```

| Class | Description |
|-------|-------------|
| `PreviewResult` | Result with `.allowed`, `.reason`, `.tool` |
| `WhyDenied` | Denial info with `.deny_code`, `.tool`, `.field`, `.constraint`, `.value` |
| `DenyCode` | Enum: `ALLOWED`, `TOOL_NOT_ALLOWED`, `CONSTRAINT_VIOLATED`, `EXPIRED` |

#### Repr (Safe Logging)

Warrant `repr()` hides sensitive data for safe logging:

```python
print(repr(warrant))
# <Warrant id=tnu_wrt_019b... tools=[read_file, write_file] ttl=0:04:59>

# Many tools are truncated
# <Warrant id=tnu_wrt_019b... tools=[a, b, c, +3 more] ttl=0:04:59>
```

⚠️ **Replay Window:** PoP signatures are valid for ~2 minutes to handle clock skew. For sensitive operations, implement deduplication using `warrant.dedup_key(tool, args)`. See [Protocol: Replay Protection](./protocol#replay-protection).

#### Principle of Least Authority (POLA)

Tenuo follows **POLA**: when you attenuate a warrant, the child starts with **NO capabilities**. You must explicitly specify what you want. This prevents accidentally granting more authority than intended.

| Method | Behavior |
|--------|----------|
| `capability(tool, {})` | Grant only that tool |
| `inherit_all()` | Explicitly opt-in to inherit all parent capabilities |
| `tools([...])` | After `inherit_all()`, narrow to subset |

**Pattern 1: Grant specific capabilities (recommended)**

```python
# Child only gets what you explicitly grant
builder = parent.attenuate()
builder.capability("read_file", {"path": Exact("/data/report.txt")})
builder.holder(worker_kp.public_key)
child = builder.delegate(kp)
# child.tools == ["read_file"] (only!)
```

**Pattern 2: Inherit all, then narrow**

```python
# Start with all parent capabilities, then narrow
builder = parent.attenuate()
builder.inherit_all()                    # Explicit opt-in
builder.tools(["read_file"])             # Keep only this tool
builder.holder(worker_kp.public_key)
child = builder.delegate(kp)
```

**Pattern 3: Via delegate() (convenience)**

The `delegate()` method automatically calls `inherit_all()` internally, making it easier for simple cases:

```python
with set_signing_key_context(my_keypair):
    child = parent.delegate(
        holder=worker.public_key,
        tools=["read_file"],  # Narrow tools
        path=Exact("/data/q3.pdf"),  # Narrow constraints
    )
```

**Via Issuer warrant (alternative):**

```python
# Create issuer warrant, then issue execution with specific tools
issuer_warrant = Warrant.issue_issuer(
    issuable_tools=["read_file", "send_email"],
    keypair=control_plane_kp,
    ttl_seconds=3600,
)

builder = issuer_warrant.issue_execution()
builder.tool("read_file")
builder.holder(worker_kp.public_key)
builder.ttl(300)
exec_warrant = builder.build(issuer_kp)
```

#### Terminal Warrants

A warrant is **terminal** when it cannot delegate further (`depth >= max_depth`).

```python
# Create terminal warrant
builder = parent.attenuate()
builder.inherit_all()     # POLA: inherit parent capabilities
builder.terminal()        # Mark as terminal
builder.holder(worker_kp.public_key)
terminal = builder.delegate(kp)

assert terminal.is_terminal()  # True
# terminal.attenuate().delegate(...) will fail
```

---

### BoundWarrant

Warrant bound to a signing key for convenience. **Non-serializable** to prevent accidental key exposure.

```python
from tenuo import Warrant, BoundWarrant

# Create bound warrant
warrant, keypair = Warrant.quick_issue(["read_file"], ttl=300)
bound = BoundWarrant(warrant, keypair)

# Or bind from existing warrant
bound = warrant.bind(keypair)
```

#### Why BoundWarrant?

- **Convenience**: No need to pass keypair to every method
- **Safety**: Cannot be serialized (prevents accidental key exposure)
- **Ergonomic**: All warrant properties/methods available via forwarding

#### Properties (Forwarded from Warrant)

| Property | Type | Description |
|----------|------|-------------|
| `id` | `str` | Unique warrant ID |
| `tools` | `List[str]` | Authorized tools |
| `ttl_remaining` | `timedelta` | Time remaining |
| `ttl` | `timedelta` | Alias for `ttl_remaining` |
| `expires_at` | `datetime` | Expiration datetime |
| `is_expired` | `bool` | Whether expired |
| `is_terminal` | `bool` | Whether terminal |
| `capabilities` | `dict` | Constraint summary |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `delegate(holder, tools=None, **constraints)` | `BoundWarrant` | Delegate (uses bound key) |
| `auth_headers(tool, args)` | `dict` | HTTP headers (uses bound key) |
| `unbind()` | `tuple[Warrant, SigningKey]` | Extract warrant and key |
| `preview_can(tool, **args)` | `PreviewResult` | Check if allowed |
| `why_denied(tool, **args)` | `WhyDenied` | Get denial reason |

```python
# Delegation with bound key (no keypair arg needed)
child = bound.delegate(worker.public_key, tools=["read_file"])

# Generate headers
headers = bound.auth_headers("read_file", {"path": "/data/x.txt"})

# Serialization blocked
import pickle
pickle.dumps(bound)  # Raises TypeError!
```

#### Repr (Safe)

```python
print(repr(bound))
# <BoundWarrant id=tnu_wrt_019b... KEY_BOUND=True>
```

---

### IssuanceBuilder

Builder for issuing execution warrants from issuer warrants.

```python
builder = issuer_warrant.issue_execution()
```

#### Setter Methods (Chainable)

| Method | Returns | Description |
|--------|---------|-------------|
| `tool(name)` | `IssuanceBuilder` | Add single tool |
| `tools(names)` | `IssuanceBuilder` | Add multiple tools |
| `capability(tool, constraints)` | `IssuanceBuilder` | Add tool with constraints |
| `holder(public_key)` | `IssuanceBuilder` | Set authorized holder |
| `ttl(seconds)` | `IssuanceBuilder` | Set TTL (required) |
| `clearance(level)` | `IssuanceBuilder` | Set clearance level |
| `intent(intent)` | `IssuanceBuilder` | Set intent/purpose |
| `max_depth(depth)` | `IssuanceBuilder` | Set max delegation depth |
| `terminal()` | `IssuanceBuilder` | Make warrant non-delegatable |
| `build(keypair)` | `Warrant` | Build and sign the warrant |

#### Getter Methods (Dual-Purpose)

All setter methods are dual-purpose - call without arguments to get current value:

```python
builder.holder()       # Returns configured holder or None
builder.ttl()          # Returns configured TTL or None
builder.clearance()    # Returns configured clearance level or None
builder.intent()       # Returns configured intent or None
```

Note: `with_*` methods are available as aliases for backward compatibility.

---

### AttenuationBuilder

Builder for attenuating (narrowing) existing warrants.

```python
builder = warrant.attenuate()
```

#### Methods

All setter methods are **dual-purpose**: call with argument to set (returns self for chaining), call without to get current value.

| Method | Returns | Description |
|--------|---------|-------------|
| `inherit_all()` | `AttenuationBuilder` | **POLA opt-in**: Inherit all capabilities from parent |
| `capability(tool, constraints)` | `AttenuationBuilder` | Grant specific capability with constraints |
| `tool(name)` | `AttenuationBuilder` | After `inherit_all()`, narrow to single tool |
| `tools(names)` | `AttenuationBuilder` | After `inherit_all()`, narrow to subset of tools |
| `issuable_tool(name)` | `AttenuationBuilder` | Narrow issuable tools (issuer warrants) |
| `issuable_tools(names)` | `AttenuationBuilder` | Narrow issuable tools (issuer warrants) |
| `holder(pk)` / `holder()` | `AttenuationBuilder` / `PublicKey` | Set/get holder |
| `ttl(seconds)` / `ttl()` | `AttenuationBuilder` / `int` | Set/get TTL |
| `clearance(level)` / `clearance()` | `AttenuationBuilder` / `Clearance` | Set/get clearance level |
| `intent(text)` / `intent()` | `AttenuationBuilder` / `str` | Set/get intent |
| `terminal()` | `AttenuationBuilder` | Make warrant terminal (no further delegation) |
| `diff()` | `str` | Preview changes (human-readable) |
| `delegate(signing_key)` | `Warrant` | Issue child with receipt |

> ⚠️ **POLA**: The builder starts with NO capabilities. Use `capability()` to grant specific tools, or `inherit_all()` to explicitly inherit all parent capabilities.

#### Examples

```python
# Pattern 1: Grant specific capability (POLA default)
child = (parent.attenuate()
    .capability("read_file", {"path": Exact("/data/q3.pdf")})
    .holder(worker_kp.public_key)
    .delegate(parent_kp))

# Pattern 2: Inherit all, then narrow
child = (parent.attenuate()
    .inherit_all()                    # Explicit opt-in
    .tools(["read_file"])             # Keep only this tool
    .holder(worker_kp.public_key)
    .delegate(parent_kp))

# Reading builder state
assert builder.holder() == worker_kp.public_key
assert builder.ttl() == 300
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

#### Tool Clearance Requirements (Optional)

The Authorizer can *optionally* enforce minimum clearance levels per tool as defense in depth. Clearance is a coarse-grained policy overlay—**not a security boundary**. Capabilities and monotonicity provide the cryptographic guarantees; clearance adds organizational convenience.

```python
from tenuo import Authorizer, Clearance

authorizer = Authorizer(trusted_roots=[root_key])

# Require specific clearance levels for tools
authorizer.require_clearance("*", Clearance.EXTERNAL)        # Default baseline
authorizer.require_clearance("delete_*", Clearance.PRIVILEGED)  # Prefix pattern
authorizer.require_clearance("admin_reset", Clearance.SYSTEM)   # Exact match

# Check what's required for a tool
print(authorizer.get_required_clearance("delete_file"))  # Clearance.PRIVILEGED
```

**Pattern types:**
- `"exact_name"` - Exact tool name match
- `"prefix_*"` - Prefix pattern (e.g., `admin_*` matches `admin_users`, `admin_config`)
- `"*"` - Default for all tools (recommended for defense in depth)

**Lookup precedence:** Exact match → Glob pattern → Default `*` → No requirement (check skipped)

**Security note:** If no clearance requirement is configured for a tool, the check is skipped. Configure a default `"*"` pattern for defense in depth.

| Method | Description |
|--------|-------------|
| `require_clearance(pattern, level)` | Set minimum clearance for tool pattern |
| `get_required_clearance(tool)` | Get required clearance level (or None) |

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

> [!IMPORTANT]
> **Pattern vs Wildcard**: `Pattern("*")` is NOT the same as `Wildcard()`.
> *   `Wildcard()` is a semantic "match anything" that can be attenuated to *any* other constraint.
> *   `Pattern("*")` is a specific glob string. Due to the complexity of proving glob subsets, `tenuo-core` only supports subsetting for simple **Prefix** (`foo*`) or **Suffix** (`*bar`) patterns.
> *   **Complex patterns** (e.g., `*foo*` or `a*b*c`) require exact equality for attenuation.
>
> **Best Practice**: Use `Wildcard()` in root warrants if you want to allow full flexibility for children to narrow down. Use `Pattern("*")` only if you specifically mean a glob match that will only be narrowed to other simple prefix/suffix patterns.

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

> **⚠️ Attenuation Limitation**: Regex patterns cannot be narrowed during attenuation. Child must use the **same pattern** as parent, or attenuate to `Exact()`. This is due to the undecidability of regex subset checking. See [Constraints → Regex Narrowing](./constraints#regex-narrowing) for details.

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

Common Expression Language for complex authorization logic.

```python
from tenuo import CEL

# Simple comparison
CEL('amount < 10000 && amount > 0')

# Multi-parameter logic
CEL('budget < revenue * 0.1 && currency == "USD"')

# With standard library functions
CEL('time_since(created_at) < 3600')  # Within last hour
CEL('net_in_cidr(ip, "10.0.0.0/8")')  # From private network
```

**Standard Library:**
- **Time**: `time_now(null)`, `time_is_expired(ts)`, `time_since(ts)`
- **Network**: `net_in_cidr(ip, cidr)`, `net_is_private(ip)`

See [Constraints → CEL](./constraints#cel-common-expression-language) for full documentation and examples.

**Security:**
- Sandboxed execution (no arbitrary code)
- Must return boolean
- Expressions cached (max 1000)
- No side effects (pure evaluation)

---

## Task Scoping

Context managers for scoping authority to tasks.

### `root_task`

Create root authority for a task. **Async version.**

```python
from tenuo import root_task, Capability, Pattern

async with root_task(Capability("read_file", path=Pattern("/data/*"))) as warrant:
    result = await agent.invoke(prompt)
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `*capabilities` | `Capability...` | Yes | Capabilities to authorize (tool + constraints) |
| `ttl` | `int` | No | TTL in seconds (default from `configure()`) |
| `holder_key` | `SigningKey` | No | Explicit holder (default: issuer) |

#### Requirements

- Must call `configure(issuer_key=...)` first
- At least one tool required

### `root_task_sync`

Synchronous version of `root_task`.

```python
from tenuo import root_task_sync

with root_task_sync(Capability("read_file", path="/data/*")) as warrant:
    result = protected_read_file(path="/data/report.csv")
```

Same parameters as `root_task`.

### `scoped_task`

Attenuate within an existing task scope.

```python
from tenuo import scoped_task

async with root_task(
    Capability("read_file", path="/data/*"), 
    Capability("write_file", path="/data/*")
):
    async with scoped_task(Capability("read_file", path="/data/reports/*")):
        # Narrower scope here
        result = await agent.invoke(prompt)
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `*capabilities` | `Capability...` | No | Capabilities to allow (must be subset of parent). If omitted, implies all parent capabilities. |
| `ttl` | `int` | No | Shorter TTL (None = inherit remaining) |

#### Requirements

- **Must be called within `root_task` or another `scoped_task`**
- Constraints must be monotonically attenuated (tighter than parent)

#### Preview Changes

```python
scope = scoped_task(Capability("read_file", path="/data/reports/*"))
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
async with root_task(Capability("read_file", path="/data/*")):
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

Decorator for function-level authorization with automatic argument extraction.

```python
from tenuo import lockdown
```

#### Signature

```python
@lockdown(
    warrant_or_tool=None,  # Warrant instance OR tool name string
    tool=None,             # Tool name (if not passed as first arg)
    keypair=None,          # SigningKey for PoP (or use context)
    extract_args=None,     # Optional custom extractor function
    mapping=None,          # Arg name → constraint name mapping
)
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `warrant_or_tool` | `Warrant \| str` | No | Warrant instance or tool name as first positional arg |
| `tool` | `str` | Yes* | Tool name for authorization (*not needed if tool passed as first arg) |
| `keypair` | `SigningKey` | No | SigningKey for PoP (or use context) |
| `extract_args` | `Callable` | No | Custom argument extractor. If None, uses automatic extraction. |
| `mapping` | `dict[str, str]` | No | Rename parameters: `{"param": "constraint_key"}` |

#### Argument Extraction

`@lockdown` automatically extracts all function arguments **including defaults** using Python's `inspect.signature()`:

```python
@lockdown(tool="query")
def query_db(query: str, table: str = "users", limit: int = 100):
    ...

# All arguments extracted automatically:
query_db("SELECT *")  
# → {query: "SELECT *", table: "users", limit: 100}
#                        ↑ defaults included
```

✅ **Security:** Defaults are always included (prevents bypass via omission).

**Custom extraction:**
```python
@lockdown(
    tool="transfer",
    extract_args=lambda from_account, to_account, amount, **kw: {
        "source": from_account,
        "destination": to_account,
        "amount": amount
    }
)
def transfer(from_account: str, to_account: str, amount: float):
    ...
```

**Parameter mapping (simpler):**
```python
@lockdown(
    tool="read_file",
    mapping={"file_path": "path"}  # Rename after extraction
)
def read_file(file_path: str):
    ...
# Extracted as: {path: "..."}
```

See [Argument Extraction](./argument-extraction) for comprehensive documentation.

#### Patterns

**Context-based (recommended):**

```python
@lockdown(tool="read_file")
def read_file(path: str) -> str:
    return open(path).read()

# Use with task scoping
async with root_task(Capability("read_file", path=Pattern("/data/*"))):
    read_file("/data/test.txt")
```

**Explicit warrant:**

```python
@lockdown(warrant, tool="read_file", keypair=agent_kp)
def read_file(path: str) -> str:
    return open(path).read()
```

**Tool as first arg:**

```python
@lockdown("read_file")  # Shorthand: tool name as positional arg
def read_file(path: str) -> str:
    return open(path).read()
```

### Context Functions

```python
from tenuo import (
    set_warrant_context,
    get_warrant_context,
    set_signing_key_context,
    get_signing_key_context,
)
```

| Function | Returns | Description |
|----------|---------|-------------|
| `set_warrant_context(warrant)` | Context manager | Set warrant in async-safe context |
| `set_signing_key_context(keypair)` | Context manager | Set keypair in async-safe context |
| `get_warrant_context()` | `Warrant \| None` | Get current warrant |
| `get_signing_key_context()` | `SigningKey \| None` | Get current keypair |

> **Important**: Context is a **convenience layer** for tool protection within a single process. For distributed systems, serialized state, or checkpointing, warrants must travel in request state (e.g., `tenuo_warrant` field). Context does not survive serialization boundaries.

---

## LangChain Integration

See [LangChain Integration Guide](./langchain) for full documentation.

### `secure_agent()` (Recommended)

One-liner to secure LangChain tools. This is the recommended entry point.

```python
from tenuo import SigningKey, root_task_sync
from tenuo.langchain import secure_agent

# One line to secure your tools
kp = SigningKey.generate()
tools = secure_agent([search, calculator], issuer_keypair=kp)

# Use with scoped authority
with root_task_sync(Capability("search"), Capability("calculator")):
    result = executor.invoke({"input": "What is 2+2?"})
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tools` | `List[BaseTool]` | *required* | LangChain tools to protect |
| `issuer_keypair` | `SigningKey` | `None` | SigningKey for issuing warrants (enables dev_mode) |
| `strict_mode` | `bool` | `False` | Fail on any missing warrant |
| `warn_on_missing_warrant` | `bool` | `True` | Log warnings for unprotected calls |
| `schemas` | `Dict[str, ToolSchema]` | `None` | Custom tool schemas |


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
from tenuo import Capability, Pattern

@tenuo_node
async def researcher(state, bound_warrant):
    # bound_warrant is injected automatically
    if bound_warrant.preview_can("search"):
        results = await search_tool(query=state["query"])
        return {"results": results}
    return {"messages": ["Not authorized"]}
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `*capabilities` | `Capability` | Capability objects defining tool access |
| `ttl` | `int` | Optional TTL override (seconds) |

### `@require_warrant`

Require a warrant in context without scoping.

```python
from tenuo.langgraph import require_warrant

@require_warrant
async def sensitive_node(state):
    ...
```

### `TenuoToolNode` (Recommended)

Drop-in replacement for LangGraph's `ToolNode` with automatic Tenuo protection.

```python
from tenuo.langgraph import TenuoToolNode
from tenuo import root_task_sync

# Before (manual protection):
# tools = [search, calculator]
# protected = protect_langchain_tools(tools)
# tool_node = ToolNode(protected)

# After (automatic protection):
tool_node = TenuoToolNode([search, calculator])

graph.add_node("tools", tool_node)

# Run with authorization
with root_task_sync(Capability("search"), Capability("calculator")):
    result = graph.invoke(...)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tools` | `List[BaseTool]` | *required* | LangChain tools to protect |
| `strict` | `bool` | `False` | Require constraints for high-risk tools |
| `**kwargs` | `Any` | — | Additional arguments passed to ToolNode |
 
 ### `KeyRegistry`
 
 Registry for binding private keys to warrant holders at runtime. Essential for safe checkpointing (prevents keys in state).
 
 ```python
 from tenuo import KeyRegistry, SigningKey
 
 # Register key at startup
 key = SigningKey.generate()
 KeyRegistry.get_instance().register("worker-key", key)
 
 # In LangGraph config:
 config = {"configurable": {"tenuo_key_id": "worker-key"}}
 ```
 
 > **Mechanism**: `_get_bound_warrant` checks `config["configurable"]["tenuo_key_id"]` and looks up the key in the registry to re-bind warrants inflated from state.

---

---
 
 ## FastAPI Integration
 
 Middleware and dependency injection for FastAPI applications.
 
 ```python
 from tenuo.fastapi import TenuoGuard, SecurityContext, require_warrant
 ```
 
 ### `TenuoGuard` (Middleware)
 
 Global middleware that extracts warrants/keys from headers and manages request context.
 
 ```python
 from fastapi import FastAPI
 from tenuo import configure, SigningKey
 from tenuo.fastapi import TenuoGuard
 
 app = FastAPI()
 
 app.add_middleware(
     TenuoGuard,
     # Optional config overrides
     # trusted_roots=[...], 
     # verbose_errors=True
 )
 ```
 
 ### Dependencies
 
 #### `require_warrant`
 
 Dependency that enforces presence of a valid warrant. Returns `SecurityContext`.
 
 ```python
 @app.get("/secure")
 async def secure_endpoint(
     ctx: SecurityContext = Depends(require_warrant)
 ):
     return {"warrant_id": ctx.warrant_id}
 ```
 
 ### `SecurityContext`
 
 Context object injected into route handlers.
 
 | Property | Type | Description |
 |----------|------|-------------|
 | `warrant` | `AnyWarrant` | The verified warrant object |
 | `warrant_id` | `str` | Unique warrant ID |
 | `fields` | `dict` | Custom warrant fields |
 | `key_id` | `str \| None` | ID of the signing key (if registered) |
 
 ---
 
 ## Testing Utilities

Utilities for testing code that uses Tenuo authorization.

```python
from tenuo import allow_all, for_testing, quick_issue, deterministic_headers
```

### `allow_all()`

Context manager that bypasses all `@lockdown` authorization checks. **Only works in test environments.**

```python
from tenuo import allow_all, lockdown

@lockdown(tool="dangerous_action")
def dangerous_action():
    return "executed"

# In tests (pytest, unittest, or TENUO_TEST_MODE=1)
def test_dangerous_action():
    with allow_all():
        result = dangerous_action()  # No warrant needed!
        assert result == "executed"
```

**Environment Detection:**
- Automatically enabled under `pytest` or `unittest`
- Manually enable with `TENUO_TEST_MODE=1`
- Raises `RuntimeError` if called outside test environments

### `Warrant.for_testing()`

Create test warrants without real cryptographic setup.

```python
from tenuo import Warrant

def test_my_function():
    warrant = Warrant.for_testing(["read_file", "write_file"])
    # Use for testing without real key management
```

### `Warrant.quick_issue()`

Quickly issue a warrant with auto-generated keys (for development/testing).

```python
from tenuo import Warrant

# Returns (warrant, keypair)
warrant, keypair = Warrant.quick_issue(["read_file"], ttl=300)
```

### `deterministic_headers()`

Generate deterministic HTTP headers for snapshot testing.

```python
from tenuo import deterministic_headers

headers = deterministic_headers(["read_file"])
# Always produces the same headers for the same tools
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
├── AuthorizationDenied   # Authorization failed (diff-style)
├── WarrantError          # Warrant creation/validation failed
├── ConstraintError       # Invalid constraint definition
└── ConfigurationError    # Invalid configuration
```

### `AuthorizationDenied` (Diff-Style Errors)

Authorization denied with detailed diff-style error messages showing exactly what failed.

```python
from tenuo import AuthorizationDenied, ConstraintResult, Pattern

# Example error output:
# Access denied for tool 'read_file'
#
#   ❌ path:
#      Expected: Pattern("/data/*")
#      Received: '/etc/passwd'
#      Reason: Pattern does not match
#   ✅ size: OK

# Create from constraint check
error = AuthorizationDenied.from_constraint_check(
    tool="read_file",
    constraints={"path": Pattern("/data/*"), "size": Range(max=1000)},
    args={"path": "/etc/passwd", "size": 500},
    failed_field="path",
    failed_reason="Pattern does not match",
)

print(error)  # Shows detailed diff
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

## Type Protocols

For type hinting generic warrant operations:

```python
from tenuo import ReadableWarrant, SignableWarrant, AnyWarrant
```

### `ReadableWarrant`

Protocol for objects with readable warrant properties:

```python
from typing import Protocol

class ReadableWarrant(Protocol):
    @property
    def id(self) -> str: ...
    @property
    def tools(self) -> list[str]: ...
    @property
    def ttl_remaining(self) -> timedelta: ...
    @property
    def is_expired(self) -> bool: ...
    @property
    def is_terminal(self) -> bool: ...
```

### `SignableWarrant`

Protocol for objects that can sign (delegate, create PoP):

```python
class SignableWarrant(Protocol):
    def delegate(self, holder: PublicKey, ...) -> "Warrant": ...
    def auth_headers(self, tool: str, args: dict) -> dict: ...
```

### `AnyWarrant`

Union type accepting both `Warrant` and `BoundWarrant`:

```python
AnyWarrant = Union[Warrant, BoundWarrant]

def process_warrant(w: AnyWarrant) -> None:
    print(w.id, w.tools)  # Works for both types
```

---

## See Also

- [AI Agent Patterns](./ai-agents) — P-LLM/Q-LLM, prompt injection defense
- [Constraints Guide](./constraints) — Detailed constraint usage
- [Security](./security) — Threat model and protections
- [Examples](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples) — Python usage examples
