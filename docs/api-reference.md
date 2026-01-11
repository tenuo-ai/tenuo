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
  - [SigningKey](#signingkey)
  - [PublicKey](#publickey)
  - [Signature](#signature)
  - [Warrant](#warrant)
  - [BoundWarrant](#boundwarrant)
  - [Authorizer](#authorizer)
- [Constraints](#constraints)
- [Warrant Templates](#warrant-templates)
- [Task Scoping](#task-scoping)
- [Tool Protection](#tool-protection)
- [MCP Integration](#mcp)
- [Decorators & Context](#decorators--context)
- [LangChain Integration](#langchain-integration)
- [LangGraph Integration](#langgraph-integration)
- [Testing Utilities](#testing-utilities)
- [CLI](#cli)
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
| `MAX_DELEGATION_DEPTH` | 64 | Maximum warrant delegation depth |
| `MAX_WARRANT_TTL_SECS` | 7,776,000 | Maximum TTL in seconds (90 days) |
| `DEFAULT_WARRANT_TTL_SECS` | 300 | Default TTL if not specified (5 minutes) |
| `MAX_WARRANT_SIZE` | 65,536 | Maximum single warrant serialized size (64 KB) |
| `MAX_STACK_SIZE` | 262,144 | Maximum warrant stack/chain size (256 KB) |

**Notes**:
- 16 levels of delegation is sufficient for even complex hierarchies (typical chains are 3-5 levels)
- 90 days is the protocol ceiling; deployments can (and should) configure stricter TTL limits
- Default TTL is intentionally short (5 minutes) - expand only as needed

---

## Configuration

### `configure()`

Initialize Tenuo globally. **Call once at application startup** before using `mint()` or `grant()`.

```python
from tenuo import configure, SigningKey

# Development (self-signed warrants)
kp = SigningKey.generate()  # In production: SigningKey.from_env("MY_KEY")
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
| `issuer_key` | `SigningKey` | None | SigningKey for signing warrants (required for `mint`) |
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

### `auto_configure()`

Automatic configuration from environment variables. **Zero-code setup for 12-factor apps.**

```python
from tenuo import auto_configure

# Reads TENUO_* environment variables automatically
auto_configure()
```

**Environment Variables:**

| Variable | Description | Example |
|----------|-------------|---------|
| `TENUO_ISSUER_KEY` | Base64-encoded signing key | `SGVsbG8...` |
| `TENUO_MODE` | Enforcement mode | `enforce`, `audit`, `permissive` |
| `TENUO_TRUSTED_ROOTS` | Comma-separated public keys | `key1,key2` |
| `TENUO_DEV_MODE` | Enable development mode | `1` or `true` |
| `TENUO_DEFAULT_TTL` | Default warrant TTL (seconds) | `300` |

**Returns:** `None`

**Raises:** `ConfigurationError` if required variables missing.

### `get_config()`

Get the current configuration.

```python
from tenuo import get_config

config = get_config()
print(f"TTL: {config.default_ttl}")
print(f"Dev mode: {config.dev_mode}")
print(f"Mode: {config.mode}")  # EnforcementMode enum
```

### `EnforcementMode`

Enum controlling how authorization violations are handled:

```python
from tenuo import EnforcementMode, is_audit_mode, is_enforce_mode, should_block_violation

# Check current mode
if is_audit_mode():
    print("Violations are logged but not blocked")

if should_block_violation():
    raise AuthorizationDenied(...)
```

| Mode | Behavior | Use Case |
|------|----------|----------|
| `EnforcementMode.ENFORCE` | Block unauthorized requests | Production (default) |
| `EnforcementMode.AUDIT` | Log violations but allow execution | Gradual adoption |
| `EnforcementMode.PERMISSIVE` | Log + warn header, allow execution | Development |

**Helper Functions:**

| Function | Returns |
|----------|---------|
| `is_enforce_mode()` | `True` if mode is ENFORCE |
| `is_audit_mode()` | `True` if mode is AUDIT |
| `is_permissive_mode()` | `True` if mode is PERMISSIVE |
| `should_block_violation()` | `True` if violations should be blocked |

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
| `Warrant.mint_builder()` | Create a fluent builder for new warrants |
| `warrant.grant_builder()` | Create a fluent builder for delegation |

#### `Warrant.mint_builder()` — Creating New Warrants

```python
from tenuo import Warrant, Pattern

# Fluent builder pattern
warrant = (Warrant.mint_builder()
    .capability("read_file", path=Subpath("/data"))
    .holder(worker_key.public_key)
    .ttl(3600)
    .mint(issuer_key))
```

| Method | Description |
|--------|-------------|
| `.tool(name)` | Add tool with no constraints |
| `.capability(tool, **constraints)` | Add tool with constraints |
| `.holder(pubkey)` | Set authorized holder |
| `.ttl(seconds)` | Set time-to-live |
| `.mint(key)` | Sign and create the warrant |

#### `warrant.grant_builder()` — Delegation

```python
# Delegate with narrower scope
child = (parent.grant_builder()
    .capability("read_file", path=Subpath("/data/reports"))
    .holder(worker_key.public_key)
    .ttl(300)
    .grant(parent_key))  # Parent holder signs
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `issuable_tools` | `List[str]` | Tools this warrant can issue |
| `keypair` | `SigningKey` | Issuer's keypair |
| `constraint_bounds` | `dict` | Optional constraint bounds |
| `max_issue_depth` | `int` | Max depth for issued warrants |
| `ttl_seconds` | `int` | Time-to-live in seconds |
| `holder` | `PublicKey` | Optional holder (defaults to issuer) |

#### `Warrant.mint_builder()` - Fluent API

For improved DX, use the fluent builder pattern:

```python
from tenuo import Warrant, Pattern, Range, Clearance

# Execution warrant with builder
warrant = (Warrant.mint_builder()
    .capability("read_file",
        path=Subpath("/data"),
        max_size=Range(max=1000000))
    .ttl(3600)
    .holder(keypair.public_key)
    .mint(keypair))

# Issuer warrant with builder
issuer = (Warrant.mint_builder()
    .issuer()  # Switch to issuer mode
    .issuable_tools(["read_file", "write_file"])
    .clearance(Clearance.INTERNAL)  # Optional
    .constraint_bound("path", Subpath("/data"))
    .max_issue_depth(3)
    .mint(keypair))
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
| `.mint(keypair)` | Sign and mint the warrant |

#### Instance Properties

| Property | Type | Description |
|----------|------|-------------|
| `id` | `str` | Unique warrant ID |
| `tools` | `List[str]` | Authorized tools |
| `depth` | `int` | Delegation depth (0 = root) |
| `session_id` | `str \| None` | Session identifier |
| `holder` | `PublicKey \| None` | Bound holder's public key |
| `ttl_remaining` | `timedelta` | Time remaining until expiration |
| `ttl` | `timedelta` | Alias for `ttl_remaining` |
| `expires_at` | `datetime` | Expiration time as datetime object |
| `is_expired` | `bool` | Whether warrant has expired |
| `is_terminal` | `bool` | Whether warrant cannot delegate further (`depth >= max_depth`) |
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
| `issue()` | `IssuanceBuilder` | Create execution warrant from issuer warrant |
| `delegate(holder, tools=None, **constraints)` | `Warrant` | Convenience method to delegate (requires context) |

| `verify(public_key)` | `bool` | Verify signature against issuer |
| `sign(keypair, tool, args)` | `bytes` | Sign action (Proof-of-Possession) |
| `to_base64()` | `str` | Serialize to base64 |
| `allows(tool, args=None)` | `bool` | Check if action would be allowed (Logic check) |
| `check_constraints(tool, args)` | `str \| None` | Validate constraints (Logic check) |
| `dedup_key(tool, args)` | `str` | Get deterministic cache key |
| `why_denied(tool, **args)` | `WhyDenied` | Get structured denial reason |
| `headers(keypair, tool, args)` | `dict` | Generate HTTP authorization headers |

#### Logic Checks & Debugging Methods

```python
from tenuo import Warrant, WhyDenied, DenyCode

# Logic Check (UX-only, no crypto)
# "Does the warrant allow this?"
if warrant.allows("read_file", args={"path": "/data/report.txt"}):
    print("Allowed by logic")
else:
    print(f"Would be denied")

# Why denied (for debugging)
reason = warrant.why_denied("write_file", path="/etc/passwd")
# WhyDenied(deny_code=DenyCode.TOOL_NOT_ALLOWED, tool='write_file', ...)

if reason.deny_code == DenyCode.TOOL_NOT_ALLOWED:
    print("Tool not in warrant")

# Generate HTTP headers
headers = warrant.headers(keypair, "read_file", {"path": "/data/x.txt"})
# {'X-Tenuo-Warrant': '<base64>', 'X-Tenuo-PoP': '<signature>'}
```

#### HTTP Transport Headers

The SDK uses two headers for warrant transport:

| Header | Content | Format |
|--------|---------|--------|
| `X-Tenuo-Warrant` | Warrant or chain | Base64-encoded CBOR |
| `X-Tenuo-PoP` | Proof-of-Possession | Base64-encoded signature |

**Key point:** The payload is self-describing. A single header can carry:
- **Single warrant** — CBOR map `{id: ..., tools: ...}`
- **Warrant chain** — CBOR array `[parent, ..., leaf]` (WarrantStack)

The gateway auto-detects the format (Warrant vs WarrantStack), so `X-Tenuo-Warrant` works for both. See [Gateway Configuration](./gateway-config.md) for details.

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
builder = parent.grant_builder()
builder.capability("read_file", path=Exact("/data/report.txt"))
builder.holder(worker_key.public_key)
child = builder.grant(parent_key)
# child.tools == ["read_file"] (only!)
```

**Pattern 2: Inherit all, then narrow**

```python
# Start with all parent capabilities, then narrow
builder = parent.grant_builder()
builder.inherit_all()                    # Explicit opt-in
builder.tools(["read_file"])             # Keep only this tool
builder.holder(worker_key.public_key)
child = builder.grant(parent_key)
```

**Pattern 3: Via grant() convenience method**

The `grant()` method is a convenience wrapper that uses the signing key from context:

```python
with key_scope(my_keypair):
    child = parent.grant(
        holder=worker.public_key,
        tools=["read_file"],  # Narrow tools
        path=Exact("/data/q3.pdf"),  # Narrow constraints
    )
```

> **grant() vs grant_builder()**: Both are valid. `grant()` is a convenience method that uses the signing key from `key_scope()` context. `grant_builder()...grant(key)` is the explicit fluent builder that takes the key as an argument. Use `grant()` for simple cases, `grant_builder()` for complex scenarios or when you want `diff()` preview.

**Via Issuer warrant (alternative):**

```python
# Create parent warrant, then delegate with specific tools
parent_warrant = (Warrant.mint_builder()
    .tool("read_file")
    .tool("send_email")
    .holder(control_plane_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

# Delegate to worker with narrower scope
builder = parent_warrant.grant_builder()
builder.tool("read_file")  # Only read, not send_email
builder.holder(worker_key.public_key)
builder.ttl(300)
exec_warrant = builder.grant(control_plane_key)
```

#### Terminal Warrants

A warrant is **terminal** when it cannot delegate further (`depth >= max_depth`).

```python
# Create terminal warrant (cannot be delegated further)
builder = parent.grant_builder()
builder.inherit_all()     # Inherit parent capabilities
builder.terminal()        # Mark as terminal
builder.holder(worker_key.public_key)
terminal = builder.grant(parent_key)

assert terminal.is_terminal()  # True
# terminal.grant_builder().grant(...) will fail
```

---

### BoundWarrant

Warrant bound to a signing key for convenience. **Non-serializable** to prevent accidental key exposure.

```python
from tenuo import Warrant, BoundWarrant

# Create bound warrant
warrant, keypair = Warrant.quick_mint(["read_file"], ttl=300)
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
| `validate(tool, args)` | `ValidationResult` | Full security check (PoP + constraints) |
| `allows(tool, args=None)` | `bool` | Logic check (no PoP) |
| `delegate(holder, tools=None, **constraints)` | `BoundWarrant` | Delegate (uses bound key) |
| `headers(tool, args)` | `dict` | HTTP headers (uses bound key) |
| `unbind()` | `tuple[Warrant, SigningKey]` | Extract warrant and key |
| `why_denied(tool, **args)` | `WhyDenied` | Get denial reason |

```python
# Delegation with bound key (no keypair arg needed)
child = bound.grant(to=worker.public_key, allow="read_file", ttl=300)

# Generate headers
headers = bound.headers("read_file", {"path": "/data/x.txt"})

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

Builder for delegating (granting) from parent warrants.

```python
builder = parent_warrant.grant_builder()
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
builder = warrant.grant_builder()
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
child = (parent.grant_builder()
    .capability("read_file", path=Exact("/data/q3.pdf"))
    .holder(worker_key.public_key)
    .grant(parent_key))

# Pattern 2: Inherit all, then narrow
child = (parent.grant_builder()
    .inherit_all()                    # Explicit opt-in
    .tools(["read_file"])             # Keep only this tool
    .holder(worker_key.public_key)
    .grant(parent_key))

# Reading builder state
assert builder.holder() == worker_key.public_key
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

Constrains numeric values to a range.

> [!WARNING]
> **Precision Limit**: Range uses 64-bit floats. Integers larger than 2^53 (9,007,199,254,740,992) will lose precision. Use strings for Snowflake IDs.

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

> **Note (Rust only):** Requires the `cel` feature: `tenuo = { features = ["cel"] }`

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

## Warrant Templates

Pre-built capability patterns for common AI agent scenarios. Use directly or as starting points.

```python
from tenuo.templates import FileReader, FileWriter, DatabaseReader, WebSearcher, CommonAgents
```

### File Access Templates

```python
from tenuo import mint
from tenuo.templates import FileReader, FileWriter

# Read-only access to a directory
async with mint(FileReader.in_directory("/data/reports")) as w:
    content = read_file("/data/reports/q4.txt")  # ✓ allowed
    content = read_file("/etc/passwd")  # ✗ denied

# Read a specific file only
async with mint(FileReader.exact_file("/config/app.json")) as w:
    content = read_file("/config/app.json")  # ✓ allowed

# Read files with specific extensions
async with mint(FileReader.extensions("/docs", [".md", ".txt"])) as w:
    read_file("/docs/readme.md")  # ✓ allowed
    read_file("/docs/data.json")  # ✗ denied

# Write access (use with caution)
async with mint(FileWriter.in_directory("/tmp/agent-output")) as w:
    write_file("/tmp/agent-output/report.txt", data)  # ✓ allowed
```

### Database Templates

```python
from tenuo.templates import DatabaseReader, DatabaseWriter

# Read from specific tables
async with mint(DatabaseReader.tables(["users", "products"])) as w:
    query("SELECT * FROM users")  # ✓ allowed
    query("SELECT * FROM transactions")  # ✗ denied

# Read with row limit (prevent data exfiltration)
async with mint(DatabaseReader.with_row_limit(["users"], max_rows=10)) as w:
    query("SELECT * FROM users LIMIT 10")  # ✓ allowed

# Full-table access within a schema
async with mint(DatabaseReader.schema("public")) as w:
    query("SELECT * FROM public.users")  # ✓ allowed
```

### Web Access Templates

```python
from tenuo.templates import WebSearcher, ApiClient

# Web search with domain restrictions
async with mint(WebSearcher.domains(["api.openai.com", "*.google.com"])) as w:
    search("openai docs", domain="api.openai.com")  # ✓ allowed

# API client with method restrictions
async with mint(ApiClient.readonly("api.example.com")) as w:
    get("/users")  # ✓ allowed
    post("/users", {...})  # ✗ denied
```

### Agent Templates

```python
from tenuo.templates import CommonAgents

# Research agent: read-only web search + file reading
async with mint(*CommonAgents.research_agent("/data/docs")) as w:
    ...

# Writer agent: file writing to specific directory
async with mint(*CommonAgents.writer_agent("/output")) as w:
    ...

# Analyst agent: database read + search
async with mint(*CommonAgents.analyst_agent(tables=["metrics", "reports"])) as w:
    ...
```

---

## Task Scoping

Context managers for scoping authority to tasks.

### `mint`

Create root authority for a task. **Async version.**

```python
from tenuo import mint, Capability, Subpath

async with mint(Capability("read_file", path=Subpath("/data"))) as warrant:
    result = await agent.invoke(prompt)
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `*capabilities` | `Capability...` | Yes | Capabilities to authorize (tool + constraints) |
| `ttl` | `int` | No | TTL in seconds (default from `configure()`) |
| `holder_key` | `SigningKey` | No | Explicit holder (default: issuer) |

#### Requirements

- Must call `configure(issuer_key=...)` first
- At least one tool required

### `mint_sync`

Synchronous version of `mint`.

```python
from tenuo import mint_sync

with mint_sync(Capability("read_file", path="/data/*")) as warrant:
    result = protected_read_file(path="/data/report.csv")
```

Same parameters as `mint`.

### `grant`

Attenuate within an existing task scope.

```python
from tenuo import grant

async with mint(
    Capability("read_file", path="/data/*"), 
    Capability("write_file", path="/data/*")
):
    async with grant(Capability("read_file", path="/data/reports/*")):
        # Narrower scope here
        result = await agent.invoke(prompt)
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `*capabilities` | `Capability...` | No | Capabilities to allow (must be subset of parent). If omitted, implies all parent capabilities. |
| `ttl` | `int` | No | Shorter TTL (None = inherit remaining) |

#### Requirements

- **Must be called within `mint` or another `grant`**
- Constraints must be monotonically attenuated (tighter than parent)

#### Preview Changes

```python
scope = grant(Capability("read_file", path="/data/reports/*"))
scope.preview().print()  # See diff before entering
async with scope:
    ...
```

---

## Tool Protection

Tenuo provides three APIs for protecting tools. Choose based on your use case:

| Use Case | API | Import | Pattern |
|----------|-----|--------|---------|
| Protect individual functions | `@guard(tool="...")` | `from tenuo import guard` | Decorator on your functions |
| LangChain tools (recommended) | `guard(tools, bound)` | `from tenuo.langchain import guard` | Wraps LangChain tools |
| Batch wrap (context-based) | `guard_tools(tools)` | `from tenuo import guard_tools` | Mutates tools in place |

### Key Differences

**`@guard` (decorator)**
- Use on **your own functions** that you define
- Automatically extracts function arguments for authorization
- Uses context (`warrant_scope`, `key_scope`) for warrant and keypair
- Best for: Custom tools, Flask/FastAPI endpoints, standalone functions

**`guard()` from `tenuo.langchain`**
- Use for **LangChain `BaseTool` instances**
- Takes a `BoundWarrant` (warrant + keypair combined)
- Returns wrapped tools ready for LangChain agents
- Best for: LangChain/LangGraph integrations

**`guard_tools()`**
- Batch wrapper for **multiple tools at once**
- Mutates tools in place by default (`inplace=True`)
- Uses context for warrant/keypair (like `@guard`)
- Best for: Non-LangChain batch protection, custom frameworks

> [!TIP]
> **Quick Decision Tree:**
> - Using LangChain? → `guard()` from `tenuo.langchain`
> - Protecting your own function? → `@guard` decorator
> - Need to wrap many tools at once? → `guard_tools()`

---

### `guard_tools` (Context-Based)

Wrap tools to enforce warrant authorization using context (for non-LangChain use).

> For LangChain integration, use [`guard()`](#guard-recommended) from `tenuo.langchain` instead.

```python
from tenuo import guard_tools
```

#### Signature

```python
guard_tools(
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
from tenuo import guard_tools, mint

# Define your tools
tools = [read_file, send_email, query_db]

# Wrap them (mutates in place by default)
guard_tools(tools)

# Use with scoped authority
async with mint(Capability("read_file", path="/data/*")):
    result = await tools[0](path="/data/report.csv")
```

#### Non-mutating variant

```python
original = [read_file, send_email]
protected = guard_tools(original, inplace=False)
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

### `@guard`

Decorator for function-level authorization with automatic argument extraction.

```python
    from tenuo import guard
```

#### Signature

```python
@guard(
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
| `warrant_or_tool` | `Warrant \| str` | No | Warrant instance OR tool name (positional) |
| `tool` | `str` | Yes* | Tool name (*unless passed as first arg) |
| `keypair` | `SigningKey` | No | Key for PoP (uses context if None) |
| `extract_args` | `Callable` | No | Custom argument extractor function |
| `mapping` | `Dict[str, str]` | No | Rename args after extraction |

#### Argument Extraction

`@guard` automatically extracts all function arguments **including defaults** using Python's `inspect.signature()`:

```python
@guard(tool="query")
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
@guard(
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
@guard(
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
@guard(tool="read_file")
def read_file(path: str) -> str:
    return open(path).read()

# Use with task scoping
async with mint(Capability("read_file", path=Subpath("/data"))):
    read_file("/data/test.txt")
```

**Explicit warrant:**

```python
@guard(warrant, tool="read_file", keypair=agent_key)
def read_file(path: str) -> str:
    return open(path).read()
```

**Tool as first arg:**

```python
@guard("read_file")  # Shorthand: tool name as positional arg
def read_file(path: str) -> str:
    return open(path).read()
```

### Context Functions

```python
from tenuo import (
    warrant_scope,
    get_warrant_context,
    key_scope,
    get_signing_key_context,
)
```

| Function | Returns | Description |
|----------|---------|-------------|
| `warrant_scope(warrant)` | Context manager | Set warrant in async-safe context |
| `key_scope(keypair)` | Context manager | Set keypair in async-safe context |
| `get_warrant_context()` | `Warrant \| None` | Get current warrant |
| `get_signing_key_context()` | `SigningKey \| None` | Get current keypair |

> **Important**: Context is a **convenience layer** for tool protection within a single process. For distributed systems, serialized state, or checkpointing, warrants must travel in request state (e.g., `tenuo_warrant` field). Context does not survive serialization boundaries.

---

## LangChain Integration

See [LangChain Integration Guide](./langchain) for full documentation.

### `guard()` (Recommended)

Unified API for protecting LangChain tools:

```python
from tenuo import SigningKey, Warrant
from tenuo.langchain import guard

# Create warrant and bind key
keypair = SigningKey.generate()  # In production: SigningKey.from_env("MY_KEY")
warrant = Warrant.mint_builder().tool("search").tool("calculator").mint(keypair)
bound = warrant.bind(keypair)

# Protect tools
protected_tools = guard([search, calculator], bound)

# Use in your agent
agent = create_openai_tools_agent(llm, protected_tools, prompt)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tools` | `List[Any]` | *required* | LangChain `BaseTool` or callable |
| `bound` | `BoundWarrant` | `None` | Bound warrant (positional, or use context) |
| `strict` | `bool` | `False` | Require constraints on critical tools |
| `config` | `LangChainConfig` | `None` | Per-tool constraints |

**Returns:** `List[TenuoTool]` for `BaseTool` inputs, `List[Callable]` for callables.

### `guard_tools()` 

Wraps multiple tools with Tenuo authorization. See above for full signature.


---

## LangGraph Integration

See [LangGraph Integration Guide](./langgraph) for full documentation.

### Two-Layer Model

| Layer | Decorator | Purpose |
|-------|-----------|---------|
| **Scoping** | `@tenuo_node` | Narrows what's allowed in this node |
| **Enforcement** | `@guard` | Checks warrant at tool invocation |

**Both layers are required for security.**

### `@tenuo_node`

Scope authority for a LangGraph node.

```python
from tenuo.langgraph import tenuo_node
from tenuo import Capability, Pattern

@tenuo_node
async def researcher(state, bound_warrant):
    # bound_warrant is injected automatically
    if bound_warrant.allows("search"):
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
from tenuo import mint_sync

# Before (manual protection):
# tools = [search, calculator]
# protected = protect_langchain_tools(tools)
# tool_node = ToolNode(protected)

# After (automatic protection):
tool_node = TenuoToolNode([search, calculator])

graph.add_node("tools", tool_node)

# Run with authorization
with mint_sync(Capability("search"), Capability("calculator")):
    result = graph.invoke(...)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tools` | `List[BaseTool]` | *required* | LangChain tools to protect |
| `strict` | `bool` | `False` | Require constraints for high-risk tools |
| `**kwargs` | `Any` | — | Additional arguments passed to ToolNode |
 
### `KeyRegistry`

Thread-safe singleton for managing multiple signing keys by ID. Useful for multi-agent, multi-tenant, and service-to-service scenarios.

```python
from tenuo import KeyRegistry, SigningKey

registry = KeyRegistry.get_instance()

# Register keys
registry.register("worker", SigningKey.from_env("WORKER_KEY"))
registry.register("orchestrator", SigningKey.from_env("ORCH_KEY"))

# Retrieve
key = registry.get("worker")

# Multi-tenant: namespace keys per tenant
registry.register("api", tenant_key, namespace="tenant-123")
key = registry.get("api", namespace="tenant-123")
```

**Methods:**

| Method | Description |
|--------|-------------|
| `get_instance()` | Get the singleton (class method) |
| `register(key_id, key, namespace="default")` | Register a key |
| `get(key_id, namespace="default")` | Retrieve a key (raises `KeyError` if missing) |
| `reset_instance()` | Clear the singleton (for testing) |

**Use cases:**
- **LangGraph**: Keep keys out of state (checkpointing-safe)
- **Multi-tenant**: Isolate keys per tenant via namespace
- **Service mesh**: Different keys per downstream service
- **Key rotation**: Register `current` and `previous` keys

> **LangGraph integration**: `TenuoToolNode` and `guard()` automatically look up keys from the registry using `config["configurable"]["tenuo_key_id"]`.

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
from tenuo.testing import (
    allow_all,
    assert_authorized,
    assert_denied,
    assert_can_grant,
    assert_cannot_grant,
    deterministic_headers,
)
```

### `allow_all()`

Context manager that bypasses all `@guard` authorization checks. **Only works in test environments.**

```python
from tenuo import guard
from tenuo.testing import allow_all

@guard(tool="dangerous_action")
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

### `assert_authorized()` / `assert_denied()`

Assert authorization outcomes with detailed error messages.

```python
from tenuo import guard
from tenuo.testing import assert_authorized, assert_denied

@guard(tool="read_file")
def read_file(path: str):
    return f"Content of {path}"

def test_authorization():
    # Assert code succeeds
    with assert_authorized():
        read_file("/data/report.txt")
    
    # Assert code is denied (with optional code/reason check)
    with assert_denied(code="ConstraintViolation"):
        read_file("/etc/passwd")
    
    # Assert with custom message
    with assert_denied(message="Should block access to system files"):
        read_file("/etc/shadow")
```

**Parameters for `assert_denied`:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `code` | `str` | Expected error code (e.g., `"ConstraintViolation"`) |
| `expected_reason` | `str` | Substring expected in error message |
| `message` | `str` | Custom assertion failure message |

### `assert_can_grant()` / `assert_cannot_grant()`

Assert delegation (attenuation) rules are enforced correctly.

```python
from tenuo import Warrant
from tenuo.testing import assert_can_grant, assert_cannot_grant

def test_delegation_chain():
    # Create a root warrant
    root, root_key = Warrant.quick_mint(["search", "read_file"], ttl=3600)
    
    # Assert we CAN grant a subset of tools
    child, child_key = assert_can_grant(
        root, root_key,
        child_tools=["read_file"],  # Subset of parent
    )
    
    # Assert we CANNOT grant tools not in parent
    assert_cannot_grant(
        root, root_key,
        child_tools=["delete_file"],  # Not in parent!
        expected_reason="ToolNotAuthorized",
    )
```

### `Warrant.quick_mint()`

Quickly create a warrant with auto-generated keys (for development/testing).

```python
from tenuo import Warrant

# Returns (warrant, signing_key)
warrant, key = Warrant.quick_mint(["read_file", "search"], ttl=300)

# Use the warrant
bound = warrant.bind(key)
headers = bound.headers("search", {"query": "test"})
```

### `Warrant.for_testing()`

Create test warrants without key management. **Only works in test environments.**

```python
from tenuo import Warrant

def test_my_function():
    warrant = Warrant.for_testing(["read_file", "write_file"])
    # Use for testing without real key management
```

### `deterministic_headers()`

Generate deterministic HTTP headers for snapshot testing.

```python
from tenuo.testing import deterministic_headers

headers = deterministic_headers(warrant, key, "read_file", {"path": "/data/x"})
# Headers are deterministic for the same inputs
```

---

## CLI

Command-line tools for Tenuo operations.

### `tenuo discover`

Analyze audit logs and generate capability definitions. **Essential for gradual adoption.**

```bash
# Analyze logs and generate YAML capabilities
tenuo discover --input audit.log --output capabilities.yaml

# Generate Python code instead
tenuo discover --input audit.log --format python
```

**How it works:**

1. Deploy your app with `mode="audit"` (logs tool calls but doesn't block)
2. Run the app normally for a period
3. Use `discover` to analyze logs and generate minimal capabilities
4. Review and refine the generated capabilities
5. Switch to `mode="enforce"`

**Example Output (YAML):**

```yaml
capabilities:
  search:
    query: Pattern("*")
  read_file:
    path: OneOf(["/data/reports/*", "/data/docs/*"])
  query:
    table: OneOf(["users", "products"])
    operation: Exact("SELECT")
```

**Example Output (Python):**

```python
from tenuo import Capability, Pattern, OneOf, Exact

capabilities = [
    Capability("search", query=Pattern("*")),
    Capability("read_file", path=OneOf(["/data/reports/*", "/data/docs/*"])),
    Capability("query", table=OneOf(["users", "products"]), operation=Exact("SELECT")),
]
```

### `tenuo decode`

Decode and inspect a warrant (warrants contain no secrets, safe to share).

```bash
tenuo decode eyJ3YXJyYW50IjoiLi4uIn0=

# Output:
# Warrant ID: wrt_abc123
# Issuer: pk_xyz...
# Holder: pk_abc...
# Tools: ["search", "read_file"]
# TTL: 3600s (59m remaining)
# Constraints:
#   read_file.path: Pattern("/data/*")
```

### `tenuo validate`

Validate a warrant against specific tool and arguments.

```bash
tenuo validate --warrant eyJ3... --tool read_file --args '{"path": "/data/report.txt"}'

# Output:
# ✅ Authorization would succeed
#   Tool: read_file
#   Path: /data/report.txt matches Pattern("/data/*")

tenuo validate --warrant eyJ3... --tool read_file --args '{"path": "/etc/passwd"}'

# Output:
# ❌ Authorization would fail
#   Tool: read_file
#   Path: /etc/passwd does NOT match Pattern("/data/*")
```

---

## Exceptions

```python
from tenuo import TenuoError, ScopeViolation, WarrantViolation
```

### Exception Hierarchy

```
TenuoError (base)
├── ScopeViolation        # Authorization failed (formerly AuthorizationError)
├── WarrantViolation      # Warrant creation/validation failed (formerly WarrantError)
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
    def headers(self, tool: str, args: dict) -> dict: ...
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
