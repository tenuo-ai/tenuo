# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.8] - 2025-12-22

### ⚠️ Breaking Changes

- **LangGraph API**: Removed legacy `key_id` in state pattern. Key IDs must now be passed via config:
  ```python
  # Before (alpha.7)
  state = {"warrant": warrant, "key_id": "worker"}
  
  # After (alpha.8) 
  state = {"warrant": warrant}
  config = {"configurable": {"tenuo_key_id": "worker"}}
  graph.invoke(state, config=config)
  ```

- **LangChain API**: Unified `protect_tools()` and `protect_langchain_tools()` into single `protect()` function:
  ```python
  # Before (alpha.7)
  from tenuo.langchain import protect_tools, protect_langchain_tools
  
  # After (alpha.8)
  from tenuo.langchain import protect
  protected = protect(tools, bound_warrant=bw)
  ```

### Added

- **`BoundWarrant`**: Convenience wrapper for `Warrant` + `SigningKey` for repeated operations
  ```python
  bound = warrant.bind_key(key)
  bound.auth_headers("tool", args)  # No need to pass key each time
  bound.authorize("tool", args)     # Automatic PoP signing
  ```

- **Key Management**:
  - `SigningKey.from_env(name)` - Load key from environment variable (auto-detects base64/hex)
  - `SigningKey.from_file(path)` - Load key from file
  - `Keyring` - Manage root key + previous keys for rotation
  - `KeyRegistry` - Thread-safe singleton for multi-agent key access

- **LangGraph Integration**:
  - `auto_load_keys()` - Load all `TENUO_KEY_*` environment variables automatically
  - `secure(node, key_id=...)` - Wrap pure nodes with authorization
  - `TenuoToolNode` - Drop-in replacement for LangGraph's ToolNode with authorization

- **FastAPI Integration**:
  - `TenuoGuard(tool)` - Dependency for route protection
  - `SecurityContext` - Returns verified warrant and extracted args
  - `configure_tenuo(app, ...)` - App-level configuration

- **Debugging**:
  - `why_denied(tool, args)` - Structured explanation of authorization failures
  - `diagnose(warrant)` - Full warrant inspection
  - `warrant.ttl` - Alias for `ttl_remaining`
  - `warrant.capabilities` - Human-readable constraint dict

- **Security**:
  - `BoundWarrant` uses `__slots__` to prevent `__dict__`/`vars()` access to private key
  - Opaque error messages by default (detailed info logged, not exposed to clients)
  - `expose_error_details=False` config option to control error verbosity

### Changed

- Warrant convenience properties (`ttl_remaining`, `is_expired`, `is_terminal`) now consistently exposed
- `preview_would_allow()` docstring includes security warning about PoP
- Error responses include `request_id` for log correlation
- Documentation comprehensively updated for new patterns

### Security

- **Error Leakage Prevention**: Authorization errors no longer reveal constraint details to clients by default. Detailed info is logged server-side with `request_id` for correlation.
- **BoundWarrant Protection**: `__slots__` prevents accidental exposure of private key via introspection.

---

## [0.1.0-alpha.7] - 2025-12-22

### ⚠️ Breaking Changes

- **Renamed `TrustLevel` → `Clearance`**: The `TrustLevel` type has been renamed to `Clearance` throughout the codebase for clearer terminology.
  
  ```python
  # Before (alpha.6)
  from tenuo import TrustLevel
  warrant.trust_level = TrustLevel.Internal
  
  # After (alpha.7)
  from tenuo import Clearance
  warrant.clearance = Clearance.INTERNAL
  ```

- **Removed `trust_ceiling`**: The `trust_ceiling` field has been removed from issuer warrants. Clearance monotonicity is now enforced using the issuer's own `clearance` instead.
  
  ```python
  # Before (alpha.6)
  Warrant.issue_issuer(
      issuable_tools=["read_file"],
      trust_ceiling=TrustLevel.Internal,  # Removed
      keypair=kp,
  )
  
  # After (alpha.7)
  Warrant.issue_issuer(
      issuable_tools=["read_file"],
      keypair=kp,
      clearance=Clearance.INTERNAL,  # Optional, uses monotonicity
  )
  ```

- **CLI**: `--trust-level` renamed to `--clearance`
- **Python API**: `warrant.trust_level` → `warrant.clearance`
- **Rust API**: `WarrantBuilder::trust_ceiling()` method removed
- **Wire Format**: Field 12 (`trust_ceiling`) removed, Field 17 renamed from `trust_level` to `clearance`

### Added

- **`Clearance.custom(level)`**: Create organization-specific clearance levels (0-255)
- **`Clearance.level`** property: Get the raw numeric value
- **`Clearance.meets(required)`** method: Readable check if clearance meets requirement
  
  ```python
  # Organization-specific levels
  CONTRACTOR = Clearance.custom(15)  # Between External (10) and Partner (20)
  
  # Readable checks
  if warrant.clearance.meets(Clearance.INTERNAL):
      # clearance is INTERNAL or higher
  ```

### Changed

- Clearance enforcement now uses standard monotonicity (child cannot exceed parent's clearance)
- Simplified documentation to de-emphasize clearance levels as a secondary feature

---

## [0.1.0-alpha.6] - 2025-12-19

### Added

- **Tool Trust Requirements**: Gateway-level policy overlay for defense in depth
  ```python
  authorizer = Authorizer(trusted_roots=[root_key])
  authorizer.require_trust("admin_*", TrustLevel.System)
  authorizer.require_trust("delete_*", TrustLevel.Privileged)
  authorizer.require_trust("*", TrustLevel.External)  # Default
  ```
  - `require_trust(pattern, level)` on `Authorizer` and `DataPlane`
  - `get_required_trust(tool)` to check requirements
  - Pattern validation (rejects invalid patterns like `**`, `*admin*`)
  - Exact match → Glob pattern → Default `*` precedence

- **Trust Level Monotonicity**: Execution→Execution attenuation now enforces that child `trust_level` cannot exceed parent's trust level (cryptographically enforced)

- **InsufficientTrustLevel Error**: New error variant when warrant's trust level is below tool's required level

- `trust_levels_demo.py` - Comprehensive example showing trust level enforcement

### Changed

- `ai-agents.md` - Simplified with honest trust level framing, added CaMeL paper reference
- `Warrant` now exposes `trust_level` setter on `AttenuationBuilder`
- Cross-linked documentation (ai-agents, quickstart, constraints, security)

### Documentation

- Added "Offline Verification" to security guarantees
- Clarified trust levels are an optional safety net, not a security boundary
- Added CaMeL framework reference (Google DeepMind)

---

## [0.1.0-alpha.5] - 2025-12-20

### ⚠️ Breaking Changes

- **Principle of Least Authority (POLA)**: `attenuate()` now creates a child warrant with NO capabilities by default. You must explicitly specify capabilities using `capability()` or opt-in to full inheritance with `inherit_all()`.

  ```python
  # Before (alpha.3) - implicit inheritance, recipient signed
  child = parent.attenuate().with_ttl(300).delegate_to(child_kp, parent_kp)

  # After (alpha.5) - explicit inheritance, parent holder signs
  child = parent.attenuate().inherit_all().ttl(300).delegate(parent_kp)
  
  # Or specify only needed capabilities (recommended)
  child = (parent.attenuate()
      .capability("read_file", {"path": Pattern("/data/*")})
      .holder(worker_kp.public_key)
      .delegate(parent_kp))  # parent_kp signs (they hold the parent warrant)
  ```

- **Delegation API**: Renamed `delegate_to(child_kp, parent_kp)` to `delegate(parent_kp)` to clarify that the parent's holder signs the child warrant (standard delegation model). This enforces `child.issuer == parent.holder` (Invariant I1).

- **AttenuationBuilder API**: Unified method naming (removed `with_` prefix for consistency with `WarrantBuilder`):
  - `.with_capability()` → `.capability()`
  - `.with_holder()` → `.holder()`
  - `.with_ttl()` → `.ttl()`
  - `.with_tools()` → `.tools()`
  - `.with_intent()` → `.intent()`
  - All methods are dual-purpose: call with arg to set, call without to get current value
  - Old `with_*` methods kept as aliases for backward compatibility

- **Wire format**: Removed `issuer_chain` field from warrant payload. Chain verification now uses `WarrantStack` (ordered array of warrants) with `parent_hash` linking.

### Added

- `inherit_all()` method on `AttenuationBuilder` - explicit opt-in to inherit all parent capabilities
- `test_pola.py` - comprehensive test suite for POLA behavior
- `docs/_internal/thi-spec.md` - Tenuo Host Interface specification for stateful extensions
- Wire format compliance tests
- Dual-purpose getter/setter methods on `AttenuationBuilder`

### Changed

- Documentation now prioritizes Simple API (`root_task`, `scoped_task`, `protect_tools`) over low-level API
- Updated quickstart, README, and landing page with clearer examples
- Internal wire format aligned with `docs/wire-format-spec.md`
- `AttenuationBuilder` API unified with `WarrantBuilder` (no `with_` prefix)

### Security

- POLA ensures attenuated warrants cannot accidentally inherit excessive permissions
- Explicit capability granting reduces attack surface from implicit inheritance

## [0.1.0-alpha.3] - 2025-12-XX

- Initial public alpha release
- Fluent builder API for warrants
- Constraint types: Pattern, Exact, Range, OneOf, Regex, CIDR, URL
- LangChain and LangGraph integrations
- MCP client support
- ~27μs offline verification
