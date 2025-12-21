# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### ⚠️ Breaking Changes

- **Removed `trust_ceiling`**: The `trust_ceiling` field has been removed from issuer warrants. Trust level monotonicity is now enforced using the issuer's own `trust_level` instead. This simplifies the API and aligns with the capability-based security model.
  
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
      trust_level=TrustLevel.Internal,  # Optional, uses monotonicity
  )
  ```

- **Python API**: `Warrant.issue_issuer()` no longer requires `trust_ceiling` parameter
- **Rust API**: `WarrantBuilder::trust_ceiling()` method removed
- **Wire Format**: Field 12 (`trust_ceiling`) is now reserved and ignored on read

### Changed

- Trust level enforcement now uses standard monotonicity (child cannot exceed parent's trust level)
- Simplified documentation to de-emphasize trust levels as a core concept

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
