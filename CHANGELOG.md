# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.4] - 2025-12-19

### ⚠️ Breaking Changes

- **Principle of Least Authority (POLA)**: `attenuate()` now creates a child warrant with NO capabilities by default. You must explicitly specify capabilities using `with_capability()` or opt-in to full inheritance with `inherit_all()`.

  ```python
  # Before (alpha.3) - implicit inheritance
  child = parent.attenuate().with_ttl(300).delegate_to(kp, kp)

  # After (alpha.4) - explicit inheritance required
  child = parent.attenuate().inherit_all().with_ttl(300).delegate_to(kp, kp)
  
  # Or specify only needed capabilities (recommended)
  child = (parent.attenuate()
      .with_capability("read_file", {"path": Pattern("/data/*")})
      .delegate_to(kp, kp))
  ```

- **Wire format**: Removed `issuer_chain` field from warrant payload. Chain verification now uses `WarrantStack` (ordered array of warrants) with `parent_hash` linking.

### Added

- `inherit_all()` method on `AttenuationBuilder` - explicit opt-in to inherit all parent capabilities
- `test_pola.py` - comprehensive test suite for POLA behavior
- `docs/_internal/thi-spec.md` - Tenuo Host Interface specification for stateful extensions
- Wire format compliance tests

### Changed

- Documentation now prioritizes Simple API (`root_task`, `scoped_task`, `protect_tools`) over low-level API
- Updated quickstart, README, and landing page with clearer examples
- Internal wire format aligned with `docs/wire-format-spec.md`

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
