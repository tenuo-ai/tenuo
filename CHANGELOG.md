# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.8] - 2025-12-22

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

- **LangChain Integration**:
  - `protect(tools, bound_warrant=...)` - Unified tool protection function

- **Debugging**:
  - `why_denied(tool, args)` - Structured explanation of authorization failures
  - `diagnose(warrant)` - Full warrant inspection
  - `warrant.ttl` - Alias for `ttl_remaining`
  - `warrant.capabilities` - Human-readable constraint dict

- **Security**:
  - `BoundWarrant` uses `__slots__` to prevent `__dict__`/`vars()` access to private key
  - Opaque error messages by default (detailed info logged, not exposed to clients)

- **Clearance Levels**:
  - `Clearance.custom(level)` - Create organization-specific clearance levels (0-255)
  - `Clearance.meets(required)` - Readable check if clearance meets requirement

- **Constraint Types**: Pattern, Exact, Range, OneOf, Regex, CIDR, URL, Contains, Subset, All, Any

- **POLA (Principle of Least Authority)**: `attenuate()` creates a child warrant with NO capabilities by default - explicit is better than implicit

### Changed

- Warrant convenience properties (`ttl_remaining`, `is_expired`, `is_terminal`) consistently exposed
- Error responses include `request_id` for log correlation
- Documentation comprehensively updated

---

## [0.1.0-alpha.3] - 2025-12-15

### Added

- Initial public alpha release
- Fluent builder API for warrants
- LangChain and LangGraph integrations
- MCP client support
- ~27μs offline verification
