# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.2] - 2026-01-01

### Added

#### Zero-Trust Constraints (Trust Cliff)
- When **any** constraint is defined on a capability, unknown fields are now **rejected by default**
- Use `Wildcard()` or `Any()` to explicitly allow specific fields
- Use `_allow_unknown=True` to opt out entirely
- `_allow_unknown` is NOT inherited during attenuation (security by design)

#### Multi-Signature Approval
- New `Approval` class for cryptographic multi-sig workflows
- `Authorizer.authorize()` now accepts a list of approvals
- `compute_approval_hash()` for creating approval request hashes
- Full CBOR/JSON serialization support for approvals

#### Enhanced Authorization Diagnostics
- `check_constraints()` for constraint validation without PoP
- Enhanced `why_denied()` with zero-trust hints and suggestions
- Exported advanced constraint types: `AnyOf`, `All`, `Not`, `Cidr`, `UrlPattern`, `Regex`, `CEL`

#### New Demos
- **JIT Warrant Demo**: Just-in-time capability proposal with human approval, orchestrator-worker delegation
- **Local LLM Demo**: Prompt injection defense with local LLMs
- **Trust Cliff Demo**: Interactive demonstration of zero-trust behavior

### Changed

- CI now tests Python 3.9-3.14 across Linux (x86_64, ARM64), macOS (ARM64), and Windows (x86_64)

### Fixed

- URL domain checking now uses proper `urlparse` instead of substring matching (security fix)
- Fixed `Any` vs `AnyOf` naming conflict in documentation

---

## [0.1.0-beta.1] - 2025-12-27

### Initial Release

Capability tokens for AI agents. Issue scoped, time-limited warrants that delegate authority through a chain of custody with cryptographic enforcement.

#### Core

- **Warrant API**: Issue, attenuate, authorize, delegate
- **Proof-of-Possession (PoP)**: Cryptographic holder binding
- **Monotonic Attenuation**: Authority can only shrink through delegation
- **~27μs Verification**: Offline, no network calls required
- **Constraint Types**: Pattern, Exact, Range, OneOf, Regex, CIDR, UrlPattern, Contains, Subset, All, Any, CEL

#### Python SDK

- **BoundWarrant**: Convenient key binding for repeated operations
- **Key Management**: `SigningKey.from_env()`, `SigningKey.from_file()`, `Keyring`, `KeyRegistry`
- **Debugging**: `why_denied()`, `diagnose()`, `ttl`, `capabilities`

#### Framework Integrations

- **LangChain**: `guard()` for tool authorization
- **LangGraph**: `TenuoToolNode` drop-in replacement, `load_tenuo_keys()`
- **FastAPI**: `TenuoGuard` dependency injection, `SecurityContext`
- **MCP**: `SecureMCPClient` for tool discovery

#### Developer Experience

- Interactive Explorer at [tenuo.dev/explorer](https://tenuo.dev/explorer/)
- Comprehensive documentation at [tenuo.dev](https://tenuo.dev)
- Jupyter notebooks for quick start

---

*This is the first public release.*
