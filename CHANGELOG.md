# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.9] - 2025-12-23

### Summary

Capability tokens for AI agents. Issue scoped, time-limited warrants that delegate authority through a chain of custody with cryptographic enforcement.

### Core

- **Warrant API**: Issue, attenuate, authorize, delegate
- **Proof-of-Possession (PoP)**: Cryptographic holder binding
- **Monotonic Attenuation**: Authority can only shrink through delegation
- **~27μs Verification**: Offline, no network calls required
- **Constraint Types**: Pattern, Exact, Range, OneOf, Regex, CIDR, URL, Contains, Subset, All, Any

### Python SDK

- **BoundWarrant**: Convenient key binding for repeated operations
- **Key Management**: `SigningKey.from_env()`, `SigningKey.from_file()`, `Keyring`, `KeyRegistry`
- **Debugging**: `why_denied()`, `diagnose()`, `ttl`, `capabilities`

### Framework Integrations

- **LangChain**: `guard()` for tool authorization
- **LangGraph**: `TenuoToolNode` drop-in replacement, `load_tenuo_keys()`
- **FastAPI**: `TenuoGuard` dependency injection, `SecurityContext`
- **MCP**: `SecureMCPClient` for tool discovery

### Developer Experience

- Interactive Explorer at [tenuo.dev/explorer](https://tenuo.dev/explorer)
- Comprehensive documentation at [tenuo.dev](https://tenuo.dev)
- Jupyter notebooks for quick start

---

*Prior alpha releases (0.1.0-alpha.1 through 0.1.0-alpha.8) established the foundation. Full development history preserved in `history-backup-alpha` branch.*
