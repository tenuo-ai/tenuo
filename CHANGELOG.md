# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### OpenAI Integration
- **Direct API wrapping**: `guard()` function wraps `openai.OpenAI()` client with guardrails
- **GuardBuilder fluent API**: `.allow()`, `.deny()`, `.constrain()` for clean constraint definition
- **Two-tier protection**: Tier 1 (runtime guardrails) and Tier 2 (warrant + PoP)
- **Streaming TOCTOU protection**: Buffer-verify-emit pattern prevents timing attacks
- **Responses API support**: `client.responses.create()` with guardrails
- **OpenAI Agents SDK integration**: `create_tool_guardrail()`, `create_warrant_guardrail()`
- **Tool schema validation**: Warns on typos in constraint parameter names

#### New Constraints
- **Subpath constraint**: Secure path containment that blocks `..` traversal attacks (normalizes paths lexically, blocks null bytes, requires absolute paths)
- **UrlSafe constraint**: SSRF protection that blocks dangerous URLs by default (private IPs, loopback, cloud metadata, IP encoding bypasses)
- **Shlex constraint**: Shell injection protection that validates command strings (blocks operators, substitution, expansion; requires binary allowlist)
- **Audit logging**: `AuditEvent` with session_id, constraint_hash, warrant_id
- **Debug mode**: `enable_debug()` for verbose logging
- **Pre-flight validation**: `client.validate()` catches misconfigurations early

### Security

- **Fail-closed on malformed JSON**: Agents SDK guardrail now raises `MalformedToolCall` instead of silently defaulting to `{}`
- **Skip/log mode filtering**: Responses API now filters denied function_calls from output (matching Chat Completions behavior)

---

## [0.1.0-beta.4] - 2026-01-05

### Added

#### Cryptographic Benchmark Suite
- **37 security tests** validating forgery resistance, delegation monotonicity, key separation, multi-sig enforcement, and temporal constraints
- Comprehensive report generation with `python -m benchmarks.cryptographic.report`

#### AgentDojo Integration
- Full prompt injection benchmark with Tenuo constraint enforcement
- **CEL constraints** for list validation (`value.all(r, r.endsWith('@company.com'))`)
- **JIT warrant mode** (`--jit`) for task-specific constraint policies
- Task-aware policy selection via `task_policies.py`

#### Enhanced Diagnostics
- `check_constraints_detailed()` returns structured `(field, reason)` tuples
- Robust field extraction in `why_denied()` (no more regex parsing)

### Security

- **Issuer trust verification**: `Authorizer` now verifies warrant issuer is in `trusted_roots` before any other checks
- **Path injection hardening**: FastAPI example uses `os.path.normpath` with traversal check
- **Workflow permissions**: Explicit `permissions:` blocks in GitHub Actions workflows
- **Log redaction**: Key material redacted from demo binary logs

### Improved

- CEL feature now enabled by default in Python SDK
- Better exception handling with `FeatureNotEnabled` error type
- Featured in [Awesome Object Capabilities](https://github.com/dckc/awesome-ocap)

---

## [0.1.0-beta.3] - 2026-01-03

### Added

#### Approval Security Hardening
- **Domain separation**: Approval signatures now include `tenuo-approval-v1` context prefix, preventing cross-protocol signature reuse attacks
- **Nonce for replay protection**: Each approval includes a 128-bit random nonce for cryptographic uniqueness
- **Stateless by design**: Nonces are not tracked server-side (intentional); applications can opt into tracking if needed

#### Documentation
- New "Stateless Design & Replay Protection" section in approval module docs
- Documented 6 layers of replay protection

---

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
