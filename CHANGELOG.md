# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.7] - 2026-01-18

### Core & Protocol
- **Approval Envelope**: Refactored `Approval` to use the `SignedApproval` envelope pattern (separating `ApprovalPayload` from signature), aligning with the v1.0 spec and matching the Warrant architecture.
- **Protocol Parity**: Synchronized `tenuo-core` with v1.0 spec, updating `WarrantType` serialization to integers (CBOR) and reconciling all test vectors.
- **Test Vectors**: Updated `docs/spec/test-vectors.md` and fixed vectors A.12/A.13 to match the canonical generator output.

### Infrastructure
- **Unified `uv` Toolchain**: Migrated all Python dependency management to `uv` for consistent, fast, and reliable builds.
- **CI Stability**: Fixed "No virtual environment" errors in GitHub Actions by using `--system` flag with `uv pip install`.

### Documentation
- **AgentQL Integration**: Added AgentQL integration examples.
- **Example consistency**: Standardized all `pip install` instructions in examples and notebooks to use `uv pip install`.

---

## [0.1.0-beta.6] - 2026-01-15

### Added

#### A2A Integration (`tenuo[a2a]`)
- **A2AServer**: ASGI server for receiving warrant-authorized tasks from other agents
- **A2AClient**: Client for delegating tasks to remote agents with warrant-based authorization
- **Streaming support**: Server-Sent Events (SSE) for real-time task updates with `send_task_streaming()`
- **Stream timeout**: Configurable timeout (default 5 min) prevents slow-drip DoS attacks
- **Replay protection**: In-memory cache with amortized cleanup (every 1000 requests)
- **Chain validation**: Verifies delegation chains with monotonic constraint narrowing
- **Skill constraints**: `@server.skill("name", constraints={"arg": Subpath})` binds warrant constraints to function parameters
- **Agent discovery**: `/.well-known/agent.json` endpoint with `x-tenuo` extension
- **Key pinning**: `A2AClient(url, pin_key="z6Mk...")` prevents TOFU attacks
- **Comprehensive error types**: `MissingWarrantError`, `UntrustedIssuerError`, `SkillNotGrantedError`, etc.

#### Google ADK Integration (`tenuo.google_adk`)
- **TenuoGuard**: Core class for tool authorization in ADK agents
- **TenuoPlugin**: Plugin-based integration for `InMemoryRunner`
- **GuardBuilder**: Fluent API for constraint definition (`.allow()`, `.with_warrant()`, `.map_skill()`)
- **Two-tier protection**: Tier 1 (inline constraints) and Tier 2 (warrant + PoP)
- **Tool filtering**: `guard.filter_tools()` removes unauthorized tools before agent creation
- **ScopedWarrant**: Prevents cross-agent warrant leaks in multi-agent sessions
- **Decorators**: `@guard_tool(path=Subpath("/data"))` for static constraint definition
- **Denial handling**: Configurable `on_denial` ("raise", "return", "skip")
- **Audit callbacks**: Track all authorization decisions

#### Core Improvements
- **Unified `satisfies()` method**: All constraints now expose `constraint.satisfies(value)` in Python bindings
- **Explicit `Range` coercion**: String-encoded numbers are coerced to float for Range constraints
- **Better type annotations**: Fixed mypy errors across google_adk, a2a, fastapi modules

### Security

- **Adversarial test suite**: 15+ tests for A2A security (chain splicing, issuer impersonation, PoP bypass, replay attacks, DoS)
- **Fail-closed constraint checking**: Unknown constraint types are rejected, not ignored
- **Wire-level authorization**: A2A server uses `warrant.authorize()` (Rust core) for all skill execution

### Changed

- **warrant_key default**: Google ADK now uses `"__tenuo_warrant__"` (was `"tenuo_warrant"`)
- **Removed dead code**: `denial_template` and `expiry_policy` parameters removed from TenuoGuard

### Documentation

- Updated `docs/a2a.md` with stream timeout documentation
- Updated `docs/google-adk.md` with Tier 1/Tier 2 examples
- Removed outdated internal specs (`google-adk-integration-spec-v4.md`, `tenuo-a2a.md`)
- Renamed `tenuo-llm.txt` → `llms.txt` (follows llmstxt.org convention)

---

## [0.1.0-beta.5] - 2026-01-10

### Added

#### OpenAI Integration
- **Direct API wrapping**: `guard()` function wraps `openai.OpenAI()` client with guardrails
- **GuardBuilder fluent API**: `.allow()`, `.deny()`, `.constrain()` for clean constraint definition
- **Two-tier protection**: Tier 1 (runtime guardrails) and Tier 2 (warrant + PoP)
- **Streaming TOCTOU protection**: Buffer-verify-emit pattern prevents timing attacks
- **Responses API support**: `client.responses.create()` with guardrails
- **OpenAI Agents SDK integration**: `create_tier1_guardrail()`, `create_tier2_guardrail()`
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

- Interactive Explorer at [tenuo.ai/explorer](https://tenuo.ai/explorer/)
- Comprehensive documentation at [tenuo.ai](https://tenuo.ai)
- Jupyter notebooks for quick start

---

*This is the first public release.*
