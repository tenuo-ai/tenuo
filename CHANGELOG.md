# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.10] - 2026-02-20

### Added
- **ApprovalPolicy**: Human-in-the-loop authorization for sensitive tool calls
- **Transparent PoP in Temporal**: Outbound workflow interceptor computes Proof-of-Possession automatically for `workflow.execute_activity()` — no wrapper needed
- **`activity_fns` config**: `TenuoInterceptorConfig` accepts activity functions for parameter name resolution in transparent PoP
- **`x-tenuo-arg-keys` header**: Ensures outbound/inbound PoP signing consistency
- **Authorizer API hardening**: `check_chain()` and `authorize_one()` — two independent security boundaries
- **Mandatory PoP timestamp**: `warrant.sign()` requires explicit `timestamp` argument for replay safety
- **Wire fidelity tests**: Verify all constraint types survive serialization roundtrip
- **Example rot detection**: `test_examples.py` validates all examples import and parse correctly
- **Website**: Replace pricing page with "Request Early Access" form, feature CrewAI and Temporal on landing page

### Fixed
- Temporal demo: correct API usage (`Warrant.mint_builder()`, property access, sandbox passthrough, Payload headers)
- Temporal interceptor: add missing `init()` and `workflow_interceptor_class()` methods
- `tenuo_headers()`: use `secret_key_bytes()` for `SigningKey`
- Deprecated `.attenuate()` calls in Google ADK docs
- Deprecated `Warrant.issue()` in docs and notebook
- 6 stale examples fixed, ruff lint errors in A2A and MCP examples resolved

## [0.1.0-beta.9] - 2026-02-17

### Added
- **Temporal distributed deployment**: Header propagation via outbound interceptor — works when client and worker are separate processes
- **`AuthorizedWorkflow`**: Base class with fail-fast validation and automatic PoP
- **`TenuoClientInterceptor`**: Client-side warrant header injection
- **Live integration tests**: 36 tests including 5 against an in-process Temporal server
- **Examples**: `authorized_workflow_demo.py`, `multi_warrant.py`, `delegation.py`

### Fixed
- Broken header propagation in distributed Temporal deployments
- AWS/GCP key resolver tests on CI without cloud SDKs installed
- mypy errors for optional dependencies (`temporalio`, `google.adk`, `agents`)

## [0.1.0-beta.8] - 2026-02-14

### Added

#### Unified Enforcement Module
- **Shared `enforce_tool_call()` function**: Single code path for all Python integrations (LangGraph, CrewAI, AutoGen, OpenAI, Google ADK)
- **`_enforcement.py`**: 670+ lines of shared enforcement logic with consistent behavior across frameworks
- **`BaseGuardBuilder`**: DRY builder pattern extracted to `_builder.py` for all integration guard builders
- **Defense-in-depth documentation**: Clear separation between Python-side policies (UX) and Rust core (security boundary)
- **Tool risk schemas**: `ToolSchema` with risk levels (`critical`, `high`, `medium`, `low`) and recommended constraints

#### Temporal Integration (`tenuo[temporal]`)
- **Workflow authorization**: Warrant-based protection for Temporal workflows
- **Activity guards**: Constraint enforcement on Temporal activities

#### Authorizer Improvements
- **Signing key requirement**: Authorizers now require signing keys for cryptographic receipts (breaking change)
- **Audit events for denials**: Missing/invalid warrant denials now emit audit events
- **CBOR encoding fix**: Warrant chains encoded as byte strings (not arrays) per spec

#### CrewAI Integration (`tenuo[crewai]`)
- **GuardBuilder API**: Fluent builder for protecting CrewAI tools with Tenuo authorization
- **Tier 1 (constraints-only)**: Lightweight validation using `GuardBuilder().allow("tool", arg=Constraint).build()`
- **Tier 2 (warrants + PoP)**: Cryptographic enforcement with `WarrantDelegator` for hierarchical delegation
- **GuardedCrew**: Policy-based multi-agent crew protection with seal mode to prevent delegation circumvention
- **Tool Namespacing**: `agent_role::tool_name` prevents cross-agent confusion in multi-agent scenarios
- **Hierarchical Delegation**: Manager → Worker patterns with attenuation-only narrowing
- **`on_denial` modes**: `raise` (default), `log`, or `skip` for flexible error handling
- **4 complete examples**: Basic protection, hierarchical delegation, guarded crew, and flow integration
- **3,074 lines of tests**: Comprehensive unit, adversarial, and integration test coverage

#### Version Compatibility System
- **Runtime Version Warnings**: Non-blocking warnings for known version issues instead of hard failures
- **Compatibility Matrix Documentation**: Tracks minimum/recommended/latest versions for all integrations (OpenAI, AutoGen, CrewAI, LangChain, LangGraph, MCP, Google ADK)
- **Automated Monitoring**: Dependabot + CI compatibility matrix + upstream release monitor for early breaking change detection
- **Integration Maintenance Guide**: `INTEGRATION_MAINTENANCE.md` contributor runbook for managing integration lifecycle
- **Smoke Tests**: API contract verification across minimum and latest dependency versions

#### Security & Reliability Improvements
- **A2A Security Fixes**: 4 critical security issues resolved in A2A server
  - Fail-closed audience validation (missing/mismatched `aud` claims now rejected)
  - Robust expiry checking with proper None handling
  - Constraint deserialization support for Range, Cidr, OneOf, NotOneOf, Regex
  - Config validation with fail-closed behavior for secure defaults
- **Integration Consistency**: Standardized holder verification approach across CrewAI, A2A, and Google ADK (all now trust Rust core's cryptographic PoP verification)
- **Google ADK Warnings**: Added security warnings and runtime detection for argument remapping validation bypass risks

### Changed
- **Version Constraints**: Relaxed to permissive constraints with runtime warnings (e.g., `crewai>=1.0` instead of pinned versions)
- **Holder Verification**: Removed redundant Python-side holder checks in CrewAI (Rust core's `verify_pop()` provides cryptographic enforcement)
- **Maturin 1.12 compatibility**: Updated build configuration for latest maturin

### Dependencies
- Upgraded `axum` from 0.7.9 to 0.8.8
- Upgraded `cel-interpreter` from 0.8.1 to 0.10.0
- Upgraded `moka` from 0.12.12 to 0.12.13
- Upgraded `secrecy` to 0.10.x and `pyo3` to 0.24.1
- Explorer: React 18 → 19, jsdom 23 → 28, Playwright 1.58

### Documentation
- Added "Shared Enforcement Core" section to `enforcement.md`
- Added "Tool Policies (Defense in Depth)" section explaining risk levels and schemas
- Added FastAPI/A2A troubleshooting to `debugging.md`
- Added comprehensive CrewAI integration guide (`docs/crewai.md`, 779 lines)
- Added compatibility matrix with version recommendations (`docs/compatibility-matrix.md`, 193 lines)
- Added integration maintenance system documentation (`INTEGRATION_MAINTENANCE.md`, 143 lines)
- Updated main README to feature CrewAI integration
- Created security review documentation for all three integrations

---

## [0.1.0-beta.7] - 2026-02-01

### Added

#### AutoGen Integration (`tenuo[autogen]`)
- **GuardBuilder API**: Fluent builder for protecting AutoGen AgentChat tools with Tenuo authorization
- **Tier 1 (constraints-only)**: Lightweight validation using `GuardBuilder().allow("tool", arg=Constraint).build()`
- **Tier 2 (warrant + PoP)**: Cryptographic enforcement with `with_warrant(warrant, signing_key)`
- **Streaming TOCTOU protection**: Buffer-verify-emit strategy via `guard_stream()` prevents time-of-check time-of-use attacks
- **Flexible argument extraction**: Handles dicts, Pydantic models, dataclasses, and positional/keyword args
- **`on_denial` modes**: `raise` (default), `log`, or `skip` for flexible error handling
- **5 demo files**: Unprotected baseline, protected tools, attenuation, GuardBuilder Tier 1/2

#### Authorizer Observability
- **Audit Event Streaming**: Authorization decisions streamed to control plane with full warrant chain (base64-encoded CBOR `WarrantStack` for chain reconstruction)
- **Runtime Metrics**: Uptime, request counts, avg/p99 latency, memory usage sent with each heartbeat
- **Environment Labels**: Auto-detected K8s context (namespace, pod, node), cloud region, and deployment identifiers
- **Aggregate Stats**: Per-heartbeat summaries (allow/deny counts, top deny reasons, top actions, unique principals/warrants)
- **SRL Health**: Tracks revocation list fetch status, verification failures, and current SRL version

### Core & Protocol
- **Approval Envelope**: Refactored `Approval` to use the `SignedApproval` envelope pattern (separating `ApprovalPayload` from signature), aligning with the v1.0 spec and matching the Warrant architecture.
- **Protocol Parity**: Synchronized `tenuo-core` with v1.0 spec, updating `WarrantType` serialization to integers (CBOR) and reconciling all test vectors.
- **Test Vectors**: Updated `docs/spec/test-vectors.md` and fixed vectors A.12/A.13 to match the canonical generator output.

### Infrastructure
- **Unified `uv` Toolchain**: Migrated all Python dependency management to `uv` for consistent, fast, and reliable builds.
- **CI Stability**: Fixed "No virtual environment" errors in GitHub Actions by using `--system` flag with `uv pip install`.

### Documentation
- **AutoGen Integration**: Added `docs/autogen.md` guide and 5 example demos
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
