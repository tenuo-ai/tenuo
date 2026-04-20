# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

- **MCP Proof-of-Possession now always signs raw wire arguments.** Previously,
  when a `CompiledMcpConfig` was loaded on the client, `SecureMCPClient` would
  run `extract_constraints(...)` before signing and compute PoP over the
  extracted (renamed/coerced) view. The server did the same on its side, so
  PoP byte parity depended on both sides having *identical* configs loaded —
  a subtle drift mode caused every call to be rejected with
  "Signature verification failed" whenever the client had no config or a
  slightly different one. The PoP signature now covers the raw MCP
  `arguments` dict on both client and server; constraint extraction runs
  server-only and feeds only the policy-matching path. This removes an
  entire class of silent-denial misconfigurations but changes the bytes
  that go into the PoP digest — clients and servers must upgrade together.

### Added

- **Split-view authorize APIs in `tenuo-core`** — `Warrant::authorize_with_pop_args`,
  `Warrant::authorize_with_pop_args_and_config`, `Authorizer::authorize_one_with_pop_args`,
  and `Authorizer::check_chain_with_pop_args` accept two argument dicts:
  `pop_args` (covered by the PoP signature, approval gates, request hash, and
  approval signatures) and `constraint_args` (matched against the warrant's
  per-tool constraints). Exposed to Python via `authorize_one_with_pop_args`
  and `check_chain_with_pop_args`. The existing single-arg methods are
  unchanged and become thin wrappers that pass the same dict for both — no
  behavior change for non-transport callers.
- **`tenuo._pop_canonicalize.strip_none_values(args)`** helper — a small
  pure-Python canonicalizer that both sides of the MCP handshake apply to
  wire args before they cross the Rust FFI boundary. Drops top-level `None`
  values and `None` list elements so optional tool parameters with
  `Optional[...] = None` defaults don't crash the canonicalizer.

### Fixed

- **MCP PoP parity across config asymmetry.** A client without a
  `CompiledMcpConfig` loaded (or with a different one) can now call a server
  that does have a config; PoP byte parity no longer depends on the
  extraction schema. Signature-verification denials now only mean what they
  should: the caller is not the legitimate holder of the warrant.
- **`None` values in tool arguments no longer crash signing/verification.**
  Calling `warrant.sign` or invoking an MCP tool with arguments like
  `{"encoding": None, "limit": None}` used to raise
  `ValueError: value must be str, int, float, bool, or list` from the Rust
  core. Both the MCP client and MCP verifier now apply `strip_none_values`
  symmetrically before the FFI boundary, so optional arguments left unset
  flow through cleanly.
- **Misleading "unauthenticated arguments" server warning removed.** With
  split-view authorize, every raw wire arg is covered by the PoP signature
  regardless of the extraction mapping, so the warning was factually wrong
  under the new model.

### Migration

- Upgrade client and server together. A pre-upgrade client talking to a
  post-upgrade server (or vice versa) will still cross-verify in the
  common case where client and server have identical configs loaded, but
  will silently fail anywhere the old and new canonicalization diverge
  (i.e. most of the real-world mismatch scenarios this PR was written to
  fix). If you cannot upgrade both sides simultaneously, pin the
  `tenuo-python` / `tenuo-core` versions on each side and plan a
  coordinated rollout.

## [0.1.0-beta.22] - 2026-04-14

### Fixed

- **Delegation constraint violations no longer hang workflows** — `TemporalConstraintViolation` raised inside `tenuo_execute_child_workflow()`, `workflow_grant()`, and `workflow_issue_execution()` is now wrapped as `ApplicationError(non_retryable=True)`. Previously, misconfigured delegation chains (e.g. delegating a tool the parent doesn't have) caused infinite Temporal retries.
- **PopDedupStore warning downgraded to DEBUG** — the "using in-memory PopDedupStore" message no longer prints at WARNING level on every worker startup during local development.

### Added

- **`client_interceptor` auto-discovery** — `execute_workflow_authorized()` and `start_workflow_authorized()` now find the `TenuoClientInterceptor` automatically from the client's plugin config. The `client_interceptor` parameter is optional when using `TenuoTemporalPlugin`.
- **Key format auto-detection** — `EnvKeyResolver` now accepts both base64 and hex-encoded keys in `TENUO_KEY_*` environment variables (auto-detected by length and character set).
- **`__dir__()` on `tenuo.temporal`** — lazy-loaded symbols now appear in `dir()`, `help()`, and tab-completion.
- **`start_workflow_authorized()` documented** — getting-started guide and reference now show the signal/query pattern alongside `execute_workflow_authorized()`.
- **`TENUO_KEY_` convention documented** — getting-started guide and reference now explain the `key_id` → env var mapping with a table and inline key generation example.
- **`UrlSafe` vs `UrlPattern` clarified** — reference doc now explains the distinction (structured validation vs glob matching) and when to use each.

### Changed

- **Examples use public imports and `TenuoTemporalPlugin`** — all 5 example files (`demo.py`, `delegation.py`, `multi_warrant.py`, `cloud_iam_layering.py`, `temporal_mcp_layering.py`) now import from `tenuo.temporal` (not private `_`-prefixed submodules) and use `TenuoTemporalPlugin` with `Client.connect(plugins=[...])` instead of manual `TenuoPlugin` + `SandboxedWorkflowRunner`.
- **`activity_fns` removed from examples** — `TenuoTemporalPlugin` auto-discovers activity functions from the worker config, so explicit `activity_fns=[...]` is no longer needed (or shown) in examples.

## [0.1.0-beta.21] - 2026-04-14

### Changed

- **Modularized `tenuo.temporal` package** — the monolithic `temporal.py` (5 300+ lines) is now 15 focused submodules (`_interceptors`, `_workflow`, `_client`, `_config`, `_pop`, `_headers`, `_decorators`, `_state`, `_dedup`, `_observability`, `_constants`, `_resolvers`, `_warrant_source`, `exceptions`, `temporal_plugin`). Public imports (`from tenuo.temporal import X`) are unchanged thanks to `__getattr__` lazy loading. Internal (`_`-prefixed) symbols must now be imported from their submodule.
- **`docs/temporal.md` split** — deep reference content moved to `docs/temporal-reference.md` (908 lines). Quick-start guide stays in `temporal.md`.
- **Removed `docs/temporal-sandbox-passthrough.md`** — rationale folded into `temporal-reference.md`.

### Fixed

- **`TenuoMetrics` now wired into interceptors** — `record_authorized` and `record_denied` are called on allow/deny paths when a `TenuoMetrics` instance is configured. Previously the `metrics` config field was accepted but never used.
- **`WarrantExpired` raised consistently** — core `ExpiredError` is now surfaced as `WarrantExpired` instead of being wrapped as a generic `TemporalConstraintViolation`.
- **Denial metrics include latency** — `start_ns` is now passed to all `_emit_denial_event` call sites (chain-depth denial was missing it).
- **Removed stale "partner program" terminology** from code comments, test names, and docs.

### Added

- **Activity summaries for Temporal Web UI** — the outbound interceptor auto-prefixes activity summaries with `[tenuo.TenuoTemporalPlugin] <tool>` for debuggability in the Temporal UI. `tenuo_execute_activity` accepts a `summary` kwarg. (#376)
- **`error_code` on all Temporal exception classes** — `TenuoContextError` (`CONTEXT_MISSING`), `TenuoArgNormalizationError` (`ARG_NORMALIZATION_FAILED`), and `TenuoPreValidationError` (`PRE_VALIDATION_FAILED`) now carry `error_code` like all other exception types.
- **`_bind_warrant_headers` helper** — deduplicates warrant resolution logic between `execute_workflow_authorized` and `start_workflow_authorized`.
- **`PopDedupStore` in `_dedup.py`** — PoP replay deduplication extracted from `exceptions.py` to its own module.
- **Package layout table** in `docs/temporal-reference.md` mapping public symbols to canonical submodule homes.
- **New tests:** UrlSafe/Wildcard constraint interceptor tests, metrics wiring tests (allow + deny), error_code presence tests, `set_activity_approvals` unit tests.

## [0.1.0-beta.20] - 2026-04-13

### Breaking

- **Removed `trusted_approvers` and `approval_threshold` from `TenuoPluginConfig`.**
  The warrant is now the single source of truth for who can approve and how many
  approvals are required. Passing these options to `TenuoPluginConfig()` will raise
  `TypeError`. Set `required_approvers` and `approval_threshold` on the warrant at
  mint time instead.

### Security

- **Temporal child workflow header isolation** — child workflows started via `workflow.execute_child_workflow()` no longer inherit parent Tenuo headers. Use `tenuo_execute_child_workflow()` for explicit attenuation. (#349)
- **Temporal mint activity fail-closed** — `_tenuo_internal_mint_activity` raises `TenuoContextError` if the parent warrant lacks `issue_execution()` instead of silently falling back to `attenuate()`. (#349)
- **CodeQL path injection fix** — resolved path injection alert in docs preview server. (#361)
- **Authorizer approval response blind spots** — fixed cases where the authorizer could miss approval verification errors. (#362)

### Added

- **A2A approval transport** — threaded approval transport through the A2A adapter for human-in-the-loop flows. (#363)
- **`tenuo_continue_as_new()` attenuation guard** — raises `NotImplementedError` if the `tenuo_attenuation` argument is provided (not yet implemented). (#349)

### Fixed

- **WASM connect token field key** — corrected the field key used for registration tokens in WASM builds. (#357)
- **Connect token URL normalization** — fixed URL normalization and removed phantom Helm ServiceMonitor. (#360)
- **Stale doc references** — removed `llms.txt`, `INTEGRATION_MAINTENANCE.md`, IETF stub, and fixed dead API references. (#358, #359)
- **Docs merge artifact** — removed `HEAD` merge artifact from `temporal.md` security heading, corrected `current_warrant()` docs, fixed code fences and missing imports. (#349)

### Changed

- **`@guard` enforcement delegation** — refactored `@guard` to delegate enforcement to `enforce_tool_call`. (#356)

## [0.1.0-beta.19] - 2026-04-10

### Security

- **Guarded telemetry emissions** — all `emit_for_enforcement` calls across every adapter are now wrapped in `try/except` with `logger.warning` so a control-plane outage cannot crash the authorization path.
- **MCP client connection detection** — replaced fragile string-matching on exception class names with proper `isinstance` checks.
- **Explorer** — Vite updated to 8.0.8+ (addresses GHSA-p9ff-h696-f583, GHSA-v2wj-q39q-566r, GHSA-4w7w-66w2-5vf9).

### Added

- **MCP `request_hash` threading** — Rust-computed approval request hash flows through `MCPVerificationResult`, the JSON-RPC error payload, and `MCPApprovalRequired` so clients can correlate approvals end-to-end.
- **`tenuo.cp_transport`** — HTTP submission extracted from `tenuo.cp_approval`; core is now pure protocol/serialization.
- **ADK `redact_args_in_logs`** — `TenuoGuard` can redact tool arguments in audit logs to prevent PII leakage.
- **Property-based test suite** — 20+ Hypothesis test modules covering enforcement, FFI boundaries, MCP, Temporal, FastAPI, LangChain/LangGraph, A2A, and agent frameworks.

### Changed

- **MCP client reconnect** — exponential backoff with jitter instead of immediate retry; `.tools` returns a snapshot for thread safety.
- **Temporal dedup cache** — `OrderedDict`-backed eviction (O(1) amortized); `resolve_sync` has a 30 s timeout.
- **LangGraph** — warrant deserialization capped at 64 KB; request IDs use full UUIDs.
- Removed stale "Tenuo Cloud" references from open-source docstrings.

## [0.1.0-beta.18] - 2026-04-09

### Added

- **FastMCP `TenuoMiddleware`** — `tenuo.mcp.TenuoMiddleware` runs `MCPVerifier` on every `tools/call` via FastMCP's middleware pipeline. Optional `tenuo[fastmcp]` extra.
- **Temporal `TenuoTemporalPlugin`** — registers client + worker interceptors and sandbox passthrough. `TenuoPluginConfig.from_env()` for zero-config setup.
- **Telemetry auto-discovery** — set `TENUO_CONNECT_TOKEN` and all adapters report events automatically.

### Removed

- Deprecated `ApprovalPolicy`, `ApprovalRule`, `require_approval`.

### Dependencies

- `tenuo[fastmcp]` requires `fastmcp>=3.2.1`.

## [0.1.0-beta.17] - 2026-04-05

### Security

- **CodeQL / supply-chain hygiene** — `docs/_preview.py` resolves markdown only under `docs/` (realpath containment). Explorer uses `replaceAll` where global replacement is intended. Blog layout loads GoatCounter over HTTPS with Subresource Integrity.

### Added

- **Signed approval envelopes in audit payloads** — `VerifiedApproval` and `ApprovalRecord` include `signed_approval_cbor_b64` (standard base64 CBOR `SignedApproval`) so control planes can verify approver signatures independently. Python: `VerifiedApproval` type and `ChainVerificationResult.verified_approvals`.

### Documentation

- **Heartbeat receipts** — clarify when to use `SignedEvent.signature` versus `signing_payload` for verification (#327).

### Dependencies

- **PyO3 0.28** — Python extension updated for PyO3 0.28; `pyo3` is pinned to `=0.28.3` in `tenuo-core` and `tenuo-python` for reproducible builds.

## [0.1.0-beta.16] - 2026-03-31

### Added

- **Approval records in authorizer receipts** — `AuthorizationEvent` now includes verified `ApprovalRecord`s when human-in-the-loop approvals contributed to an authorization decision. Only approvals that passed all cryptographic and policy checks are included.
- `**VerifiedApproval` struct** — new type propagated through `ChainVerificationResult` to avoid redundant Ed25519 re-verification in the audit path.

### Security

- **15 new cryptographic tests** — comprehensive round-trip, tamper-detection, and domain-separation tests for `SignedApproval`, `SignedEvent`, and `RegistrationProof`/`RotationProof`.
- **8 pin tests for approval verification** — lock down security properties (forged signatures, duplicate approvers, expired approvals, wrong request hashes) across refactoring.
- **CodeQL alerts resolved** — `replaceAll` for wildcard patterns in explorer (#33, #50), SRI integrity on CDN resources (#34).

### Changed

- **A2A server hot-path optimizations** — `Warrant` class lookup via `sys.modules` instead of per-request import; audit log `write`+`flush` offloaded to thread pool via `run_in_executor`; JTI extracted once and reused.
- **PoP verification allocation reduction** — `id.to_hex()` hoisted above the window loop; `challenge_bytes` and `preimage` buffers pre-allocated and reused across iterations.
- **Cycle detection optimized** — single-element chains skip `HashSet` entirely; multi-warrant chains use `WarrantId` bytes instead of `String` formatting.
- **matchit 0.8 migration** — route patterns now use native `{param}` syntax; removed the `convert_pattern_to_matchit` translation layer.

### Dependencies

- `rand` 0.9 → 0.10, `sha2` 0.10 → 0.11 (`tenuo-core`)
- `matchit` 0.7 → 0.8 (`tenuo-core`)
- `vitest` 3 → 4, `@vitest/ui` 3 → 4 (`tenuo-explorer`)
- `codecov/codecov-action` 5 → 6
- `docker/build-push-action` 6 → 7, `docker/login-action` 3 → 4, `docker/setup-buildx-action` 3 → 4, `docker/setup-qemu-action` 3 → 4

---

## [0.1.0-beta.15] - 2026-03-28

### Added

- `**ArgApprovalGate::Exempt`** — new approval gate variant (in development). See Tenuo Cloud documentation for usage details.
- `**WRAP_TOOL_CALL_SUPPORTED` flag** exported from `tenuo.langgraph` — lets callers detect at runtime whether the installed LangGraph version supports authorization hooks (`wrap_tool_call` requires LangGraph ≥ 0.3 / Python 3.10+).
- **rand 0.9 upgrade** — `SigningKey::generate` now uses `OsRng.try_fill_bytes` with `Zeroizing<[u8; 32]>` to guarantee secure memory erasure of ephemeral key bytes.

### Security

- **Ed25519 strict verification** — `PublicKey::verify` now uses `verify_strict` (rejecting non-canonical `s` scalars and small-order `R` points) and `PublicKey::from_bytes` rejects small-order / weak public keys at import time, closing the Ed25519 cofactor attack surface.
- **I1 delegation authority check** added to `Authorizer::verify_link` — child warrant's issuer must equal the parent's `authorized_holder`, preventing forged delegation chains constructed outside the SDK.
- **Approval gate monotonicity** enforced at wire-verification time in `Authorizer::verify_link` — gates cannot be weakened or stripped in hand-crafted chains that bypass `AttenuationBuilder`.
- **WASM `verify_approval_set` deduplication** corrected — approval entries are now deduplicated by approver public key rather than by list index, preventing approval replay with duplicate keys.
- `**TenuoToolNode` fail-fast on unsupported LangGraph** — constructor raises `RuntimeError` (instead of silently creating a non-enforcing node) when `wrap_tool_call` is unavailable.
- `**guard()` raises on unsupported clients** — passing an Anthropic, Vertex, or unknown client now raises `NotImplementedError` instead of returning an unguarded client.
- **Temporal `dry_run` visibility** — `TenuoInterceptorConfig(dry_run=True)` now emits a `warnings.warn` (Python-level) in addition to a logger warning, ensuring the shadow-mode flag surfaces even when logging is suppressed.

### Fixed

- **picomatch CVE** (CVSS 5.3 — prototype pollution via POSIX bracket expressions) patched in `tenuo-explorer` build toolchain via npm `overrides` pinning `picomatch ≥ 4.0.4`.

### Dependencies

- `rand` 0.8 → 0.9 (`tenuo-core`)
- `moka` 0.12.14 → 0.12.15 (`tenuo-core`)
- `tempfile` 3.26.0 → 3.27.0 (`tenuo-core`)

---

## [0.1.0-beta.14] - 2026-03-21

### Added

- **WASM constraint builder — type-keyed dispatch**: `create_warrant_from_config` now accepts `{ "type": "Shlex", ... }`, `{ "type": "UrlSafe", ... }`, `{ "type": "Subpath", ... }` and all other constraint types directly, alongside the existing key-based format.
- **WASM constraint builder — full `UrlSafe` support**: All `UrlSafe` fields are now configurable: `allow_ports`, `schemes`, `block_private`, `block_loopback`, `block_metadata`, `block_reserved`, `block_internal_tlds`.
- **WASM constraint builder — `Shlex` `allowed` alias**: Accepts both `"allow"` and `"allowed"` as the binary list key.

### Fixed

- Audit receipts now always carry the confirmed authorizer identity, not a pre-registration placeholder.
- `UrlSafe` decoded output now correctly includes `block_reserved: false` when explicitly overridden.
- Five pre-existing Clippy warnings in `tenuo-wasm` resolved.

---

## [0.1.0-beta.13] - 2026-03-20

### Added

- `**TENUO_CONNECT_TOKEN`**: Single-token onboarding for the `tenuo-authorizer` binary and Python SDK. Copy the token from the dashboard — no separate URL, API key, or signing key env vars needed.
  - Signing key is auto-generated if not provided.
  - Authorizer name defaults to pod/hostname when not set explicitly.
- `**/status` endpoint** on the authorizer binary: exposes registration state and uptime for health checks and readiness probes.

### Fixed

- **Security**: `rustls-webpki` upgraded to `0.103.10` (`RUSTSEC-2026-0049`).
- Several correctness gaps in the connect token startup path.

---

## [0.1.0-beta.12] - 2026-03-19

### Added

- **Tenuo Cloud integration** for Python SDK: authorization decisions can be streamed to Tenuo Cloud for audit and observability. Works with MCP, LangGraph, Temporal, and Google ADK.
- **WASM — `evaluate_approval_gates()`**: Check whether a tool call requires human approval before proceeding.
- **Formal verification**: Alloy models and Z3 proofs for core AAT constraint properties, with conformance oracle tests bridging the formal models to the Rust implementation.
- **IETF Draft**: Published `draft-niyikiza-oauth-attenuating-agent-tokens-00`.

### Fixed

- **Three attenuation soundness holes** (`#227`): Cross-type coercions that could allow authority expansion through delegation.
- **Temporal integration**: Replay deduplication, Python 3.9 compatibility, dry-run shadow mode.
- **Explorer npm vulnerabilities**: Upgraded `vite`, `@vitejs/plugin-react`, `jsdom`.

### Changed

- `reqwest` upgraded from `0.11` to `0.13`, `thiserror` from `1.0` to `2.0`, `tower` from `0.4` to `0.5`.

---

## [0.1.0-beta.11] - 2026-03-06

### Added

#### MCP Server-Side Verification

- `**MCPVerifier`**: Framework-agnostic server-side warrant verification for MCP tool handlers
- `**verify_mcp_call()`**: Standalone convenience function for one-off verification
- **Multi-transport client**: `SecureMCPClient` now supports SSE and StreamableHTTP transports in addition to stdio
- `**params._meta` transport**: Warrant + PoP are carried in the MCP spec's extension point (`params._meta["tenuo"]`), keeping tool arguments clean — no schema pollution
- **MCP session reconnection**: `SecureMCPClient` auto-reconnects on transport failures (`EOFError`, `EPIPE`, `ECONNRESET`, `anyio.ClosedResourceError`) with a single retry
- **JSON-RPC error codes**: `-32001` (denied), `-32002` (approval required), `-32602` (invalid params)

#### A2A Automated Handshake (CSR Pattern)

- `**agent/register` endpoint**: Agents request warrants at runtime without pre-configured key sharing
- `**WarrantRequest` / `VerifiedWarrantRequest`**: Typed dataclasses for the registration protocol
- **Self-signed challenge token**: Proves key ownership via Ed25519 without a round-trip
- `**issue()` oracle**: Handler receives a bound callable — the signing key never leaves the server
- `**RegistrationDisabledError` (-32017)** / `**RegistrationDeniedError` (-32018)**: Structured errors for the registration flow
- `**A2AClient.request_warrant()`**: Client-side method to perform the full CSR handshake
- `**A2AServerBuilder.registration_handler()`**: Server-side configuration for the handler

#### Approval Gates (renamed from Guards)

- `**approval_gate.rs`**: Renamed guard module to approval gate for clarity — per-tool approval policy evaluation
- `**ApprovalGate`**: Replaces `Guard` across core, Python bindings, and all integrations
- `**GuardTriggered` exception**: Exposed in Python SDK for approval gate evaluation results

#### Core Hardening

- **Clearance monotonicity fix**: Clearance levels now correctly enforce monotonic narrowing during delegation
- **Extension validation**: Fixed gaps in warrant extension validation
- **PoP error clarity**: `PopExpired` message now says "outside replay window" instead of ambiguous wording

#### A2A Protocol

- **Structured error types**: `TenuoA2AError`, `HandshakeError`, `VerificationError` for better error handling
- **Typed protocol messages**: `TaskRequest`, `TaskResponse`, `StreamEvent` dataclasses
- **Improved client**: Retry logic, connection pooling, and better error propagation

### Fixed

- Flaky timing-sensitive tests in CI (autogen expiry, MCP guard denial mode)
- mypy compatibility for optional `mcp` stubs on Python 3.9
- Deprecated API references in docs (`.attenuate()`, `Warrant.issue()`)
- Prevent logging of sensitive key material in A2A server
- Temporal key preloading and workflow sandbox restrictions
- Explorer clipboard error handling and tool arg auto-populate

### Documentation

- Updated `docs/mcp.md` with server-side verification and multi-transport examples
- Removed deprecated API patterns from cross-language comparison table

---

## [0.1.0-beta.10] - 2026-02-20

### Added

#### Human-in-the-Loop Approvals

- **ApprovalPolicy**: Cryptographically verified human authorization for sensitive tool calls
- **M-of-N multi-sig**: `threshold` parameter on `ApprovalPolicy` — require multiple approvers (e.g., 2-of-3) before execution
- **Configurable TTL hierarchy**: Policy `default_ttl` → handler `ttl_seconds` → 300s fallback
- **Diagnostic error messages**: Specific rejection reasons for 1-of-1 failures; summary for m-of-n (e.g., "required 2, received 1 [rejected: 1 expired, 1 not trusted]")
- **Built-in handlers**: `cli_prompt()`, `auto_approve()`, `auto_deny()`, `sign_approval()` — all produce real Ed25519 `SignedApproval` tokens
- **Framework integration**: `.approval_policy()` and `.on_approval()` on all GuardBuilders (CrewAI, AutoGen, OpenAI, Google ADK, LangGraph, LangChain)
- **13 Rust security tests** for m-of-n verification, **11 Python m-of-n tests**, **9 TTL propagation tests**

#### Temporal Integration Improvements

- **Transparent PoP**: Outbound workflow interceptor computes Proof-of-Possession automatically for `workflow.execute_activity()` — no wrapper needed
- `**activity_fns` config**: `TenuoInterceptorConfig` accepts activity functions for parameter name resolution
- **Authorizer API hardening**: `check_chain()` and `authorize_one()` — two independent security boundaries
- **Mandatory PoP timestamp**: `warrant.sign()` requires explicit `timestamp` argument for replay safety

#### Developer Experience

- **Wire fidelity tests**: Verify all constraint types survive serialization roundtrip
- **Example rot detection**: `test_examples.py` validates all examples import and parse correctly
- **Examples README**: Comprehensive listing of all 80+ examples across all integrations

### Fixed

- Temporal interceptor: add missing `init()` and `workflow_interceptor_class()` methods
- `tenuo_headers()`: use `secret_key_bytes()` for `SigningKey`
- Deprecated `.attenuate()` calls in Google ADK docs, `Warrant.issue()` in docs and notebook
- Runtime errors in 7 examples: context_pattern, hierarchical_delegation, fastapi_integration, approval_policy_demo, jit_warrant_demo, async_patterns, langgraph_mcp_integration
- Python 3.9 dropped from macOS/ARM CI runners (EOL, prebuilt packages broken on newer macOS)

### Documentation

- `**docs/approvals.md`**: Complete approval policy guide with m-of-n, TTL hierarchy, framework integration, and security properties

## [0.1.0-beta.9] - 2026-02-17

### Added

- **Temporal distributed deployment**: Header propagation via outbound interceptor — works when client and worker are separate processes
- `**AuthorizedWorkflow`**: Base class with fail-fast validation and automatic PoP
- `**TenuoClientInterceptor`**: Client-side warrant header injection
- **Live integration tests**: 36 tests including 5 against an in-process Temporal server
- **Examples**: `demo.py`, `multi_warrant.py`, `delegation.py`

### Fixed

- Broken header propagation in distributed Temporal deployments
- AWS/GCP key resolver tests on CI without cloud SDKs installed
- mypy errors for optional dependencies (`temporalio`, `google.adk`, `agents`)

## [0.1.0-beta.8] - 2026-02-14

### Added

#### Unified Enforcement Module

- **Shared `enforce_tool_call()` function**: Single code path for all Python integrations (LangGraph, CrewAI, AutoGen, OpenAI, Google ADK)
- `**_enforcement.py`**: 670+ lines of shared enforcement logic with consistent behavior across frameworks
- `**BaseGuardBuilder`**: DRY builder pattern extracted to `_builder.py` for all integration guard builders
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
- `**on_denial` modes**: `raise` (default), `log`, or `skip` for flexible error handling
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
- `**on_denial` modes**: `raise` (default), `log`, or `skip` for flexible error handling
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
