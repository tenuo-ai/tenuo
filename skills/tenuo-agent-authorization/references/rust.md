# Rust integration

Use this reference for projects using the `tenuo` crate directly, embedding verification in a Rust service, or building a Rust enforcement component. Confirm the resolved crate version, enabled features, and docs.rs API before editing code.

Do not treat this reference as an API specification. Use `cargo metadata` to locate the resolved crate source. Registry and vendored crate sources include the crate README and declared examples; inspect those exact-version files first. If local source is insufficient, compare the resolved crate with the Rust entry in the [release contract](../release.json). Use these immutable sources only when the versions match:

- [MCP transport and received-authorization boundary](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-core/examples/sdk_mcp_demo.rs)
- [Long-lived runtime, trusted roots, revocation, sessions, and receipts](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-core/examples/sdk_runtime.rs)
- [Core SDK guide and feature flags](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-core/README.md)
- [End-to-end authorization behavior](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-core/tests/integration.rs) and [security cases](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-core/tests/security.rs)
- [Adversarial trust, PoP, and argument-binding tests](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-core/tests/red_team.rs)

The Rust CI builds and tests the crate with all features, which compiles the declared examples. Adapt their architecture using the resolved crate's types rather than copying remembered syntax.

## Choose the surface

- Use the direct data-plane authorizer when the application already controls warrant decoding, PoP construction, approvals, and argument representation.
- Use the `sdk` feature for guard, runtime, session, delegation, and received-authorization abstractions.
- Enable only the transport features the boundary uses. MCP and HTTP transport helpers do not create network isolation by themselves.
- Use received-authorization verification at an effecting service. The holder path signs; the receiving enforcement path verifies and must not possess or invent the holder key.

`ObservingGuard` assesses calls but does not enforce. Do not substitute it for `Guard` while claiming deny-before-effect behavior. Development and test utilities are not production trust bootstrap.

## Runtime and trust

Provision trusted roots independently of requests. Persist holder identity only in the principal that owns it, and apply sufficiently fresh signed revocation state when revocation is part of the claimed guarantee. Select an explicit TTL-only fallback policy when current revocation state is unavailable; do not silently continue with an undefined policy.

Treat receipt collection as best-effort evidence unless the chosen sink and effect are transactionally coupled. Backpressure or receipt failure must not accidentally change an explicitly selected authorization failure policy.

## Boundary behavior

Decode untrusted transport data with the supported transport module, enforce size and resource limits at the server boundary, and verify immediately before the effect. Pass the same normalized arguments into verification and execution. Do not authorize a borrowed or parsed view and then reconstruct materially different values for the operation.

Separate authorization denial from infrastructure failure in internal telemetry, but fail closed for both when the effect requires authorization. Return stable, non-sensitive error codes to untrusted callers.

## Test shape

Use an invocation counter or recording fake effect. Cover allowed execution, missing and malformed authority, untrusted roots, wrong-holder PoP, expiry, capability and constraint denial, wider delegation, transport round trips, replay handling when claimed, and direct-route bypass. Include concurrent tests when sessions or authority are stored in task-local or shared runtime state.
