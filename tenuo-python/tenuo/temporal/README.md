# `tenuo.temporal` — authorization layer for Temporal Python SDK

This package interposes as a Temporal `WorkerInterceptor` (and, when the plugin is used, a `SimplePlugin`) to:

- verify a signed **warrant** on every activity inbound before the activity body runs;
- sign a **Proof-of-Possession** (PoP) on every activity/child-workflow dispatch from inside the workflow sandbox;
- surface denials as non-retryable `ApplicationError`s with a stable wire-type taxonomy.

Activity definitions require no changes. Authorization is transparent to user workflow code.

## Entry points

| Entry point | Use when |
|---|---|
| `tenuo.temporal_plugin.TenuoTemporalPlugin` | **Recommended.** Full plugin: wires the worker interceptor, the client interceptor, the sandboxed workflow runner, and the required internal activity registration in one step. Pass to `Client.connect(..., plugins=[...])`. |
| `tenuo.temporal.TenuoWorkerInterceptor` | Manual setup when you need custom `SandboxedWorkflowRunner` / `workflow_runner` / worker wiring. Callers must also register `*TENUO_TEMPORAL_ACTIVITIES` and call `register_worker_config(task_queue, config)` before `Worker(...)`. |

## File map

| File | Purpose |
|---|---|
| `_interceptors.py` | Activity-inbound authorization (warrant extract → chain check → PoP verify → dedup → execute) and workflow-outbound PoP signing. The `execute_activity` method has phase markers for navigation. |
| `_workflow.py` | User-facing helpers (`execute_workflow_authorized`, `AuthorizedWorkflow`, `tenuo_execute_activity`, `tenuo_execute_child_workflow`, `workflow_grant`, `set_activity_approvals`, `tenuo_continue_as_new`), and the `_tenuo_internal_mint_activity` that delegations dispatch into. |
| `_client.py` | Client-side header injection, keyed by `workflow_id`, via `TenuoClientInterceptor` and `execute_workflow_authorized`. |
| `_headers.py` | Serialize / extract warrant bytes across the Temporal header boundary (raw CBOR, optional gzip). |
| `_config.py` | `TenuoPluginConfig` — the single configuration surface. |
| `_state.py` | `run_id`-keyed workflow header store; `task_queue`-scoped worker-config registry. |
| `_pop.py` | PoP argument-name normalization (positional → named, `**kwargs` resolution). |
| `_dedup.py` | `PopDedupStore` protocol + `InMemoryPopDedupStore`. |
| `_resolvers.py` | Holder-key resolvers: `Env`, `Vault`, `AWSSecretsManager`, `GCPSecretManager`, `Composite`. |
| `_decorators.py` | `@tool(name)` and `@unprotected` activity decorators. |
| `_observability.py` | `TemporalAuditEvent`, `TenuoMetrics`. |
| `_constants.py` | Wire header names and encoding limits. |
| `exceptions.py` | Public exception taxonomy with stable `error_code` attributes. |
| `_warrant_source.py` | Internal helpers for warrant construction and chain encoding. |

## Invariants worth knowing before editing

These are non-obvious from the code alone; each has a corresponding test guard cited inline so the claim is verifiable, not trust-me.

- **Per-run state keying.** `_workflow_headers_store` and `_workflow_config_store` are keyed by `run_id`, not `workflow_id`. `workflow_id` is only unique per namespace; `run_id` is globally unique. Keying by `workflow_id` would cross-contaminate tenants that share a Python process. _Guard:_ `tests/adapters/test_tenant_isolation.py::TestRunIdKeyingIsolatesTenants`.
- **Task-queue-scoped worker config.** `register_worker_config(...)` requires a non-empty `task_queue`, and lookup is strict-match. No "last-registered wins" fallback. _Guard:_ `tests/adapters/test_tenant_isolation.py::TestWorkerConfigIsRoutedByTaskQueue`.
- **Workflow-clock discipline.** All time-based checks inside the sandbox (warrant TTL, PoP time window) use `workflow.now()`. Using wall-clock time would make replay non-deterministic and crash long-running workflows on replay after the original warrant's `expires_at`. _Guard:_ `tests/e2e/test_temporal_replay.py::test_tenuo_plugin_replay_clock_boundary_crossing` (uses `WorkflowEnvironment.start_time_skipping()` to cross a PoP window boundary).
- **Sandbox passthrough.** `tenuo` and `tenuo_core` must be passthrough modules (the PyO3 core can only initialize once per process). `TenuoTemporalPlugin` handles this; manual setup with a custom `SandboxedWorkflowRunner` must set it explicitly. _Guard:_ `tests/adapters/test_temporal_replay_safety.py::TestPassthroughModules`.
- **Wire format.** `x-tenuo-warrant` is raw CBOR bytes (not base64, not JSON). `x-tenuo-compressed` is `b"0"` or `b"1"`. PoP (`x-tenuo-pop`) is base64-encoded bytes. _Guards:_ `tests/property/test_temporal_props.py::TestTemporalWireRoundtrip` (Hypothesis-based) and `tests/e2e/test_temporal_e2e.py::TestMalformedWarrantHeadersAtIngress` (adversarial).
- **Denial → non-retryable wire type.** Every denial surfaces as `ApplicationError(non_retryable=True, type=<error_code>)` where `error_code` is one of the stable codes in `exceptions.py` (`CHAIN_INVALID`, `WARRANT_EXPIRED`, `POP_VERIFICATION_FAILED`, `CONSTRAINT_VIOLATED`, `LOCAL_ACTIVITY_BLOCKED`, `CONTEXT_MISSING`, etc.). _Guards:_ `tests/adapters/test_temporal.py::TestNonRetryableWrapping`, `tests/e2e/test_temporal_e2e.py::TestChainDepthEnforcement`, `tests/property/test_temporal_props.py::TestWrapAsNonRetryable`.

## Tests

- `tenuo-python/tests/e2e/test_temporal_e2e.py` — mocked end-to-end activity-inbound and workflow-outbound flows.
- `tenuo-python/tests/e2e/test_temporal_live.py` — same paths against a real in-process `WorkflowEnvironment.start_local()`.
- `tenuo-python/tests/e2e/test_temporal_examples_smoke.py` — loads each `examples/temporal/*.py` script and runs `main()` against `WorkflowEnvironment` (redirecting `Client.connect` away from `localhost:7233`).
- `tenuo-python/tests/e2e/test_temporal_replay.py` — record-and-replay determinism, including denial, trusted-root rotation, and PoP time-window clock-boundary crossing via `start_time_skipping()`.
- `tenuo-python/tests/adapters/test_temporal.py` — per-helper unit and regression tests.
- `tenuo-python/tests/adapters/test_temporal_plugin.py` — `SimplePlugin` contract coverage.
- `tenuo-python/tests/adapters/test_tenant_isolation.py` — `run_id` keying and `task_queue` routing invariants.
- `tenuo-python/tests/property/test_temporal_props.py` — Hypothesis-based wire-format and error-wrapping invariants.
- `tenuo-python/tests/unit/test_temporal_normalize_pop_args.py` — PoP argument normalization.

The live and replay suites run in a dedicated `temporal-integration` CI job.

**Where a new test goes.** Activity-inbound or workflow-outbound regression guard that doesn't need a live server → `test_temporal_e2e.py`. Behavior that only reproduces against a real Temporal server (retries, long-poll timing, sandbox runner composition) → `test_temporal_live.py`. Published example scripts must stay runnable → `test_temporal_examples_smoke.py`. Anything that must survive replay → `test_temporal_replay.py`. Wire-format / error-taxonomy invariants expressible as a property → `test_temporal_props.py`. Tenant-isolation / cross-worker routing → `test_tenant_isolation.py`.

## Further documentation

- [`docs/temporal.md`](../../../docs/temporal.md) — getting-started guide (prerequisites, minimal example, conceptual model).
- [`docs/temporal-reference.md`](../../../docs/temporal-reference.md) — production reference (key management, rotation, dedup stores, approval gates, troubleshooting).
- [`tenuo-python/examples/temporal/`](../../examples/temporal/) — runnable examples (single-warrant, multi-warrant, delegation, Cloud IAM layering, MCP layering).
- [`CHANGELOG.md`](../../../CHANGELOG.md) — notable behavior changes per release.
