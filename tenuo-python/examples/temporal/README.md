# Tenuo Temporal Integration Examples

Warrant-based authorization for Temporal workflows and activities with **transparent PoP**.

## Prerequisites

1. **Temporal CLI and server**

On macOS:

```bash
brew install temporal
temporal server start-dev
```

On Linux or CI, install the CLI from [Temporal downloads](https://docs.temporal.io/cli#install) or your package manager, then run `temporal server start-dev` (or point workers at your own cluster).

2. **Python dependencies**

```bash
uv pip install "tenuo[temporal]"
```

For the **Temporal + MCP** example you also need the MCP extra and **Python 3.10+**:

```bash
uv pip install "tenuo[temporal,mcp]"
```

**Going to production:** see [Path to production](../../../docs/temporal.md#path-to-production) in `docs/temporal.md` (keys, passthrough, `activity_fns`, child workflows, dedup, root refresh). Enforcement is self-hosted on your workers; Tenuo Cloud is optional.

## Examples

Five examples showing a clean progression from basic transparent authorization to advanced patterns:

| Example | Concept | What it demonstrates |
|---------|---------|---------------------|
| [`demo.py`](demo.py) | **Transparent authorization** | Standard `workflow.execute_activity()`, zero workflow changes, sequential + parallel reads, unauthorized access denial |
| [`cloud_iam_layering.py`](cloud_iam_layering.py) | **IAM + MCP layering** | Same pattern as [`temporal_mcp_layering.py`](temporal_mcp_layering.py): activity uses `SecureMCPClient` to call [`cloud_iam_mcp_server.py`](cloud_iam_mcp_server.py) (`s3_get_object`). Two Tenuo boundaries (Temporal + MCP), then IAM at AWS. Per-tenant key prefixes; `TENUO_DEMO_DRY_RUN=1` mocks the MCP server (no boto3 in the activity) |
| [`multi_warrant.py`](multi_warrant.py) | **Multi-tenant isolation** | Identical workflow code for different tenants, isolation via warrant only, cross-access denial |
| [`delegation.py`](delegation.py) | **Inline attenuation** | Per-stage pipeline authorization with attenuated child workflows via `tenuo_execute_child_workflow()` |
| [`temporal_mcp_layering.py`](temporal_mcp_layering.py) | **Temporal + MCP** | Abstract pattern: `SecureMCPClient` + [`temporal_mcp_server.py`](temporal_mcp_server.py) (`safe_echo`). [`cloud_iam_layering.py`](cloud_iam_layering.py) is the same shape with S3 (`cloud_iam_mcp_server.py`) |

### Quick start

```bash
temporal server start-dev                          # Terminal 1
cd tenuo-python/examples/temporal && python demo.py  # Terminal 2
```

Then try **`cloud_iam_layering.py`**: **Python 3.10+** and `uv pip install "tenuo[temporal,mcp]"`. For real S3, install `boto3` in the environment (the **MCP server subprocess** uses it, not the activity). Use `TENUO_DEMO_DRY_RUN=1` so the MCP server returns synthetic bodies without AWS.

```bash
cd tenuo-python/examples/temporal
TENUO_DEMO_DRY_RUN=1 python cloud_iam_layering.py
```

**`cloud_iam_layering.py`** mints warrants with **two capabilities** each: `read_s3_via_mcp` (Temporal activity) and `s3_get_object` (MCP tool), both with the same `bucket` / `key` constraints. It runs: allowed read inside a prefix, Temporal denial outside the prefix, cross-tenant denial, and a fourth case where Temporal allows the activity but MCP denies `s3_get_object` (warrant without that capability).

### Temporal + MCP (advanced)

[`temporal_mcp_layering.py`](temporal_mcp_layering.py) is optional and **requires Python 3.10+** and `uv pip install "tenuo[temporal,mcp]"`. It spawns [`temporal_mcp_server.py`](temporal_mcp_server.py) as an MCP stdio subprocess.

- **Temporal boundary:** warrant must include `invoke_mcp_echo` (and PoP covers the `message` argument).
- **MCP boundary:** the same holder key signs PoP for `safe_echo`; the server verifies `params._meta["tenuo"]`. The demo mints one warrant with both capabilities, then a second warrant with only the Temporal activity so the MCP layer denies while Temporal still allows the activity.
- **Demo caveat:** the activity reads warrant material from a process-local dict set in `main()`. Production code should load warrants and keys via your normal `KeyResolver` / policy path instead of globals.

```bash
cd tenuo-python/examples/temporal
python temporal_mcp_layering.py
```

## Transparent Authorization Pattern

Recommended start path: use `execute_workflow_authorized(...)` for deterministic header binding in concurrent clients.

```python
result = await execute_workflow_authorized(
    client=client,
    client_interceptor=client_interceptor,
    workflow_run_fn=MyWorkflow.run,
    workflow_id="wf-123",
    warrant=warrant,
    key_id="agent1",
    args=[path],
    task_queue="my-queue",
)
```

With `TenuoPlugin` on the worker, you can call normal `workflow.execute_activity(...)`. No Tenuo imports are required inside the workflow for that path. If the warrant uses named field constraints (`path=`, `bucket=`, …), configure `activity_fns` (below).

```python
@workflow.defn
class MyWorkflow:
    @workflow.run
    async def run(self, path: str) -> str:
        return await workflow.execute_activity(
            read_file,
            args=[path],
            start_to_close_timeout=timedelta(seconds=30),
        )
```

The outbound interceptor:
- Computes PoP with deterministic timestamps (`workflow.now()`)
- Injects warrant and PoP into activity headers
- Works with `asyncio.gather()` for parallel activities
- Uses `workflow.now()` so replay stays deterministic

### Activity registry (`activity_fns`) when you **must** set it

PoP signs a canonical **argument dictionary**. If your warrant uses **named field constraints** (for example `capability("read_file", path=Subpath("/data/..."))`), that dict must use **real parameter names** (`path`), not placeholders (`arg0`, `arg1`, …).

The outbound interceptor learns parameter names from, in order:

1. The Temporal SDK’s `input.fn` (when present)
2. `tenuo_execute_activity()` (records the function for that call)
3. **`TenuoPluginConfig.activity_fns`**: pass the **same** callables as `Worker(activities=[...])`
4. Otherwise it falls back to `arg0`, `arg1`, …

If (4) happens while your warrant has field constraints for that tool, verification will not match the warrant. The worker **logs a warning**; with **`strict_mode=True`** it **raises** instead so you fix config before production.

**Rule of thumb:** if the warrant names arguments (`path=`, `message=`, …), set `activity_fns` next to `TenuoPlugin` (see `demo.py`). Tool-only capabilities without per-field constraints often do not need it.

See also: the **Activity registry (`activity_fns`) and PoP argument names** section in [`docs/temporal.md`](../../../docs/temporal.md) (repository root).

### When to use Tenuo-specific functions

- **`AuthorizedWorkflow`** + **`execute_authorized_activity()`**: fail fast if warrant headers are missing at workflow start; same PoP mechanism as transparent `execute_activity()`.
- **`workflow.execute_activity()`**: use with `activity_fns` when warrants name arguments (unless the SDK always provides `input.fn` for those calls).

Use **`tenuo_execute_activity()`** if you need correct parameter names for PoP and you have not set `activity_fns` (it records the function reference for the outbound interceptor):
- Multi-warrant workflows where different activities run under different warrants
- Per-stage delegation where you narrow the warrant before each stage
- Any workflow that does not extend `AuthorizedWorkflow` but needs transparent PoP

**Child workflows:** never use raw `workflow.execute_child_workflow()` for Tenuo-backed children; headers are not propagated. Use **`tenuo_execute_child_workflow()`** for attenuation and header injection:

```python
# Only needed for per-child authorization decisions
await tenuo_execute_child_workflow(
    ReaderChild.run,
    args=[source_dir],
    id=f"reader-{workflow.info().workflow_id}",
    tools=["read_file", "list_directory"],  # Subset of parent's tools
    ttl_seconds=60,                          # Scoped lifetime
)
```

This is an authorization decision (choosing what scope and duration to delegate), not infrastructure.

**How it works:**
1. Reads the parent warrant from workflow context
2. Derives a narrowed child warrant internally (monotonic attenuation)
3. Validates that requested tools are a subset of parent's tools
4. Injects the attenuated child warrant via the outbound interceptor
5. Child workflow receives ONLY the narrowed capabilities

The child receives only the attenuated warrant, not the parent's full scope.

## Worker setup (required)

Tenuo's core is a PyO3 Rust extension. Unlike pure-Python integrations (e.g. OpenTelemetry's `TracingInterceptor`), Tenuo signs the Proof-of-Possession challenge *inside the workflow sandbox* at `execute_activity()` dispatch time, committing the exact tool and arguments the workflow is authorising. Because PyO3 extensions cannot be re-imported per sandbox task, both `tenuo` and `tenuo_core` must be declared as passthrough modules:

```python
from temporalio.worker.workflow_sandbox import (
    SandboxedWorkflowRunner, SandboxRestrictions,
)

from tenuo.temporal import EnvKeyResolver, TenuoPlugin, TenuoPluginConfig

resolver = EnvKeyResolver()
resolver.preload_keys(["agent1"])  # cache before Worker(...); sandbox PoP cannot read os.environ

interceptor = TenuoPlugin(
    TenuoPluginConfig(
        key_resolver=resolver,
        on_denial="raise",
        trusted_roots=[control_key.public_key],  # required (or tenuo.configure(trusted_roots=[...]) before building config)
        strict_mode=True,  # optional: fail-fast on ambiguous PoP with named constraints
    )
)

worker = Worker(
    client,
    task_queue="my-queue",
    workflows=[MyWorkflow],
    activities=[read_file],
    interceptors=[interceptor],
    workflow_runner=SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "tenuo", "tenuo_core",  # Required: PyO3 extension cannot be re-imported per sandbox task
        )
    ),
)
```

Omitting this causes `ImportError: PyO3 modules may only be initialized once per interpreter process`. The worker may still look healthy while every workflow task fails. See [Sandbox passthrough explained](../../../docs/temporal.md#sandbox-passthrough-explained) in `docs/temporal.md`.

## Architecture

```
Client                    Workflow                    Activity
  |                          |                           |
  |-- set_headers_for_workflow() |                      |
  |-- execute_workflow() --->|                           |
  |                          |                           |
  |                    Inbound interceptor:              |
  |                    Extract Tenuo headers             |
  |                          |                           |
  |                    workflow.execute_activity()       |
  |                          |                           |
  |                    Outbound interceptor:             |
  |                    Compute PoP (transparent)         |
  |                    Inject headers into activity  --->|
  |                          |                           |
  |                          |    Activity interceptor:  |
  |                          |    Verify warrant chain   |
  |                          |    Verify PoP signature   |
  |                          |    Check constraints      |
  |                          |                           |
  |                          |<--- Execute if OK --------|
```

Headers propagate through Temporal's native header mechanism,
so this works in distributed deployments (separate client/worker processes).

PoP is computed in the outbound interceptor using `workflow.now()` for deterministic replay. Workflow code can stay free of Tenuo imports when you use transparent `execute_activity()` (and set `activity_fns` when warranted).

## Security defaults

All security features are fail-closed:

- `require_warrant=True`: activities without warrants are denied
- `block_local_activities=True`: blocks unapproved local activity bypass
- `redact_args_in_logs=True`: redacts argument values in logs
- `trusted_roots` is required (or set via `tenuo.configure(trusted_roots=[...])`); PoP is always verified for warranted activities

## Testing

```bash
cd tenuo-python
pytest tests/e2e/test_temporal_e2e.py -v   # mocked Temporal integration tests (no server)
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `ConfigurationError` … `trusted_roots` | `TenuoPluginConfig` built without roots and no global `configure` | Pass `trusted_roots=[control_key.public_key]` or call `tenuo.configure(trusted_roots=[...])` before constructing the config |
| `ImportError: PyO3 modules ... initialized once` | Missing passthrough modules | Add `with_passthrough_modules("tenuo", "tenuo_core")` to sandbox config |
| `TenuoContextError: No Tenuo headers in store` | Workflow started without headers | Use `execute_workflow_authorized(...)` or call `set_headers_for_workflow(workflow_id, tenuo_headers(...))` before `execute_workflow` |
| `TemporalConstraintViolation: No warrant provided` | Headers not reaching worker | Ensure `TenuoClientInterceptor` is in the client's interceptor list |
| `PopVerificationError: replay detected` | Same activity attempt reached two workers (fleet-wide dedup not configured) | Expected with in-memory dedup and multiple worker pods; configure `pop_dedup_store` with a shared backend for fleet-wide suppression |
| `KeyResolutionError: Cannot resolve key: <id>` | Signing key not found by `KeyResolver` | For `EnvKeyResolver`: set `TENUO_KEY_<key_id>` and call `resolver.preload_keys([...])` before `Worker(...)` (workflows need cached keys; the sandbox blocks `os.environ`). For cloud resolvers: verify secret name, permissions, and region |
| Warning: `PoP signing … uses positional argument keys (arg0, …)` | Warrant uses named field constraints but activity function reference not available | Add `activity_fns=[read_file, ...]` to `TenuoPluginConfig` (same list as `Worker(activities=...)`), or use `tenuo_execute_activity()` |
| `TenuoContextError` (in `strict_mode`) | Same as above but fail-fast is on | See above; remove `strict_mode=True` temporarily to diagnose, then fix `activity_fns` |
| Activity denied despite valid warrant | PoP computation failed silently | Check worker logs for WARNING/ERROR messages from outbound interceptor; verify `key_id` matches a key accessible to `KeyResolver` |
| Child has no warrant / activities always denied | Child started with `workflow.execute_child_workflow()` | Use `tenuo_execute_child_workflow()` ([docs/temporal.md#child-workflow-delegation](../../../docs/temporal.md#child-workflow-delegation)) |

## Learn More

- [Temporal Documentation](https://docs.temporal.io)
- [Tenuo Temporal Integration Docs](https://tenuo.ai/temporal)
- [Tenuo Core Concepts](https://tenuo.ai/concepts)
