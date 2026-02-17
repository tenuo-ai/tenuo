# Tenuo Temporal Integration Examples

Warrant-based authorization for Temporal workflows and activities.

## Prerequisites

1. **Temporal Server**

```bash
brew install temporal            # macOS
temporal server start-dev        # Start dev server
```

2. **Python Dependencies**

```bash
pip install "tenuo[temporal]"
```

## Examples

| Example | Pattern | What it demonstrates |
|---------|---------|---------------------|
| [`authorized_workflow_demo.py`](authorized_workflow_demo.py) | **AuthorizedWorkflow** (recommended) | Base class with `self.execute_authorized_activity()`, parallel reads via `asyncio.gather`, fail-fast header validation |
| [`demo.py`](demo.py) | `tenuo_execute_activity()` | Lower-level API, sequential + parallel reads, unauthorized access denial |
| [`multi_warrant.py`](multi_warrant.py) | Multi-tenant isolation | Concurrent workflows with distinct warrants scoped to separate directories |
| [`delegation.py`](delegation.py) | Warrant delegation | Per-stage pipeline authorization with attenuated warrants |

### Quick start

```bash
temporal server start-dev        # Terminal 1
python authorized_workflow_demo.py  # Terminal 2
```

## Two workflow patterns

### AuthorizedWorkflow (recommended)

Subclass `AuthorizedWorkflow` for automatic header validation and PoP:

```python
@workflow.defn
class MyWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, path: str) -> str:
        return await self.execute_authorized_activity(
            read_file, args=[path],
            start_to_close_timeout=timedelta(seconds=30),
        )
```

`AuthorizedWorkflow` validates Tenuo headers at workflow start — if they're missing, the workflow fails immediately instead of mid-execution.

### tenuo_execute_activity (advanced)

Use the free function when you need multi-warrant or delegation patterns:

```python
@workflow.defn
class PipelineWorkflow:
    @workflow.run
    async def run(self, path: str) -> str:
        return await tenuo_execute_activity(
            read_file, args=[path],
            start_to_close_timeout=timedelta(seconds=30),
        )
```

## Worker setup (required)

Tenuo's core is a PyO3 native module that must bypass Temporal's workflow sandbox:

```python
from temporalio.worker.workflow_sandbox import (
    SandboxedWorkflowRunner, SandboxRestrictions,
)

interceptor = TenuoInterceptor(
    TenuoInterceptorConfig(
        key_resolver=EnvKeyResolver(),
        on_denial="raise",
        trusted_roots=[control_key.public_key],
        audit_callback=on_audit,
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
            "tenuo", "tenuo_core",  # Required for PoP
        )
    ),
)
```

## Architecture

```
Client                    Workflow                    Activity
  |                          |                           |
  |-- set_headers()          |                           |
  |-- execute_workflow() --->|                           |
  |                          |                           |
  |                    Inbound interceptor:              |
  |                    Extract Tenuo headers             |
  |                          |                           |
  |                    execute_authorized_activity()     |
  |                    Sign PoP challenge                |
  |                          |                           |
  |                    Outbound interceptor:             |
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

## Security defaults

All security features are fail-closed:

- `require_warrant=True` — activities without warrants are denied
- `block_local_activities=True` — prevents bypass via local activities
- `redact_args_in_logs=True` — prevents secret leaks in logs
- PoP verification is mandatory when `trusted_roots` is set

## Testing

```bash
cd tenuo-python
pytest tests/test_temporal_e2e.py -v    # 31 integration tests
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `ImportError: PyO3 modules ... initialized once` | Missing passthrough modules | Add `with_passthrough_modules("tenuo", "tenuo_core")` to sandbox config |
| `TenuoContextError: No Tenuo headers in store` | Workflow started without headers | Call `client_interceptor.set_headers(tenuo_headers(...))` before `execute_workflow` |
| `ConstraintViolation: No warrant provided` | Headers not reaching worker | Ensure `TenuoClientInterceptor` is in the client's interceptor list |
| `Incorrect padding` / `signature must be 64 bytes` | Direct `workflow.execute_activity()` call | Use `tenuo_execute_activity()` or `self.execute_authorized_activity()` instead |

## Learn More

- [Temporal Documentation](https://docs.temporal.io)
- [Tenuo Temporal Integration Docs](https://tenuo.ai/temporal)
- [Tenuo Core Concepts](https://tenuo.ai/concepts)
