# Tenuo Temporal Integration Example

This example demonstrates how to use Tenuo's warrant-based authorization with Temporal workflows.

## Overview

Temporal is a durable workflow orchestration platform. This integration brings Tenuo's capability-based authorization to Temporal workflows and activities, ensuring that:

- Activities are authorized against warrant constraints
- Proof-of-Possession (PoP) is verified for every activity execution
- Warrants propagate through workflow headers automatically
- Authorization checks are replay-safe using Temporal's scheduled_time

## Prerequisites

1. **Temporal Server**: You need a running Temporal server

```bash
# Install Temporal CLI
brew install temporal  # macOS
# or download from https://docs.temporal.io/cli

# Start development server
temporal server start-dev
```

2. **Python Dependencies**

```bash
pip install "tenuo[temporal]"
```

## Running the Demo

```bash
# Make sure Temporal server is running
temporal server start-dev

# In another terminal, run the demo
python demo.py
```

## What the Demo Shows

The demo creates a workflow that:

1. **Issues a Warrant**: Control plane issues a warrant with constraints
   - `read_file`: Limited to `/tmp/tenuo-demo` directory (Subpath constraint)
   - `list_directory`: Same constraint
   - TTL: 1 hour

2. **Worker with Interceptor**: Worker is configured with TenuoInterceptor
   - All activity executions are automatically authorized
   - PoP verification is mandatory
   - Fail-closed: missing warrants block execution

3. **Workflow Execution**: Workflow lists and reads files
   - Activities execute only if authorized
   - Attempts to access files outside allowed paths are blocked

4. **Demonstrates Denial**: Shows constraint enforcement
   - Attempting to access `/etc` directory is blocked
   - Authorization errors are raised

## Key Components

### Interceptor Configuration

```python
interceptor = TenuoInterceptor(
    TenuoInterceptorConfig(
        key_resolver=EnvKeyResolver(),  # Resolves signing keys
        on_denial="raise",              # Fail-closed behavior
        audit_callback=on_audit,        # Optional audit logging
    )
)
```

### Warrant Headers

```python
# Start workflow with warrant
result = await client.execute_workflow(
    MyWorkflow.run,
    args=[...],
    headers=tenuo_headers(warrant, "key-id", signing_key),
)
```

### Activity Protection

Activities require no code changes. Authorization is enforced by the interceptor:

```python
@activity.defn
async def read_file(path: str) -> str:
    """Automatically protected by Tenuo."""
    return Path(path).read_text()
```

## Architecture

```
Control Plane          Worker                  Activity
    |                    |                        |
    |-- Issue Warrant -->|                        |
    |                    |-- Start Workflow ----->|
    |                    |                        |
    |                    |<- Interceptor ---------|
    |                    |   (Check warrant)      |
    |                    |   (Verify PoP)         |
    |                    |   (Check constraints)  |
    |                    |                        |
    |                    |-- Execute if allowed ->|
```

## Production Considerations

### Key Management

Use VaultKeyResolver in production:

```python
from tenuo.temporal import VaultKeyResolver

resolver = VaultKeyResolver(
    url="https://vault.company.com:8200",
    path_template="tenuo/keys/{key_id}",
    cache_ttl=300,
)
```

### Observability

Enable metrics and audit logging:

```python
from tenuo.temporal import TenuoMetrics

metrics = TenuoMetrics()
config = TenuoInterceptorConfig(
    key_resolver=resolver,
    audit_callback=on_audit,
    metrics=metrics,  # Prometheus metrics
)
```

### Security Defaults

All security features are fail-closed by default:
- `require_warrant=True`: Activities without warrants are denied
- `block_local_activities=True`: Prevents bypass via local activities
- `redact_args_in_logs=True`: Prevents secret leaks in logs
- PoP verification is mandatory (no opt-out)

## Testing

Run the integration tests:

```bash
cd tenuo-python
pytest tests/test_temporal.py -v
pytest tests/test_temporal_integration.py -v
```

Tests verify:
- Configuration defaults
- Decorator behavior (@tool, @unprotected)
- Exception error codes
- Audit event structure
- Chain depth validation
- Warrant expiration

## Learn More

- [Temporal Documentation](https://docs.temporal.io)
- [Tenuo Temporal Integration Docs](https://tenuo.ai/temporal)
- [Tenuo Core Concepts](https://tenuo.ai/concepts)
- [Security Model](https://tenuo.ai/security)
