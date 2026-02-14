---
title: Temporal Integration
description: Warrant-based authorization for durable workflows
---

# Tenuo Temporal Integration

> **Status**: Implemented (Activity authorization + PoP + Delegation)

## Overview

Tenuo integrates with [Temporal](https://temporal.io) to bring warrant-based authorization to durable workflows. Activities are transparently authorized against the workflow's warrant without code changes to your activity definitions.

**Key Features:**
- **Activity-level authorization**: Each activity execution is authorized against warrant constraints
- **Proof-of-Possession (PoP)**: Mandatory signature verification using Temporal's `scheduled_time` (replay-safe)
- **Warrant propagation**: Warrants flow through workflow headers automatically
- **Child workflow delegation**: Attenuate warrants when spawning child workflows
- **Fail-closed**: Missing or invalid warrants block execution by default
- **Enterprise key management**: VaultKeyResolver, KMSKeyResolver, CompositeKeyResolver

---

## Installation

```bash
uv pip install "tenuo[temporal]"
```

Requires Temporal server running locally or in production.

---

## Quick Start

### Basic Workflow Protection

```python
from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.worker import Worker

from tenuo_core import SigningKey, IssuanceBuilder, Subpath
from tenuo.temporal import (
    TenuoInterceptor,
    TenuoInterceptorConfig,
    EnvKeyResolver,
    tenuo_headers,
    current_warrant,
)

# Define protected activities
@activity.defn
async def read_file(path: str) -> str:
    """Read file - protected by Tenuo."""
    return Path(path).read_text()

@activity.defn
async def write_file(path: str, content: str) -> str:
    """Write file - protected by Tenuo."""
    Path(path).write_text(content)
    return f"Wrote {len(content)} bytes"

# Define workflow
@workflow.defn
class DataProcessingWorkflow:
    @workflow.run
    async def run(self, input_path: str, output_path: str) -> str:
        # Access warrant from context
        warrant = current_warrant()

        # Read input file
        data = await workflow.execute_activity(
            read_file,
            args=[input_path],
            start_to_close_timeout=timedelta(seconds=30),
        )

        # Process and write output
        processed = data.upper()
        await workflow.execute_activity(
            write_file,
            args=[output_path, processed],
            start_to_close_timeout=timedelta(seconds=30),
        )

        return f"Processed {len(data)} bytes"

# Setup
async def main():
    client = await Client.connect("localhost:7233")

    # Generate keys
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    # Issue warrant
    warrant = (
        IssuanceBuilder()
        .holder(agent_key.public_key())
        .capability("read_file", {"path": Subpath("/data/input")})
        .capability("write_file", {"path": Subpath("/data/output")})
        .ttl(3600)
        .mint(control_key)
    )

    # Configure interceptor
    interceptor = TenuoInterceptor(
        TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(),
            on_denial="raise",
        )
    )

    # Start worker with interceptor
    async with Worker(
        client,
        task_queue="data-processing",
        workflows=[DataProcessingWorkflow],
        activities=[read_file, write_file],
        interceptors=[interceptor],  # Add Tenuo interceptor
    ):
        # Execute workflow with warrant
        result = await client.execute_workflow(
            DataProcessingWorkflow.run,
            args=["/data/input/report.txt", "/data/output/report.txt"],
            id="process-001",
            task_queue="data-processing",
            headers=tenuo_headers(warrant, "agent-key-1", agent_key),
        )
```

**What happens:**
1. Workflow starts with warrant in headers
2. Each activity execution is intercepted
3. Warrant constraints are checked (path must match Subpath)
4. Proof-of-Possession signature is verified
5. Activity executes only if authorized

---

## Configuration

### Interceptor Config

```python
from tenuo.temporal import TenuoInterceptorConfig

config = TenuoInterceptorConfig(
    key_resolver=EnvKeyResolver(),        # Required: key resolution strategy
    on_denial="raise",                    # "raise" | "log" | "skip"
    require_warrant=True,                 # Fail-closed: deny if no warrant
    block_local_activities=True,          # Prevent local activity bypass
    redact_args_in_logs=True,             # Prevent secret leaks in logs
    max_chain_depth=10,                   # Max delegation depth
    audit_callback=on_audit,              # Optional audit event handler
    metrics=TenuoMetrics(),               # Optional Prometheus metrics
)
```

### Key Resolvers

**Development: EnvKeyResolver**
```python
from tenuo.temporal import EnvKeyResolver
import os
import base64

# Set environment variable
os.environ["TENUO_KEY_agent1"] = base64.b64encode(
    agent_key.secret_key_bytes()
).decode()

resolver = EnvKeyResolver()  # Reads from TENUO_KEY_{key_id}
```

**Production: VaultKeyResolver**
```python
from tenuo.temporal import VaultKeyResolver

resolver = VaultKeyResolver(
    url="https://vault.company.com:8200",
    mount="secret",
    path_template="tenuo/keys/{key_id}",
    cache_ttl=300,  # 5 minute cache
)
```

**Fallback Chain: CompositeKeyResolver**
```python
from tenuo.temporal import CompositeKeyResolver

resolver = CompositeKeyResolver([
    VaultKeyResolver(url="https://vault.prod"),  # Try Vault first
    EnvKeyResolver(),                            # Fallback to env vars
])
```

---

## Proof-of-Possession

Tenuo enforces mandatory PoP verification for all activity executions. The challenge is computed deterministically using Temporal's `scheduled_time` for replay safety.

### Automatic PoP with tenuo_execute_activity

```python
from tenuo.temporal import tenuo_execute_activity

@workflow.defn
class MyWorkflow:
    @workflow.run
    async def run(self) -> str:
        # Automatically signs PoP challenge
        result = await tenuo_execute_activity(
            read_file,
            args=["/data/report.txt"],
            start_to_close_timeout=timedelta(seconds=30),
        )
        return result
```

### Manual PoP (advanced)

```python
# If you need full control over activity execution
from temporalio import workflow
from tenuo.temporal import current_warrant, current_key_id

info = workflow.info()
warrant = current_warrant()

# Compute challenge
challenge = warrant.compute_pop_challenge(
    workflow_id=info.workflow_id,
    activity_id=info.activity_id,
    tool_name="read_file",
    args={"path": "/data/file.txt"},
    scheduled_time=workflow.now(),
)

# Sign with holder key
pop_signature = signing_key.sign(challenge)

# Pass as header
await workflow.execute_activity(
    read_file,
    args=["/data/file.txt"],
    headers={"x-tenuo-pop": base64.b64encode(pop_signature)},
)
```

---

## Child Workflow Delegation

Attenuate warrants when spawning child workflows:

```python
from tenuo.temporal import attenuated_headers

@workflow.defn
class ParentWorkflow:
    @workflow.run
    async def run(self) -> str:
        # Parent has: read_file + write_file

        # Child gets only read_file with reduced TTL
        result = await workflow.execute_child_workflow(
            ChildWorkflow.run,
            args=["/data/input"],
            headers=attenuated_headers(
                tools=["read_file"],  # Subset of parent tools
                ttl_seconds=60,       # Shorter than parent
            ),
        )
        return result
```

---

## Decorators

### @tool() - Activity-to-Tool Mapping

Map activity names to different tool names in warrants:

```python
from tenuo.temporal import tool

@activity.defn
@tool("read_file")
async def fetch_document(doc_id: str) -> str:
    """Activity name is 'fetch_document', warrant checks 'read_file'."""
    return await storage.get(doc_id)
```

### @unprotected - Local Activities

Mark activities as safe for local execution (bypass interceptor):

```python
from tenuo.temporal import unprotected

@activity.defn
@unprotected
async def get_config_value(key: str) -> str:
    """Internal config lookup - no warrant needed."""
    return config[key]

# Can be used as local activity
await workflow.execute_local_activity(
    get_config_value,
    args=["database_url"],
)
```

---

## Audit Events

Subscribe to authorization decisions:

```python
from tenuo.temporal import TemporalAuditEvent

def on_audit(event: TemporalAuditEvent):
    if event.decision == "ALLOW":
        logger.info(
            f"Allowed: {event.tool} in {event.workflow_type} "
            f"(warrant: {event.warrant_id})"
        )
    else:
        logger.warning(
            f"Denied: {event.tool} in {event.workflow_type} - "
            f"{event.denial_reason}"
        )

config = TenuoInterceptorConfig(
    key_resolver=resolver,
    audit_callback=on_audit,
    audit_allow=True,   # Log allowed actions
    audit_deny=True,    # Log denied actions
)
```

---

## Observability

### Prometheus Metrics

```python
from tenuo.temporal import TenuoMetrics

metrics = TenuoMetrics(prefix="tenuo_temporal")

config = TenuoInterceptorConfig(
    key_resolver=resolver,
    metrics=metrics,
)

# Exposes metrics at /metrics:
# - tenuo_temporal_activities_authorized_total{tool, workflow_type}
# - tenuo_temporal_activities_denied_total{tool, reason, workflow_type}
# - tenuo_temporal_authorization_latency_seconds_bucket{tool}
```

---

## Security Model

### Fail-Closed by Default

All security checks default to deny:

| Check | Missing/Invalid | Behavior |
|-------|----------------|----------|
| Warrant header | Missing | Denied (require_warrant=True) |
| Warrant expired | Expired | Raises WarrantExpired |
| Tool not in warrant | Not allowed | Raises ConstraintViolation |
| Constraint violated | Args don't match | Raises ConstraintViolation |
| PoP signature | Missing/invalid | Raises PopVerificationError |
| Local activity | Protected function | Raises LocalActivityError |

### Replay Safety

PoP challenges use Temporal's `scheduled_time` instead of wall clock time. This ensures deterministic replay without breaking workflow history.

---

## Exceptions

All exceptions include `error_code` for wire format compatibility:

```python
from tenuo.temporal import (
    ConstraintViolation,      # error_code: "CONSTRAINT_VIOLATED"
    WarrantExpired,           # error_code: "WARRANT_EXPIRED"
    ChainValidationError,     # error_code: "CHAIN_INVALID"
    PopVerificationError,     # error_code: "POP_VERIFICATION_FAILED"
    LocalActivityError,       # error_code: "LOCAL_ACTIVITY_BLOCKED"
    KeyResolutionError,       # error_code: "KEY_NOT_FOUND"
)
```

---

## Best Practices

1. **Use tenuo_execute_activity()** for automatic PoP signing
2. **Set up VaultKeyResolver** for production key management
3. **Enable audit logging** to track authorization decisions
4. **Use @unprotected** sparingly - only for truly internal operations
5. **Attenuate warrants** for child workflows to enforce least privilege
6. **Configure metrics** for observability in production
7. **Keep TTLs short** for sensitive operations (minutes, not hours)

---

## Example: Multi-Stage Pipeline

```python
from temporalio import workflow
from tenuo.temporal import current_warrant, attenuated_headers, tenuo_execute_activity

@workflow.defn
class DataPipeline:
    @workflow.run
    async def run(self, data_source: str) -> str:
        warrant = current_warrant()
        logger.info(f"Pipeline running with tools: {warrant.tools()}")

        # Stage 1: Extract (read_file capability)
        raw_data = await tenuo_execute_activity(
            read_file,
            args=[data_source],
            start_to_close_timeout=timedelta(seconds=60),
        )

        # Stage 2: Transform (spawn child with compute capability)
        transformed = await workflow.execute_child_workflow(
            TransformWorkflow.run,
            args=[raw_data],
            headers=attenuated_headers(
                tools=["transform_data"],
                ttl_seconds=300,
            ),
        )

        # Stage 3: Load (write_file capability)
        output_path = "/data/output/result.json"
        await tenuo_execute_activity(
            write_file,
            args=[output_path, transformed],
            start_to_close_timeout=timedelta(seconds=60),
        )

        return f"Pipeline complete: {output_path}"
```

---

## Comparison with Other Integrations

| Integration | Use Case | Durable | PoP | Delegation |
|-------------|----------|---------|-----|------------|
| **OpenAI** | Streaming agents | No | Optional | No |
| **LangChain** | Tool chains | No | Optional | Via context |
| **CrewAI** | Multi-agent crews | No | Yes (Tier 2) | Yes |
| **Temporal** | Long-running workflows | Yes | Mandatory | Yes |

Temporal integration is designed for workflows that may run for hours or days, with full replay support and durable state.

---

## More Information

- [Temporal Documentation](https://docs.temporal.io)
- [Tenuo Core Concepts](./concepts.md)
- [Security Model](./security.md)
- [Example Code](https://github.com/tenuo-ai/tenuo/tree/feat/temporal-integration/tenuo-python/examples/temporal)
