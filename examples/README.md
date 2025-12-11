# Tenuo Examples

This directory contains examples demonstrating various Tenuo features and integration patterns.

## Quick Start

```bash
# Install dependencies
cd tenuo-python
pip install -e .
pip install langchain langchain-openai langgraph fastapi uvicorn httpx

# Run any example
python examples/basic_usage.py
```

## Examples Overview

### Core Features

| Example | Description |
|---------|-------------|
| [`basic_usage.py`](basic_usage.py) | Keypair generation, warrant creation, attenuation, authorization, and PoP binding |
| [`constraints.py`](constraints.py) | All constraint types: `Pattern`, `Exact`, `Range`, `OneOf`, `CEL` |
| [`decorator_example.py`](decorator_example.py) | `@lockdown` decorator patterns: explicit, mapping, and ContextVar |
| [`human_in_the_loop.py`](human_in_the_loop.py) | M-of-N multi-signature approvals for sensitive actions |
| [`end_to_end_pop.py`](end_to_end_pop.py) | Complete Proof-of-Possession flow |

### LangChain / LangGraph Integration

| Example | Description |
|---------|-------------|
| [`langchain_integration.py`](langchain_integration.py) | `protect_tools()` pattern for single-agent LangChain apps |
| [`langchain_auto_instrumentation.py`](langchain_auto_instrumentation.py) | Auto-instrumentation with config-based constraints |
| [`secure_graph_example.py`](secure_graph_example.py) | `SecureGraph` for multi-agent LangGraph with dynamic constraints |
| [`tenuo-graph.yaml`](tenuo-graph.yaml) | SecureGraph configuration file example |

### Infrastructure & Deployment

| Example | Description |
|---------|-------------|
| [`control_plane.py`](control_plane.py) | FastAPI control plane service for agent enrollment |
| [`cp_enrollment_tester.sh`](cp_enrollment_tester.sh) | Shell script to test control plane enrollment |
| [`kubernetes_integration.py`](kubernetes_integration.py) | Kubernetes deployment patterns |
| [`gateway-config.yaml`](gateway-config.yaml) | Gateway configuration for HTTP routing |
| [`test_gateway_revocation.py`](test_gateway_revocation.py) | Gateway config loading and revocation testing |

### MCP (Model Context Protocol)

| Example | Description |
|---------|-------------|
| [`mcp_integration.py`](mcp_integration.py) | MCP tool constraint extraction |
| [`mcp-config.yaml`](mcp-config.yaml) | MCP configuration file example |

## Example Walkthroughs

### 1. Basic Usage (`basic_usage.py`)

Demonstrates the fundamental Tenuo workflow:

```python
# Generate keypairs
control_keypair = Keypair.generate()
worker_keypair = Keypair.generate()

# Create root warrant with constraints
root_warrant = Warrant.create(
    tool="manage_infrastructure",
    constraints={"cluster": Pattern("staging-*"), "budget": Range.max_value(10000.0)},
    ttl_seconds=3600,
    keypair=control_keypair
)

# Attenuate for worker (constraints shrink)
worker_warrant = root_warrant.attenuate(
    constraints={"cluster": Exact("staging-web"), "budget": Range.max_value(1000.0)},
    keypair=worker_keypair
)

# Authorize action
result = worker_warrant.authorize("manage_infrastructure", {"cluster": "staging-web", "budget": 500.0})
```

### 2. LangChain Integration (`langchain_integration.py`)

Shows the "zero Tenuo imports in user code" pattern:

```python
# Tools are plain functions - NO Tenuo imports
def read_file(file_path: str) -> str:
    return open(file_path).read()

def write_file(file_path: str, content: str) -> str:
    open(file_path, 'w').write(content)
    return "OK"

# Wrap tools at setup time
from tenuo.langchain import protect_tools

secure_tools = protect_tools(
    tools=[read_file, write_file],
    warrant=warrant,
    keypair=keypair,
    config={"read_file": {"constraints": {"file_path": {"pattern": "/tmp/*"}}}}
)
```

### 3. SecureGraph (`secure_graph_example.py`)

Demonstrates automatic warrant flow in multi-agent LangGraph:

```python
from tenuo.langgraph import SecureGraph

# Config with dynamic constraints
config = {
    "nodes": {
        "researcher": {
            "attenuate": {
                "tools": ["search", "read_file"],
                "constraints": {"file_path": {"pattern": "/data/${state.project_id}/*"}}
            }
        }
    }
}

# Wrap graph
secure = SecureGraph(graph=graph, config=config, root_warrant=warrant, keypair=kp)

# State values interpolated into constraints at runtime
result = secure.invoke({"input": "...", "project_id": "alpha"})
```

### 4. Human-in-the-Loop (`human_in_the_loop.py`)

Multi-signature approvals for sensitive operations:

```python
# Create warrant requiring 2-of-3 admin approvals
warrant = Warrant.create(
    tool="delete_database",
    constraints={"db_name": Exact("production-db")},
    required_approvers=[admin_alice.public_key(), admin_bob.public_key(), admin_charlie.public_key()],
    min_approvals=2,
    ...
)

# Agent attempts action
authorizer.authorize(warrant, "delete_database", args, signature=pop_sig, approvals=[])
# ❌ Denied: 0/2 approvals

# With approvals
authorizer.authorize(warrant, "delete_database", args, signature=pop_sig, 
                     approvals=[approval_alice, approval_bob])
# ✅ Authorized: 2/2 approvals
```

## Security Best Practices

1. **Always use PoP binding**: `authorized_holder=agent_keypair.public_key()`
2. **Use short TTLs**: Task-scoped warrants should be 30s-5min
3. **Attenuate narrowly**: Give the minimum scope needed
4. **Set keypair context**: Enable automatic PoP signatures

## See Also

- [Python SDK README](../tenuo-python/README.md)
- [Kubernetes Integration Guide](../docs/kubernetes-integration.md)
- [LangChain Spec](../docs/langchain_spec.md)
