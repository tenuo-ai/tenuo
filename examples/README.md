# Tenuo Examples

Examples demonstrating Tenuo features and integration patterns.

## Quick Start

```bash
# Install dependencies
cd tenuo-python
pip install -e .
pip install langchain langchain-openai langgraph fastapi uvicorn httpx

# Run the security demo (recommended first)
python examples/secure_agent_demo.py
```

## Examples Overview

### Core Features

| Example | Description |
|---------|-------------|
| [`secure_agent_demo.py`](secure_agent_demo.py) | **Start here!** Prompt injection defense, TTL, PoP, delegation chains |
| [`constraints.py`](constraints.py) | All constraint types: `Pattern`, `Exact`, `Range`, `OneOf`, `CEL` |
| [`decorator_example.py`](decorator_example.py) | `@lockdown` decorator patterns: explicit, mapping, ContextVar |
| [`human_in_the_loop.py`](human_in_the_loop.py) | M-of-N multi-signature approvals for sensitive actions |

### LangChain / LangGraph

| Example | Description |
|---------|-------------|
| [`langchain_integration.py`](langchain_integration.py) | `protect_tools()` for single-agent LangChain apps |
| [`secure_graph_example.py`](secure_graph_example.py) | `SecureGraph` for multi-agent LangGraph with attack demo |

### Infrastructure

| Example | Description |
|---------|-------------|
| [`control_plane.py`](control_plane.py) | FastAPI control plane service |
| [`kubernetes_integration.py`](kubernetes_integration.py) | Kubernetes deployment patterns |
| [`test_gateway_revocation.py`](test_gateway_revocation.py) | Gateway config and revocation |
| [`mcp_integration.py`](mcp_integration.py) | MCP tool constraint extraction |

## Walkthroughs

### 1. Security Demo (`secure_agent_demo.py`)

Interactive demo showing WHY cryptographic authorization matters:

```
DEMO 1: Prompt Injection → Blocked by warrant scope
DEMO 2: TTL Expiration → Temporal blast radius limits  
DEMO 3: Credential Theft → PoP makes stolen warrants useless
DEMO 4: Scope Expansion → Monotonic attenuation enforced
```

### 2. LangChain (`langchain_integration.py`)

Zero Tenuo imports in your tool code:

```python
# Tools are plain functions
def read_file(file_path: str) -> str:
    return open(file_path).read()

# Wrap at setup
from tenuo.langchain import protect_tools
secure_tools = protect_tools([read_file], warrant=warrant, keypair=kp)
```

### 3. SecureGraph (`secure_graph_example.py`)

Multi-agent with dynamic constraints and attack simulation:

```python
from tenuo.langgraph import SecureGraph

config = {
    "nodes": {
        "researcher": {
            "attenuate": {
                "tools": ["search", "read_file"],
                "constraints": {"path": {"pattern": "/data/${state.project_id}/*"}}
            }
        }
    }
}

secure = SecureGraph(graph=graph, config=config, root_warrant=warrant, keypair=kp)
result = secure.invoke({"input": "...", "project_id": "alpha"})
```

### 4. Constraints (`constraints.py`)

All 14 constraint types with examples:

```python
Pattern("staging-*")           # Glob matching
Exact("staging-web")           # Exact value
Range.max_value(1000.0)        # Numeric limits
OneOf(["read", "write"])       # Allowed set
CEL('value.startsWith("s")')   # Complex expressions
```

## Security Best Practices

1. **Always use PoP binding**: `authorized_holder=agent_keypair.public_key()`
2. **Use short TTLs**: 30s-5min for task-scoped warrants
3. **Attenuate narrowly**: Minimum scope needed
4. **Set keypair context**: Enable automatic PoP signatures

## See Also

- [Python SDK README](../tenuo-python/README.md)
- [Kubernetes Guide](../docs/kubernetes-integration.md)
- [LangChain Infographic](../docs/langchain-infographic.html)
