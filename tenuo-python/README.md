# Tenuo Python SDK

**Capability tokens for AI agents**

[![PyPI](https://img.shields.io/pypi/v/tenuo.svg)](https://pypi.org/project/tenuo/)
[![Python Versions](https://img.shields.io/pypi/pyversions/tenuo.svg)](https://pypi.org/project/tenuo/)

Python bindings for [Tenuo](https://github.com/tenuo/tenuo), providing cryptographically-enforced capability attenuation for AI agent workflows.

## Installation

```bash
pip install tenuo
```

Or from source:

```bash
pip install maturin
cd tenuo-python
maturin develop
```

The package provides a clean Python API that wraps the Rust extension:

```python
from tenuo import Keypair, Warrant, Pattern, Exact, Range
```

## Quick Start

```python
from tenuo import Keypair, Warrant, Pattern, Exact, Range

# Generate a keypair
keypair = Keypair.generate()

# Issue a warrant with constraints
warrant = Warrant.create(
    tool="manage_infrastructure",
    constraints={
        "cluster": Pattern("staging-*"),
        "budget": Range.max_value(10000.0)
    },
    ttl_seconds=3600,
    keypair=keypair
)

# Attenuate for a worker (capabilities shrink)
worker_keypair = Keypair.generate()
worker_warrant = warrant.attenuate(
    constraints={
        "cluster": Exact("staging-web"),
        "budget": Range.max_value(1000.0)
    },
    keypair=worker_keypair
)

# Authorize an action
authorized = worker_warrant.authorize(
    tool="manage_infrastructure",
    args={"cluster": "staging-web", "budget": 500.0}
)
print(f"Authorized: {authorized}")  # True
```

## Pythonic Features

The `tenuo` package provides a clean Python API with additional features:

### Decorators

Use the `@lockdown` decorator to enforce authorization. It supports two patterns:

**Explicit warrant (simple case):**
```python
from tenuo import lockdown, Warrant, Pattern, Range

warrant = Warrant.create(
    tool="upgrade_cluster",
    constraints={"cluster": Pattern("staging-*")},
    ttl_seconds=3600,
    keypair=keypair
)

@lockdown(warrant, tool="upgrade_cluster")
def upgrade_cluster(cluster: str, budget: float):
    # This function can only be called if the warrant authorizes it
    print(f"Upgrading {cluster} with budget {budget}")
    # ... implementation
```

**ContextVar pattern (LangChain/FastAPI):**
```python
from tenuo import lockdown, set_warrant_context

# Set warrant in context (e.g., in FastAPI middleware or LangChain callback)
@lockdown(tool="upgrade_cluster")  # No explicit warrant - uses context
def upgrade_cluster(cluster: str, budget: float):
    # Warrant is automatically retrieved from context
    print(f"Upgrading {cluster} with budget {budget}")

# In your request handler:
with set_warrant_context(warrant):
    upgrade_cluster(cluster="staging-web", budget=5000.0)
```

See [`examples/decorator_example.py`](../examples/decorator_example.py) for a complete example of explicit binding, argument mapping, and the ContextVar pattern.

### Exceptions

Pythonic exceptions for better error handling:

```python
from tenuo import TenuoError, AuthorizationError, WarrantError

try:
    warrant.authorize("tool", args)
except AuthorizationError as e:
    print(f"Authorization failed: {e}")
```

## LangChain Integration

Tenuo integrates seamlessly with LangChain agents and tools. The key pattern is to:

1. **Decorate your tool functions** with `@lockdown(tool="...")`
2. **Set the warrant in context** before running the agent
3. **All tool calls are automatically protected**

### Simple Example

```python
from tenuo import Keypair, Warrant, Pattern, lockdown, set_warrant_context
from langchain.tools import Tool
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI

# 1. Create protected tool function
@lockdown(tool="read_file", extract_args=lambda file_path, **kwargs: {"file_path": file_path})
def read_file(file_path: str) -> str:
    """Read a file. Protected by Tenuo."""
    with open(file_path, 'r') as f:
        return f.read()

# 2. Create warrant that restricts access
keypair = Keypair.generate()
warrant = Warrant.create(
    tool="read_file",
    constraints={"file_path": Pattern("/tmp/*")},  # Only /tmp/ files
    ttl_seconds=3600,
    keypair=keypair
)

# 3. Create LangChain tools and agent
tools = [Tool(name="read_file", func=read_file, description="Read a file")]
llm = ChatOpenAI(model="gpt-3.5-turbo")
agent = create_openai_tools_agent(llm, tools)
executor = AgentExecutor(agent=agent, tools=tools)

# 4. Run agent with warrant protection
with set_warrant_context(warrant):
    response = executor.invoke({"input": "Read /tmp/test.txt"})
    # Agent can only access files matching Pattern("/tmp/*")
```

See [`examples/langchain_simple.py`](../examples/langchain_simple.py) for a complete working example, or [`examples/langchain_integration.py`](../examples/langchain_integration.py) for an advanced example with callbacks.

## MCP Integration

Tenuo provides native support for the [Model Context Protocol](https://modelcontextprotocol.io):

```python
from tenuo import McpConfig, CompiledMcpConfig, Warrant

# Load MCP configuration
config = McpConfig.from_file("mcp-config.yaml")
compiled = CompiledMcpConfig.compile(config)

# Extract constraints from MCP tool call
arguments = {"path": "/var/log/app.log", "maxSize": 1024}
result = compiled.extract_constraints("filesystem_read", arguments)

# Authorize (with warrant chain and PoP signature)
warrant = Warrant.from_base64(warrant_chain_base64)
authorized = warrant.authorize("filesystem_read", result.constraints)
```

See [`examples/mcp_integration.py`](../examples/mcp_integration.py) for a complete example.

## Examples

Run the examples to see Tenuo in action:

```bash
# Basic usage (explicit warrant pattern)
python examples/basic_usage.py

# Decorator patterns (explicit, mapping, and context)
python examples/decorator_example.py

# MCP integration
python examples/mcp_integration.py

# Constraints demonstration
python examples/constraints.py

# Control plane implementation
python examples/control_plane.py

# Kubernetes integration
python examples/kubernetes_integration.py

# LangChain integration
python examples/langchain_simple.py
python examples/langchain_integration.py
```

## Documentation

- **[Website](https://tenuo.github.io/tenuo/)**: Landing page and guides
- **[Rust API](https://docs.rs/tenuo-core)**: Full Rust API documentation
- **[Examples](../examples/)**: Python usage examples

## Security Considerations

### Secret Key Management

The `Keypair.secret_key_bytes()` method creates a copy of the secret key in Python's managed memory. Python's garbage collector does not guarantee secure erasure of secrets, and the key material may persist in memory until garbage collection occurs.

**Best Practices:**
- **Minimize keypair lifetime**: Create keypairs only when needed and let them go out of scope quickly
- **Avoid `secret_key_bytes()` unless necessary**: Only call this method when absolutely required (e.g., for key backup/export)
- **Don't store secret keys in long-lived variables**: Avoid keeping secret key bytes in variables that persist across function calls
- **Use Rust for production key management**: For high-security deployments, consider using the Rust API directly, which provides better memory safety guarantees

**For most use cases**, you should not need to access secret key bytes directly. The `Keypair` object handles signing operations internally, and you can use `public_key()` to share public keys.

### Memory Safety

Tenuo's Python bindings use PyO3 to wrap the Rust core, providing memory safety from corruption. However, Python's memory management model means that secret material copied into Python objects may persist in memory until garbage collection. This is a standard limitation of Python crypto bindings and is consistent with libraries like `cryptography` and `pyca/cryptography`.

## License

MIT OR Apache-2.0
