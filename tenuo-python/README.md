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

See `examples/context_pattern.py` for a complete LangChain/FastAPI integration example.

### Exceptions

Pythonic exceptions for better error handling:

```python
from tenuo import TenuoError, AuthorizationError, WarrantError

try:
    warrant.authorize("tool", args)
except AuthorizationError as e:
    print(f"Authorization failed: {e}")
```

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

See `examples/mcp_integration.py` for a complete example.

## Examples

Run the examples to see Tenuo in action:

```bash
# Basic usage (explicit warrant pattern)
python examples/basic_usage.py

# ContextVar pattern (LangChain/FastAPI integration)
python examples/context_pattern.py

# Decorator with explicit warrant
python examples/decorator_example.py

# MCP integration
python examples/mcp_integration.py
```

## Documentation

- **[Website](https://tenuo.github.io/tenuo/)**: Landing page and guides
- **[Rust API](https://docs.rs/tenuo-core)**: Full Rust API documentation
- **[Examples](examples/)**: Python usage examples

## License

MIT OR Apache-2.0
