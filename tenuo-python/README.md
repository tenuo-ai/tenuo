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
maturin develop
```

## Quick Start

```python
from tenuo import Keypair, Warrant, Pattern, Range
from datetime import timedelta

# Generate a keypair
keypair = Keypair.generate()

# Issue a warrant
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
```

## MCP Integration

Tenuo provides native support for the [Model Context Protocol](https://modelcontextprotocol.io):

```python
from tenuo import McpConfig, CompiledMcpConfig, Authorizer, PublicKey

# Load MCP configuration
config = McpConfig.from_file("mcp-config.yaml")
compiled = CompiledMcpConfig.compile(config)

# Initialize authorizer
control_plane_key = PublicKey.from_bytes(bytes.fromhex("f32e74b5..."))
authorizer = Authorizer.new(control_plane_key)

# Extract constraints from MCP tool call
arguments = {"path": "/var/log/app.log", "maxSize": 1024}
result = compiled.extract_constraints("filesystem_read", arguments)

# Authorize
warrant = Warrant.from_base64(warrant_chain_base64)
authorizer.check(warrant, "filesystem_read", result.constraints, pop_signature)
```

## Documentation

- **[Website](https://tenuo.github.io/tenuo/)**: Landing page and guides
- **[Rust API](https://docs.rs/tenuo-core)**: Full Rust API documentation
- **[Examples](examples/)**: Python usage examples

## License

MIT OR Apache-2.0

