# Tenuo Python SDK

**Capability tokens for AI agents**

[![PyPI](https://img.shields.io/pypi/v/tenuo.svg)](https://pypi.org/project/tenuo/)
[![Python Versions](https://img.shields.io/pypi/pyversions/tenuo.svg)](https://pypi.org/project/tenuo/)

> **v0.1.0-alpha.4** — See [CHANGELOG](../CHANGELOG.md) for breaking changes.

Python bindings for [Tenuo](https://github.com/tenuo-ai/tenuo), providing cryptographically-enforced capability attenuation for AI agent workflows.

## Installation

```bash
pip install tenuo
```

## Quick Start

The package provides a clean Python API that wraps the Rust extension:

```python
from tenuo import SigningKey, Warrant, Pattern, Exact, Range

# Generate a keypair
keypair = SigningKey.generate()

# Issue a warrant with fluent builder (recommended)
warrant = (Warrant.builder()
    .capability("manage_infrastructure", {
        "cluster": Pattern("staging-*"),
        "replicas": Range.max_value(15)
    })
    .holder(keypair.public_key)         # Bind to self initially
    .ttl(3600)
    .issue(keypair))

# Attenuate for a worker (POLA: explicitly specify capabilities)
worker_keypair = SigningKey.generate()
worker_warrant = (warrant.attenuate_builder()
    .with_capability("manage_infrastructure", {
        "cluster": Exact("staging-web"),  # Narrowed from staging-*
        "replicas": Range.max_value(10)   # Reduced from 15
    })
    .with_holder(worker_keypair.public_key)
    .delegate(keypair))  # keypair signs (they hold the parent warrant)

# Note: As of v0.1.0-alpha.4, attenuated warrants start with NO capabilities
# by default (Principle of Least Authority). Use inherit_all() to keep all
# parent capabilities, then narrow specific ones.

# Authorize an action (requires Proof-of-Possession)
# See docs/security.md for PoP replay prevention best practices.
#
# 1. Create a PoP signature using the worker's private key
args = {"cluster": "staging-web", "replicas": 5}
pop_signature = worker_warrant.create_pop_signature(worker_keypair, "manage_infrastructure", args)

# 2. Authorize with the signature
# Note: signature must be converted to bytes
authorized = worker_warrant.authorize(
    tool="manage_infrastructure",
    args=args,
    signature=bytes(pop_signature)
)
print(f"Authorized: {authorized}")  # True
```

## Installation Options

### With Framework Support

For LangChain integration:
```bash
pip install tenuo[langchain]
```

For LangGraph integration (includes LangChain):
```bash
pip install tenuo[langgraph]
```

### Development

```bash
pip install tenuo[dev]
```

This includes all optional dependencies plus development tools (pytest, mypy, ruff).

### From Source

```bash
pip install maturin
cd tenuo-python
maturin develop
```

## Security Considerations

### Secret Key Management

The `SigningKey.secret_key_bytes()` method creates a copy of the secret key in Python's managed memory. Python's garbage collector does not guarantee secure erasure of secrets, and the key material may persist in memory until garbage collection occurs.

**Best Practices:**
- **Minimize signing key lifetime**: Create keys only when needed and let them go out of scope quickly
- **Avoid `secret_key_bytes()` unless necessary**: Only call this method when absolutely required (e.g., for key backup/export)
- **Don't store secret keys in long-lived variables**: Avoid keeping secret key bytes in variables that persist across function calls
- **Use Rust for production key management**: For high-security deployments, consider using the Rust API directly, which provides better memory safety guarantees

**For most use cases**, you should not need to access secret key bytes directly. The `SigningKey` object handles signing operations internally, and you can use `public_key` (property) to share public keys.

### Memory Safety

Tenuo's Python bindings use PyO3 to wrap the Rust core, providing memory safety from corruption. However, Python's memory management model means that secret material copied into Python objects may persist in memory until garbage collection. This is a standard limitation of Python crypto bindings and is consistent with libraries like `cryptography` and `pyca/cryptography`.

## Pythonic Features

The `tenuo` package provides a clean Python API with additional features:

### Decorators

Use the `@lockdown` decorator to enforce authorization. It supports two patterns:

**Explicit warrant (simple case):**
```python
from tenuo import lockdown, Warrant, Pattern, Range

warrant = (Warrant.builder()
    .capability("scale_cluster", {"cluster": Pattern("staging-*")})
    .holder(keypair.public_key)
    .ttl(3600)
    .issue(keypair))

@lockdown(warrant, tool="scale_cluster")
def scale_cluster(cluster: str, replicas: int):
    # This function can only be called if the warrant authorizes it
    print(f"Scaling {cluster} to {replicas} replicas")
    # ... implementation
```

**ContextVar pattern (LangChain/FastAPI):**
```python
from tenuo import lockdown, set_warrant_context, set_signing_key_context

# Set warrant in context (e.g., in FastAPI middleware or LangChain callback)
@lockdown(tool="scale_cluster")  # No explicit warrant - uses context
def scale_cluster(cluster: str, replicas: int):
    # Warrant is automatically retrieved from context
    print(f"Scaling {cluster} to {replicas} replicas")

# In your request handler:
# Set BOTH warrant and keypair in context (required for PoP)
with set_warrant_context(warrant), set_signing_key_context(keypair):
    scale_cluster(cluster="staging-web", replicas=5)
```

See `examples/context_pattern.py` for a complete LangChain/FastAPI integration example.

### Exceptions

Pythonic exceptions for better error handling:

```python
from tenuo import TenuoError, AuthorizationError, WarrantError

try:
    # Create PoP signature first
    pop_sig = warrant.create_pop_signature(keypair, "tool", args)
    warrant.authorize("tool", args, signature=bytes(pop_sig))
except AuthorizationError as e:
    print(f"Authorization failed: {e}")
```

## LangChain Integration

### `secure_agent()` - One-Liner Setup (Recommended)

The simplest way to protect LangChain tools:

```python
from tenuo import SigningKey, root_task_sync, Capability
from tenuo.langchain import secure_agent
from langchain_community.tools import DuckDuckGoSearchRun
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI

# One line to secure your tools
kp = SigningKey.generate()
tools = secure_agent(
    [DuckDuckGoSearchRun()],
    issuer_keypair=kp,
    warn_on_missing_warrant=True  # Loud warnings if you forget context
)

# Create agent as normal
llm = ChatOpenAI(model="gpt-3.5-turbo")
agent = create_openai_tools_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)

# Run with scoped authority
with root_task_sync(Capability("duckduckgo_search", query="*")):
    result = executor.invoke({"input": "What's the latest AI news?"})
```

### Protecting Custom Tool Functions

For your own tools, use the `@lockdown` decorator:

```python
from tenuo import lockdown, set_warrant_context, set_signing_key_context

@lockdown(tool="read_file")
def read_file(file_path: str) -> str:
    """Read a file. Protected by Tenuo."""
    with open(file_path, 'r') as f:
        return f.read()

# Set context and call
with set_warrant_context(warrant), set_signing_key_context(keypair):
    content = read_file("/tmp/test.txt")
```

See `examples/langchain_simple.py` for a complete working example.

## LangGraph Integration

### `TenuoToolNode` - Drop-in ToolNode Replacement

For LangGraph users, `TenuoToolNode` is a drop-in replacement for `ToolNode`:

```python
from tenuo import root_task_sync
from tenuo.langgraph import TenuoToolNode

# Before (manual protection):
# protected = protect_langchain_tools(tools)
# tool_node = ToolNode(protected)

# After (automatic protection):
tool_node = TenuoToolNode([search, calculator])

graph.add_node("tools", tool_node)

# Run with authorization
with root_task_sync(Capability("search"), Capability("calculator")):
    result = graph.invoke({"messages": [...]})
```

### Scoping Graph Nodes

Use `@tenuo_node` to scope authority for specific nodes:

```python
from tenuo.langgraph import tenuo_node

@tenuo_node(Capability("search", query="*public*"))
async def researcher(state):
    # Only search tool allowed, query must contain "public"
    return await search_tool(state["query"])
```

## Diff-Style Error Messages

When authorization fails, Tenuo provides detailed error messages showing exactly what went wrong:

```python
from tenuo import AuthorizationDenied

# Error output shows expected vs received:
# Access denied for tool 'read_file'
#
#   ❌ path:
#      Expected: Pattern("/data/*")
#      Received: '/etc/passwd'
#      Reason: Pattern does not match
#   ✅ size: OK
```

This makes debugging authorization issues fast and straightforward.

## MCP Integration

Tenuo provides full [Model Context Protocol](https://modelcontextprotocol.io) client integration:

```python
from tenuo.mcp import SecureMCPClient
from tenuo import configure, root_task, Capability, Pattern, SigningKey

# Configure Tenuo
keypair = SigningKey.generate()
configure(issuer_key=keypair)

# Connect to MCP server
async with SecureMCPClient("python", ["mcp_server.py"]) as client:
    # Auto-discover and protect tools
    protected_tools = await client.get_protected_tools()
    
    # Use with warrant authorization
    async with root_task(Capability("read_file", path=Pattern("/data/*"))):
        result = await protected_tools["read_file"](path="/data/file.txt")
```

**Requires Python ≥3.10** (MCP SDK limitation)

See `examples/mcp_client_demo.py` for a complete end-to-end example with a real MCP server.

## Audit Logging

Tenuo provides SIEM-compatible structured audit logging for all authorization decisions:

```python
from tenuo import audit_logger, AuditEventType

# Configure audit logger (optional, defaults to stdout)
# audit_logger.configure(service_name="my-service")

# Authorization events are automatically logged by @lockdown and protect_tools
# You can also log manually:
audit_logger.log_authorization_success(
    warrant_id=warrant.id,
    tool="read_file",
    constraints={"path": "/tmp/test.txt"}
)
```

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

- **[Concepts](https://tenuo.ai/concepts)**: Why Tenuo? Problem/solution
- **[API Reference](https://tenuo.ai/api-reference)**: Python SDK reference
- **[Constraints](https://tenuo.ai/constraints)**: Constraint types and usage
- **[LangChain Integration](https://tenuo.ai/langchain)**: Tool protection
- **[Security Model](https://tenuo.ai/security)**: Threat model, best practices
- **[Examples](examples/README.md)**: Python usage examples


## License

MIT OR Apache-2.0
