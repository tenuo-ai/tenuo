# Tenuo Python SDK

**Capability tokens for AI agents**

[![PyPI](https://img.shields.io/pypi/v/tenuo.svg)](https://pypi.org/project/tenuo/)
[![Python Versions](https://img.shields.io/pypi/pyversions/tenuo.svg)](https://pypi.org/project/tenuo/)

> **v0.1.0-alpha.7** — See [CHANGELOG](../CHANGELOG.md) for breaking changes.

Python bindings for [Tenuo](https://github.com/tenuo-ai/tenuo), providing cryptographically-enforced capability attenuation for AI agent workflows.

## Installation

```bash
pip install tenuo
```

## Quick Start

### The Safe Path (Recommended)

Keep keys separate from warrants:

```python
from tenuo import Warrant, SigningKey, Pattern

# Warrant in state/storage - serializable, no secrets
warrant = receive_warrant_from_orchestrator()

# Explicit key at call site - keys never in state
key = SigningKey.from_env("MY_SERVICE_KEY")
headers = warrant.auth_headers(key, "search", {"query": "test"})

# Delegation with attenuation
child = warrant.delegate(
    to=worker_pubkey,
    allow={"search": {"query": Pattern("safe*")}},
    ttl=300,
    key=key
)
```

### BoundWarrant (For Repeated Operations)

When you need to make many calls with the same warrant+key:

```python
from tenuo import Warrant, SigningKey

warrant = receive_warrant()
key = SigningKey.from_env("MY_KEY")

# Bind key for repeated use
bound = warrant.bind_key(key)

for item in items:
    headers = bound.auth_headers("process", {"item": item})
    # ...

# Authorize directly
if bound.authorize("search", {"query": "test"}):
    # Authorized!
    pass

# ⚠️ BoundWarrant is non-serializable (contains key)
# Use bound.warrant to get the plain Warrant for storage
```

### Low-Level API (Full Control)

```python
from tenuo import SigningKey, Warrant, Pattern, Range

# Generate keypair
keypair = SigningKey.generate()

# Issue warrant with fluent builder
warrant = (Warrant.builder()
    .capability("manage_infrastructure", {
        "cluster": Pattern("staging-*"),
        "replicas": Range.max_value(15)
    })
    .holder(keypair.public_key)
    .ttl(3600)
    .issue(keypair))

# Authorize with Proof-of-Possession
args = {"cluster": "staging-web", "replicas": 5}
pop_sig = warrant.create_pop_signature(keypair, "manage_infrastructure", args)
authorized = warrant.authorize(
    tool="manage_infrastructure",
    args=args,
    signature=bytes(pop_sig)
)
```

## Installation Options

```bash
pip install tenuo                # Core only
pip install tenuo[fastapi]       # + FastAPI integration
pip install tenuo[langchain]     # + LangChain
pip install tenuo[langgraph]     # + LangGraph (includes LangChain)
pip install tenuo[mcp]           # + MCP client (Python ≥3.10)
pip install tenuo[dev]           # Development tools
```

## Key Management

### Loading Keys

```python
from tenuo import SigningKey

# From environment variable (auto-detects base64/hex)
key = SigningKey.from_env("TENUO_ROOT_KEY")

# From file (auto-detects format)
key = SigningKey.from_file("/run/secrets/tenuo-key")

# Generate new
key = SigningKey.generate()
```

### KeyRegistry (For LangGraph)

Thread-safe key management for multi-agent workflows:

```python
from tenuo import KeyRegistry, SigningKey

registry = KeyRegistry.get_instance()
registry.register("worker", SigningKey.from_env("WORKER_KEY"))
registry.register("orchestrator", SigningKey.from_env("ORCH_KEY"))

# Retrieve
key = registry.get("worker")
```

### Keyring (For Key Rotation)

```python
from tenuo import Keyring, SigningKey

keyring = Keyring(
    root=SigningKey.from_env("CURRENT_KEY"),
    previous=[SigningKey.from_env("OLD_KEY")]
)

# All public keys for verification
all_pubkeys = keyring.all_public_keys
```

## FastAPI Integration

```python
from fastapi import FastAPI, Depends
from tenuo.fastapi import TenuoGuard, SecurityContext, configure_tenuo

app = FastAPI()
configure_tenuo(app, trusted_issuers=[issuer_pubkey])

@app.get("/search")
async def search(
    query: str,
    ctx: SecurityContext = Depends(TenuoGuard("search"))
):
    # ctx.warrant is verified
    # ctx.args contains extracted arguments
    return {"results": [...]}
```

## LangChain Integration

```python
from tenuo import Warrant, SigningKey
from tenuo.langchain import protect

# Create bound warrant
keypair = SigningKey.generate()
warrant = Warrant.builder().tool("search").issue(keypair)
bound = warrant.bind_key(keypair)

# Protect tools
from langchain_community.tools import DuckDuckGoSearchRun
protected_tools = protect([DuckDuckGoSearchRun()], bound_warrant=bound)

# Use in agent
agent = create_openai_tools_agent(llm, protected_tools, prompt)
```

### Using `@lockdown` Decorator

```python
from tenuo import lockdown, set_warrant_context, set_signing_key_context

@lockdown(tool="read_file")
def read_file(path: str) -> str:
    return open(path).read()

with set_warrant_context(warrant), set_signing_key_context(keypair):
    content = read_file("/tmp/test.txt")  # ✅ Authorized
    content = read_file("/etc/passwd")    # ❌ Blocked
```

## LangGraph Integration

```python
from tenuo import KeyRegistry
from tenuo.langgraph import secure, TenuoToolNode, auto_load_keys

# Load keys from TENUO_KEY_* environment variables
auto_load_keys()

# Wrap pure nodes
def my_agent(state):
    return {"messages": [...]}

graph.add_node("agent", secure(my_agent, key_id="worker"))
graph.add_node("tools", TenuoToolNode([search, calculator]))

# Run with warrant in state
state = {"warrant": warrant, "messages": [...]}
config = {"configurable": {"tenuo_key_id": "worker"}}
result = graph.invoke(state, config=config)
```

### Nodes That Need Warrant Access

```python
from tenuo.langgraph import tenuo_node
from tenuo import BoundWarrant

@tenuo_node
def smart_router(state, bound_warrant: BoundWarrant):
    if bound_warrant.preview_can("search"):
        return {"next": "researcher"}
    return {"next": "fallback"}
```

## Debugging

### `why_denied()` - Understand Failures

```python
result = warrant.why_denied("read_file", {"path": "/etc/passwd"})
if result.denied:
    print(f"Code: {result.deny_code}")
    print(f"Field: {result.field}")
    print(f"Suggestion: {result.suggestion}")
```

### `diagnose()` - Inspect Warrants

```python
from tenuo import diagnose

diagnose(warrant)
# Prints: ID, TTL, constraints, tools, etc.
```

### Convenience Properties

```python
# Time remaining
warrant.ttl_remaining  # timedelta
warrant.ttl            # alias for ttl_remaining

# Status
warrant.is_expired     # bool
warrant.is_terminal    # bool (can't delegate further)

# Human-readable
warrant.capabilities   # dict of tool -> constraints
```

## MCP Integration

_(Requires Python ≥3.10)_

```python
from tenuo.mcp import SecureMCPClient

async with SecureMCPClient("python", ["mcp_server.py"]) as client:
    tools = await client.get_protected_tools()
    
    async with root_task(Capability("read_file", path=Pattern("/data/*"))):
        result = await tools["read_file"](path="/data/file.txt")
```

## Security Considerations

### BoundWarrant Serialization

`BoundWarrant` contains a private key and **cannot be serialized**:

```python
bound = warrant.bind_key(key)

# ❌ This raises TypeError
pickle.dumps(bound)
json.dumps(bound)

# ✅ Extract warrant for storage
state["warrant"] = bound.warrant  # Plain Warrant is serializable
```

### preview_can() is Not Authorization

```python
# ✅ OK for UI hints
if bound.preview_can("delete"):
    show_delete_button()

# ❌ WRONG: Not a security check!
if bound.preview_can("delete"):
    delete_database()  # No PoP verification!

# ✅ Correct: Use authorize()
if bound.authorize("delete", {"target": "users"}):
    delete_database()
```

### Error Details Not Exposed

Authorization errors are opaque by default:

```python
# Client sees: "Authorization denied (ref: abc123)"
# Logs show: "[abc123] Constraint failed: path=/etc/passwd, expected=Pattern(/data/*)"
```

## Examples

```bash
# Basic usage
python examples/basic_usage.py

# FastAPI integration
python examples/fastapi_integration.py

# LangGraph protected
python examples/langgraph_protected.py

# MCP integration
python examples/mcp_integration.py
```

## Documentation

- **[Quickstart](https://tenuo.ai/quickstart)** — Get running in 5 minutes
- **[FastAPI](https://tenuo.ai/fastapi)** — Zero-boilerplate API protection
- **[LangChain](https://tenuo.ai/langchain)** — Tool protection
- **[LangGraph](https://tenuo.ai/langgraph)** — Multi-agent security
- **[Security](https://tenuo.ai/security)** — Threat model, best practices
- **[API Reference](https://tenuo.ai/api-reference)** — Full SDK docs

## License

MIT OR Apache-2.0
