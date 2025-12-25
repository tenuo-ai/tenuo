# Tenuo Python SDK

**Capability tokens for AI agents**

[![PyPI](https://img.shields.io/pypi/v/tenuo.svg)](https://pypi.org/project/tenuo/)
[![Python Versions](https://img.shields.io/pypi/pyversions/tenuo.svg)](https://pypi.org/project/tenuo/)

> **Status: v0.1 Alpha** — See [CHANGELOG](../CHANGELOG.md) for breaking changes.

Python bindings for [Tenuo](https://github.com/tenuo-ai/tenuo), providing cryptographically-enforced capability attenuation for AI agent workflows.

## Installation

```bash
pip install tenuo
```

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/tenuo-ai/tenuo/blob/main/notebooks/tenuo_demo.ipynb)
[![Explorer](https://img.shields.io/badge/🔬_Explorer-decode_warrants-00d4ff)](https://tenuo.dev/explorer)

## Quick Start

### 30-Second Demo (Copy-Paste)

```python
from tenuo import configure, SigningKey, mint_sync, guard, Capability, Pattern

configure(issuer_key=SigningKey.generate(), dev_mode=True, audit_log=False)

@guard(tool="search")
def search(query: str) -> str:
    return f"Results for: {query}"

with mint_sync(Capability("search", query=Pattern("weather *"))):
    print(search(query="weather NYC"))   # ✅ Results for: weather NYC
    print(search(query="stock prices"))  # ❌ AuthorizationDenied
```

### The Safe Path (Recommended)

Keep keys separate from warrants:

```python
from tenuo import Warrant, SigningKey, Pattern

# Warrant from orchestrator - Warrant() accepts base64 string
warrant = Warrant(received_warrant_string)

# Explicit key at call site - keys never in state
key = SigningKey.from_env("MY_SERVICE_KEY")
headers = warrant.headers(key, "search", {"query": "test"})

# Delegation with attenuation
child = warrant.grant(
    to=worker_pubkey,
    allow="search",
    query=Pattern("safe*"),
    ttl=300,
    key=key
)
```

### BoundWarrant (For Repeated Operations)

When you need to make many calls with the same warrant+key:

```python
from tenuo import Warrant, SigningKey

warrant = Warrant(received_string)  # Reconstruct from base64
key = SigningKey.from_env("MY_KEY")

# Bind key for repeated use
bound = warrant.bind(key)

for item in items:
    headers = bound.headers("process", {"item": item})
    # ...

# Validate before use
result = bound.validate("search", {"query": "test"})
if result:
    # Authorized!
    pass

# ⚠️ BoundWarrant is non-serializable (contains key)
# Use bound.warrant to get the plain Warrant for storage
```

### Low-Level API (Full Control)

```python
# ┌─────────────────────────────────────────────────────────────────┐
# │  CONTROL PLANE / ORCHESTRATOR                                   │
# │  Issues warrants to agents. Only needs agent's PUBLIC key.      │
# └─────────────────────────────────────────────────────────────────┘
from tenuo import SigningKey, Warrant, Pattern, Range, PublicKey

issuer_key = SigningKey.from_env("ISSUER_KEY")
agent_pubkey = PublicKey.from_env("AGENT_PUBKEY")  # From registration

warrant = (Warrant.mint_builder()
    .capability("manage_infrastructure", {
        "cluster": Pattern("staging-*"),
        "replicas": Range.max_value(15)
    })
    .holder(agent_pubkey)
    .ttl(3600)
    .mint(issuer_key))

# Send warrant to agent: send_to_agent(str(warrant))
```

```python
# ┌─────────────────────────────────────────────────────────────────┐
# │  AGENT / WORKER                                                 │
# │  Receives warrant, uses own private key for Proof-of-Possession │
# └─────────────────────────────────────────────────────────────────┘
from tenuo import SigningKey, Warrant

agent_key = SigningKey.from_env("AGENT_KEY")  # Agent's private key (never shared)
warrant = Warrant(received_warrant_string)    # Deserialize from orchestrator

args = {"cluster": "staging-web", "replicas": 5}
pop_sig = warrant.sign(agent_key, "manage_infrastructure", args)
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

### Key Management

#### KeyRegistry (Thread-Safe Singleton)

**Problem**: In LangGraph and similar frameworks, state gets checkpointed to databases. If you put a `SigningKey` in state, your private key gets persisted—a serious security risk.

**Solution**: KeyRegistry keeps keys in memory, outside of state. Only string IDs flow through your graph.

```python
from tenuo import KeyRegistry, SigningKey

registry = KeyRegistry.get_instance()

# At startup: register keys (keys stay in memory)
registry.register("worker", SigningKey.from_env("WORKER_KEY"))
registry.register("orchestrator", SigningKey.from_env("ORCH_KEY"))

# In your code: lookup by ID (ID is just a string, safe to checkpoint)
key = registry.get("worker")

# Multi-tenant: namespace keys per tenant
registry.register("api", tenant_a_key, namespace="tenant-a")
registry.register("api", tenant_b_key, namespace="tenant-b")
key = registry.get("api", namespace="tenant-a")
```

**Use cases:**
- **LangGraph**: Keys never in state → checkpointing-safe
- **Multi-tenant SaaS**: Isolate keys per tenant with namespaces
- **Service mesh**: Different keys per downstream service
- **Key rotation**: Register both `current` and `previous` keys

#### Keyring (For Key Rotation)

```python
from tenuo import Keyring, SigningKey

keyring = Keyring(
    root=SigningKey.from_env("CURRENT_KEY"),
    previous=[SigningKey.from_env("OLD_KEY")]
)

# All public keys for verification (current + previous)
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
from tenuo.langchain import guard

# Create bound warrant
keypair = SigningKey.generate()  # In production: SigningKey.from_env("MY_KEY")
warrant = (Warrant.mint_builder()
    .tools(["search"])
    .mint(keypair))
bound = warrant.bind(keypair)

# Protect tools
from langchain_community.tools import DuckDuckGoSearchRun
protected_tools = guard([DuckDuckGoSearchRun()], bound)

# Use in agent
agent = create_openai_tools_agent(llm, protected_tools, prompt)
```

### Using `@guard` Decorator

Protect your own functions with `@guard`. Authorization is **evaluated at call time**, not decoration time - the same function can have different permissions with different warrants:

```python
from tenuo import guard

@guard(tool="read_file")
def read_file(path: str) -> str:
    return open(path).read()

# BoundWarrant as context manager - sets both warrant and key
bound = warrant.bind(keypair)
with bound:
    content = read_file("/tmp/test.txt")  # ✅ Authorized
    content = read_file("/etc/passwd")    # ❌ Blocked

# Different warrant, different permissions
with other_warrant.bind(keypair):
    content = read_file("/etc/passwd")    # Could be ✅ if this warrant allows it
```

## LangGraph Integration

```python
from tenuo import KeyRegistry
from tenuo.langgraph import guard, TenuoToolNode, load_tenuo_keys

# Load keys from TENUO_KEY_* environment variables
load_tenuo_keys()

# Wrap pure nodes
def my_agent(state):
    return {"messages": [...]}

graph.add_node("agent", guard(my_agent, key_id="worker"))
graph.add_node("tools", TenuoToolNode([search, calculator]))

# Run with warrant in state (str() returns base64)
state = {"warrant": str(warrant), "messages": [...]}
config = {"configurable": {"tenuo_key_id": "worker"}}
result = graph.invoke(state, config=config)
```

### Nodes That Need Warrant Access

```python
from tenuo.langgraph import tenuo_node
from tenuo import BoundWarrant

@tenuo_node
def smart_router(state, bound_warrant: BoundWarrant):
    if bound_warrant.allows("search"):
        return {"next": "researcher"}
    return {"next": "fallback"}
```

## Audit Logging

Tenuo logs all authorization events as JSON for observability:

```json
{"event_type": "authorization_success", "tool": "search", "action": "authorized", ...}
{"event_type": "authorization_failure", "tool": "delete", "error_code": "CONSTRAINT_VIOLATION", ...}
```

To suppress logs (for testing/demos):

```python
configure(issuer_key=key, dev_mode=True, audit_log=False)
```

Or configure the audit logger directly:

```python
from tenuo.audit import audit_logger
audit_logger.configure(enabled=False)  # Disable
audit_logger.configure(use_python_logging=True, logger_name="tenuo")  # Use Python logging
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
    
    async with mint(Capability("read_file", path=Pattern("/data/*"))):
        result = await tools["read_file"](path="/data/file.txt")
```

## Security Considerations

### BoundWarrant Serialization

`BoundWarrant` contains a private key and **cannot be serialized**:

```python
bound = warrant.bind(key)

# ❌ This raises TypeError
pickle.dumps(bound)
json.dumps(bound)

# ✅ Extract warrant for storage (str() returns base64)
state["warrant"] = str(bound.warrant)
# Reconstruct later with Warrant(string)
```

### `allows()` vs `validate()`
 
 ```python
 # ✅ allows() = Logic Check (Math only)
 # Good for UI logic, conditional routing, fail-fast
 if bound.allows("delete"):
     show_delete_button()
 
 if bound.allows("delete", {"target": "users"}):
     print("Deletion would be permitted by constraints")
 
 # ✅ validate() = Full Security Check (Math + Crypto)
 # Proves you hold the key and validates the PoP signature
 result = bound.validate("delete", {"target": "users"})
 if result:
     delete_database()
 else:
     print(f"Failed: {result.reason}")
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

- **[Quickstart](https://tenuo.dev/quickstart)** — Get running in 5 minutes
- **[FastAPI](https://tenuo.dev/fastapi)** — Zero-boilerplate API protection
- **[LangChain](https://tenuo.dev/langchain)** — Tool protection
- **[LangGraph](https://tenuo.dev/langgraph)** — Multi-agent security
- **[Security](https://tenuo.dev/security)** — Threat model, best practices
- **[API Reference](https://tenuo.dev/api-reference)** — Full SDK docs

## License

MIT OR Apache-2.0
