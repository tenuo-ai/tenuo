---
title: Quick Start
description: Get started with Tenuo in 5 minutes
---

# Quick Start

Get Tenuo running in 5 minutes.

📊 **Visual learner?** See the [Demo Walkthrough](./demo.html) for a step-by-step flow.

---

## What is Tenuo?

Tenuo is a capability-based authorization library for AI agent workflows. It uses signed tokens called **warrants** to control what actions agents can perform.

**Core invariant**: When a warrant is delegated, its capabilities can only **shrink**. A $1000 budget becomes $500. Access to `staging-*` narrows to `staging-web`.

```
┌─────────────────────────────────────────────────────────┐
│  Agent Request: "restart staging-web"                   │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Tenuo Layer                                            │
│  ✓ Does this warrant allow "restart" on "staging-web"?  │
│  ✓ Is the delegation chain valid?                       │
│  ✓ Is the holder's signature correct?                   │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Infrastructure IAM (AWS / K8s / etc.)                  │
│  ✓ Does this service account have permission?           │
└─────────────────────────────────────────────────────────┘
```

Tenuo adds a **delegation layer** on top of your existing IAM. It tracks *who* delegated authority, *what limits* apply, and *why* an agent is acting.

---

## Installation

### Python

```bash
pip install tenuo
```

### Rust

```toml
[dependencies]
tenuo-core = "0.1"
```

### CLI

```bash
cargo install tenuo-cli
```

---

## Python Quick Start

### 1. Create a Warrant

```python
from tenuo import Keypair, Warrant, Pattern, Range

# Generate a keypair (issuer)
keypair = Keypair.generate()

# Issue a warrant
warrant = Warrant.issue(
    tools="manage_infrastructure",
    keypair=keypair,
    holder=keypair.public_key(),
    constraints={
        "cluster": Pattern("staging-*"),    # Glob pattern
        "budget": Range(max=10000.0)        # Max $10,000
    },
    ttl_seconds=3600
)
```

### 2. Attenuate (Delegate with Narrower Scope)

```python
from tenuo import Exact

# Worker gets a narrower warrant
worker_keypair = Keypair.generate()

worker_warrant = warrant.attenuate(
    constraints={
        "cluster": Exact("staging-web"),    # Narrowed from staging-*
        "budget": Range(max=1000.0)         # Reduced to $1,000
    },
    keypair=worker_keypair
)
```

### 3. Authorize an Action

```python
# Worker signs a Proof-of-Possession
args = {"cluster": "staging-web", "budget": 500.0}
pop_sig = worker_warrant.create_pop_signature(
    worker_keypair, "manage_infrastructure", args
)

# Check authorization
authorized = worker_warrant.authorize(
    tool="manage_infrastructure",
    args=args,
    signature=bytes(pop_sig)
)
print(f"Authorized: {authorized}")  # True
```

### 4. Protect Tools with Decorators

```python
from tenuo import lockdown, set_warrant_context, set_keypair_context

@lockdown(tool="upgrade_cluster")
def upgrade_cluster(cluster: str, budget: float):
    print(f"Upgrading {cluster} with budget {budget}")

# Set context for all decorated functions
with set_warrant_context(warrant), set_keypair_context(keypair):
    upgrade_cluster(cluster="staging-web", budget=500.0)
```

### 5. LangChain One-Liner (Recommended)

```python
from tenuo import Keypair, root_task_sync
from tenuo.langchain import secure_agent

# One line to secure your LangChain tools
kp = Keypair.generate()
tools = secure_agent([search, calculator], issuer_keypair=kp)

# Run with scoped authority
with root_task_sync(tools=["search", "calculator"]):
    result = executor.invoke({"input": "What is 2+2?"})
```

### 6. LangGraph Drop-in

```python
from tenuo.langgraph import TenuoToolNode

# Drop-in replacement for ToolNode
tool_node = TenuoToolNode([search, calculator])
graph.add_node("tools", tool_node)
```

---

## Rust Quick Start

### 1. Create a Warrant

```rust
use tenuo_core::{Keypair, Warrant, Pattern, Range};
use std::time::Duration;

let keypair = Keypair::generate();
let warrant = Warrant::builder()
    .tools(vec!["manage_infrastructure".to_string()])
    .constraint("cluster", Pattern::new("staging-*")?)
    .constraint("budget", Range::max(10000.0))
    .ttl(Duration::from_secs(3600))
    .build(&keypair)?;
```

### 2. Attenuate

```rust
use tenuo_core::Exact;

let worker_keypair = Keypair::generate();
let worker_warrant = warrant.attenuate()
    .constraint("cluster", Exact::new("staging-web"))
    .constraint("budget", Range::max(1000.0))
    .authorized_holder(worker_keypair.public_key())
    .build(&keypair)?;
```

### 3. Authorize

```rust
use tenuo_core::Authorizer;

let authorizer = Authorizer::new(keypair.public_key());
let chain = vec![warrant, worker_warrant];

let sig = worker_warrant.create_pop_signature(
    "manage_infrastructure", &args, &worker_keypair
);

authorizer.authorize(&chain, "manage_infrastructure", &args, Some(&sig), &[])?;
```

---

## CLI Quick Start

### Generate Keys

```bash
tenuo keygen --out root.pem
tenuo keygen --out worker.pem
```

### Issue a Warrant

```bash
tenuo issue \
  --tool manage_infrastructure \
  --signing-key root.pem \
  --constraint "cluster=pattern:staging-*" \
  --constraint "budget=range:..10000" \
  --ttl 3600 \
  --out root.warrant
```

### Attenuate

```bash
tenuo attenuate \
  --warrant root.warrant \
  --signing-key root.pem \
  --holder worker.pem \
  --constraint "cluster=exact:staging-web" \
  --constraint "budget=range:..1000" \
  --out worker.warrant
```

### Verify

```bash
tenuo verify \
  --warrant worker.warrant \
  --tool manage_infrastructure \
  --args '{"cluster": "staging-web", "budget": 500}'
```

### Inspect

```bash
tenuo inspect --warrant worker.warrant
```

---

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Warrant** | Signed token granting specific capabilities |
| **Attenuation** | Creating a child warrant with narrower scope |
| **Constraint** | Rule that limits what a warrant can authorize |
| **PoP** | Proof-of-Possession signature proving holder identity |
| **Chain** | Sequence of warrants from root to current holder |

---

## Constraint Types

| Type | Example | Matches |
|------|---------|---------|
| `Exact` | `Exact("prod")` | Only "prod" |
| `Pattern` | `Pattern("staging-*")` | "staging-web", "staging-db" |
| `OneOf` | `OneOf(["a", "b"])` | "a" or "b" |
| `Range` | `Range(min=0, max=1000)` | 0 to 1000 |
| `Regex` | `Regex(r"^user_\d+$")` | "user_123", "user_456" |

See [Constraints](./constraints) for the full list.

---

## Debugging Authorization Failures

Tenuo provides diff-style error messages when authorization fails:

```
Access denied for tool 'read_file'

  ❌ path:
     Expected: Pattern("/data/*")
     Received: '/etc/passwd'
     Reason: Pattern does not match
  ✅ size: OK
```

This makes it easy to see exactly which constraint failed and why.

---

## Next Steps

- **[Concepts](./concepts)** — Why Tenuo? Threat model, core invariants
- **[Protocol](./protocol)** — How it works under the hood
- **[API Reference](./api-reference)** — Complete Python SDK docs (includes MCP)
- **[CLI Reference](./cli)** — Full CLI documentation
- **[LangChain](./langchain)** — Protect LangChain tools
- **[LangGraph](./langgraph)** — Scope LangGraph nodes
- **[Security](./security)** — Threat model, best practices

---

## MCP Integration

Tenuo supports [Model Context Protocol](https://modelcontextprotocol.io) natively:

```python
from tenuo import McpConfig, CompiledMcpConfig

# Load MCP config
config = McpConfig.from_file("mcp-config.yaml")
compiled = CompiledMcpConfig.compile(config)

# Extract constraints from MCP tool call
result = compiled.extract_constraints("filesystem_read", {"path": "/var/log/app.log"})

# Authorize using extracted constraints
authorized = warrant.authorize("filesystem_read", result.constraints, pop_sig)
```

See [API Reference → MCP Integration](./api-reference#mcp-integration) for details.
