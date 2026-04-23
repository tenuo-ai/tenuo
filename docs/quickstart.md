---
title: Quick Start
description: Get started with Tenuo in 5 minutes
---

# Quick Start

## What is Tenuo?

Tenuo is a warrant-based authorization library for AI agent workflows. A **warrant** is a signed token specifying which tools an agent can call, under what constraints, and for how long.

```
Agent: "restart staging-web"
        │
        ▼
Tenuo:  Does this warrant allow "restart" on "staging-web"?
        Is the delegation chain valid?
        │
        ▼
IAM:    Does this service account have permission?
```

Tenuo adds a **delegation layer** on top of your existing IAM. If an LLM is prompt-injected, it can request anything, but the warrant only allows what you scoped. The injection succeeds at the LLM level; authorization stops the action.

**Core invariant**: when a warrant is delegated, its capabilities can only **narrow**, never widen. Enforced cryptographically.

## Install

```bash
uv pip install tenuo
```

With framework support (quotes required in zsh):

```bash
uv pip install "tenuo[openai]"      # OpenAI Agents SDK
uv pip install "tenuo[temporal]"    # Temporal workflows
uv pip install "tenuo[langchain]"   # LangChain / LangGraph
uv pip install "tenuo[crewai]"      # CrewAI
uv pip install "tenuo[google_adk]"  # Google ADK
uv pip install "tenuo[mcp]"         # MCP (Python ≥3.10)
uv pip install "tenuo[a2a]"         # A2A inter-agent delegation
uv pip install "tenuo[fastapi]"     # FastAPI
uv pip install "tenuo[autogen]"     # AutoGen AgentChat (Python ≥3.10)
```

## Try It (Copy-Paste, Runs Immediately)

```python
from tenuo import configure, mint_sync, Capability, Subpath, SigningKey, guard
from tenuo.exceptions import AuthorizationDenied

# 1. Configure once at startup
configure(issuer_key=SigningKey.generate(), dev_mode=True, audit_log=False)

# 2. Protect tools with @guard
@guard(tool="read_file")
def read_file(path: str) -> str:
    return f"Contents of {path}"

# 3. Scope authority to tasks
with mint_sync(Capability("read_file", path=Subpath("/data"))):
    print(read_file("/data/reports/q3.pdf"))  # Allowed

    try:
        read_file("/etc/passwd")  # Blocked
    except AuthorizationDenied as e:
        print(f"Blocked: {e}")
```

**What happened:**
- `@guard(tool="read_file")` marks the function as requiring authorization
- `mint_sync(...)` creates a warrant scoped to `/data/` (using `Subpath` for path traversal protection)
- The second call fails because `/etc/passwd` is not under `/data/`

## Choose Your Integration

**What framework are you using?**

| Framework | Integration | Getting Started |
|-----------|-------------|-----------------|
| **OpenAI SDK** | `from tenuo.openai import guard` | [OpenAI Guide](./openai) |
| **Temporal** | `from tenuo.temporal import TenuoTemporalPlugin` | [Temporal Guide](./temporal) |
| **LangChain** | `from tenuo.langchain import auto_protect` | [LangChain Guide](./langchain) |
| **LangGraph** | `from tenuo.langgraph import guard_node` | [LangGraph Guide](./langgraph) |
| **CrewAI** | `from tenuo.crewai import ...` | [CrewAI Guide](./crewai) |
| **Google ADK** | `from tenuo.google_adk import TenuoGuard` | [ADK Guide](./google-adk) |
| **MCP** | `from tenuo.mcp import SecureMCPClient` | [MCP Guide](./mcp) |
| **FastAPI** | `from tenuo.fastapi import SecureAPIRouter` | [FastAPI Guide](./fastapi) |
| **AutoGen** | `from tenuo.autogen import ...` | [AutoGen Guide](./autogen) |
| **A2A** | `from tenuo.a2a import ...` | [A2A Guide](./a2a) |
| **Custom** | `from tenuo import Warrant, SigningKey` | [API Reference](./api-reference) |

**Do you have agents communicating across processes?** Add [A2A](./a2a) alongside your runtime integration.

### Quick Examples

**OpenAI**: wrap the client, tools are automatically protected:

```python
from tenuo.openai import guard
client = guard(openai.OpenAI(), warrant=warrant, signing_key=key)
```

**LangGraph**: scope authority per graph node:

```python
from tenuo.langgraph import guard_node, TenuoToolNode
graph.add_node("agent", guard_node(my_agent, key_id="worker"))
graph.add_node("tools", TenuoToolNode([search, write_file]))
```

**MCP**: verify tool calls between client and server:

```python
from tenuo.mcp import SecureMCPClient
client = SecureMCPClient(server_url, warrant=warrant, signing_key=key)
```

**Temporal**: one plugin, zero workflow changes:

```python
from temporalio.client import Client
from tenuo.temporal import TenuoTemporalPlugin, TenuoPluginConfig, EnvKeyResolver

# issuer_pubkey is the public key that mints your warrants —
# e.g. ``control_key.public_key`` from the snippets above.
plugin = TenuoTemporalPlugin(TenuoPluginConfig(
    key_resolver=EnvKeyResolver(), trusted_roots=[issuer_pubkey],
))
client = await Client.connect("localhost:7233", plugins=[plugin])
```

Each framework guide includes a full working example, production configuration, and troubleshooting.

## Debugging Authorization Failures

When something is denied, use `why_denied()` for diagnostics:

```python
result = warrant.why_denied("read_file", {"path": "/etc/passwd"})
if result.denied:
    print(f"Denied: {result.deny_code}")
    print(f"Field: {result.field}")
    print(f"Suggestion: {result.suggestion}")
```

Or inspect a warrant interactively in the [Explorer Playground](https://tenuo.ai/explorer/). Warrants contain only signed claims, not secrets, so they're safe to share.

## Next Steps

- **[Going to Production](./production-guide)**: enforcement modes, gradual rollout, key management ([Tenuo Cloud](https://cloud.tenuo.ai) or self-hosted)
- **[AI Agent Patterns](./ai-agents)**: P-LLM/Q-LLM architecture, prompt injection defense
- **[Concepts](./concepts)**: threat model, core invariants, why warrant-based auth
- **[Constraint Types](./constraints)**: `Subpath`, `Pattern`, `Range`, `UrlSafe`, `Exact`, and more
- **[Security Model](./security)**: full threat model, PoP mechanics, delegation chain verification
- **[API Reference](./api-reference)**: low-level `Warrant`, `SigningKey`, `BoundWarrant` API
