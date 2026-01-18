# Tenuo Python Examples

This directory contains working examples demonstrating how to use the Tenuo Python SDK.

## Prerequisites

```bash
# Using uv (recommended)
uv pip install tenuo

# Or standard pip
pip install tenuo
```

## Quick Start

**OpenAI** - Semantic constraints that block attacks:
```python
from openai import OpenAI
from tenuo.openai import GuardBuilder
from tenuo.constraints import Subpath, UrlSafe

client = (GuardBuilder(OpenAI())
    .allow("read_file", path=Subpath("/data"))  # Blocks path traversal
    .allow("fetch", url=UrlSafe())              # Blocks SSRF attacks
    .build())
```

**Google ADK** - Same semantic protection:
```python
from tenuo.google_adk import GuardBuilder
from tenuo.constraints import Subpath

guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .build())

agent = Agent(tools=[...], before_tool_callback=guard.before_tool)
```

**A2A (Multi-Agent)** - Warrant-based delegation:
```python
from tenuo.a2a import A2AServerBuilder

server = (A2AServerBuilder()
    .name("Worker")
    .url("https://worker.example.com")
    .key(my_key)
    .accept_warrants_from(orchestrator_key)
    .build())
```

> **Simple Allowlist?** Use `protect(client, tools=[...])` for basic protection without constraints.

---

## Featured Demo: Research Agent with Guardrails

**The best way to see Tenuo in action — works in dry-run mode OR with real OpenAI!**

```bash
# Install core dependencies
uv pip install "tenuo[mcp]"

# Run demo (dry-run mode - no API keys needed!)
python research_agent_demo.py

# Optional: For real LLM integration
uv pip install langchain-openai
export OPENAI_API_KEY="sk-..."

# Optional: For real web search
uv pip install tavily-python
export TAVILY_API_KEY="tvly-..."  # Free tier: https://tavily.com

# Run with real LLM
python research_agent_demo.py
```

This demo shows Tenuo's key capabilities:
- **Delegation chains**: Control Plane -> Orchestrator -> Worker
- **Attenuation**: Each hop narrows capabilities (can't exceed parent)
- **Cryptographic audit**: Signed proof of every action
- **Multi-agent separation**: Different workers get different capabilities
- **Prompt injection defense**: Warrant blocks unauthorized actions
- **Multi-mission isolation**: Same worker, different mission warrants
- **Real LLM integration**: OpenAI GPT with warrant-protected tools (or dry-run)
- **High-level templates**: `FileReader`, `WebSearcher`, `DatabaseReader` for easy adoption

---

## Available Examples

### Basics
- **[basic_usage.py](basic_usage.py)**: The "Hello World" of Tenuo. Shows how to create a keypair, issue a warrant, and authorize a tool call. Demonstrates POLA (Principle of Least Authority) with explicit capabilities.
- **[trust_cliff_demo.py](trust_cliff_demo.py)**: Demonstrates the "Trust Cliff" - once you add ANY constraint, unknown arguments are rejected. Shows `_allow_unknown`, `Wildcard()`, and non-inheritance during attenuation.
- **[clearance_demo.py](clearance_demo.py)**: Shows how to assign clearance levels to warrants and configure clearance requirements per tool (gateway policy). Demonstrates clearance hierarchy enforcement and defense in depth.
- **[issuer_execution_pattern.py](issuer_execution_pattern.py)**: **RECOMMENDED PATTERN** - Shows the production best practice: ISSUER warrants for planners, EXECUTION warrants for workers. Demonstrates clearance levels and separation of concerns. **Start here for production deployments.**
- **[decorator_example.py](decorator_example.py)**: Demonstrates the `@guard` decorator pattern for protecting functions with minimal boilerplate.
- **[context_pattern.py](context_pattern.py)**: Shows how to use `warrant_scope` for thread-safe/async-safe warrant passing (essential for web frameworks like FastAPI).

### Multi-Agent Delegation
- **[orchestrator_worker.py](orchestrator_worker.py)**: **Core delegation pattern** - Shows how orchestrators attenuate warrants for workers. Demonstrates Tenuo's key value: authority that shrinks as it flows through the system. Essential for understanding multi-agent workflows.

### MCP Integration
- **[research_agent_demo.py](research_agent_demo.py)**: **RUNNABLE DEMO** - Pure Python MCP demo with delegation chains, attenuation, and cryptographic audit. Uses mock or real Tavily search. **Best first demo!**
- **[mcp_research_server.py](mcp_research_server.py)**: The MCP server used by `research_agent_demo.py`. Demonstrates `web_search`, `write_file`, `read_file` tools.

### LangChain Integration
- **[langchain_simple.py](langchain_simple.py)**: Minimal example of protecting LangChain tools. Shows how to wrap a tool and run an agent with a warrant. **Start here for LangChain integration.**
- **[langchain_integration.py](langchain_integration.py)**: Advanced LangChain integration with callbacks. Demonstrates warrant context propagation through LangChain's callback system.
- **[langchain_protect_tools.py](langchain_protect_tools.py)**: Protecting third-party tools (e.g., from `langchain_community`) using `guard()`. Shows how to secure tools you don't control.
- [langchain_mcp_integration.py](langchain_mcp_integration.py): **LangChain + MCP + Tenuo** - Complete integration showing how to authorize MCP tool calls with Tenuo warrants. Demonstrates constraint extraction, authorization flow, and end-to-end security.

### LangGraph Integration
- **[langgraph_protected.py](langgraph_protected.py)**: **State-Aware Agent (Advanced)** - Shows how to secure LangGraph agents with checkpointing. Key patterns:
    1.  **Serialization**: Storing base64 warrant tokens in state (not generic objects) to support `MemorySaver`.
    2.  **Key Binding**: Binding keys at runtime based on process identity (`KeyRegistry`).
    3.  **TenuoToolNode**: Drop-in secure tool execution node.
    4.  **Authorization**: Enforcing capabilities on state transitions.

### OpenAI Integration
- **[openai_guardrails.py](openai_guardrails.py)**: **Tier 1 Protection** - Direct OpenAI API wrapping with `guard()` and `GuardBuilder`. Shows constraint types, denial modes, streaming protection, and audit logging. Demonstrates `Subpath` for path traversal protection.
- **[openai_warrant.py](openai_warrant.py)**: **Tier 2 Protection** - Full cryptographic authorization with warrants and Proof-of-Possession. Shows key separation, constraint enforcement, and `client.validate()`.
- **[openai_async.py](openai_async.py)**: **Async Patterns** - Async client wrapping, streaming with TOCTOU protection, concurrent calls, and async error handling.
- **[openai_agents_sdk.py](openai_agents_sdk.py)**: **Agents SDK Integration** - Using Tenuo guardrails with OpenAI's Agents SDK. Shows `create_tier1_guardrail()` and `create_tier2_guardrail()`.

### Google ADK Integration
- **[google_adk_incident_response/](google_adk_incident_response/)**: **Multi-Agent Security Demo** - Detector, Analyst, and Responder agents with warrant-based authorization. Shows Tier 2 protection with monotonic attenuation.
- **[google_adk_a2a_incident/](google_adk_a2a_incident/)**: **Distributed A2A Demo** - Same incident response scenario but with real A2A HTTP calls between separate agent processes. Shows warrant delegation over the network.

### A2A (Agent-to-Agent) Integration
- **[a2a_demo.py](a2a_demo.py)**: **Research Pipeline Demo** - Multi-agent delegation with warrant-based authorization. Shows User -> Orchestrator -> Worker flow with constraint attenuation and attack scenarios.

**Security Constraints:**
- `Subpath("/data")` - Blocks path traversal attacks (normalizes `../` before checking containment)
- `UrlSafe()` - Blocks SSRF attacks (private IPs, metadata endpoints, IP encoding bypasses)

### MCP (Model Context Protocol)
- **[mcp_integration.py](mcp_integration.py)**: Demonstrates how to integrate Tenuo with MCP servers, extracting constraints from MCP tool calls.

### Web Frameworks
- **[fastapi_integration.py](fastapi_integration.py)**: Complete FastAPI application with Tenuo authorization. Shows:
    - Middleware for warrant extraction and context setting
    - Multiple protected endpoints
    - Error handling and proper HTTP responses
    - SigningKey loading from secrets
    - Request-scoped warrant validation

### Error Handling
- **[error_handling_guide.py](error_handling_guide.py)**: Comprehensive error handling patterns. Covers:
    - Common error scenarios (expired warrants, PoP failures, constraint violations)
    - Error classification and severity levels
    - Recovery strategies (when to retry vs abort)
    - Production-ready error handling patterns

### Infrastructure
- **[kubernetes_integration.py](kubernetes_integration.py)**: A complete simulation of a Kubernetes deployment. Shows how to:
    - Load identity keys from volume mounts
    - Read warrants from headers
    - Use the context pattern in a mock service

## Running Examples

All examples are standalone scripts. You can run them directly:

```bash
# Basic examples (no dependencies beyond tenuo)
python basic_usage.py
python clearance_demo.py  # Clearance level enforcement
python decorator_example.py
python context_pattern.py

# Multi-agent delegation (core pattern)
python orchestrator_worker.py

# Featured MCP demo (requires: uv pip install "tenuo[mcp,langchain]" langchain-openai langgraph)
# Also requires: OPENAI_API_KEY (TAVILY_API_KEY optional for real search)
python research_agent_demo.py

# LangChain examples (requires: uv pip install langchain langchain-openai langchain-community)
python langchain_simple.py
python langchain_integration.py
python langchain_protect_tools.py
python langchain_protect_tools.py
python langchain_mcp_integration.py  # LangChain + MCP + Tenuo

# LangGraph example (requires: uv pip install langgraph)
python langgraph_protected.py

# OpenAI examples (requires: uv pip install openai)
python openai_guardrails.py     # Tier 1: runtime guardrails
python openai_warrant.py        # Tier 2: cryptographic authorization
python openai_agents_sdk.py     # Agents SDK integration

# Google ADK examples (requires: uv pip install tenuo[adk])
python google_adk_incident_response/demo.py  # Multi-agent incident response

# A2A examples (requires: uv pip install tenuo[a2a])
python a2a_demo.py              # Research pipeline with delegation

# MCP example (uses local config file, no external server needed)
python mcp_integration.py

# Web framework example (requires: uv pip install fastapi uvicorn)
python fastapi_integration.py
# Or run with: uvicorn fastapi_integration:app --reload

# Error handling guide
python error_handling_guide.py

# Kubernetes example (simulation, no actual K8s needed)
python kubernetes_integration.py
```

## Key Concepts Demonstrated

1. **Zero-Intrusion**: Tools don't import Tenuo security code. Security is applied via decorators or wrappers, keeping business logic clean.
2. **Context Propagation**: Warrants are passed via `ContextVar`, making them thread-safe and async-safe. Perfect for web frameworks like FastAPI.
3. **Fail-Closed**: Missing warrants block execution. If no warrant is in context, authorization fails by default.
4. **PoP Automation**: Proof-of-Possession signatures are generated automatically by the SDK when using `@guard` or `guard()`.
5. **Closed-World Constraints (Trust Cliff)**: Once you add ANY constraint, unknown arguments are rejected. Use `_allow_unknown=True` to opt out, or `Wildcard()` to explicitly allow fields. See [trust_cliff_demo.py](trust_cliff_demo.py).

## Learning Path

**New to Tenuo?** Start here:
1. `research_agent_demo.py` - **Best first demo!** Real OpenAI + web search with guardrails
2. `basic_usage.py` - Core concepts (warrants, constraints, attenuation, POLA)
3. `clearance_demo.py` - Clearance level enforcement
4. `decorator_example.py` - Simplest protection pattern
5. `context_pattern.py` - Context-based patterns (for web frameworks)
6. `orchestrator_worker.py` - **Multi-agent delegation (core value proposition)**

**Integrating with LangChain?**
1. `research_agent_demo.py` - **Start here!** Complete runnable demo
2. `langchain_simple.py` - Basic LangChain protection
3. `langchain_protect_tools.py` - Protecting third-party tools
4. `langchain_integration.py` - Advanced callback patterns

**Integrating with OpenAI?**
1. `openai_guardrails.py` - **Start here!** Tier 1 runtime protection
2. `openai_warrant.py` - Tier 2 cryptographic authorization
3. `openai_agents_sdk.py` - Agents SDK guardrails

**Production Patterns:**
- `orchestrator_worker.py` - **Multi-agent delegation (understand this first!)**
- `langgraph_protected.py` - **State-aware agents with checkpointing (LangGraph)**
- `fastapi_integration.py` - Complete web application with authorization
- `error_handling_guide.py` - Production error handling strategies
- `kubernetes_integration.py` - Real-world deployment patterns
- `mcp_integration.py` - MCP server integration

**Note:** Queue integration patterns (RabbitMQ, SQS, etc.) will be available in v0.2 with framework-specific packages to reduce boilerplate.
