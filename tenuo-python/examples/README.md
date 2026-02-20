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
- **[tier1_demo.py](tier1_demo.py)**: Tier 1 API — constraints-only protection without warrants. Simplest way to add guardrails.
- **[trust_cliff_demo.py](trust_cliff_demo.py)**: Demonstrates the "Trust Cliff" - once you add ANY constraint, unknown arguments are rejected. Shows `_allow_unknown`, `Wildcard()`, and non-inheritance during attenuation.
- **[clearance_demo.py](clearance_demo.py)**: Shows how to assign clearance levels to warrants and configure clearance requirements per tool (gateway policy). Demonstrates clearance hierarchy enforcement and defense in depth.
- **[issuer_execution_pattern.py](issuer_execution_pattern.py)**: **RECOMMENDED PATTERN** - Shows the production best practice: ISSUER warrants for planners, EXECUTION warrants for workers. Demonstrates clearance levels and separation of concerns. **Start here for production deployments.**
- **[decorator_example.py](decorator_example.py)**: Demonstrates the `@guard` decorator pattern for protecting functions with minimal boilerplate.
- **[context_pattern.py](context_pattern.py)**: Shows how to use `warrant_scope` for thread-safe/async-safe warrant passing (essential for web frameworks like FastAPI).
- **[chain_demo.py](chain_demo.py)**: Demonstrates warrant chaining and delegation depth.

### Multi-Agent Delegation
- **[orchestrator_worker.py](orchestrator_worker.py)**: **Core delegation pattern** - Shows how orchestrators attenuate warrants for workers. Demonstrates Tenuo's key value: authority that shrinks as it flows through the system. Essential for understanding multi-agent workflows.
- **[delegation_patterns.py](delegation_patterns.py)**: Advanced delegation patterns including multi-hop chains and constraint narrowing.
- **[delegation_receipts.py](delegation_receipts.py)**: Cryptographic delegation receipts for audit trails.

### Approval Policy (Human-in-the-Loop)
- **[approval_policy_demo.py](approval_policy_demo.py)**: Demonstrates m-of-n multi-sig approval policies — single approver and multi-sig scenarios with configurable TTL.
- **[jit_warrant_demo/](jit_warrant_demo/)**: **JIT Warrant Demo** - Complete just-in-time warrant issuance with human multi-sig approval. Run with `python jit_warrant_demo/demo.py --simulate`.
  - `demo.py` — Main entry point (use `--simulate` for no-LLM mode)
  - `human_approval.py` — Multi-sig approval flow
  - `executor.py` — Warrant-enforced tool execution
  - `orchestrator.py` — Agent orchestration with approval gates
  - `control_plane.py` — Warrant issuance authority

### MCP (Model Context Protocol)
- **[mcp/](mcp/)**: MCP server and client integration examples
  - **[mcp_server_demo.py](mcp/mcp_server_demo.py)**: MCP server with `read_file` and `list_directory` tools
  - **[mcp_client_demo.py](mcp/mcp_client_demo.py)**: MCP client with Tenuo-protected tool calls
  - **[mcp_integration.py](mcp/mcp_integration.py)**: Complete MCP + Tenuo integration
  - **[mcp_research_server.py](mcp/mcp_research_server.py)**: MCP server used by `research_agent_demo.py`
  - **[crewai_mcp_demo.py](mcp/crewai_mcp_demo.py)**: CrewAI + MCP + Tenuo integration
  - **[langchain_mcp_demo.py](mcp/langchain_mcp_demo.py)**: LangChain + MCP + Tenuo integration
  - **[mcp_a2a_delegation.py](mcp/mcp_a2a_delegation.py)**: MCP with A2A warrant delegation
- **[research_agent_demo.py](research_agent_demo.py)**: **RUNNABLE DEMO** - Pure Python MCP demo with delegation chains, attenuation, and cryptographic audit. Uses mock or real Tavily search. **Best first demo!**

### LangChain / LangGraph Integration
- **[langchain/](langchain/)**: Complete LangChain and LangGraph integration examples
  - **[simple.py](langchain/simple.py)**: Minimal example of protecting LangChain tools. **Start here for LangChain integration.**
  - **[integration.py](langchain/integration.py)**: Advanced integration with callbacks and context propagation
  - **[protect_tools.py](langchain/protect_tools.py)**: Securing third-party tools from `langchain_community`
  - **[mcp_integration.py](langchain/mcp_integration.py)**: LangChain + MCP + Tenuo complete integration
  - **[langgraph_protected.py](langchain/langgraph_protected.py)**: State-aware agents with checkpointing (serialization, key binding, TenuoToolNode)
  - **[langgraph_mcp_integration.py](langchain/langgraph_mcp_integration.py)**: LangGraph + MCP multi-agent graph with context-based authorization

### OpenAI Integration
- **[openai/](openai/)**: Complete OpenAI integration examples
  - **[guardrails.py](openai/guardrails.py)**: Tier 1 runtime guardrails (no warrants)
  - **[warrant.py](openai/warrant.py)**: Tier 2 cryptographic authorization with PoP
  - **[async_patterns.py](openai/async_patterns.py)**: Async/streaming patterns with TOCTOU protection
  - **[agents_sdk.py](openai/agents_sdk.py)**: OpenAI Agents SDK integration

### CrewAI Integration
- **[crewai/](crewai/)**: Complete CrewAI integration examples
  - **[quickstart.py](crewai/quickstart.py)**: Minimal CrewAI + Tenuo quickstart
  - **[demo_simple.py](crewai/demo_simple.py)**: Simple guarded crew with constraint enforcement
  - **[guarded_crew.py](crewai/guarded_crew.py)**: Full crew with GuardBuilder and tool protection
  - **[guarded_flow.py](crewai/guarded_flow.py)**: CrewAI Flow with Tenuo guards (requires crewai with Flow support)
  - **[hierarchical_delegation.py](crewai/hierarchical_delegation.py)**: Tier 2 hierarchical delegation with WarrantDelegator and escalation prevention
  - **[research_team_demo.py](crewai/research_team_demo.py)**: Multi-agent research team with delegation chains
  - **[demo_live.py](crewai/demo_live.py)**: Live demo with real LLM (requires API key)

### AutoGen Integration
- **[autogen_demo_unprotected.py](autogen_demo_unprotected.py)**: AgentChat workflow with no protections (baseline/attack illustration).
- **[autogen_demo_protected_tools.py](autogen_demo_protected_tools.py)**: Guarded tools with UrlSafe allowlist + Subpath.
- **[autogen_demo_protected_attenuation.py](autogen_demo_protected_attenuation.py)**: Per-agent attenuation + escalation blocking.
- **[autogen_demo_guardbuilder_tier1.py](autogen_demo_guardbuilder_tier1.py)**: GuardBuilder (constraints-only) with on_denial raise/log/skip.
- **[autogen_demo_guardbuilder_tier2.py](autogen_demo_guardbuilder_tier2.py)**: GuardBuilder with warrant + PoP (Tier 2).

### Google ADK Integration
- **[google_adk_incident_response/](google_adk_incident_response/)**: **Multi-Agent Security Demo** - Detector, Analyst, and Responder agents with warrant-based authorization. Shows Tier 2 protection with monotonic attenuation.
- **[google_adk_a2a_incident/](google_adk_a2a_incident/)**: **Distributed A2A Demo** - Same incident response scenario but with real A2A HTTP calls between separate agent processes. Shows warrant delegation over the network.

### A2A (Agent-to-Agent) Integration
- **[a2a/](a2a/)**: Agent-to-agent communication examples
  - **[demo.py](a2a/demo.py)**: **Research Pipeline Demo** - Multi-agent delegation with warrant-based authorization. Shows User -> Orchestrator -> Worker flow with constraint attenuation and attack scenarios.
  - **[crewai_delegation.py](a2a/crewai_delegation.py)**: CrewAI + A2A warrant delegation
  - **[multi_hop_delegation.py](a2a/multi_hop_delegation.py)**: Multi-hop delegation chains across agents
  - **[streaming_demo.py](a2a/streaming_demo.py)**: Streaming A2A communication with warrants

### Temporal Integration
- **[temporal/](temporal/)**: Temporal workflow integration examples
  - **[demo.py](temporal/demo.py)**: Basic Temporal workflow with Tenuo warrant protection
  - **[delegation.py](temporal/delegation.py)**: Warrant delegation across Temporal activities
  - **[multi_warrant.py](temporal/multi_warrant.py)**: Multiple warrants in Temporal workflow chains

### AgentQL Integration
- **[agentql/](agentql/)**: Browser automation with Tenuo guardrails
  - **[demo.py](agentql/demo.py)**: AgentQL browser agent with Tenuo-enforced tool constraints
  - **[demo_llm.py](agentql/demo_llm.py)**: AgentQL with live LLM integration
  - **[benchmark.py](agentql/benchmark.py)**: Performance benchmarks for guarded browser automation

### Local LLM Integration
- **[local_llm_demo/](local_llm_demo/)**: LM Studio integration for fully local AI agents with Tenuo security. Run with `python local_llm_demo/demo.py` (requires LM Studio running locally).

### Web Frameworks
- **[fastapi_integration.py](fastapi_integration.py)**: Complete FastAPI application with Tenuo authorization. Shows:
    - SecureAPIRouter for automatic route protection
    - Multiple protected endpoints with auto-inferred tool names
    - Error handling and proper HTTP responses
    - SigningKey loading from secrets
    - Client-side PoP signature verification

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

### Blog Demos
- **[blog_demos/map_territory/](blog_demos/map_territory/)**: Supporting examples for the "Map vs Territory" blog post on TOCTOU attacks and streaming safety.

**Security Constraints:**
- `Subpath("/data")` - Blocks path traversal attacks (normalizes `../` before checking containment)
- `UrlSafe()` - Blocks SSRF attacks (private IPs, metadata endpoints, IP encoding bypasses)

## Running Examples

All examples are standalone scripts. You can run them directly:

```bash
# Basic examples (no dependencies beyond tenuo)
python basic_usage.py
python tier1_demo.py
python clearance_demo.py
python decorator_example.py
python context_pattern.py
python chain_demo.py

# Multi-agent delegation (core pattern)
python orchestrator_worker.py
python delegation_patterns.py

# Approval policy (human-in-the-loop)
python approval_policy_demo.py
python jit_warrant_demo/demo.py --simulate

# Featured MCP demo (requires: uv pip install "tenuo[mcp,langchain]" langchain-openai langgraph)
python research_agent_demo.py

# MCP examples
python mcp/mcp_client_demo.py
python mcp/mcp_integration.py

# LangChain examples (requires: uv pip install langchain langchain-openai langchain-community)
python langchain/simple.py
python langchain/integration.py
python langchain/protect_tools.py
python langchain/mcp_integration.py

# LangGraph examples (requires: uv pip install langgraph)
python langchain/langgraph_protected.py
python langchain/langgraph_mcp_integration.py

# OpenAI examples (requires: uv pip install openai)
python openai/guardrails.py
python openai/warrant.py
python openai/async_patterns.py
python openai/agents_sdk.py

# CrewAI examples (requires: uv pip install crewai)
python crewai/quickstart.py
python crewai/demo_simple.py
python crewai/guarded_crew.py
python crewai/hierarchical_delegation.py

# Google ADK examples (requires: uv pip install tenuo[adk])
python google_adk_incident_response/demo.py

# A2A examples (requires: uv pip install tenuo[a2a])
python a2a/demo.py

# Temporal examples (requires: uv pip install tenuo[temporal])
python temporal/demo.py
python temporal/delegation.py
python temporal/multi_warrant.py

# Web framework example (requires: uv pip install fastapi uvicorn)
python fastapi_integration.py

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
6. **M-of-N Approvals**: Human-in-the-loop authorization with configurable multi-sig thresholds and TTL. See [approval_policy_demo.py](approval_policy_demo.py).

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
2. `langchain/simple.py` - Basic LangChain protection
3. `langchain/protect_tools.py` - Protecting third-party tools
4. `langchain/integration.py` - Advanced callback patterns

**Integrating with OpenAI?**
1. `openai/guardrails.py` - **Start here!** Tier 1 runtime protection
2. `openai/warrant.py` - Tier 2 cryptographic authorization
3. `openai/agents_sdk.py` - Agents SDK guardrails

**Integrating with CrewAI?**
1. `crewai/quickstart.py` - **Start here!** Minimal integration
2. `crewai/guarded_crew.py` - Full crew with constraints
3. `crewai/hierarchical_delegation.py` - Warrant delegation between agents

**Production Patterns:**
- `orchestrator_worker.py` - **Multi-agent delegation (understand this first!)**
- `langchain/langgraph_protected.py` - **State-aware agents with checkpointing (LangGraph)**
- `approval_policy_demo.py` - Human-in-the-loop m-of-n approvals
- `fastapi_integration.py` - Complete web application with authorization
- `error_handling_guide.py` - Production error handling strategies
- `kubernetes_integration.py` - Real-world deployment patterns

**Note:** Queue integration patterns (RabbitMQ, SQS, etc.) will be available in v0.2 with framework-specific packages to reduce boilerplate.
