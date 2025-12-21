# Tenuo Python Examples

This directory contains working examples demonstrating how to use the Tenuo Python SDK.

## Prerequisites

```bash
pip install tenuo
```

## Available Examples

### Basics
- **[basic_usage.py](basic_usage.py)**: The "Hello World" of Tenuo. Shows how to create a keypair, issue a warrant, and authorize a tool call. Demonstrates POLA (Principle of Least Authority) with explicit capabilities.
- **[trust_levels_demo.py](trust_levels_demo.py)**: **NEW in alpha.5** - Shows how to assign trust levels to warrants and configure trust requirements per tool (gateway policy). Demonstrates trust hierarchy enforcement and defense in depth.
- **[issuer_execution_pattern.py](issuer_execution_pattern.py)**: **RECOMMENDED PATTERN** - Shows the production best practice: ISSUER warrants for planners, EXECUTION warrants for workers. Demonstrates trust levels and separation of concerns. **Start here for production deployments.**
- **[decorator_example.py](decorator_example.py)**: Demonstrates the `@lockdown` decorator pattern for protecting functions with minimal boilerplate.
- **[context_pattern.py](context_pattern.py)**: Shows how to use `set_warrant_context` for thread-safe/async-safe warrant passing (essential for web frameworks like FastAPI).

### Multi-Agent Delegation
- **[orchestrator_worker.py](orchestrator_worker.py)**: **Core delegation pattern** - Shows how orchestrators attenuate warrants for workers. Demonstrates Tenuo's key value: authority that shrinks as it flows through the system. Essential for understanding multi-agent workflows.

### LangChain Integration
- **[langchain_simple.py](langchain_simple.py)**: Minimal example of protecting LangChain tools. Shows how to wrap a tool and run an agent with a warrant. **Start here for LangChain integration.**
- **[langchain_integration.py](langchain_integration.py)**: Advanced LangChain integration with callbacks. Demonstrates warrant context propagation through LangChain's callback system.
- **[langchain_protect_tools.py](langchain_protect_tools.py)**: Protecting third-party tools (e.g., from `langchain_community`) using `protect_tools()`. Shows how to secure tools you don't control.
- **[langchain_mcp_integration.py](langchain_mcp_integration.py)**: **LangChain + MCP + Tenuo** - Complete integration showing how to authorize MCP tool calls with Tenuo warrants. Demonstrates constraint extraction, authorization flow, and end-to-end security.

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
python trust_levels_demo.py  # NEW in alpha.5: Trust level enforcement
python decorator_example.py
python context_pattern.py

# Multi-agent delegation (core pattern)
python orchestrator_worker.py

# LangChain examples (requires: pip install langchain langchain-openai langchain-community)
python langchain_simple.py
python langchain_integration.py
python langchain_protect_tools.py
python langchain_mcp_integration.py  # LangChain + MCP + Tenuo

# MCP example (uses local config file, no external server needed)
python mcp_integration.py

# Web framework example (requires: pip install fastapi uvicorn)
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
4. **PoP Automation**: Proof-of-Possession signatures are generated automatically by the SDK when using `@lockdown` or `protect_tools()`.

## Learning Path

**New to Tenuo?** Start here:
1. `basic_usage.py` - Core concepts (warrants, constraints, attenuation, POLA)
2. `trust_levels_demo.py` - **NEW in alpha.5**: Trust level enforcement
3. `decorator_example.py` - Simplest protection pattern
4. `context_pattern.py` - Context-based patterns (for web frameworks)
5. `orchestrator_worker.py` - **Multi-agent delegation (core value proposition)**

**Integrating with LangChain?**
1. `langchain_simple.py` - Basic LangChain protection
2. `langchain_protect_tools.py` - Protecting third-party tools
3. `langchain_integration.py` - Advanced callback patterns

**Production Patterns:**
- `orchestrator_worker.py` - **Multi-agent delegation (understand this first!)**
- `fastapi_integration.py` - Complete web application with authorization
- `error_handling_guide.py` - Production error handling strategies
- `kubernetes_integration.py` - Real-world deployment patterns
- `mcp_integration.py` - MCP server integration

**Note:** Queue integration patterns (RabbitMQ, SQS, etc.) will be available in v0.2 with framework-specific packages to reduce boilerplate.
