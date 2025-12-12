# Tenuo Python Examples

This directory contains working examples demonstrating how to use the Tenuo Python SDK.

## Prerequisites

```bash
pip install tenuo
```

## Available Examples

### Basics
- **[basic_usage.py](basic_usage.py)**: The "Hello World" of Tenuo. Shows how to create a keypair, issue a warrant, and authorize a tool call.
- **[decorator_example.py](decorator_example.py)**: Demonstrates the `@lockdown` decorator pattern for protecting functions with minimal boilerplate.
- **[context_pattern.py](context_pattern.py)**: Shows how to use `set_warrant_context` for thread-safe/async-safe warrant passing (essential for web frameworks like FastAPI).

### LangChain Integration
- **[langchain_simple.py](langchain_simple.py)**: Minimal example of protecting LangChain tools. Shows how to wrap a tool and run an agent with a warrant. **Start here for LangChain integration.**
- **[langchain_integration.py](langchain_integration.py)**: Advanced LangChain integration with callbacks. Demonstrates warrant context propagation through LangChain's callback system.
- **[langchain_protect_tools.py](langchain_protect_tools.py)**: Protecting third-party tools (e.g., from `langchain_community`) using `protect_tools()`. Shows how to secure tools you don't control.

### MCP (Model Context Protocol)
- **[mcp_integration.py](mcp_integration.py)**: Demonstrates how to integrate Tenuo with MCP servers, extracting constraints from MCP tool calls.

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
python decorator_example.py
python context_pattern.py

# LangChain examples (requires: pip install langchain langchain-openai)
python langchain_simple.py
python langchain_integration.py
python langchain_protect_tools.py

# MCP example (requires MCP server setup)
python mcp_integration.py

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
1. `basic_usage.py` - Core concepts (warrants, constraints, attenuation)
2. `decorator_example.py` - Simplest protection pattern
3. `context_pattern.py` - Context-based patterns (for web frameworks)

**Integrating with LangChain?**
1. `langchain_simple.py` - Basic LangChain protection
2. `langchain_protect_tools.py` - Protecting third-party tools
3. `langchain_integration.py` - Advanced callback patterns

**Production Patterns:**
- `kubernetes_integration.py` - Real-world deployment patterns
- `mcp_integration.py` - MCP server integration
