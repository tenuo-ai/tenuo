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
- **[langchain_simple.py](langchain_simple.py)**: Minimal example of protecting LangChain tools. Shows how to wrap a tool and run an agent with a warrant.
- **[langchain_integration.py](langchain_integration.py)**: Advanced integration using LangChain callbacks to automatically inject warrants into the execution context.

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
python basic_usage.py
python langchain_simple.py
```

## Key Concepts Demonstrated

1. **Zero-Intrusion**: Tools don't import Tenuo security code.
2. **Context Propagation**: Warrants are passed via context, not function arguments.
3. **Fail-Closed**: Missing warrants block execution.
4. **PoP Automation**: Proof-of-Possession signatures are generated automatically by the SDK.
