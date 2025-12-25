---
title: LangChain Integration
description: Tool protection for LangChain agents
---

# Tenuo LangChain Integration

> **Status**: ✅ Implemented  

📊 **Visual guide**: See the [LangChain Infographic](./langchain-infographic.html) for where Tenuo fits in your agent stack.

## Overview

Tenuo integrates with LangChain using a **zero-intrusion** pattern:

1. Tools remain pure business logic - no security imports
2. Security is applied at composition time via `guard()` or decorators
3. Warrants are passed through context or explicit `BoundWarrant`
4. Fail-closed: missing or invalid warrants block execution

---

## Installation

```bash
pip install tenuo[langchain]
```

---

## Quick Start

### Using `guard()` (Recommended)

The unified `guard()` function wraps any LangChain tools:

```python
from tenuo import Warrant, SigningKey, Pattern
from tenuo.langchain import guard
from langchain_community.tools import DuckDuckGoSearchRun

# 1. Create warrant and bind key
key = SigningKey.generate()  # In production: SigningKey.from_env("MY_KEY")
warrant = (Warrant.mint_builder()
    .capability("duckduckgo_search", query=Pattern("*"))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

bound = warrant.bind(key)

# 2. Protect tools
protected_tools = guard([DuckDuckGoSearchRun()], bound)

# 3. Use in your agent
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4")
agent = create_openai_tools_agent(llm, protected_tools, prompt)
executor = AgentExecutor(agent=agent, tools=protected_tools)

result = executor.invoke({"input": "Search for AI news"})
```

### Using `@guard` Decorator

For tools you define yourself:

```python
from tenuo import guard

@guard(tool="read_file")
def read_file(file_path: str) -> str:
    """Pure business logic - no security code"""
    with open(file_path, 'r') as f:
        return f.read()

# Execute with BoundWarrant as context manager
bound = warrant.bind(key)
with bound:
    content = read_file("/tmp/test.txt")  # ✅ Authorized
    content = read_file("/etc/passwd")    # ❌ Blocked
```

---

## The `guard()` Function

Unified API for protecting tools - handles both `BaseTool` instances and plain callables:

```python
from tenuo.langchain import guard

# Protect LangChain BaseTools
protected = guard([search_tool, calculator_tool], bw)

# Protect plain functions
protected = guard([my_func, other_func], bw)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tools` | `List[Any]` | List of `BaseTool` or callable |
| `bound` | `BoundWarrant` | Bound warrant (positional, optional) |
| `strict` | `bool` | Require constraints on critical tools |

**Returns:**
- For `BaseTool` inputs: `List[TenuoTool]`
- For callable inputs: `List[Callable]`

---

## The `@guard` Decorator

```python
@guard(tool="read_file")
def read_file(file_path: str, max_size: int = 1000) -> str:
    with open(file_path) as f:
        return f.read()[:max_size]
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `tool` | Tool name to check against warrant (required) |
| `extract_args` | Optional function to extract args |
| `mapping` | Optional dict to rename parameters |

### How It Works: Dynamic Runtime Evaluation

`@guard` does **nothing at decoration time**. Authorization happens **when the function is called**:

```
┌─────────────────────┐
│  Import Time        │  @guard wraps function, stores tool name
│  (no warrant yet)   │  No authorization check happens here
└─────────────────────┘
          │
          ▼
┌─────────────────────┐
│  Runtime            │  with bound:  ← warrant+key set in context
│  (warrant exists)   │      read_file("/data/x")  ← NOW authorization runs
└─────────────────────┘
```

**This means the same function can have different permissions at different times:**

```python
@guard(tool="read_file")
def read_file(path: str): ...

# Task 1: warrant allows /projects/acme/*
with warrant_for_acme.bind(key):
    read_file("/projects/acme/report.pdf")  # ✅ Allowed
    read_file("/projects/beta/secret.pdf")  # ❌ Blocked

# Task 2: warrant allows /projects/beta/*  
with warrant_for_beta.bind(key):
    read_file("/projects/acme/report.pdf")  # ❌ Blocked
    read_file("/projects/beta/secret.pdf")  # ✅ Allowed
```

### Authorization Flow

When `read_file("/data/x")` is called inside `with bound:`:

1. Wrapper reads warrant and key from context
2. Extracts all parameters including defaults
3. Verifies tool is in warrant's allowed tools
4. Verifies args satisfy warrant constraints
5. Generates PoP signature using the key
6. Executes if authorized, raises `AuthorizationDenied` if not

### Automatic Extraction (Recommended)

When no `extract_args` is provided, Tenuo extracts **all** parameters including defaults:

```python
@guard(tool="transfer")
def transfer(from_account: str, to_account: str, amount: float, memo: str = ""):
    ...

# Called as: transfer("acct1", "acct2", 100.0)
# Extracted: {from_account: "acct1", to_account: "acct2", amount: 100.0, memo: ""}
```

### Parameter Mapping

For simple renames:

```python
@guard(
    tool="read_file",
    mapping={"file_path": "path"}  # Rename for constraint matching
)
def read_file(file_path: str):
    ...
```

---

## Context Management

### Explicit BoundWarrant (Preferred)

```python
from tenuo import Warrant, SigningKey

key = SigningKey.generate()
warrant = (Warrant.mint_builder()
    .tool("search")
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

bound = warrant.bind(key)

# Pass to guard()
protected = guard(tools, bound)
```

### Context Variables (For Decorators)

```python
# BoundWarrant as context manager - sets both warrant and key scope
bound = warrant.bind(key)
with bound:
    # All @guard calls use this warrant and key
    result = protected_function()
```

**Properties:**
- Thread-safe (uses `contextvars`)
- Async-safe
- Nestable (inner context shadows outer)

---

## Error Handling

```python
from tenuo.exceptions import AuthorizationDenied

try:
    result = protected_tool(path="/etc/passwd")
except AuthorizationDenied as e:
    print(f"Denied: {e}")
    # Use why_denied() for details (internal logging only)
```

### Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `Tool 'x' not authorized` | Tool not in warrant | Add tool to warrant |
| `Constraint failed` | Argument violates constraint | Request within bounds |
| `No warrant in context` | Missing context | Use `warrant_scope()` or pass to `guard()` |
| `Warrant expired` | TTL exceeded | Request fresh warrant |

---

## Constraints

Constraints restrict tool arguments:

| Type | Example | Description |
|------|---------|-------------|
| `Exact` | `Exact("prod")` | Must equal exactly |
| `Pattern` | `Pattern("/tmp/*")` | Glob pattern match |
| `Regex` | `Regex(r"^prod-.*")` | Regex match |
| `Range` | `Range(min=0, max=100)` | Numeric range |
| `OneOf` | `OneOf(["a", "b"])` | One of values |

---

## Full Example

```python
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from tenuo import SigningKey, Warrant, Pattern
from tenuo.langchain import guard

# 1. Create key and warrant
key = SigningKey.generate()  # In production: SigningKey.from_env("MY_KEY")
warrant = (Warrant.mint_builder()
    .tool("search")  # No constraints
    .capability("read_file", path=Pattern("/tmp/*"))  # With path constraint
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

bound = warrant.bind(key)

# 2. Define tools
from langchain_community.tools import DuckDuckGoSearchRun

@guard(tool="read_file")
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()

# 3. Protect tools
protected_tools = guard([DuckDuckGoSearchRun(), read_file], bound)

# 4. Create agent
llm = ChatOpenAI(model="gpt-4")
agent = create_openai_tools_agent(llm, protected_tools, prompt)
executor = AgentExecutor(agent=agent, tools=protected_tools)

# 5. Run
result = executor.invoke({"input": "Read /tmp/test.txt"})
```

---

## High-Level APIs

### `auto_protect()` (Zero Config)

The fastest way to add protection - defaults to **audit mode** so you can deploy without breaking anything:

```python
from tenuo.langchain import auto_protect

# Wrap your executor - logs all tool calls, doesn't block
protected_executor = auto_protect(executor)
result = protected_executor.invoke({"input": "Search for AI news"})

# After analyzing logs, switch to enforce mode
protected_executor = auto_protect(executor, mode="enforce")
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `agent_or_tools` | `Any` | required | AgentExecutor, list of tools, or single tool |
| `mode` | `str` | `"audit"` | `"audit"` (log only), `"enforce"` (block), `"permissive"` (warn) |
| `infer_schemas` | `bool` | `True` | Infer tool schemas from type hints |

### `SecureAgentExecutor` (Drop-in Replacement)

A drop-in replacement for LangChain's `AgentExecutor` with built-in protection:

```python
from tenuo.langchain import SecureAgentExecutor
from tenuo import configure, mint, Capability, SigningKey

configure(issuer_key=SigningKey.generate(), dev_mode=True)

# Same interface as AgentExecutor
executor = SecureAgentExecutor(
    agent=agent,
    tools=tools,
    strict=False,  # Require constraints on critical tools
    warn_on_missing_warrant=True,  # Log when tools called without context
)

# Use with mint() context
async with mint(Capability("search"), Capability("read_file")):
    result = await executor.ainvoke({"input": "Search and read"})
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `agent` | `Any` | required | LangChain agent |
| `tools` | `List[Any]` | required | List of tools |
| `strict` | `bool` | `False` | Require constraints on critical tools |
| `warn_on_missing_warrant` | `bool` | `True` | Log warnings for unprotected calls |
| `schemas` | `Dict[str, Any]` | `None` | Custom tool schemas |

### `guard_tools()` (Wrap Tools)

Wrap tools with protection - you manage the `mint()`/`grant()` context:

```python
from tenuo.langchain import guard_tools
from tenuo import configure, mint_sync, Capability, SigningKey

kp = SigningKey.generate()
configure(issuer_key=kp, dev_mode=True)

# Wrap tools
protected_tools = guard_tools([search_tool, calculator], issuer_key=kp)

# Create agent with protected tools
agent = create_openai_tools_agent(llm, protected_tools, prompt)
executor = AgentExecutor(agent=agent, tools=protected_tools)

# Run with authorization context
with mint_sync(Capability("search"), Capability("calculator")):
    result = executor.invoke({"input": "Calculate 2+2"})
```

### `guard_agent()` (Wrap Entire Executor)

Wrap an entire executor with built-in authorization context:

```python
from tenuo.langchain import guard_agent
from tenuo import SigningKey, Capability, Pattern

kp = SigningKey.generate()

# One line to add protection
protected = guard_agent(
    executor,
    issuer_key=kp,
    capabilities=[
        Capability("search"),
        Capability("read_file", path=Pattern("/data/*")),
    ],
)

# Now run - authorization is automatic!
result = protected.invoke({"input": "Read /data/report.txt"})
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `agent_or_executor` | `Any` | AgentExecutor, RunnableAgent, or agent with tools |
| `issuer_key` | `SigningKey` | Signing key (enables dev_mode if provided) |
| `capabilities` | `List[Capability]` | Capabilities to scope the agent to |
| `strict` | `bool` | Require constraints for critical tools |
| `warn_on_missing` | `bool` | Log warnings for missing warrants |

---

## See Also

- [LangGraph Integration](./langgraph) — Multi-agent graph security
- [Argument Extraction](./argument-extraction) — How extraction works
- [Security](./security) — Threat model, best practices
- [API Reference](./api-reference) — Full Python API documentation
