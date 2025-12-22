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
2. Security is applied at composition time via `protect()` or decorators
3. Warrants are passed through context or explicit `BoundWarrant`
4. Fail-closed: missing or invalid warrants block execution

---

## Installation

```bash
pip install tenuo[langchain]
```

---

## Quick Start

### Using `protect()` (Recommended)

The unified `protect()` function wraps any LangChain tools:

```python
from tenuo import Warrant, SigningKey, Pattern
from tenuo.langchain import protect
from langchain_community.tools import DuckDuckGoSearchRun

# 1. Create warrant and bind key
keypair = SigningKey.generate()
warrant = (Warrant.builder()
    .tool("duckduckgo_search")
    .capability("duckduckgo_search", {"query": Pattern("*")})
    .holder(keypair.public_key)
    .ttl(3600)
    .issue(keypair))

bound = warrant.bind_key(keypair)

# 2. Protect tools
protected_tools = protect([DuckDuckGoSearchRun()], bound_warrant=bound)

# 3. Use in your agent
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4")
agent = create_openai_tools_agent(llm, protected_tools, prompt)
executor = AgentExecutor(agent=agent, tools=protected_tools)

result = executor.invoke({"input": "Search for AI news"})
```

### Using `@lockdown` Decorator

For tools you define yourself:

```python
from tenuo import lockdown, set_warrant_context, set_signing_key_context

@lockdown(tool="read_file")
def read_file(file_path: str) -> str:
    """Pure business logic - no security code"""
    with open(file_path, 'r') as f:
        return f.read()

# Execute with warrant context
with set_warrant_context(warrant), set_signing_key_context(keypair):
    content = read_file("/tmp/test.txt")  # ✅ Authorized
    content = read_file("/etc/passwd")    # ❌ Blocked
```

---

## The `protect()` Function

Unified API for protecting tools - handles both `BaseTool` instances and plain callables:

```python
from tenuo.langchain import protect

# Protect LangChain BaseTools
protected = protect([search_tool, calculator_tool], bound_warrant=bw)

# Protect plain functions
protected = protect([my_func, other_func], bound_warrant=bw)

# With per-tool constraints (attenuation)
from tenuo.langchain import LangChainConfig, ToolConfig

config = LangChainConfig(
    tools={
        "search": ToolConfig(constraints={"query": Pattern("safe*")}),
        "calculator": ToolConfig(constraints={})
    }
)
protected = protect([search, calculator], bound_warrant=bw, config=config)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tools` | `List[Any]` | List of `BaseTool` or callable |
| `bound_warrant` | `BoundWarrant` | Explicit warrant+key (optional) |
| `config` | `LangChainConfig` | Per-tool constraints (optional) |
| `strict` | `bool` | Require constraints on critical tools |

**Returns:**
- For `BaseTool` inputs: `List[TenuoTool]`
- For callable inputs: `List[Callable]`

---

## The `@lockdown` Decorator

```python
@lockdown(tool="read_file")
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

**Behavior:**

1. Retrieves warrant from context (or uses explicit `BoundWarrant`)
2. Extracts all parameters including defaults
3. Verifies tool is in warrant's allowed tools
4. Verifies args satisfy warrant constraints
5. Generates PoP signature
6. Executes if authorized, raises exception if not

### Automatic Extraction (Recommended)

When no `extract_args` is provided, Tenuo extracts **all** parameters including defaults:

```python
@lockdown(tool="transfer")
def transfer(from_account: str, to_account: str, amount: float, memo: str = ""):
    ...

# Called as: transfer("acct1", "acct2", 100.0)
# Extracted: {from_account: "acct1", to_account: "acct2", amount: 100.0, memo: ""}
```

### Parameter Mapping

For simple renames:

```python
@lockdown(
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

warrant = Warrant.builder()...issue(keypair)
bound = warrant.bind_key(keypair)

# Pass to protect()
protected = protect(tools, bound_warrant=bound)
```

### Context Variables (For Decorators)

```python
from tenuo import set_warrant_context, set_signing_key_context

with set_warrant_context(warrant), set_signing_key_context(keypair):
    # All @lockdown calls use this warrant and keypair
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
| `No warrant in context` | Missing context | Use `set_warrant_context()` or `bound_warrant=` |
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
from tenuo.langchain import protect

# 1. Create keypair and warrant
keypair = SigningKey.generate()
warrant = (Warrant.builder()
    .tool("search")
    .tool("read_file")
    .capability("read_file", {"path": Pattern("/tmp/*")})
    .holder(keypair.public_key)
    .ttl(3600)
    .issue(keypair))

bound = warrant.bind_key(keypair)

# 2. Define tools
from langchain_community.tools import DuckDuckGoSearchRun

@lockdown(tool="read_file")
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()

# 3. Protect tools
protected_tools = protect(
    [DuckDuckGoSearchRun(), read_file],
    bound_warrant=bound
)

# 4. Create agent
llm = ChatOpenAI(model="gpt-4")
agent = create_openai_tools_agent(llm, protected_tools, prompt)
executor = AgentExecutor(agent=agent, tools=protected_tools)

# 5. Run
result = executor.invoke({"input": "Read /tmp/test.txt"})
```

---

## See Also

- [LangGraph Integration](./langgraph) — Multi-agent graph security
- [Argument Extraction](./argument-extraction) — How extraction works
- [Security](./security) — Threat model, best practices
- [API Reference](./api-reference) — Full Python API documentation
