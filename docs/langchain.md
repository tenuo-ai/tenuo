---
title: LangChain Integration
description: Tool protection for LangChain agents
---

# Tenuo LangChain Integration

> **Status**: Implemented  

**Visual guide**: See the [LangChain Infographic](./langchain-infographic.html) for where Tenuo fits in your agent stack.

## Overview

Tenuo integrates with LangChain using a **zero-intrusion** pattern:

1. Tools remain pure business logic - no security imports
2. Security is applied at composition time via `guard()` or decorators
3. Warrants are passed through context or explicit `BoundWarrant`
4. Fail-closed: missing or invalid warrants block execution

---

## Installation

```bash
uv pip install "tenuo[langchain]"
```

---

## 30-Second Demo

Copy-paste this to see Tenuo in action. No setup required beyond the install.

```python
# mdpytest:skip
import asyncio
from tenuo import configure, mint, guard, Capability, Pattern, SigningKey
from langchain_core.tools import tool

# One-time setup
configure(issuer_key=SigningKey.generate(), dev_mode=True, audit_log=False)

# Define a protected tool
@tool
@guard(tool="search")
def search(query: str) -> str:
    """Search the web."""
    return f"Results for: {query}"

async def main():
    # Scope authority: only "weather*" queries allowed
    async with mint(Capability("search", query=Pattern("weather*"))):
        print(search.invoke({"query": "weather NYC"}))  # Works
        
        try:
            search.invoke({"query": "stock prices"})   # Blocked
        except Exception as e:
            print(f"Blocked: {e}")

asyncio.run(main())
```

**What happened?**
- `@guard(tool="search")` marks the tool as requiring authorization
- `mint(...)` creates a scoped warrant allowing only `weather*` queries
- The second call fails because `stock prices` doesn't match `Pattern("weather*")`

Even if an LLM is prompt-injected to call `search("hack commands")`, **the constraint still blocks it**.

<a href="https://colab.research.google.com/github/tenuo-ai/tenuo/blob/main/notebooks/tenuo_integrations.ipynb"><img src="https://colab.research.google.com/assets/colab-badge.svg" alt="Try in Colab"></a>

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
from langchain_core.prompts import ChatPromptTemplate

llm = ChatOpenAI(model="gpt-4")
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
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
    content = read_file("/tmp/test.txt")  # Authorized
    content = read_file("/etc/passwd")    # Blocked
```

> **Two `guard` symbols:** `from tenuo import guard` is the `@guard(tool="...")` decorator for individual functions. `from tenuo.langchain import guard` is a list wrapper equivalent to `guard_tools()`. When in doubt, use `guard_tools()`.

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
    read_file("/projects/acme/report.pdf")  # Allowed
    read_file("/projects/beta/secret.pdf")  # Blocked

# Task 2: warrant allows /projects/beta/*  
with warrant_for_beta.bind(key):
    read_file("/projects/acme/report.pdf")  # Blocked
    read_file("/projects/beta/secret.pdf")  # Allowed
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

LangChain integration uses typed `TenuoError` exceptions with canonical wire codes:

```python
from tenuo.exceptions import (
    TenuoError,
    ToolNotAuthorized,
    ConstraintViolation,
    ExpiredError,
)

try:
    result = protected_tool(path="/etc/passwd")
except ConstraintViolation as e:
    print(f"Constraint failed: {e}")
    print(f"Wire code: {e.get_wire_code()}")  # 1501
    print(f"Wire name: {e.get_wire_name()}")  # "constraint-violation"
    print(f"HTTP status: {e.get_http_status()}")  # 403
except ExpiredError as e:
    print(f"Warrant expired: {e}")
    print(f"Wire code: {e.get_wire_code()}")  # 1300
except TenuoError as e:
    # Catch-all for any Tenuo error
    print(f"Authorization failed: {e}")
    print(f"Error details: {e.to_dict()}")
```

### Wire Code Support

All exceptions include canonical wire codes (1000-2199) for machine-readable error handling:

```python
try:
    protected_tool(amount=5000)
except TenuoError as e:
    error_dict = e.to_dict()
    # {
    #   "error_code": "constraint_violation",  # Legacy snake_case
    #   "wire_code": 1501,                     # Canonical numeric code
    #   "wire_name": "constraint-violation",   # Canonical kebab-case
    #   "message": "...",
    #   "details": {...}
    # }
```

### Common Errors

| Error | Wire Code | Cause | Fix |
|-------|-----------|-------|-----|
| `ToolNotAuthorized` | 1500 | Tool not in warrant | Add tool to warrant |
| `ConstraintViolation` | 1501 | Argument violates constraint | Request within bounds |
| `ConfigurationError` | 1201 | Missing context/warrant | Use `warrant_scope()` or pass to `guard()` |
| `ExpiredError` | 1300 | TTL exceeded | Request fresh warrant |
| `SignatureInvalid` | 1100 | Bad PoP signature | Check signing key |
| `RevokedError` | 1800 | Warrant revoked | Request new warrant |

See [wire format specification](./spec/wire-format-v1#appendix-a-error-code-reference) for the complete list.

---

## Constraints

Constraints restrict tool arguments:

| Type | Example | Description |
|------|---------|-------------|
| `Exact` | `Exact("prod")` | Must equal exactly |
| `Pattern` | `Pattern("/tmp/*")` | Glob pattern match |
| `Subpath` | `Subpath("/data")` | Path containment (blocks traversal) |
| `UrlSafe` | `UrlSafe(allow_domains=["api.com"])` | SSRF-protected URLs |
| `Shlex` | `Shlex(allow=["ls", "cat"])` | Shell injection protection |
| `Regex` | `Regex(r"^prod-.*")` | Regex match |
| `Range` | `Range(min=0, max=100)` | Numeric range |
| `OneOf` | `OneOf(["a", "b"])` | One of values |

---

## Full Example

```python
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from tenuo import SigningKey, Warrant, Pattern, Subpath, guard
from tenuo.langchain import guard_tools

# 1. Create key and warrant
key = SigningKey.generate()  # In production: SigningKey.from_env("MY_KEY")
warrant = (Warrant.mint_builder()
    .tool("search")  # No constraints
    .capability("read_file", path=Subpath("/tmp"))  # With path constraint
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
protected_tools = guard_tools([DuckDuckGoSearchRun(), read_file], bound)

# 4. Create agent
llm = ChatOpenAI(model="gpt-4")
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
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
        Capability("read_file", path=Subpath("/data")),
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

## Human Approval

Add human-in-the-loop approval with `approval_handler` and `approvals` parameters on `guard_tools()` or `TenuoTool`. See [Human Approvals](approvals.md) for the full guide.

```python
from tenuo.langchain import guard_tools, TenuoTool
from tenuo.approval import cli_prompt

approver_key = SigningKey.generate()

# Via guard_tools: specify which tools require approval and the handler
protected = guard_tools(
    [search, delete_database],
    bound_warrant,
    approvals=["delete_database"],
    approval_handler=cli_prompt(approver_key=approver_key),
)

# Or per-tool via TenuoTool
tool = TenuoTool(
    inner=delete_database,
    approval_handler=cli_prompt(approver_key=approver_key),
)
```

---

## Delegation Chains

When an orchestrator delegates a subset of its authority to a worker, the worker's warrant is a *child* of the orchestrator's warrant. To verify the child, `Authorizer.check_chain` must see the full chain of parent warrants. Use `chain_scope` to provide this context.

```python
from tenuo import (
    SigningKey, Warrant, configure, reset_config,
    chain_scope, warrant_scope, key_scope,
)
from tenuo.langchain import guard_tools

issuer = SigningKey.generate()
orchestrator = SigningKey.generate()
worker = SigningKey.generate()
configure(issuer_key=issuer, dev_mode=True)

# Root warrant: orchestrator can search, read_file, delete_file
root = (Warrant.mint_builder()
    .capability("search")
    .capability("read_file")
    .capability("delete_file")
    .holder(orchestrator.public_key)
    .ttl(3600)
    .mint(issuer))

# Attenuated child: worker can only search and read_file
child = (root.grant_builder()
    .capability("search")
    .capability("read_file")
    .holder(worker.public_key)
    .ttl(1800)
    .grant(orchestrator))

tools = guard_tools([search_tool, read_file_tool, delete_file_tool])

# Set up delegation context: chain + leaf warrant + signing key
with chain_scope([root]):
    with warrant_scope(child):
        with key_scope(worker):
            result = tools[0].invoke({"query": "test"})  # search: allowed
            # tools[2].invoke({"path": "/x"})            # delete_file: DENIED
```

`chain_scope` provides parent warrants to `enforce_tool_call` so that `Authorizer.check_chain` can walk the delegation chain back to a trusted root. Without it, delegated warrants fail because the child's issuer (the orchestrator) isn't itself a trusted root — the chain is needed to prove that authority was properly delegated from the issuer.

---

## See Also

- [LangGraph Integration](./langgraph)  -- Multi-agent graph security
- [Human Approvals](./approvals)  -- Approval policy guide
- [Argument Extraction](./constraints#argument-extraction)  -- How extraction works
- [Security](./security)  -- Threat model, best practices
- [API Reference](./api-reference)  -- Full Python API documentation
