---
title: Integration Safety
description: Fail-safe mechanisms to catch integration bugs before production
---

# Integration Safety

> **The Primary Attack Surface: Integration Mistakes**

Tenuo's core is cryptographically secure. But **integration bugs** are the primary attack surface:
- Forgetting to add `@lockdown` to a tool
- Missing `set_warrant_context()` or `root_task()`
- Dynamic nodes without wrappers
- Wrapper that checks tool names but skips `authorize()`

This page documents **fail-safe mechanisms** to catch these bugs.

---

## The Problem

Your red team tests show it:

```python
# Attack 8: Dynamic node bypass
def unprotected_node(state):
    # No @lockdown, no @tenuo_node → executes without authorization
    delete_database()
    return "Dangerous action executed"

# Attack 10: Buggy wrapper
def buggy_wrapper(warrant, arg):
    if "search" not in warrant.tools:  # ← Checks tool name
        raise Unauthorized()
    # ❌ MISSING: warrant.authorize("search", {"query": arg})
    return execute_search(arg)  # ← Bypasses constraints!
```

**Root cause**: Security relies on developers remembering to:
1. Wrap ALL tools with `@lockdown`
2. Set warrant context before calling tools  
3. Call `warrant.authorize()` (not just check tool names)

---

## Solution 1: Strict Mode

**Fail-closed enforcement**: Panic if a tool is called without warrant context.

### configure(strict_mode=True)

```python
from tenuo import configure, Keypair

configure(
    issuer_key=Keypair.generate(),
    strict_mode=True,  # ← Enforce warrant presence
)
```

**Behavior:**

```python
from tenuo import lockdown

@lockdown(tool="read_file")
def read_file(path: str):
    return open(path).read()

# ❌ Called without warrant context
read_file("/data/test.txt")
```

**Actionable Error Message:**

```
RuntimeError: [MISSING_CONTEXT] No warrant context available for tool 'read_file'.

  Tool: read_file
  Function: my_module.read_file
  Location: /app/handlers.py:42

To fix:
  1. Wrap the call with: async with root_task(tools=[...]):
  2. Or use: with set_warrant_context(warrant), set_keypair_context(keypair):
  3. Or pass warrant explicitly: @lockdown(warrant, tool='read_file')
```

The error includes:
- **Error code** (`MISSING_CONTEXT`, `EXPIRED`, `SCOPE_VIOLATION`, etc.)
- **Tool name** being called
- **Function** full path (`module.function`)
- **Callsite** (`filename:line`)
- **Fix suggestions** specific to the error type

**When to use:**
- ✅ **Development/staging** - Catch integration bugs early
- ✅ **CI/CD** - Fail tests if warrant context is missing  
- ⚠️ **Production** - Only if you want hard failures (might cause outages if misconfigured)

---

## Solution 2: Warning Mode

**Loud warnings**: Log and warn (but don't crash) when tools are called without warrants.

### configure(warn_on_missing_warrant=True)

```python
from tenuo import configure, Keypair

configure(
    issuer_key=Keypair.generate(),
    warn_on_missing_warrant=True,  # ← Warn on missing warrants
)
```

**Behavior:**

```python
@lockdown(tool="read_file")
def read_file(path: str):
    return open(path).read()

# Called without warrant context
read_file("/data/test.txt")
# UserWarning: ⚠️ INTEGRATION WARNING: Tool 'read_file' called without warrant context.
# This may indicate a missing @lockdown decorator or forgotten set_warrant_context().
# In production, use strict_mode=True to fail-closed.
#
# Also logged to audit trail with error_code: "missing_warrant_warning"
#
# Then raises: Unauthorized: No warrant available for read_file
```

**When to use:**
- ✅ **Development** - Surface integration issues without breaking tests
- ✅ **Staging** - Collect warnings before production deployment
- ⚠️ **Production** - Use if you want visibility without hard failures

---

## Solution 3: Tripwire Mode

**Auto-escalate to strict mode** after N warnings. Prevents "warn fatigue" where warnings become noise.

### configure(max_missing_warrant_warnings=10)

```python
configure(
    issuer_key=Keypair.generate(),
    warn_on_missing_warrant=True,
    max_missing_warrant_warnings=10,  # ← Auto-flip to strict after 10 warnings
)
```

**Behavior:**

```python
# First 9 calls: warnings
for i in range(9):
    unprotected_tool()  # UserWarning: Tool 'tool' called without warrant context

# 10th call: tripwire triggers
unprotected_tool()
# UserWarning: Tripwire triggered: 10 missing warrant warnings reached threshold (10).
#              Switching to strict mode (hard fail).
# RuntimeError: [MISSING_CONTEXT] No warrant context available for tool 'tool'.
```

**Use case:** Production deployment with safety net. Start with warnings, auto-escalate if someone is flooding the system without warrants.

---

## Solution 4: Audit Log Monitoring

Even without strict/warning modes, ALL authorization failures are logged.

### Monitor for Missing Warrants

```python
from tenuo import audit_logger

# Configure audit output
audit_logger.configure(
    service_name="my-service",
    output_file="/var/log/tenuo-audit.jsonl"
)

# All calls to @lockdown without warrants generate:
# {
#   "event_type": "AUTHORIZATION_FAILURE",
#   "error_code": "no_warrant",
#   "tool": "read_file",
#   "details": "No warrant available for read_file",
#   "timestamp": "2024-01-15T10:30:00Z"
# }
```

**Query for integration bugs:**

```bash
# Find tools called without warrants
jq 'select(.error_code == "no_warrant") | .tool' /var/log/tenuo-audit.jsonl | sort | uniq

# Find strict mode violations
jq 'select(.error_code == "strict_mode_violation")' /var/log/tenuo-audit.jsonl
```

---

## Comparison

| Mode | Missing Warrant Behavior | Use Case |
|------|-------------------------|----------|
| **Default** | Raises `Unauthorized` | Production (minimal overhead) |
| **`warn_on_missing_warrant=True`** | Warns + raises | Development/staging (surface bugs) |
| **`strict_mode=True`** | Panics with `RuntimeError` | CI/CD (fail tests), strict production |

---

## Best Practices

### 1. Use Strict Mode in Tests

```python
# conftest.py or test setup
from tenuo import configure, Keypair

@pytest.fixture(scope="session", autouse=True)
def tenuo_strict():
    configure(
        issuer_key=Keypair.generate(),
        dev_mode=True,
        strict_mode=True,  # Fail tests if warrant missing
    )
```

**Why**: Catches integration bugs in CI before production.

### 2. Use Warning Mode in Staging

```python
# staging.py
configure(
    issuer_key=load_staging_key(),
    trusted_roots=[staging_control_plane_key],
    warn_on_missing_warrant=True,  # Surface issues without breaking
)
```

**Why**: Collects warnings to fix before production deployment.

### 3. Monitor Audit Logs in Production

```python
# production.py
configure(
    issuer_key=load_prod_key(),
    trusted_roots=[prod_control_plane_key],
    # strict_mode=False (default)
    # warn_on_missing_warrant=False (default)
)

# But enable comprehensive audit logging
audit_logger.configure(
    service_name="prod-agent",
    output_file="/var/log/tenuo-audit.jsonl",
    include_full_args=False,  # GDPR: Don't log PII
)
```

**Why**: Detect issues via monitoring without risking availability.

### 4. Use Type Checkers

```python
# Enable mypy strict mode
# mypy.ini
[mypy]
strict = True
warn_return_any = True
```

**Why**: Catches missing decorators at static analysis time.

---

## Common Integration Bugs

### Bug 1: Unprotected Tool

❌ **Vulnerable:**
```python
def dangerous_tool(arg: str):
    # No @lockdown decorator!
    delete_database(arg)
```

✅ **Detected by strict mode:**
```
RuntimeError: Tool 'dangerous_tool' called without warrant
```

### Bug 2: Missing Context

❌ **Vulnerable:**
```python
@lockdown(tool="read_file")
def read_file(path: str):
    ...

# Called without warrant context
read_file("/data/test.txt")  # ← No set_warrant_context() or root_task()
```

✅ **Detected by strict mode:**
```
RuntimeError: STRICT MODE VIOLATION: Tool 'read_file' called without warrant context
```

### Bug 3: Dynamic Node

❌ **Vulnerable:**
```python
# LangGraph dynamically adds node
graph.add_node("dynamic", lambda s: dangerous_action(s))
# No @tenuo_node, no @lockdown → bypasses authorization
```

✅ **Detected by strict mode:**
- If `dangerous_action` has `@lockdown`, strict mode catches it
- If `dangerous_action` has NO decorator, you need code review or linting

### Bug 4: Partial Wrapper

❌ **Vulnerable:**
```python
def my_wrapper(warrant, arg):
    if "search" not in warrant.tools:
        raise Unauthorized()
    # ❌ Forgot to check constraints!
    return search(arg)
```

✅ **Detected by:**
- Code review (check for `warrant.authorize()` calls)
- Integration tests with constrained warrants
- Audit log monitoring (unexpected constraint violations)

---

## Async Context Sharp Edges

Python `contextvars` work correctly in most async scenarios, but there are known pitfalls:

### ✅ Works Correctly

```python
# async/await - context propagates
async with root_task(tools=["search"]):
    result = await search("query")  # ✅ Has warrant context

# asyncio.gather - context propagates
async with root_task(tools=["search", "read"]):
    results = await asyncio.gather(
        search("query"),   # ✅ Has warrant context
        read_file("path")  # ✅ Has warrant context
    )
```

### ⚠️ Known Issues

```python
# 1. create_task BEFORE context is set
task = asyncio.create_task(search("query"))  # ❌ No context yet!
async with root_task(tools=["search"]):      # Context set after task created
    await task  # Task runs without context

# 2. Thread pool executors
async with root_task(tools=["search"]):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, sync_search, "query")  # ❌ Different thread

# 3. Manual threads
async with root_task(tools=["search"]):
    thread = Thread(target=sync_search, args=("query",))
    thread.start()  # ❌ Threads don't inherit contextvars
```

### Mitigations

```python
# For create_task: create INSIDE the context
async with root_task(tools=["search"]):
    task = asyncio.create_task(search("query"))  # ✅ Context copied at creation
    await task

# For thread pools: use copy_context
import contextvars

async with root_task(tools=["search"]):
    ctx = contextvars.copy_context()
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, ctx.run, sync_search, "query")  # ✅

# For manual threads: use copy_context
async with root_task(tools=["search"]):
    ctx = contextvars.copy_context()
    thread = Thread(target=ctx.run, args=(sync_search, "query"))
    thread.start()  # ✅
```

**Best Practice**: Enable `strict_mode=True` in development to surface these issues early.

---

## Error Codes

Tenuo uses structured error codes for all authorization failures:

| Code | Meaning |
|------|---------|
| `MISSING_CONTEXT` | No warrant in context |
| `INVALID_WARRANT` | Warrant malformed or wrong type |
| `EXPIRED` | Warrant has expired |
| `SCOPE_VIOLATION` | Tool not in warrant.tools |
| `CONSTRAINT_VIOLATION` | Args don't satisfy constraints |
| `POP_MISSING` | Keypair not available for PoP |
| `POP_INVALID` | PoP signature invalid |
| `HOLDER_MISMATCH` | Wrong keypair for warrant holder |

All errors include:
- Error code
- Tool name
- Function name and module
- Callsite (filename:line)
- Specific fix suggestions

---

## Limitations

### ⚠️ Strict Mode Cannot Detect

1. **Missing `@lockdown` decorator entirely**
   - If a tool has no decorator, strict mode never runs
   - **Mitigation**: Code review, linting, type checking

2. **Wrapper bypass**
   - If wrapper checks tool names but not constraints
   - **Mitigation**: Always use `warrant.authorize()`, never manual checks

3. **LangGraph dynamic nodes**
   - If node is added without `@tenuo_node` or `@lockdown` on its tools
   - **Mitigation**: Fail-closed graph compilation (validate all nodes wrapped)

### What Strict Mode DOES Detect

- ✅ `@lockdown` used without warrant context
- ✅ Missing `set_warrant_context()` or `root_task()`
- ✅ Tools called outside authorization scope
- ✅ Context isolation issues (threads, async)

### ⚠️ Static Analysis Gap

Strict mode only catches runtime issues. Tools without `@lockdown` are invisible to Tenuo entirely.

```python
# This function is NEVER checked by Tenuo
def dangerous_tool(arg: str):
    delete_database(arg)  # No @lockdown = no protection

# Tenuo only sees functions it decorates
@lockdown(tool="safe_tool")
def safe_tool(arg: str):
    read_data(arg)  # ✅ Protected
```

**Future**: We're exploring a `tenuo lint` command to statically detect unprotected functions.

---

## Implementation Details

### Strict Mode Check (decorators.py)

```python
if not warrant_to_use:
    from .config import get_config
    config = get_config()
    
    if config.strict_mode:
        raise RuntimeError(
            f"STRICT MODE VIOLATION: Tool '{tool_name}' called without warrant context.\n"
            f"Fix: Ensure set_warrant_context() or root_task() is active."
        )
    
    if config.warn_on_missing_warrant:
        warnings.warn(
            f"⚠️ INTEGRATION WARNING: Tool '{tool_name}' called without warrant context.",
            category=SecurityWarning
        )
    
    # Standard error
    raise Unauthorized(f"No warrant available for {tool_name}")
```

**Performance**: Negligible (only checked when warrant is actually missing).

---

## Testing Integration Safety

### Test Strict Mode

```python
from tenuo import configure, lockdown, Keypair
import pytest

def test_strict_mode_catches_missing_warrant():
    configure(strict_mode=True, dev_mode=True, issuer_key=Keypair.generate())
    
    @lockdown(tool="test")
    def my_tool():
        return "executed"
    
    # Should raise RuntimeError (not Unauthorized)
    with pytest.raises(RuntimeError, match="STRICT MODE VIOLATION"):
        my_tool()
```

### Test Warning Mode

```python
from tenuo import configure, lockdown, Keypair
import warnings

def test_warning_mode():
    configure(warn_on_missing_warrant=True, dev_mode=True, issuer_key=Keypair.generate())
    
    @lockdown(tool="test")
    def my_tool():
        return "executed"
    
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        try:
            my_tool()
        except:
            pass
        
        # Should have generated warning
        assert len(w) == 1
        assert "INTEGRATION WARNING" in str(w[0].message)
```

---

## Migration Guide

### Step 1: Enable in Development

```python
# dev_config.py
configure(
    issuer_key=dev_keypair,
    dev_mode=True,
    warn_on_missing_warrant=True,  # Start with warnings
)
```

### Step 2: Fix Warnings

Run your test suite and fix all warnings:
```bash
pytest -W error::tenuo.decorators.SecurityWarning
```

### Step 3: Enable Strict Mode in CI

```python
# test_config.py
configure(
    issuer_key=Keypair.generate(),
    dev_mode=True,
    strict_mode=True,  # Fail tests on missing warrants
)
```

### Step 4: Production (Optional)

```python
# prod_config.py  
configure(
    issuer_key=prod_keypair,
    trusted_roots=[control_plane_key],
    strict_mode=False,  # Don't want hard crashes in prod
    warn_on_missing_warrant=False,  # Rely on audit logs
)
```

Monitor audit logs for `error_code: "no_warrant"`.

---

## FAQ

### Q: Should I use strict_mode in production?

**A:** It depends on your risk tolerance:

| Risk | Default | Strict Mode |
|------|---------|-------------|
| **Integration bug** | Tool executes, authorization fails, logs error | Application crashes immediately |
| **Availability** | ✅ Graceful degradation | ❌ Hard failure |
| **Security** | ⚠️ Unauthorized call might succeed if wrapper is buggy | ✅ Fail-closed guarantee |

**Recommendation**: Use strict mode in CI/staging. In production, use audit log monitoring unless you need absolute fail-closed guarantees.

### Q: Does strict_mode have performance impact?

**A:** No. The check only runs when a warrant is **actually missing** (error path).

### Q: Can I enable strict_mode per-module?

**A:** Not directly, but you can:
```python
# Use context override (advanced)
from tenuo.config import _config_context, TenuoConfig

strict_config = TenuoConfig(strict_mode=True, ...)
token = _config_context.set(strict_config)
try:
    # Code here runs with strict mode
    ...
finally:
    _config_context.reset(token)
```

### Q: What about LangChain/LangGraph tools?

**A:** Strict mode works for ANY tool protected with `@lockdown`:
- LangChain tools wrapped with `protect_tools()` ✅
- LangGraph nodes with `@tenuo_node` ✅
- Custom tools with `@lockdown` ✅

---

## See Also

- [Security Tests](https://github.com/horkosdev/tenuo/tree/main/tenuo-python/tests/security) - Attack scenarios that strict mode catches
- [API Reference → configure()](./api-reference#configuration) - Full configuration options
- [Security Model](./security) - Overall security guarantees
- [Argument Extraction](./argument-extraction) - How authorization works
