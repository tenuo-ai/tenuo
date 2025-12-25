---
title: Debugging Guide
description: Troubleshoot authorization failures with Tenuo
---

# Debugging Guide

When authorization fails, Tenuo provides tools to understand exactly what went wrong.

---

## Quick Debugging

### 1. Use `why_denied()`

Get a structured explanation of authorization failures:

```python mdpytest:skip
result = warrant.why_denied("read_file", {"path": "/etc/passwd"})

if result.denied:
    print(f"Denied: {result.deny_code}")
    print(f"Field: {result.field}")
    print(f"Suggestion: {result.suggestion}")
```

**Output:**
```
Denied: CONSTRAINT_VIOLATION
Field: path
Suggestion: Request a path matching Pattern("/data/*")
```

### 2. Use `diagnose()`

Get a complete warrant inspection:

```python mdpytest:skip
from tenuo import diagnose

diagnose(warrant)
```

**Output:**
```
=== Warrant Inspection ===
ID: tnu_wrt_019b482c2a0473e3aa5ccf39e70e197c
Issuer: ed25519:abc123...
Holder: ed25519:def456...
Expires At: 2025-12-22T15:00:00Z
TTL Remaining: 0:45:30
Is Terminal: False
Is Expired: False

Tools: ['search', 'read_file']

Capabilities:
  search:
    query: Pattern("*")
  read_file:
    path: Pattern("/data/*")
```

---

## Common Issues

### Tool Not Authorized

**Error:** `Tool 'delete_file' is not authorized`

**Cause:** The warrant doesn't include this tool in its allowed tools list.

**Debug:**
```python mdpytest:skip
print(f"Warrant tools: {warrant.tools}")
# ['search', 'read_file']  # delete_file not listed
```

**Fix:** Request a warrant that includes the tool, or use a different tool.

---

### Constraint Violation

**Error:** `Constraint 'path' violated`

**Cause:** The argument doesn't match the warrant's constraint.

**Debug:**
```python mdpytest:skip
result = warrant.why_denied("read_file", {"path": "/etc/passwd"})
print(f"Field: {result.field}")
print(f"Constraint: {result.constraint}")
print(f"Value: {result.value}")
```

**Output:**
```
Field: path
Constraint: Pattern("/data/*")
Value: /etc/passwd
```

**Fix:** Request within the allowed constraints.

---

### Warrant Expired

**Error:** `Warrant has expired`

**Debug:**
```python mdpytest:skip
print(f"Expired: {warrant.is_expired}")
print(f"Expires at: {warrant.expires_at}")
print(f"TTL remaining: {warrant.ttl_remaining}")
```

**Fix:** Request a fresh warrant from the issuer.

---

### Missing Context

**Error:** `No warrant in context`

**Cause:** `@guard` decorator expects a warrant in context, but none was set.

**Fix:**
```python mdpytest:skip
from tenuo import warrant_scope, key_scope

# Wrap your call
with warrant_scope(warrant), key_scope(keypair):
    protected_function()
```

Or use explicit `BoundWarrant`:
```python mdpytest:skip
protected = guard(tools, warrant.bind(key))
```

---

### Key Mismatch

**Error:** `PoP signature invalid`

**Cause:** The keypair used to sign doesn't match the warrant's holder.

**Debug:**
```python mdpytest:skip
print(f"Warrant holder: {warrant.authorized_holder}")
print(f"Key public: {keypair.public_key}")
# Compare - should be equal
```

**Fix:** Use the correct keypair.

---

## Convenience Properties

Quick status checks:

```python mdpytest:skip
# Time until expiry
warrant.ttl_remaining   # timedelta(seconds=3600)
warrant.ttl             # alias

# Status flags
warrant.is_expired      # bool
warrant.is_terminal     # bool - can't delegate further

# Human-readable constraints
warrant.capabilities    # dict
# {'search': {'query': 'Pattern("*")'}, 'read_file': {'path': 'Pattern("/data/*")'}}

# Expiration time
warrant.expires_at      # "2025-12-22T15:00:00Z"
```

---

## Logic Checks (UX Only)

⚠️ **These are NOT security checks** - use for UI hints only:

```python mdpytest:skip
# Check if tool is in warrant
if warrant.allows("search"):
    show_search_button()

# Check if args would pass constraints
if warrant.allows("read_file", args={"path": "/data/file.txt"}):
    show_file_picker()
```

**Never use for authorization decisions:**
```python mdpytest:skip
# ❌ WRONG
if warrant.allows("delete"):
    delete_database()  # No PoP verification!

# ✅ CORRECT
if bound.validate("delete", {"id": "123"}):
    delete_database()
```

---

## Error Message Reference

| Error | Meaning | Common Fix |
|-------|---------|------------|
| `Tool 'X' not authorized` | Tool not in warrant | Add tool to warrant |
| `Constraint 'X' violated` | Arg doesn't match constraint | Use allowed values |
| `Warrant expired` | TTL exceeded | Get fresh warrant |
| `No warrant in context` | Missing context | Use `warrant_scope()` |
| `PoP signature invalid` | Wrong key | Use holder's keypair |
| `MonotonicityViolation` | Tried to expand scope | Scopes only shrink |
| `Key 'X' not found` | Key not in registry | Register key or `load_tenuo_keys()` |

---

## Logging

Enable debug logging for detailed traces:

```python mdpytest:skip
import logging

# Tenuo components
logging.getLogger("tenuo").setLevel(logging.DEBUG)
logging.getLogger("tenuo.fastapi").setLevel(logging.DEBUG)
logging.getLogger("tenuo.langgraph").setLevel(logging.DEBUG)
```

---

## Request IDs

Authorization errors include a request ID for log correlation:

```python mdpytest:skip
# Client sees:
# "Authorization denied (ref: abc123)"

# Logs show:
# [abc123] Tool 'search' denied: query=/etc/passwd, expected=Pattern(/data/*)
```
```python mdpytest:skip
@guard(tool="search")
def search(query: str):
    ...
```

Use this ID to find detailed logs on the server side.

---

## Interactive Debugging

**[🔬 Explorer Playground](https://tenuo.dev/explorer)** — Paste any warrant to:
- Decode and inspect constraints visually
- Test authorization with different arguments
- See the delegation chain
- Generate code snippets

Warrants contain only signed claims, not secrets—safe to paste and share.

---

## See Also

- [Security](./security) — Threat model, best practices
- [API Reference](./api-reference) — Full Python API documentation
- [Constraints](./constraints) — Constraint types and behavior

