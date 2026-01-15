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

```python
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

```python
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

### 3. Use `explain()` for Errors

Print actionable diagnostics from any Tenuo exception:

```python
from tenuo import explain, explain_str

try:
    protected_function()
except TenuoError as e:
    explain(e)  # Prints to stderr with suggested fixes
```

**Output:**
```
❌ CONSTRAINT_VIOLATION: Argument 'path' violated constraint
   Constraint: Pattern("/data/*")
   Value: /etc/passwd
   
💡 How to fix:
   - Request a path matching the pattern "/data/*"
   - Example: /data/reports/q3.csv
```

Get as string instead:
```python
message = explain_str(e)  # Returns string instead of printing
```

---

### 4. Use `warrant.explain()`

Get a human-readable explanation of any warrant:

```python
# Basic explanation
print(warrant.explain())

# Include delegation chain
print(warrant.explain(include_chain=True))
```

**Output:**
```
Warrant tnu_wrt_019b482c...
  Issuer: ed25519:abc123...
  Holder: ed25519:def456...
  Tools: ['search', 'read_file']
  TTL: 45m remaining
  Depth: 2

Chain:
  [0] Root (control_plane) → issued to orchestrator
  [1] orchestrator → delegated to worker
  [2] worker (current)
```

---

### 5. Use `info()`

Get environment and configuration info for debugging:

```python
from tenuo import info

print(info())
```

**Output:**
```
Tenuo Configuration
==================================================

[OK] SDK Version: 0.1.0b5
[OK] Rust Core: loaded (wire version 1)
[OK] Issuer Key: configured
```

---

## CLI Debugging

Use the CLI to decode and inspect warrants:

```bash
# Decode a warrant
tenuo decode "eyJ0eXAi..."

# Validate authorization
tenuo validate "eyJ0eXAi..." --tool read_file --args '{"path": "/data/file.txt"}'

# Check configuration
tenuo version
```

See [CLI Reference](./cli) for full command documentation.

---

## Explorer Playground

**[🔬 Tenuo Explorer](https://tenuo.dev/explorer/)** — Interactive warrant debugging:

- **Decode** any warrant visually
- **Test authorization** with different arguments
- **Inspect delegation chains**
- **Generate code snippets** (Python, Rust)
- **Build warrants** with the visual builder

Warrants contain only signed claims, not secrets. They're safe to paste and share.

---

## Common Issues

### Tool Not Authorized

**Error:** `Tool 'delete_file' is not authorized`

**Cause:** The warrant doesn't include this tool in its allowed tools list.

**Debug:**
```python
print(f"Warrant tools: {warrant.tools}")
# ['search', 'read_file']  # delete_file not listed
```

**Fix:** Request a warrant that includes the tool, or use a different tool.

---

### Constraint Violation

**Error:** `Constraint 'path' violated`

**Cause:** The argument doesn't match the warrant's constraint.

**Debug:**
```python
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

### Unknown Field Rejected

**Error:** `unknown field not allowed (zero-trust mode)`

**Cause:** You defined at least one constraint, which activates **closed-world mode**. All arguments must be explicitly constrained.

**Debug:**
```python
result = warrant.why_denied("api_call", {"url": "...", "timeout": 30})
print(f"Field: {result.field}")
# Field: timeout (unknown)
```

**Fix options:**
1. Add a constraint for the field: `timeout=Range.max_value(60)`
2. Use `Wildcard()` to allow any value: `timeout=Wildcard()`
3. Opt out of closed-world: `_allow_unknown=True`

See [Closed-World Mode](./constraints#closed-world-mode-trust-cliff) for details.

---

### Warrant Expired

**Error:** `Warrant has expired`

**Debug:**
```python
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
```python
from tenuo import warrant_scope, key_scope

# Wrap your call
with warrant_scope(warrant), key_scope(keypair):
    protected_function()
```

Or use explicit `BoundWarrant`:
```python
protected = guard(tools, warrant.bind(key))
```

---

### Key Mismatch

**Error:** `PoP signature invalid`

**Cause:** The keypair used to sign doesn't match the warrant's holder.

**Debug:**
```python
print(f"Warrant holder: {warrant.holder}")
print(f"Key public: {keypair.public_key}")
# Compare - should be equal
```

**Fix:** Use the correct keypair.

---

## Convenience Properties

Quick status checks:

```python
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

```python
# Check if tool is in warrant
if warrant.allows("search"):
    show_search_button()

# Check if args would pass constraints
if warrant.allows("read_file", args={"path": "/data/file.txt"}):
    show_file_picker()
```

**Never use for authorization decisions:**
```python
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
| `unknown field not allowed` | Closed-world mode active | Add constraint or `_allow_unknown` |
| `Warrant expired` | TTL exceeded | Get fresh warrant |
| `No warrant in context` | Missing context | Use `warrant_scope()` |
| `PoP signature invalid` | Wrong key | Use holder's keypair |
| `MonotonicityViolation` | Tried to expand scope | Scopes only shrink |
| `Key 'X' not found` | Key not in registry | Register key or `load_tenuo_keys()` |

---

## Logging

Enable debug logging for detailed traces:

```python
import logging

# Tenuo components
logging.getLogger("tenuo").setLevel(logging.DEBUG)
logging.getLogger("tenuo.fastapi").setLevel(logging.DEBUG)
logging.getLogger("tenuo.langgraph").setLevel(logging.DEBUG)
```

---

## Request IDs

Authorization errors include a request ID for log correlation:

```python
# Client sees:
# "Authorization denied (ref: abc123)"

# Logs show:
# [abc123] Tool 'search' denied: query=/etc/passwd, expected=Pattern(/data/*)
```
```python
@guard(tool="search")
def search(query: str):
    ...
```

Use this ID to find detailed logs on the server side.

---

## See Also

- [Security](./security) — Threat model, best practices
- [API Reference](./api-reference) — Full Python API documentation
- [Constraints](./constraints) — Constraint types and behavior

