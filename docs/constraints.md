---
title: Constraints
description: How to use constraints to scope authority precisely
---

# Tenuo Constraints

> How to use constraints to scope authority precisely.

---

## Overview

Constraints are key-value pairs that restrict what a warrant authorizes. When a tool is invoked, Tenuo checks that the arguments satisfy the warrant's constraints.

```python
# Create warrant with constraints
warrant = Warrant.issue(
    tools=["read_file"],
    constraints={
        "path": Pattern("/data/*"),      # Path must match /data/*
        "max_size": Range.max_value(1000) # Size must be ≤ 1000
    },
    ...
)

# Tool invocation checks constraints
@lockdown(tool="read_file")
def read_file(path: str, max_size: int):
    ...  # Only runs if path matches and max_size ≤ 1000
```

---

## Constraint Types

### Pattern (Glob)

Matches strings against glob patterns with `*` wildcard.

```python
from tenuo import Pattern

# Matches anything under /data/
Pattern("/data/*")

# Matches any .csv file
Pattern("*.csv")

# Exact match (no wildcard)
Pattern("specific-value")
```

**Examples:**
| Pattern | Value | Match? |
|---------|-------|--------|
| `/data/*` | `/data/file.txt` | ✅ |
| `/data/*` | `/data/reports/q3.csv` | ✅ |
| `/data/*` | `/etc/passwd` | ❌ |
| `*.csv` | `report.csv` | ✅ |
| `*.csv` | `report.json` | ❌ |

---

### Exact

Matches exactly one value.

```python
from tenuo import Exact

# Only allows "production"
Exact("production")

# Only allows this specific ID
Exact("user-12345")
```

---

### OneOf

Matches any value in a set.

```python
from tenuo import OneOf

# Allows any of these environments
OneOf(["staging", "production", "dev"])

# Allows specific actions
OneOf(["read", "list"])
```

---

### Range

Constrains numeric values to a range.

```python
from tenuo import Range

# 0 to 100 (inclusive)
Range(min=0, max=100)

# At most 1000
Range.max_value(1000)

# At least 10
Range.min_value(10)
```

**Examples:**
| Range | Value | Match? |
|-------|-------|--------|
| `Range.max_value(100)` | `50` | ✅ |
| `Range.max_value(100)` | `150` | ❌ |
| `Range(min=10, max=50)` | `25` | ✅ |
| `Range(min=10, max=50)` | `5` | ❌ |

---

### Regex

Matches strings against regular expressions.

```python
from tenuo import Regex

# Matches production-* pattern
Regex(r"^production-[a-z]+$")

# Matches email format
Regex(r"^[a-z]+@company\.com$")
```

---

### NotOneOf

Excludes specific values (use sparingly - prefer allowlists).

```python
from tenuo import NotOneOf

# Block admin and root
NotOneOf(["admin", "root"])
```

⚠️ **Security**: Always prefer `OneOf` (allowlist) over `NotOneOf` (denylist).

---

## Constraint Narrowing (Attenuation)

When attenuating a warrant, child constraints must be **contained** within parent constraints.

### Pattern Narrowing

```python
# Parent: /data/*
parent = Warrant.issue(constraints={"path": Pattern("/data/*")}, ...)

# ✅ Child: /data/reports/* (narrower)
child = parent.attenuate(constraints={"path": Pattern("/data/reports/*")}, ...)

# ❌ Child: /* (wider - FAILS)
child = parent.attenuate(constraints={"path": Pattern("/*")}, ...)
```

### Range Narrowing

```python
# Parent: max 1000
parent = Warrant.issue(constraints={"budget": Range.max_value(1000)}, ...)

# ✅ Child: max 500 (narrower)
child = parent.attenuate(constraints={"budget": Range.max_value(500)}, ...)

# ❌ Child: max 2000 (wider - FAILS)
child = parent.attenuate(constraints={"budget": Range.max_value(2000)}, ...)
```

### OneOf Narrowing

```python
# Parent: ["a", "b", "c"]
parent = Warrant.issue(constraints={"action": OneOf(["a", "b", "c"])}, ...)

# ✅ Child: ["a", "b"] (subset)
child = parent.attenuate(constraints={"action": OneOf(["a", "b"])}, ...)

# ❌ Child: ["a", "b", "d"] (adds "d" - FAILS)
child = parent.attenuate(constraints={"action": OneOf(["a", "b", "d"])}, ...)
```

---

## Using Constraints with Tools

### With @lockdown Decorator

```python
from tenuo import lockdown, Pattern, Range

@lockdown(tool="transfer_money")
def transfer_money(account: str, amount: float):
    # Tenuo checks: 
    # - "account" against any Pattern/Exact constraint
    # - "amount" against any Range constraint
    ...
```

### With protect_tools

```python
from tenuo import protect_tools

from tenuo import protect_tools

# Protect tools (uses warrant/keypair from context)
protected = protect_tools([read_file, write_file, delete_file])
```

---

## Common Patterns

### File Path Constraints

```python
# Read-only access to reports directory
with root_task(tools=["read_file"], path=Pattern("/data/reports/*")):
    await read_file(path="/data/reports/q3.csv")  # ✅
    await read_file(path="/etc/passwd")           # ❌
```

### Budget/Amount Limits

```python
# Limit transaction amounts
with root_task(tools=["transfer"], amount=Range.max_value(1000)):
    await transfer(amount=500)   # ✅
    await transfer(amount=5000)  # ❌
```

### Environment Restrictions

```python
# Only staging and dev
with root_task(tools=["deploy"], env=OneOf(["staging", "dev"])):
    await deploy(env="staging")    # ✅
    await deploy(env="production") # ❌
```

### Scoped Database Access

```python
# Only specific tables
with root_task(tools=["query"], table=OneOf(["users", "orders"])):
    await query(table="users")   # ✅
    await query(table="secrets") # ❌
```

---

## See Also

- [API Reference](./api-reference.md) — Full constraint API
- [Security](./security.md) — How constraints fit into the security model
- [LangGraph Integration](./langgraph.md) — Using constraints with LangGraph
