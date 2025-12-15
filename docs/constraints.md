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

### Wildcard

Matches anything. The universal superset that can be attenuated to any other constraint type.

```python
from tenuo import Wildcard

# Allows any value
Wildcard()
```

**Use case:** Root warrants that grant broad authority, which can be narrowed later.

```python
# Parent: any query
with root_task(tools=["search"], query=Wildcard()):
    ...

# Child: narrowed to specific pattern
with scoped_task(query=Pattern("*public*")):
    ...
```

⚠️ **Security**: Wildcard can only appear in root warrants. Attenuating to Wildcard is blocked (would re-widen authority).

> **Note**: `Wildcard()` is different from `Pattern("*")`. See the [Pattern section below](#pattern-glob) for details.

---

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

> **⚠️ Important Distinction: `Wildcard()` vs `Pattern("*")` vs `"*"`**
>
> These three are **NOT** the same:
>
> 1. **`Wildcard()`** - Universal constraint that can be attenuated to *any* other constraint type (Pattern, Exact, Range, etc.)
> 2. **`Pattern("*")`** - A glob pattern that matches any string, but can only be attenuated to other patterns or Exact
> 3. **`"*"` (string literal)** - Just a regular string value that happens to contain an asterisk
>
> ```python
> # ✅ Flexible: Wildcard can become anything
> with root_task(tools=["search"], query=Wildcard()):
>     with scoped_task(query=Pattern("/data/*")):  # ✅ OK
>         ...
>     with scoped_task(query=Range.max_value(100)):  # ✅ OK
>         ...
>
> # ⚠️ Limited: Pattern can only narrow to other patterns or exact values
> with root_task(tools=["search"], query=Pattern("*")):
>     with scoped_task(query=Pattern("/data/*")):  # ✅ OK (simple prefix)
>         ...
>     with scoped_task(query=Exact("specific")):  # ✅ OK
>         ...
>     with scoped_task(query=Range.max_value(100)):  # ❌ Type mismatch
>         ...
> ```
>
> **Best Practice**: Use `Wildcard()` in root warrants for maximum flexibility. Use `Pattern("*")` only if you specifically need glob matching semantics.
>
> **Attenuation Rules for Pattern**:
> - Simple **prefix** patterns (`foo*`) can be narrowed to more specific prefixes
> - Simple **suffix** patterns (`*bar`) can be narrowed to more specific suffixes  
> - **Complex patterns** (e.g., `*foo*`, `a*b*c`) require exact equality for attenuation

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

⚠️ **Security**: Always prefer `OneOf` (allowlist) over `NotOneOf` (denylist). `NotOneOf` should only be used to "carve holes" in a parent's positive constraint.

---

### Contains

List must contain all specified values.

```python
from tenuo import Contains

# List must include both "read" and "write"
Contains(["read", "write"])
```

**Example:**
```python
# Warrant requires ["read", "write"] permissions
warrant = Warrant.issue(
    tools=["access_resource"],
    constraints={"permissions": Contains(["read", "write"])},
    ...
)

# ✅ Matches: ["read", "write", "admin"]
# ❌ Doesn't match: ["read"] (missing "write")
```

---

### Subset

List must be a subset of allowed values.

```python
from tenuo import Subset

# List must only contain allowed values
Subset(["staging", "dev", "test"])
```

**Example:**
```python
# Warrant allows only specific environments
warrant = Warrant.issue(
    tools=["deploy"],
    constraints={"environments": Subset(["staging", "dev"])},
    ...
)

# ✅ Matches: ["staging"]
# ✅ Matches: ["staging", "dev"]
# ❌ Doesn't match: ["staging", "production"] (includes disallowed "production")
```

---

### All (AND)

All nested constraints must match.

```python
from tenuo import All, Pattern, Range

# Path must match pattern AND size must be in range
All([
    Pattern("/data/*"),
    Range.max_value(1000)
])
```

**Use case:** Combine multiple constraint types for the same parameter.

---

### AnyOf (OR)

At least one nested constraint must match.

```python
from tenuo import AnyOf, Pattern

# Path must match at least one pattern
AnyOf([
    Pattern("/data/reports/*"),
    Pattern("/data/analytics/*")
])
```

---

### Not

Negation of a constraint.

```python
from tenuo import Not, Exact

# Anything except "production"
Not(Exact("production"))
```

⚠️ **Security**: Use sparingly. Prefer positive allowlists.

---

### CEL (Common Expression Language)

Complex logic using CEL expressions.

```python
from tenuo import CEL

# Custom logic: budget < revenue * 0.1
CEL("args.budget < args.revenue * 0.1")
```

**Example:**
```python
# Budget must be less than 10% of revenue
warrant = Warrant.issue(
    tools=["create_campaign"],
    constraints={
        "budget_check": CEL("budget < revenue * 0.1 && budget > 0")
    },
    ...
)
```

⚠️ **Note**: CEL expressions have access to `args` (tool arguments) and can reference multiple parameters.

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

# Protect tools (uses warrant/keypair from context)
protected = protect_tools([read_file, write_file, delete_file])
```

---

## Common Patterns

### Wildcard to Specific Constraints

```python
# Parent: any query
with root_task(tools=["search"], query=Wildcard()):
    # Child: narrow to pattern
    with scoped_task(query=Pattern("*public*")):
        await search(query="public data")  # ✅
```

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
