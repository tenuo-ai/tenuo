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

> **⚠️ Attenuation Limitation**: Regex constraints **cannot be narrowed** during attenuation.
>
> Child regex must have **identical pattern** to parent. This is because determining if one regex is a subset of another is mathematically undecidable in the general case.
>
> ```python
> # Parent with regex
> parent = Warrant.issue(
>     tools=["query"],
>     constraints={"env": Regex(r"^(staging|dev)-.*$")},
>     ...
> )
>
> # ❌ Cannot narrow to different regex (even if provably narrower)
> child = parent.attenuate(
>     constraints={"env": Regex(r"^staging-.*$")},  # FAILS
>     ...
> )
>
> # ✅ Can narrow to Exact value (if it matches parent regex)
> child = parent.attenuate(
>     constraints={"env": Exact("staging-web")},  # OK
>     ...
> )
>
> # ✅ Can keep same regex pattern
> child = parent.attenuate(
>     constraints={"env": Regex(r"^(staging|dev)-.*$")},  # OK
>     ...
> )
> ```
>
> **Workaround**: If you need to narrow regex constraints during delegation:
> 1. Use `Pattern()` instead (supports simple prefix/suffix narrowing)
> 2. Attenuate to `Exact()` for specific values
> 3. Keep the same regex in child warrants

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

Complex logic using CEL expressions for advanced authorization rules.

```python
from tenuo import CEL

# Simple comparison
CEL("amount < 10000 && amount > 0")

# Multi-parameter validation
CEL("budget < revenue * 0.1 && currency == 'USD'")
```

**How it works:**
- CEL expressions evaluate to **boolean** (true/false)
- For **object values**, each field becomes a top-level variable
- For **primitive values**, the value is available as `value`
- Expressions are **compiled once** and cached for performance (max 1000 entries)

**Example:**
```python
# Budget must be less than 10% of revenue
warrant = Warrant.issue(
    tools=["create_campaign"],
    constraints={
        "budget_check": CEL("budget < revenue * 0.1 && budget > 0")
    },
    keypair=keypair,
    ttl_seconds=3600
)

# When tool is called with:
# create_campaign(budget=5000, revenue=100000, ...)
# CEL evaluates: 5000 < 100000 * 0.1 && 5000 > 0 → true ✅
```

#### Standard Library Functions

Tenuo provides built-in functions for common use cases:

**Time Functions:**

```python
# Check if timestamp hasn't expired
CEL("!time_is_expired(deadline)")

# Only allow if created within last hour
CEL("time_since(created_at) < 3600")

# Get current time (requires dummy arg due to library limitation)
CEL("time_now(null).startsWith('2024')")
```

| Function | Signature | Description |
|----------|-----------|-------------|
| `time_now(unused)` | `(_) -> String` | Returns current time in RFC3339 format |
| `time_is_expired(ts)` | `(String) -> bool` | Checks if RFC3339 timestamp has passed |
| `time_since(ts)` | `(String) -> i64` | Seconds since RFC3339 timestamp (0 if invalid/future) |

**Network Functions:**

```python
# Only allow requests from internal network
CEL("net_in_cidr(ip, '10.0.0.0/8') || net_in_cidr(ip, '192.168.0.0/16')")

# Block public IPs
CEL("net_is_private(source_ip)")
```

| Function | Signature | Description |
|----------|-----------|-------------|
| `net_in_cidr(ip, cidr)` | `(String, String) -> bool` | Check if IP (v4/v6) is in CIDR block |
| `net_is_private(ip)` | `(String) -> bool` | Check if IP is in private range (RFC 1918) |

**Time-bounded Example:**
```python
# Only allow if order created within last 24 hours
warrant = Warrant.issue(
    tools=["process_order"],
    constraints={
        "freshness": CEL("time_since(created_at) < 86400")
    },
    keypair=keypair,
    ttl_seconds=3600
)
```

**Network Example:**
```python
# Only allow API calls from private network
warrant = Warrant.issue(
    tools=["api_call"],
    constraints={
        "network": CEL("net_in_cidr(source_ip, '10.0.0.0/8')")
    },
    keypair=keypair,
    ttl_seconds=3600
)
```

#### CEL Attenuation

Child CEL constraints are automatically combined with parent using AND logic:

```python
# Parent: budget < 10000
parent = Warrant.issue(
    tools=["spend"],
    constraints={"budget_rule": CEL("budget < 10000")},
    keypair=kp,
    ttl_seconds=3600
)

# Child: Add additional constraint (auto-AND'd)
child = parent.attenuate(
    constraints={"budget_rule": CEL("currency == 'USD'")},
    holder=worker_kp.public_key
)

# Effective child expression: (budget < 10000) && (currency == 'USD')
```

**Syntactic Monotonicity (Conservative Approach)**

⚠️ Tenuo enforces **Syntactic Monotonicity** for CEL, not Semantic Monotonicity.

Child expression must **literally** be `(parent) && new_predicate`. It cannot be a semantically equivalent but differently structured expression.

```python
# Parent CEL
parent = Warrant.issue(
    tools=["api_call"],
    constraints={"network": CEL("net_in_cidr(ip, '10.0.0.0/8')")},
    keypair=kp,
    ttl_seconds=3600
)

# ❌ REJECTED: Semantically narrower but not syntactically derived
child = parent.attenuate(
    constraints={"network": CEL("net_in_cidr(ip, '10.1.0.0/16')")},  # FAILS
    holder=worker_kp.public_key
)
# Even though 10.1.0.0/16 ⊂ 10.0.0.0/8, this is REJECTED

# ✅ ALLOWED: Syntactically derived (AND'd)
child = parent.attenuate(
    constraints={"network": CEL("(net_in_cidr(ip, '10.0.0.0/8')) && net_in_cidr(ip, '10.1.0.0/16')")},
    holder=worker_kp.public_key
)
# Now it's ALLOWED because it's (parent) && additional_check
```

**Why Syntactic?**

Semantic analysis (proving one expression is strictly narrower) requires:
- Automated theorem proving
- Understanding domain semantics (CIDR blocks, time logic, etc.)
- Potential false negatives or security holes

Syntactic monotonicity is **conservative but secure**: If the child is `(parent) && X`, it's guaranteed to be narrower or equal.

**Recommendation**: Use simpler constraint types (Pattern, Range, OneOf) when possible. Reserve CEL for truly complex logic that can't be expressed otherwise.

#### Security Properties

✅ **Sandboxed Execution**: CEL cannot execute arbitrary code, only evaluate expressions  
✅ **Deterministic**: Same inputs always produce same results  
✅ **Cached Programs**: Compiled expressions cached (max 1000) for performance  
✅ **Type Safe**: Must return boolean or evaluation fails  
✅ **No Side Effects**: Expressions are pure - no I/O, no state mutation  
✅ **Safe Standard Library**: Only time/network parsing functions, no file/network I/O

#### Security Considerations

**DoS Protection:**

While CEL expressions are sandboxed, extremely complex expressions could still consume CPU:

```python
# ⚠️ Potentially expensive (though bounded by compilation)
CEL("(((((a && b) || (c && d)) && ((e || f) && (g || h))) || ...) ...")
```

**Mitigations in place:**
- **Compilation fails** on malformed expressions (syntax errors caught early)
- **Cache limit** (1000 entries) prevents unbounded memory growth
- `cel-interpreter` v0.8.1 (no known DoS vulnerabilities)

**Best Practices:**
- **Keep expressions simple** - prefer built-in constraint types when possible
- **Test expressions** before deployment with representative inputs
- **Use syntactic attenuation** - child must be `(parent) && X` for safety

⚠️ **Important Notes**:
- CEL expressions **must return boolean**. Non-boolean results cause `CelError`.
- The constraint key (e.g., `"budget_check"`) is informational; the expression defines the logic.
- **Syntactic monotonicity** is enforced for attenuation (see above).
- Standard library functions are safe and deterministic (no I/O beyond time/IP parsing).

---

## Constraint Narrowing (Attenuation)

When attenuating a warrant, child constraints must be **contained** within parent constraints.

### Attenuation Compatibility Matrix

| Parent Type | Can Attenuate To |
|-------------|------------------|
| `Wildcard()` | **Any** constraint type (universal) |
| `Pattern()` | Pattern (if narrower), Exact (if matches), Regex |
| `Regex()` | **Same** Regex only, Exact (if matches) |
| `Exact()` | Same Exact only |
| `OneOf()` | OneOf (subset), NotOneOf, Exact (if in set) |
| `NotOneOf()` | NotOneOf (more exclusions) |
| `Range()` | Range (narrower bounds) |
| `Contains()` | Contains (more required values) |
| `Subset()` | Subset (fewer allowed values) |
| `All()` | All (more constraints) |
| `CEL()` | CEL (conjunction with parent) |

⚠️ **Key Limitations**:
- **Regex**: Cannot narrow to different regex patterns (undecidable subset problem)
- **Exact**: Cannot change value at all
- **No attenuation TO Wildcard**: Would re-widen authority

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
# Parent: max 15 replicas
parent = Warrant.issue(constraints={"replicas": Range.max_value(15)}, ...)

# ✅ Child: max 10 (narrower)
child = parent.attenuate(constraints={"replicas": Range.max_value(10)}, ...)

# ❌ Child: max 20 (wider - FAILS)
child = parent.attenuate(constraints={"replicas": Range.max_value(20)}, ...)
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

### Regex Narrowing

⚠️ **Regex constraints are conservative**: Child regex must have **identical pattern** to parent.

```python
# Parent: regex pattern
parent = Warrant.issue(constraints={"env": Regex(r"^(staging|dev)-.*$")}, ...)

# ❌ Cannot narrow to different regex (even if provably narrower)
child = parent.attenuate(constraints={"env": Regex(r"^staging-.*$")}, ...)  # FAILS

# ✅ Can keep same pattern
child = parent.attenuate(constraints={"env": Regex(r"^(staging|dev)-.*$")}, ...)  # OK

# ✅ Can narrow to Exact (if it matches parent regex)
child = parent.attenuate(constraints={"env": Exact("staging-web")}, ...)  # OK
```

**Why**: Determining if one regex is a subset of another is undecidable in general. Tenuo takes a conservative approach for security.

**Recommendation**: Use `Pattern()` for simple matching that needs attenuation, or `Exact()` for specific values.

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

### Replica/Capacity Limits

```python
# Limit replica counts
with root_task(tools=["scale"], replicas=Range.max_value(15)):
    await scale(replicas=5)   # ✅
    await scale(replicas=20)  # ❌
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

- [API Reference](./api-reference) — Full constraint API
- [Security](./security) — How constraints fit into the security model
- [LangGraph Integration](./langgraph) — Using constraints with LangGraph
