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
from tenuo import Warrant, Constraints, Pattern, Range

# Create warrant with per-tool constraints
warrant = Warrant.issue(
    tools={"read_file": Constraints.for_tool("read_file", {
        "path": Pattern("/data/*"),      # Path must match /data/*
        "max_size": Range.max_value(1000) # Size must be ≤ 1000
    })},
    keypair=keypair,
    holder=worker_pubkey,
    ttl_seconds=3600,
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
with root_task(Capability("search", query=Wildcard())):
    ...

# Child: narrowed to specific pattern
with scoped_task(Capability("search", query=Pattern("*public*"))):
    ...
```

**Security**: Wildcard can only appear in root warrants. Attenuating to Wildcard is blocked (would re-widen authority).

> **Note**: `Wildcard()` is different from `Pattern("*")`. See the [Pattern section below](#pattern-glob) for details.

---

### Pattern (Glob)

Matches strings against Unix shell-style glob patterns.

```python
from tenuo import Pattern

# Suffix wildcard - matches paths starting with /data/
Pattern("/data/*")

# Prefix wildcard - matches emails ending with @company.com
Pattern("*@company.com")

# Middle wildcard - matches specific file in any subdirectory
Pattern("/data/*/config.yaml")

# Single character - matches file1.txt, fileA.txt, etc.
Pattern("file?.txt")

# Character class - matches env-prod, env-staging, env-dev
Pattern("env-[psd]*")

# Exact match (no wildcard)
Pattern("specific-value")
```

**Supported Glob Syntax:**
| Syntax | Description | Example |
|--------|-------------|---------|
| `*` | Matches any characters (including none) | `staging-*` matches `staging-web` |
| `?` | Matches exactly one character | `file?.txt` matches `file1.txt` |
| `[abc]` | Matches any character in set | `[psd]*` matches `prod`, `staging`, `dev` |
| `[!abc]` | Matches any character NOT in set | `[!0-9]*` matches non-numeric start |

**Examples by Wildcard Position:**
| Pattern | Value | Match? | Description |
|---------|-------|--------|-------------|
| `/data/*` | `/data/file.txt` | Yes | Suffix wildcard |
| `/data/*` | `/etc/passwd` | No | Wrong prefix |
| `*@company.com` | `cfo@company.com` | Yes | Prefix wildcard |
| `*@company.com` | `hacker@evil.com` | No | Wrong suffix |
| `/data/*/file.txt` | `/data/reports/file.txt` | Yes | Middle wildcard |
| `/data/*/file.txt` | `/data/reports/other.txt` | No | Filename mismatch |
| `file?.txt` | `file1.txt` | Yes | Single char wildcard |
| `file?.txt` | `file12.txt` | No | Too many chars |

> **Important Distinction: `Wildcard()` vs `Pattern("*")` vs `"*"`**
>
> These three are **NOT** the same:
>
> 1. **`Wildcard()`** - Universal constraint that can be attenuated to *any* other constraint type (Pattern, Exact, Range, etc.)
> 2. **`Pattern("*")`** - A glob pattern that matches any string, but can only be attenuated to other patterns or Exact
> 3. **`"*"` (string literal)** - Just a regular string value that happens to contain an asterisk
>
> ```python
> # Flexible: Wildcard can become anything
> with root_task(Capability("search", query=Wildcard())):
>     with scoped_task(Capability("search", query=Pattern("/data/*"))):  # OK
>         ...
>     with scoped_task(Capability("search", query=Range.max_value(100))):  # OK
>         ...
>
> # Limited: Pattern can only narrow to other patterns or exact values
> with root_task(Capability("search", query=Pattern("*"))):
>     with scoped_task(Capability("search", query=Pattern("/data/*"))):  # OK (simple prefix)
>         ...
>     with scoped_task(Capability("search", query=Exact("specific"))):  # OK
>         ...
>     with scoped_task(Capability("search", query=Range.max_value(100))):  # FAILS - Type mismatch
>         ...
> ```
>
> **Best Practice**: Use `Wildcard()` in root warrants for maximum flexibility. Use `Pattern("*")` only if you specifically need glob matching semantics.
>
> **Attenuation Rules for Pattern**:
> - **Suffix wildcard** patterns (`/data/*`) can narrow to longer prefixes (`/data/reports/*`)
> - **Prefix wildcard** patterns (`*@company.com`) can narrow to exact values (`cfo@company.com`)
> - Patterns can always narrow to `Exact()` if the value matches the pattern
> - Complex patterns with multiple wildcards can be narrowed if contained within parent

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
| `Range.max_value(100)` | `50` | Yes |
| `Range.max_value(100)` | `150` | No |
| `Range(min=10, max=50)` | `25` | Yes |
| `Range(min=10, max=50)` | `5` | No |

---

### Cidr

Constrains IP addresses to a network range using CIDR notation. Supports both IPv4 and IPv6.

```python
from tenuo import Cidr

# IPv4 networks
Cidr("10.0.0.0/8")        # 10.x.x.x
Cidr("192.168.0.0/16")    # 192.168.x.x
Cidr("192.168.1.0/24")    # 192.168.1.x

# IPv6 networks
Cidr("2001:db8::/32")
```

**Examples:**
| Cidr | IP | Match? |
|------|-----|--------|
| `Cidr("10.0.0.0/8")` | `"10.1.2.3"` | Yes |
| `Cidr("10.0.0.0/8")` | `"192.168.1.1"` | No |
| `Cidr("192.168.1.0/24")` | `"192.168.1.100"` | Yes |
| `Cidr("192.168.1.0/24")` | `"192.168.2.1"` | No |

**Use case:** Restrict API calls to internal networks, validate source IPs.

```python
from tenuo import Warrant, ConstraintSet, Cidr

# Only allow requests from internal network
cs = ConstraintSet()
cs.insert("source_ip", Cidr("10.0.0.0/8"))

warrant = (Warrant.builder()
    .capability("api_call", cs)
    .holder(kp.public_key)
    .ttl(3600)
    .build(kp))
```

**Attenuation:** Child CIDR must be a subnet of parent.

```python
# Parent: 10.0.0.0/8 (all 10.x.x.x)
parent = Cidr("10.0.0.0/8")

# Valid child: 10.1.0.0/16 (narrower)
child = Cidr("10.1.0.0/16")  # OK - Subnet of parent

# Invalid child: 192.168.0.0/16 (different network)
child = Cidr("192.168.0.0/16")  # FAILS - Not a subnet
```

---

### UrlPattern

Validates URLs against scheme, host, port, and path patterns. Provides structured URL validation with proper parsing and normalization - safer than using `Pattern` or `Regex` for URL matching.

```python
from tenuo import UrlPattern

# Match HTTPS URLs to specific host
UrlPattern("https://api.example.com/*")

# Any scheme (HTTP or HTTPS)
UrlPattern("*://api.example.com/*")

# Wildcard subdomain
UrlPattern("https://*.example.com/*")

# Specific port
UrlPattern("https://api.example.com:8443/*")

# Specific path prefix
UrlPattern("https://api.example.com/api/v1/*")
```

**Pattern Components:**

| Component | Syntax | Description |
|-----------|--------|-------------|
| Scheme | `https://`, `*://` | Required. Use `*` for any scheme. |
| Host | `api.example.com`, `*.example.com` | Required. Supports `*` prefix for subdomains. |
| Port | `:8443` | Optional. Omit for default port. |
| Path | `/api/*`, `/v1/users` | Optional. Supports glob patterns. |

**Examples:**

| Pattern | URL | Match? |
|---------|-----|--------|
| `UrlPattern("https://api.example.com/*")` | `"https://api.example.com/v1/users"` | Yes |
| `UrlPattern("https://api.example.com/*")` | `"http://api.example.com/v1"` | No (wrong scheme) |
| `UrlPattern("https://*.example.com/*")` | `"https://www.example.com/home"` | Yes |
| `UrlPattern("https://*.example.com/*")` | `"https://evil.com/home"` | No (wrong domain) |
| `UrlPattern("https://api.example.com:8443/*")` | `"https://api.example.com:443/v1"` | No (wrong port) |

**Use case:** Restrict API calls to specific endpoints, enforce HTTPS, limit to trusted domains.

```python
from tenuo import Warrant, ConstraintSet, UrlPattern

# Only allow HTTPS calls to internal API
cs = ConstraintSet()
cs.insert("endpoint", UrlPattern("https://api.internal.com/v1/*"))

warrant = (Warrant.builder()
    .capability("api_call", cs)
    .holder(kp.public_key)
    .ttl(3600)
    .build(kp))
```

**Attenuation Rules:**

- **Scheme**: Can narrow (any -> https) but not widen (https -> http)
- **Host**: Can narrow (*.example.com -> api.example.com) but not widen
- **Port**: Can add restriction but not remove
- **Path**: Can narrow (/api/* -> /api/v1/*) but not widen

```python
# Parent: any subdomain, any path
parent = UrlPattern("https://*.example.com/*")

# Valid children
child = UrlPattern("https://api.example.com/*")       # OK - Specific host
child = UrlPattern("https://api.example.com/v1/*")    # OK - Specific host + path

# Invalid children
child = UrlPattern("http://api.example.com/*")        # FAILS - Different scheme
child = UrlPattern("https://*.other.com/*")           # FAILS - Different domain
```

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

> **Attenuation Limitation**: Regex constraints **cannot be narrowed** during attenuation.
>
> Child regex must have **identical pattern** to parent. This is because determining if one regex is a subset of another is mathematically undecidable in the general case.
>
> ```python
> from tenuo import Warrant, Constraints, Regex, Exact
>
> # Parent with regex
> parent = Warrant.issue(
>     tools={"query": Constraints.for_tool("query", {"env": Regex(r"^(staging|dev)-.*$")})},
>     keypair=kp, holder=kp.public_key, ttl_seconds=3600
> )
>
> # Cannot narrow to different regex (even if provably narrower)
> child = parent.attenuate().capability("query", {
>     "env": Regex(r"^staging-.*$")  # FAILS
> }).delegate(kp)
>
> # Can narrow to Exact value (if it matches parent regex)
> child = parent.attenuate().capability("query", {
>     "env": Exact("staging-web")  # OK
> }).delegate(kp)
>
> # Can keep same regex pattern
> child = parent.attenuate().capability("query", {
>     "env": Regex(r"^(staging|dev)-.*$")  # OK
> }).delegate(kp)
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

**Security**: Always prefer `OneOf` (allowlist) over `NotOneOf` (denylist). `NotOneOf` should only be used to "carve holes" in a parent's positive constraint.

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
from tenuo import Warrant, Constraints, Contains

# Warrant requires ["read", "write"] permissions
warrant = Warrant.issue(
    tools={"access_resource": Constraints.for_tool("access_resource", {
        "permissions": Contains(["read", "write"])
    })},
    keypair=kp, holder=kp.public_key, ttl_seconds=3600
)

# Matches: ["read", "write", "admin"]
# Doesn't match: ["read"] (missing "write")
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
from tenuo import Warrant, Constraints, Subset

# Warrant allows only specific environments
warrant = Warrant.issue(
    tools={"deploy": Constraints.for_tool("deploy", {
        "environments": Subset(["staging", "dev"])
    })},
    keypair=kp, holder=kp.public_key, ttl_seconds=3600
)

# Matches: ["staging"]
# Matches: ["staging", "dev"]
# Doesn't match: ["staging", "production"] (includes disallowed "production")
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

### Any (OR)

At least one nested constraint must match.

```python
from tenuo import Any, Pattern

# Path must match at least one pattern
Any([
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

**Security**: Use sparingly. Prefer positive allowlists.

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
from tenuo import Warrant, Constraints, CEL

# Budget must be less than 10% of revenue
warrant = Warrant.issue(
    tools={"create_campaign": Constraints.for_tool("create_campaign", {
        "budget_check": CEL("budget < revenue * 0.1 && budget > 0")
    })},
    keypair=keypair,
    holder=holder_pubkey,
    ttl_seconds=3600
)

# When tool is called with:
# create_campaign(budget=5000, revenue=100000, ...)
# CEL evaluates: 5000 < 100000 * 0.1 && 5000 > 0 -> true (OK)
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
from tenuo import Warrant, Constraints, CEL

# Only allow if order created within last 24 hours
warrant = Warrant.issue(
    tools={"process_order": Constraints.for_tool("process_order", {
        "freshness": CEL("time_since(created_at) < 86400")
    })},
    keypair=keypair,
    holder=holder_pubkey,
    ttl_seconds=3600
)
```

**Network Example:**
```python
from tenuo import Warrant, Constraints, CEL

# Only allow API calls from private network
warrant = Warrant.issue(
    tools={"api_call": Constraints.for_tool("api_call", {
        "network": CEL("net_in_cidr(source_ip, '10.0.0.0/8')")
    })},
    keypair=keypair,
    holder=holder_pubkey,
    ttl_seconds=3600
)
```

#### CEL Attenuation

Child CEL constraints are automatically combined with parent using AND logic:

```python
from tenuo import Warrant, Constraints, CEL

# Parent: budget < 10000
parent = Warrant.issue(
    tools={"spend": Constraints.for_tool("spend", {"budget_rule": CEL("budget < 10000")})},
    keypair=kp,
    holder=kp.public_key,
    ttl_seconds=3600
)

# Child: Add additional constraint (auto-AND'd)
child = parent.attenuate().capability("spend", {
    "budget_rule": CEL("currency == 'USD'")
}).delegate(kp)

# Effective child expression: (budget < 10000) && (currency == 'USD')
```

**Syntactic Monotonicity (Conservative Approach)**

Tenuo enforces **Syntactic Monotonicity** for CEL, not Semantic Monotonicity.

Child expression must **literally** be `(parent) && new_predicate`. It cannot be a semantically equivalent but differently structured expression.

```python
from tenuo import Warrant, Constraints, CEL

# Parent CEL
parent = Warrant.issue(
    tools={"api_call": Constraints.for_tool("api_call", {"network": CEL("net_in_cidr(ip, '10.0.0.0/8')")})},
    keypair=kp,
    holder=kp.public_key,
    ttl_seconds=3600
)

# REJECTED: Semantically narrower but not syntactically derived
child = parent.attenuate().capability("api_call", {
    "network": CEL("net_in_cidr(ip, '10.1.0.0/16')")  # FAILS
}).delegate(kp)
# Even though 10.1.0.0/16 is subset of 10.0.0.0/8, this is REJECTED

# ALLOWED: Syntactically derived (AND'd)
child = parent.attenuate().capability("api_call", {
    "network": CEL("(net_in_cidr(ip, '10.0.0.0/8')) && net_in_cidr(ip, '10.1.0.0/16')")
}).delegate(kp)
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

**Sandboxed Execution**: CEL cannot execute arbitrary code, only evaluate expressions  
**Deterministic**: Same inputs always produce same results  
**Cached Programs**: Compiled expressions cached (max 1000) for performance  
**Type Safe**: Must return boolean or evaluation fails  
**No Side Effects**: Expressions are pure - no I/O, no state mutation  
**Safe Standard Library**: Only time/network parsing functions, no file/network I/O

#### Security Considerations

**DoS Protection:**

While CEL expressions are sandboxed, extremely complex expressions could still consume CPU:

```python
# Potentially expensive (though bounded by compilation)
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

**Important Notes**:
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
| `Pattern()` | Pattern (if narrower), Exact (if matches) |
| `Regex()` | **Same** Regex only, Exact (if matches) |
| `Exact()` | Same Exact only |
| `OneOf()` | OneOf (subset), NotOneOf, Exact (if in set) |
| `NotOneOf()` | NotOneOf (more exclusions) |
| `Range()` | Range (narrower bounds), Exact (if in range) |
| `Cidr()` | Cidr (subnet), Exact (if IP in network) |
| `UrlPattern()` | UrlPattern (narrower), Exact (if matches) |
| `Contains()` | Contains (more required values) |
| `Subset()` | Subset (fewer allowed values) |
| `All()` | All (more constraints) |
| `Any()` | Any (fewer alternatives) |
| `CEL()` | CEL (conjunction with parent) |

**Key Limitations**:
- **Regex**: Cannot narrow to different regex patterns (undecidable subset problem)
- **Exact**: Cannot change value at all
- **Range**: If parent bound is exclusive, child cannot make it inclusive at the same value (would widen)
- **No attenuation TO Wildcard**: Would re-widen authority
- **Not**: Attenuation not supported (use positive constraints instead)

### Cross-Type Containment

Some constraint types can contain different types during attenuation:

| Parent | Child | Containment Rule |
|--------|-------|------------------|
| `Wildcard()` | Any type | Universal parent - contains everything |
| `Pattern("*@co.com")` | `Exact("cfo@co.com")` | Child matches parent glob |
| `Regex(r"^dev-.*")` | `Exact("dev-web")` | Child matches parent regex |
| `Range(0, 100)` | `Exact("50")` | Child numeric value within range |
| `Cidr("10.0.0.0/8")` | `Exact("10.1.2.3")` | Child IP within parent network |
| `Cidr("10.0.0.0/8")` | `Cidr("10.1.0.0/16")` | Child is subnet of parent |
| `UrlPattern("https://*.example.com/*")` | `Exact("https://api.example.com/v1")` | Child URL matches parent pattern |
| `UrlPattern("https://*.example.com/*")` | `UrlPattern("https://api.example.com/v1/*")` | Child pattern is narrower |
| `OneOf(["a","b","c"])` | `Exact("b")` | Child value is in parent set |
| `OneOf(["a","b","c"])` | `NotOneOf(["c"])` | Carves holes (allows `a`, `b`) |

**Special Rules:**

| Rule | Description |
|------|-------------|
| `Wildcard` parent | Contains ANY child constraint type |
| `Wildcard` child | NEVER allowed (would widen permissions) |
| `Regex` -> `Regex` | Must be IDENTICAL pattern (subset undecidable) |
| `Range` inclusivity | Exclusive bounds cannot become inclusive at same value |

**Examples:**

```python
# Wildcard -> Anything: Wildcard is the universal parent
parent = Wildcard()
child = Pattern("staging-*")  # OK - Wildcard contains everything
child = Range(0, 100)         # OK - even different types
child = Wildcard()            # OK - Wildcard contains Wildcard

# Nothing -> Wildcard: would expand permissions
parent = Pattern("*")
child = Wildcard()  # FAILS - cannot widen to Wildcard

# Pattern -> Exact: exact value must match the pattern
parent = Pattern("*@company.com")
child = Exact("cfo@company.com")  # OK - matches pattern

# Regex -> Exact: exact value must match the regex
parent = Regex(r"^dev-.*$")
child = Exact("dev-web")  # OK - matches regex
child = Exact("production")   # FAILS - doesn't match

# Regex -> Regex: must be identical (subset is undecidable)
parent = Regex(r"^staging-.*$")
child = Regex(r"^staging-.*$")      # OK - identical
child = Regex(r"^staging-web$")     # FAILS - even if semantically narrower

# Range -> Exact: numeric value must be within range
parent = Range(0, 100)
child = Exact("50")   # OK - 50 is in [0, 100]
child = Exact("150")  # FAILS - 150 > 100

# OneOf -> Exact: exact value must be in the set
parent = OneOf(["read", "write", "delete"])
child = Exact("read")  # OK - "read" is in set

# OneOf -> NotOneOf: carve holes from allowed set
parent = OneOf(["staging", "production", "dev"])
child = NotOneOf(["production"])  # OK - allows staging, dev only

# NotOneOf -> NotOneOf: must exclude MORE values
parent = NotOneOf(["admin"])
child = NotOneOf(["admin", "root"])  # OK - excludes more

# Contains -> Contains: must require MORE values
parent = Contains(["read"])
child = Contains(["read", "write"])  # OK - requires more

# Subset -> Subset: must allow FEWER values
parent = Subset(["a", "b", "c"])
child = Subset(["a", "b"])  # OK - allows fewer
```

**Incompatible Cross-Types** (will fail attenuation):
- `Pattern` -> `Range`: String matching vs numeric bounds  
- `OneOf` -> `Pattern`: Set membership vs glob matching
- Any type -> `Wildcard`: Would expand permissions

### Pattern Narrowing

```python
from tenuo import Warrant, Constraints, Pattern

# Parent: /data/*
parent = Warrant.issue(
    tools={"read_file": Constraints.for_tool("read_file", {"path": Pattern("/data/*")})},
    keypair=kp, holder=kp.public_key, ttl_seconds=3600
)

# Child: /data/reports/* (narrower) - OK
child = parent.attenuate().capability("read_file", {"path": Pattern("/data/reports/*")}).delegate(kp)

# Child: /* (wider) - FAILS
child = parent.attenuate().capability("read_file", {"path": Pattern("/*")}).delegate(kp)  # MonotonicityViolation
```

### Range Narrowing

```python
from tenuo import Warrant, Constraints, Range

# Parent: max 15 replicas
parent = Warrant.issue(
    tools={"scale": Constraints.for_tool("scale", {"replicas": Range.max_value(15)})},
    keypair=kp, holder=kp.public_key, ttl_seconds=3600
)

# Child: max 10 (narrower) - OK
child = parent.attenuate().capability("scale", {"replicas": Range.max_value(10)}).delegate(kp)

# Child: max 20 (wider) - FAILS
child = parent.attenuate().capability("scale", {"replicas": Range.max_value(20)}).delegate(kp)  # MonotonicityViolation
```

### OneOf Narrowing

```python
from tenuo import Warrant, Constraints, OneOf

# Parent: ["a", "b", "c"]
parent = Warrant.issue(
    tools={"action": Constraints.for_tool("action", {"type": OneOf(["a", "b", "c"])})},
    keypair=kp, holder=kp.public_key, ttl_seconds=3600
)

# Child: ["a", "b"] (subset) - OK
child = parent.attenuate().capability("action", {"type": OneOf(["a", "b"])}).delegate(kp)

# Child: ["a", "b", "d"] (adds "d") - FAILS
child = parent.attenuate().capability("action", {"type": OneOf(["a", "b", "d"])}).delegate(kp)  # MonotonicityViolation
```

### Regex Narrowing

**Regex constraints are conservative**: Child regex must have **identical pattern** to parent.

```python
from tenuo import Warrant, Constraints, Regex, Exact

# Parent: regex pattern
parent = Warrant.issue(
    tools={"query": Constraints.for_tool("query", {"env": Regex(r"^(staging|dev)-.*$")})},
    keypair=kp, holder=kp.public_key, ttl_seconds=3600
)

# Cannot narrow to different regex (even if provably narrower) - FAILS
child = parent.attenuate().capability("query", {"env": Regex(r"^staging-.*$")}).delegate(kp)  # MonotonicityViolation

# Can keep same pattern - OK
child = parent.attenuate().capability("query", {"env": Regex(r"^(staging|dev)-.*$")}).delegate(kp)

# Can narrow to Exact (if it matches parent regex) - OK
child = parent.attenuate().capability("query", {"env": Exact("staging-web")}).delegate(kp)
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
async with root_task(Capability("search", query=Wildcard())):
    # Child: narrow to pattern
    async with scoped_task(Capability("search", query=Pattern("*public*"))):
        await search(query="public data")  # OK
```

### File Path Constraints

```python
# Read-only access to reports directory
async with root_task(Capability("read_file", path=Pattern("/data/reports/*"))):
    await read_file(path="/data/reports/q3.csv")  # OK
    await read_file(path="/etc/passwd")           # FAILS
```

### Replica/Capacity Limits

```python
# Limit replica counts
async with root_task(Capability("scale", replicas=Range.max_value(15))):
    await scale(replicas=5)   # OK
    await scale(replicas=20)  # FAILS
```

### Environment Restrictions

```python
# Only staging and dev
async with root_task(Capability("deploy", env=OneOf(["staging", "dev"]))):
    await deploy(env="staging")    # OK
    await deploy(env="production") # FAILS
```

### Scoped Database Access

```python
# Only specific tables
async with root_task(Capability("query", table=OneOf(["users", "orders"]))):
    await query(table="users")   # OK
    await query(table="secrets") # FAILS
```

---

## Pattern Best Practices

### Pattern Uses Glob Syntax, Not Regex

`Pattern` uses **glob syntax** (like shell wildcards), not regular expressions:

| Syntax | Meaning | Example |
|--------|---------|---------|
| `*` | Match any characters | `staging-*` → `staging-web` |
| `?` | Match single character | `env-?` → `env-a` |
| `[abc]` | Character class | `[abc].txt` → `a.txt` |
| `{a,b}` | Alternation | `{dev,staging}-*` → `dev-web` |

**Common mistakes:**
```python
# ❌ WRONG: Pipe is not OR in glob
Pattern("weather *|news *")  # Treats | as literal character

# ✅ CORRECT: Use curly braces for alternation
Pattern("{weather,news} *")

# ✅ CORRECT: Or use Any() for complex cases
Any([Pattern("weather *"), Pattern("news *")])
```

### Prefer Explicit Over Permissive

```python
# ⚠️ Too permissive - matches everything
Pattern("*")

# ✅ Better - explicit prefix
Pattern("staging-*")

# ✅ Best for known values - use Exact or OneOf
Exact("staging-web")
OneOf(["staging-web", "staging-db"])
```

### Keep Patterns Simple

Attenuation validation works best with simple prefix/suffix patterns:

```python
# ✅ Simple prefix - attenuation works reliably
Pattern("/data/*")           # Parent
Pattern("/data/reports/*")   # Child (narrower) ✓

# ⚠️ Complex patterns - attenuation may be conservative
Pattern("*-{prod,staging}-*")  # Harder to validate containment
```

### Use Exact/OneOf for High-Security Cases

When precision matters more than flexibility:

```python
# For known, enumerable values
OneOf(["read", "write", "delete"])

# For exact matches
Exact("/etc/passwd")  # Only this exact path

# For IP ranges
Cidr("10.0.0.0/8")
```

---

## See Also

- [AI Agent Patterns](./ai-agents) — P-LLM/Q-LLM, prompt injection defense
- [API Reference](./api-reference) — Full constraint API
- [Security](./security) — How constraints fit into the security model
- [LangGraph Integration](./langgraph) — Using constraints with LangGraph
