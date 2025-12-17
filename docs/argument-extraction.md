---
title: Argument Extraction
description: How Tenuo extracts and validates tool arguments for authorization
category: Deep Dive
---

# Argument Extraction

> How Tenuo extracts tool arguments for constraint validation across different integration patterns.

---

## Quick Reference

| Integration | Extraction Method | Configuration |
|-------------|-------------------|---------------|
| Python SDK | `inspect.signature().bind()` | Automatic or `extract_args` |
| LangChain | Same as Python SDK | `@lockdown` or `protect_tools` |
| LangGraph | Tool-level (not node-level) | `@lockdown` on tools |
| Gateway | YAML config | `from: path/query/body/header/literal` |
| MCP | YAML config | Same as Gateway |

---

## Overview

Tenuo enforces constraints by comparing **tool arguments** against **warrant constraints**. The extraction mechanism varies by integration pattern but follows the same security principles:

1. **Extract all arguments** - No argument should be hidden from authorization
2. **Include defaults** - Default values must be checked (can't bypass via omission)
3. **Fail securely** - If extraction fails, authorization is denied
4. **Type safety** - Arguments converted to appropriate types for constraint checking

### Extraction vs. Policy

> ⚠️ **Crucial Distinction**: YAML configuration (for Gateway and MCP) is for **argument extraction**, not **authorization policy**.
>
> - **Extraction (YAML)**: Tells Tenuo *where* to find the "path" or "amount" in a request (e.g., "look in the JSON body at key `maxSize`").
> - **Policy (Warrants)**: Tells Tenuo *what* values are allowed (e.g., "max_size must be less than 1000").
>
> You do **not** define which users can do what in the YAML config. You define how to turn raw requests into structured arguments that can be checked against a warrant.

---

## Python SDK (`@lockdown`)

The `@lockdown` decorator extracts arguments automatically using Python's `inspect.signature()` API.

### Automatic Extraction (Default)

When no `extract_args` is provided, Tenuo uses **robust signature binding**:

```python
from tenuo import lockdown

@lockdown(tool="read_file")
def read_file(path: str, max_size: int = 1000):
    with open(path) as f:
        return f.read()[:max_size]

# All arguments extracted automatically:
read_file("/data/file.txt")           # args: {path: "/data/file.txt", max_size: 1000}
read_file("/data/file.txt", 500)     # args: {path: "/data/file.txt", max_size: 500}
read_file(path="/data/file.txt")     # args: {path: "/data/file.txt", max_size: 1000}
```

**How it works:**
1. Uses `inspect.signature(func).bind(*args, **kwargs)` to map arguments to parameters
2. Calls `bound.apply_defaults()` to include default values
3. Converts to dict: `{param_name: value}`
4. **Security**: Default values are ALWAYS included (prevents bypass)

### Manual Extraction (`extract_args`)

For custom extraction logic or parameter name mapping:

```python
@lockdown(
    tool="transfer",
    extract_args=lambda from_account, to_account, amount, **kw: {
        "source": from_account,      # Rename for constraint matching
        "destination": to_account,
        "amount": amount
    }
)
def transfer(from_account: str, to_account: str, amount: float, memo: str = ""):
    ...
```

**When to use:**
- Parameter names don't match constraint names
- Need to extract subset of arguments
- Complex argument structure needs flattening

**Security note:** If `extract_args` is provided, Tenuo trusts it completely. Ensure it extracts all security-relevant arguments.

### Parameter Mapping (`mapping`)

Alternative to `extract_args` for simple renames:

```python
@lockdown(
    tool="transfer",
    mapping={"from_account": "source", "to_account": "destination"}
)
def transfer(from_account: str, to_account: str, amount: float):
    ...
# Extracted: {source: "...", destination: "...", amount: ...}
```

**Mapping is applied AFTER automatic extraction:**
1. Automatic extraction creates: `{from_account: X, to_account: Y, amount: Z}`
2. Mapping transforms to: `{source: X, destination: Y, amount: Z}`

---

## LangChain Integration

LangChain tools are protected using `@lockdown` or `protect_tools`. Argument extraction is the same as above.

### With `@lockdown`

```python
from tenuo import lockdown

@lockdown(tool="search")
def search(query: str, max_results: int = 10):
    # Automatic extraction: {query: "...", max_results: 10}
    ...
```

### With `protect_tools`

```python
from tenuo.langchain import protect_tools
from langchain_community.tools import DuckDuckGoSearchRun

# protect_tools wraps tool.func with @lockdown(tool=tool.name)
protected = protect_tools([DuckDuckGoSearchRun()])
```

**How `protect_tools` extracts arguments:**
1. Wraps the tool's `func` attribute
2. Uses tool's `args_schema` (if available) to validate arguments
3. Applies automatic extraction via signature binding
4. Tool's parameter names become constraint keys

---

## LangGraph Integration (`@tenuo_node`)

LangGraph nodes use `@tenuo_node` which wraps `scoped_task()`. Argument extraction happens at the **tool level**, not the node level.

```python
from tenuo.langgraph import tenuo_node
from tenuo import lockdown

@lockdown(tool="search")
def search(query: str):
    ...

@tenuo_node(tools=["search"], query="*public*")
async def researcher(state):
    # Node scope enforces: only "search" tool, query must match "*public*"
    results = await search(state["query"])  # ← Extraction happens HERE
    return {"results": results}
```

**How it works:**
1. `@tenuo_node` narrows warrant scope (tools + constraints)
2. When `search()` is called, `@lockdown` extracts `{query: state["query"]}`
3. Authorization checks against narrowed warrant
4. Node constraints (e.g., `query="*public*"`) are checked by `scoped_task()`

**Key insight:** `@tenuo_node` doesn't extract arguments—it creates a scoped warrant. The underlying tool's `@lockdown` decorator does the extraction.

---

## Gateway Integration (HTTP Requests)

The `tenuo-authorizer` extracts constraints from HTTP requests using gateway configuration.

### Extraction Sources

```yaml
tools:
  scale_cluster:
    constraints:
      cluster:
        from: path           # From URL path params
        path: "cluster"
      
      replicas:
        from: body           # From JSON body
        path: "spec.replicas"
        type: integer
      
      dry_run:
        from: query          # From query string
        path: "dry_run"
        type: boolean
      
      tenant_id:
        from: header         # From HTTP header
        path: "X-Tenant-Id"
      
      environment:
        from: literal        # Static value
        value: "production"

routes:
  - pattern: "/api/v1/clusters/{cluster}/scale"
    method: ["POST"]
    tool: "scale_cluster"
```

### Request Example

```http
POST /api/v1/clusters/staging-web/scale?dry_run=true HTTP/1.1
X-Tenuo-Warrant: eyJ0eXBlIjo...
X-Tenuo-PoP: a3f8b29c...
X-Tenant-Id: acme-corp
Content-Type: application/json

{
  "spec": {
    "replicas": 5
  }
}
```

**Extracted constraints** (Python dict):
```python
{
    "cluster": "staging-web",      # From path
    "replicas": 5,                  # From body (converted to int)
    "dry_run": True,               # From query (converted to Python bool)
    "tenant_id": "acme-corp",      # From header
    "environment": "production"     # From literal
}
```

### JSON Path Syntax

Body extraction uses dot notation for nested fields:

| Path | Matches |
|------|---------|
| `name` | `{"name": "value"}` |
| `spec.replicas` | `{"spec": {"replicas": 5}}` |
| `metadata.labels.env` | `{"metadata": {"labels": {"env": "prod"}}}` |
| `items[0].id` | `{"items": [{"id": "123"}]}` (⚠️ array index NOT supported in v0.1) |

⚠️ **Note**: Array indexing is not supported. Use `items` to extract the entire array.

### Type Safety

Type conversion happens automatically:

```yaml
constraints:
  replicas:
    from: body
    path: "spec.replicas"
    type: integer  # "5" → 5, "5.0" → 5
  
  confidence:
    from: query
    path: "min_confidence"
    type: float    # "0.85" → 0.85
  
  dry_run:
    from: query
    path: "dry_run"
    type: boolean  # "true" → True, "1" → True (Python bool)
```

**Conversion failures:**
- If type conversion fails, extraction returns `None`
- If field is `required: true`, authorization is denied

---

## MCP (Model Context Protocol)

MCP configuration extraction works identically to gateway configuration.

```yaml
version: "1"
settings:
  default_ttl: 3600

servers:
  filesystem:
    path_prefix: "/data"
    
tools:
  read_file:
    constraints:
      path:
        from: body
        path: "arguments.path"
        required: true
    
    tool_ref:
      server: "filesystem"
      tool: "read_file"
```

See [MCP Integration](./mcp-integration) for full details.

---

## Security Considerations

### 1. Default Values MUST Be Checked

❌ **Vulnerable:**
```python
# Wrong: If max_size is omitted, it's not checked
@lockdown(tool="read_file", extract_args=lambda path, **kw: {"path": path})
def read_file(path: str, max_size: int = 999999):
    ...
```

✅ **Secure:**
```python
# Automatic extraction includes defaults
@lockdown(tool="read_file")
def read_file(path: str, max_size: int = 1000):
    ...
# Extraction: {path: "...", max_size: 1000} ← Always included
```

**Why this matters:** An attacker could omit the parameter to use a dangerous default if defaults aren't checked.

### 2. All Parameters Must Be Extractable

If a parameter is security-relevant (affects what the tool does), it MUST be extractable:

❌ **Vulnerable:**
```python
@lockdown(tool="query", extract_args=lambda query, **kw: {"query": query})
def query_db(query: str, table: str = "users"):
    # table is not extracted! Attacker can query any table
    ...
```

✅ **Secure:**
```python
@lockdown(tool="query")  # Automatic extraction includes both
def query_db(query: str, table: str = "users"):
    # Extraction: {query: "...", table: "users"}
    ...
```

### 3. Extraction Failures Must Block Authorization

```python
# In decorators.py (lines 302-315):
try:
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    auth_args = dict(bound.arguments)
except TypeError as e:
    # Binding failed → DENY
    audit_logger.log(AuditEvent(
        event_type=AuditEventType.AUTHORIZATION_FAILURE,
        tool=tool_name,
        action="denied",
        error_code="argument_binding_error",
        details=f"Failed to bind arguments for {tool_name}: {e}",
    ))
    raise  # ← Authorization denied
```

**Why this matters:** If we can't reliably extract arguments, we can't authorize. Failing closed is correct.

### 4. Gateway Extraction Must Be Complete

For gateway integration, ensure **all security-relevant request components** are extracted:

```yaml
# ✅ Complete extraction
tools:
  transfer:
    constraints:
      from_account:
        from: body
        path: "from"
        required: true
      to_account:
        from: body
        path: "to"
        required: true
      amount:
        from: body
        path: "amount"
        type: float
        required: true
      tenant:
        from: header
        path: "X-Tenant-Id"
        required: true
```

---

## Common Patterns

### Pattern 1: Simple Tools (Automatic)

```python
@lockdown(tool="search")
def search(query: str, max_results: int = 10):
    ...
# Extraction: automatic, includes defaults
```

✅ **Recommendation:** Use automatic extraction unless you have a specific reason not to.

### Pattern 2: Parameter Renaming

```python
@lockdown(
    tool="read_file",
    mapping={"file_path": "path"}  # Rename for constraint matching
)
def read_file(file_path: str):
    ...
# Extracted as: {path: "..."}
```

### Pattern 3: Custom Extraction Logic

```python
@lockdown(
    tool="api_call",
    extract_args=lambda url, method="GET", headers=None, **kw: {
        "url": url,
        "method": method,
        "has_auth": bool(headers and "Authorization" in headers)
    }
)
def api_call(url: str, method: str = "GET", headers: dict = None):
    ...
```

### Pattern 4: Gateway with Nested JSON

```yaml
tools:
  create_order:
    constraints:
      customer_id:
        from: body
        path: "order.customer.id"  # Nested path
        required: true
      
      total_amount:
        from: body
        path: "order.total"
        type: float
        required: true
```

---

## Troubleshooting

### Problem: Constraint not being checked

**Symptom:** Tool executes even though arguments violate constraints.

**Cause:** Argument name mismatch between tool and constraint.

```python
# Warrant has constraint: {"file_path": Pattern("/tmp/*")}
# But tool parameter is named "path"

@lockdown(tool="read_file")
def read_file(path: str):  # ← Extracted as {path: "..."}
    ...
# Constraint key "file_path" != argument key "path" → Constraint not checked!
```

**Fix:** Use `mapping` to align names:
```python
@lockdown(tool="read_file", mapping={"path": "file_path"})
def read_file(path: str):
    ...
# Extracted as: {file_path: "..."}
```

### Problem: Default value bypasses constraint

**Symptom:** Attacker omits parameter to use dangerous default.

**Cause:** Using `extract_args` without including defaults.

❌ **Vulnerable:**
```python
@lockdown(tool="query", extract_args=lambda query, **kw: {"query": query})
def query_db(query: str, limit: int = 999999):  # Dangerous default
    ...
# If caller omits limit, it's not extracted → uses 999999 unchecked
```

✅ **Secure (automatic):**
```python
@lockdown(tool="query")
def query_db(query: str, limit: int = 100):
    ...
# Automatic extraction ALWAYS includes limit (even if omitted by caller)
```

### Problem: TypeError in extraction

**Symptom:** `argument_binding_error` in audit logs.

**Cause:** Function called with wrong number/type of arguments.

**Fix:** This is correct behavior - if we can't bind arguments, we can't authorize:
```python
# Function signature: read_file(path: str)
read_file()  # Missing required arg → TypeError → Authorization denied ✅
```

---

## Testing Extraction

### Test Automatic Extraction

```python
import inspect
from tenuo import lockdown, Warrant, SigningKey, Exact, set_warrant_context, set_signing_key_context

def test_extraction():
    kp = SigningKey.generate()
    w = Warrant.issue(tools=["test"], constraints={"a": Exact(1)}, keypair=kp, ttl_seconds=300)
    
    @lockdown(tool="test")
    def func(a: int, b: int = 2):
        return f"a={a}, b={b}"
    
    with set_warrant_context(w), set_signing_key_context(kp):
        # Test default inclusion
        result = func(1)  # Should pass (a=1, b=2 extracted)
        assert result == "a=1, b=2"
```

### Test Gateway Extraction (CLI)

```bash
# Use tenuo extract command to test extraction rules
tenuo extract \
    --config ./gateway.yaml \
    --request '{"spec": {"replicas": 5}}' \
    --path /api/v1/clusters/prod/scale \
    --method POST \
    --verbose

# Output shows exactly what constraints were extracted
```

---

## Best Practices

### ✅ DO

1. **Use automatic extraction** unless you have a specific reason for custom logic
2. **Test with defaults** - ensure default values satisfy constraints
3. **Use `mapping`** for simple parameter renames
4. **Document constraint keys** - ensure tool params match constraint names
5. **Test extraction** - use `tenuo extract` for gateway configs

### ❌ DON'T

1. **Don't omit security-relevant parameters** from `extract_args`
2. **Don't bypass defaults** - always include them in extraction
3. **Don't assume parameter names** - test with actual warrant constraints
4. **Don't ignore extraction errors** - they indicate real problems

---

## Implementation Details

### Python Signature Binding (decorators.py:298-315)

```python
try:
    # Robustly bind arguments to parameters
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()  # ← CRITICAL: Includes defaults
    auth_args = dict(bound.arguments)
except TypeError as e:
    # If binding fails, DENY (fail closed)
    audit_logger.log(AuditEvent(
        event_type=AuditEventType.AUTHORIZATION_FAILURE,
        tool=tool_name,
        action="denied",
        error_code="argument_binding_error",
        details=f"Failed to bind arguments for {tool_name}: {e}",
    ))
    raise  # ← Authorization denied
```

**Security properties:**
- ✅ Handles positional, keyword, and default arguments
- ✅ Fails closed if binding fails
- ✅ Audit logged for debugging
- ✅ Raises immediately (doesn't let function execute)

### Gateway Extraction (extraction.rs:206-234)

```rust
pub fn extract(&self, ctx: &RequestContext) -> Option<ConstraintValue> {
    match &self.rule.from {
        ExtractionSource::Path => ctx.path_params.get(&self.rule.path)
            .map(|s| ConstraintValue::String(s.clone())),
        ExtractionSource::Query => ctx.query_params.get(&self.rule.path)
            .map(|s| ConstraintValue::String(s.clone())),
        ExtractionSource::Header => {
            let key = self.lowercase_key.as_ref()?;
            ctx.headers.get(key.as_ref())
                .map(|s| ConstraintValue::String(s.clone()))
        }
        ExtractionSource::Body => {
            let path = self.compiled_path.as_ref()?;
            path.extract(&ctx.body)  // ← Compiled JSON path extraction
        }
        ExtractionSource::Literal => self.rule.default.as_ref()
            .and_then(json_to_constraint_value),
    }
}
```

**Security properties:**
- ✅ Headers are case-insensitive (pre-lowercased)
- ✅ Body extraction is compiled (not regex, safe)
- ✅ Type conversion with failure handling
- ✅ Required fields enforced (`extract_all` returns error if missing)

---

## See Also

- [API Reference → @lockdown](./api-reference#lockdown) - Full decorator documentation
- [Gateway Configuration](./gateway-config) - HTTP extraction reference
- [LangGraph Integration](./langgraph) - Node scoping patterns
- [Security](./security) - Authorization model overview
- [Constraints](./constraints) - Constraint types and validation
