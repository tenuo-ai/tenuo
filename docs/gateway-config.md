---
title: Gateway Configuration
description: YAML configuration reference for Tenuo authorizer
---

# Gateway Configuration Reference

The gateway configuration file defines how the Tenuo authorizer maps HTTP requests to tools and extracts constraint values.

> ⚠️ **Important**: This configuration is for **argument extraction**, not **authorization policy**.
>
> - **Extraction**: Defines *where* to find data in an HTTP request (path, body, etc.).
> - **Policy**: Defines *what* values are allowed. This is encoded in the **Warrant**, not this file.
>
> See [Argument Extraction](./argument-extraction) for more details.

---

## Basic Structure

```yaml
version: "1"

settings:
  warrant_header: "X-Tenuo-Warrant"  # Header containing warrant (base64)
  pop_header: "X-Tenuo-PoP"          # Header containing PoP signature (hex)
  clock_tolerance_secs: 30           # Tolerance for expiration checks
  trusted_roots:                     # Control plane public keys (hex)
    - "f32e74b5b8569dc288db0109b7ec0d8eb3b4e5be7b07c647171d53fd31e7391f"

tools:
  tool_name:
    description: "Human-readable description"
    constraints:
      field_name:
        from: path|query|header|body|literal
        path: "json.path.to.value"
        required: true|false
        type: string|integer|float|boolean

routes:
  - pattern: "/api/v1/{param}/{action}"
    method: ["GET", "POST"]
    tool: "tool_name"
```

> See [Argument Extraction → Gateway Integration](./argument-extraction#gateway-integration-http-requests) for detailed extraction mechanics and security considerations.

---

## Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `warrant_header` | string | `X-Tenuo-Warrant` | HTTP header containing base64-encoded warrant |
| `pop_header` | string | `X-Tenuo-PoP` | HTTP header containing hex-encoded PoP signature |
| `clock_tolerance_secs` | int | `30` | Seconds of tolerance for expiration checks |
| `trusted_roots` | list | `[]` | Hex-encoded public keys of trusted control planes |
| `debug_mode` | bool | `false` | Enable detailed deny reasons in response headers |

> ⚠️ **Security Warning**: Never enable `debug_mode` in production! It exposes internal authorization details that could help attackers understand your security model.

### Debug Mode

When `debug_mode: true` is set, denied requests include an `X-Tenuo-Deny-Reason` header with details:

```http
HTTP/1.1 403 Forbidden
X-Tenuo-Deny-Reason: constraint_violation: replicas=50 exceeds Range(max=10)
```

This is useful for development and troubleshooting but should **never** be enabled in production.

---

## Tools

Tools define what constraints to extract for authorization.

### Constraint Extraction

```yaml
tools:
  manage_cluster:
    description: "Kubernetes cluster operations"
    constraints:
      cluster:
        from: path           # Extract from URL path parameter
        path: "cluster"      # Parameter name
        required: true       # Fail if missing
      
      action:
        from: path
        path: "action"
        required: true
      
      replicas:
        from: body           # Extract from JSON body
        path: "spec.replicas"
        type: integer        # Convert to integer
        required: false
      
      dry_run:
        from: query          # Extract from query string
        path: "dry_run"
        type: boolean
      
      api_key:
        from: header         # Extract from HTTP header
        path: "X-API-Key"
      
      environment:
        from: literal        # Static value
        value: "production"
```

### Extraction Sources

| Source | Description | Example |
|--------|-------------|---------|
| `path` | URL path parameter from route pattern | `/{cluster}/scale` → `cluster` |
| `query` | Query string parameter | `?dry_run=true` → `dry_run` |
| `header` | HTTP header value | `X-API-Key: abc123` |
| `body` | JSON body field (dot notation) | `{"spec": {"replicas": 5}}` → `spec.replicas` |
| `literal` | Static value | Always returns configured value |

### Type Conversion

| Type | Description | Example |
|------|-------------|---------|
| `string` | Default, no conversion | `"hello"` |
| `integer` | Parse as integer | `"42"` → `42` |
| `float` | Parse as float | `"3.14"` → `3.14` |
| `boolean` | Parse as boolean | `"true"` → `true` |

---

## Routes

Routes map HTTP requests to tools.

```yaml
routes:
  # Basic route
  - pattern: "/api/v1/clusters/{cluster}/scale"
    method: ["POST"]
    tool: "scale_cluster"
  
  # Multiple methods
  - pattern: "/api/v1/files/{path}"
    method: ["GET", "POST", "DELETE"]
    tool: "manage_files"
  
  # All methods (empty = any)
  - pattern: "/api/v1/health"
    method: []
    tool: "health_check"
  
  # Extra constraints (merged with tool constraints)
  - pattern: "/api/v1/admin/{action}"
    method: ["POST"]
    tool: "admin_action"
    extra_constraints:
      admin_key:
        from: header
        path: "X-Admin-Key"
        required: true
```

### Pattern Syntax

Patterns use `{param}` placeholders:

| Pattern | Matches | Path Params |
|---------|---------|-------------|
| `/api/{id}` | `/api/123` | `{id: "123"}` |
| `/api/{a}/{b}` | `/api/x/y` | `{a: "x", b: "y"}` |
| `/static/path` | `/static/path` | `{}` |

---

## Complete Example

```yaml
version: "1"

settings:
  warrant_header: "X-Tenuo-Warrant"
  pop_header: "X-Tenuo-PoP"
  clock_tolerance_secs: 30
  trusted_roots:
    - "f32e74b5b8569dc288db0109b7ec0d8eb3b4e5be7b07c647171d53fd31e7391f"

tools:
  read_file:
    description: "Read a file from the filesystem"
    constraints:
      path:
        from: body
        path: "path"
        required: true
      encoding:
        from: query
        path: "encoding"
        required: false

  write_file:
    description: "Write content to a file"
    constraints:
      path:
        from: body
        path: "path"
        required: true
      content:
        from: body
        path: "content"
        required: true
      mode:
        from: body
        path: "mode"
        required: false

  query_database:
    description: "Execute a database query"
    constraints:
      database:
        from: header
        path: "X-Database"
        required: true
      query:
        from: body
        path: "query"
        required: true
      limit:
        from: body
        path: "limit"
        type: integer
        required: false

  scale_cluster:
    description: "Scale a Kubernetes cluster"
    constraints:
      cluster:
        from: path
        path: "cluster"
        required: true
      replicas:
        from: body
        path: "spec.replicas"
        type: integer
        required: true
      dry_run:
        from: query
        path: "dry_run"
        type: boolean

routes:
  - pattern: "/api/v1/files/read"
    method: ["POST"]
    tool: "read_file"

  - pattern: "/api/v1/files/write"
    method: ["POST"]
    tool: "write_file"

  - pattern: "/api/v1/db/query"
    method: ["POST"]
    tool: "query_database"

  - pattern: "/api/v1/clusters/{cluster}/scale"
    method: ["POST", "PUT"]
    tool: "scale_cluster"
```

---

## Validation

The authorizer validates configuration on startup:

```bash
$ tenuo-authorizer serve --config gateway.yaml

# Validation errors:
# - routes[2]: Tool 'undefined_tool' is not defined
# - routes[3].pattern: Empty parameter name in '{}'
# - tools.read_file.constraints.path: Body extraction requires a path
```

---

## Performance

For production use, the configuration is compiled into optimized data structures:

- **Route matching**: O(log n) using radix tree (matchit)
- **Method matching**: O(1) using bitmask
- **Constraint extraction**: Pre-compiled paths avoid runtime parsing

---

## See Also

- [Proxy Configurations](./proxy-configs.md) — Envoy, Istio, nginx integration
- [Kubernetes Integration](./kubernetes.md) — Deployment patterns
- [CLI Reference](./cli.md) — Command-line usage
- [Protocol](./protocol.md) — Warrant format and verification
