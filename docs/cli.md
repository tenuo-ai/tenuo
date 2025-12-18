---
title: CLI Reference
description: Complete Tenuo command-line interface reference
---

# Tenuo CLI Specification v0.1.0

## Overview

**Binary:** `tenuo`

**Purpose:** Developer utilities for key management, warrant issuance, attenuation, PoP signing, and verification.

**Terminology:**

In Tenuo, a **warrant** is a cryptographically signed capability token that encodes scope (tools, constraints, TTL) and an explicit delegation chain. Warrants are bound to a holder's public key and can only be used with a proof-of-possession signature.

**Design Principles:**

- **Pipe-friendly:** Commands default to stdout for chaining (`issue | attenuate | inspect`)
- **Stateless:** No config files or local database; keys and warrants passed as arguments
- **Dev-first:** Human-readable output by default; `--json` for automation; `--quiet` for scripts

**Non-goals (`tenuo` CLI v0.1):**

The `tenuo` CLI focuses on capability issuance, attenuation, and verification. It does not provide:

- Policy engines or policy languages
- Revocation infrastructure (SRL distribution, status endpoints)
- Identity provisioning or key management beyond `keygen`
- Warrant storage or persistence

For network enforcement and service mesh integration, see the [`tenuo-authorizer`](#authorizer-binary) binary below.

---

## Commands

### `keygen`

Generate Ed25519 keypair for agent identity.
```
tenuo keygen [OPTIONS] [NAME]
```

**Arguments:**

- `[NAME]` - Base name for output files. If omitted, prints to stdout.

**Options:**

| Flag | Description |
|------|-------------|
| `--force`, `-f` | Overwrite existing files |
| `--raw` | Output raw base64 private key only (for CI/CD env vars) |
| `--show-public <PATH>` | Print public key from existing private key |

**Output format:**

Keys are PEM-encoded (PKCS#8 for private, SPKI for public):
```
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH3...
-----END PRIVATE KEY-----
```

This format is standard, OpenSSL-compatible, and safe to display in terminals.

**Examples:**
```bash
# Create ./agent.key (private) and ./agent.pub (public)
$ tenuo keygen agent

# Extract public key from existing private key
$ tenuo keygen --show-public ./agent.key

# Verify with OpenSSL
$ openssl pkey -in agent.key -text -noout
```

---

### `issue`

Issues a root warrant, equivalent to control-plane issuance in production. Useful for local development and testing.
```
tenuo issue --signing-key <KEY> --holder <KEY> [OPTIONS]
```

**Required:**

| Flag | Description |
|------|-------------|
| `--signing-key`, `-k` | Path to issuer's private key (PEM) |
| `--holder` | Holder's public key: path to PEM file or base64 string |

**Options:**

| Flag | Description |
|------|-------------|
| `--type` | Warrant type: `execution` (default) or `issuer` |
| `--tool`, `-t` | Comma-separated allowed tools (required for execution warrants) |
| `--issuable-tools` | Comma-separated issuable tools (required for issuer warrants) |
| `--trust-ceiling` | Trust ceiling for issuer warrants: `external`, `internal`, or `system` |
| `--max-issue-depth` | Maximum issue depth for issuer warrants |
| `--trust-level` | Trust level: `external`, `internal`, or `system` |
| `--ttl` | Validity duration (default: `5m`). Formats: `300s`, `10m`, `1h` |
| `--id` | Warrant ID (default: generated `wrt_...`) |
| `--constraint`, `-c` | Add constraint (repeatable). See constraint syntax below. |
| `--constraint-json` | Add constraint as JSON (for complex values). See below. |
| `--constraint-bound` | Add constraint bound for issuer warrants (repeatable) |
| `--json` | Output as JSON |
| `--quiet`, `-q` | Output warrant string only, no decoration |

**Constraint Syntax:**

Simple format for common cases:
```
--constraint "key=type:value"
```

| Type | Example | Meaning |
|------|---------|---------|
| `exact` | `path=exact:/etc/hosts` | Exact match |
| `pattern` | `path=pattern:/data/*` | Glob pattern |
| `regex` | `name=regex:^prod-.*` | Regular expression |
| `range` | `confidence=range:0.8..1.0` | Numeric range (inclusive) |
| `oneof` | `status=oneof:active,pending` | Enumerated values |

JSON format for complex values (regex with special characters, etc.):
```bash
--constraint-json '{"path":{"regex":"^/data/[^/]+/.*"}}'
```

**Example (execution warrant):**
```bash
$ tenuo issue \
    --signing-key ./issuer.key \
    --holder ./agent.pub \
    --tool search,read_file \
    --constraint "path=pattern:/data/project-1/*" \
    --ttl 1h
```

**Example (issuer warrant):**
```bash
$ tenuo issue \
    --signing-key ./issuer.key \
    --holder ./orchestrator.pub \
    --type issuer \
    --issuable-tools read_file,send_email \
    --trust-ceiling internal \
    --max-issue-depth 3 \
    --ttl 24h
```

---

### `attenuate`

Derive a child warrant with equal or narrower scope. Scope can only shrink - attempts to widen constraints will fail.
```
tenuo attenuate [OPTIONS] <WARRANT>
```

**Arguments:**

- `<WARRANT>` - Base64 warrant string. Use `-` to read from stdin.

**Required:**

| Flag | Description |
|------|-------------|
| `--signing-key`, `-k` | Current holder's private key (PEM) |

**Options:**

| Flag | Description |
|------|-------------|
| `--parent-key` | Parent warrant issuer's private key (PEM) for chain link signature. If omitted, assumes same as `--signing-key`. |
| `--holder` | Child's public key. If omitted, self-attenuates (same holder). |
| `--tool`, `-t` | Subset of tools to retain (must be subset of parent) |
| `--ttl` | New TTL (must be ≤ parent's remaining TTL) |
| `--constraint`, `-c` | Narrowing constraints (must not widen parent's constraints) |
| `--constraint-json` | Narrowing constraint as JSON |
| `--json` | Output as JSON |
| `--quiet`, `-q` | Output warrant string only |
| `--diff` | Show diff of what changed (tools, constraints, TTL) |
| `--preview` | Preview only - show what would change without creating warrant |

**Enforcement:**

Constraint narrowing is evaluated per key: adding a new constraint is always narrowing; modifying an existing constraint must reduce its accepted set.
```bash
# Parent has: path=pattern:/data/project-1/*

# This fails (widens scope):
$ tenuo attenuate ... --constraint "path=pattern:/data/*"
Error: constraint "path" would widen scope (pattern:/data/* is broader than pattern:/data/project-1/*)

# This succeeds (narrows scope):
$ tenuo attenuate ... --constraint "path=exact:/data/project-1/readme.md"
```

**Example:**
```bash
$ tenuo issue ... | tenuo attenuate - \
    --signing-key ./agent.key \
    --holder ./worker.pub \
    --tool read_file \
    --constraint "path=exact:/data/project-1/readme.md"
```

**Example (preview mode):**
```bash
$ tenuo attenuate "$WARRANT" \
    --signing-key ./agent.key \
    --tool read_file \
    --preview
# Shows what would change without creating the warrant
```

**Example (diff mode):**
```bash
$ tenuo attenuate "$WARRANT" \
    --signing-key ./agent.key \
    --holder ./worker.pub \
    --diff
# Creates warrant and shows what changed
```

---

### `sign`

Create a proof-of-possession signature over a request payload.
```
tenuo sign --key <KEY> --warrant <WARRANT> [OPTIONS] <PAYLOAD>
```

**Arguments:**

- `<PAYLOAD>` - Request body to sign. Use `-` to read from stdin.

**Required:**

| Flag | Description |
|------|-------------|
| `--key`, `-k` | Holder's private key (must match warrant's holder) |
| `--warrant`, `-w` | Base64 warrant string |
| `--tool`, `-t` | Tool name being called (required for PoP challenge) |

**Options:**

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON with warrant, payload hash, and signature |
| `--quiet`, `-q` | Output signature only |

**Payload handling:**

Cryptographic signatures are byte-sensitive. The `sign` command hashes the payload bytes as provided (SHA-256), then signs the hash. Callers are responsible for consistent serialization; the CLI does not canonicalize JSON.

**Shell caution:**

Shells often add trailing newlines. Ensure byte-exact payloads:
```bash
# Wrong: echo adds a newline
$ echo '{"action":"read"}' | tenuo sign ...

# Correct: echo -n suppresses newline
$ echo -n '{"action":"read"}' | tenuo sign ...

# Correct: use printf
$ printf '%s' '{"action":"read"}' | tenuo sign ...

# Correct: pipe from file (no shell mangling)
$ tenuo sign --key ./agent.key --warrant "$WARRANT" < request.json
```

The same payload bytes must be used for both `sign` and `verify`. A single extra byte will cause verification to fail.

**Example:**
```bash
$ tenuo sign \
    --key ./agent.key \
    --warrant "$WARRANT" \
    '{"action": "read", "path": "/data/project-1/readme.md"}'
# Output: <base64_signature>

# From file:
$ tenuo sign --key ./agent.key --warrant "$WARRANT" < request.json
```

---

### `verify`

Full verification: warrant validity + PoP signature + holder binding.
```
tenuo verify --warrant <WARRANT> --signature <SIG> [OPTIONS] <PAYLOAD>
```

**Arguments:**

- `<PAYLOAD>` - Request body that was signed. Use `-` to read from stdin.

**Required:**

| Flag | Description |
|------|-------------|
| `--warrant`, `-w` | Base64 warrant string |
| `--signature`, `-s` | Base64 signature from `sign` command |
| `--tool`, `-t` | Tool name being called (required for authorization) |

**Options:**

| Flag | Description |
|------|-------------|
| `--trusted-issuer`, `-i` | Trusted root issuer's public key (PEM or base64). Repeatable. |
| `--at <TIMESTAMP>` | Verify as of specific time (default: now). ISO 8601 format. |
| `--json` | Output detailed JSON result |
| `--quiet`, `-q` | Exit code only (0 = valid, 1 = invalid) |

**Trust model:**

Warrants are self-contained: each link in the delegation chain includes the issuer's signature, and `verify` checks that every signature is valid. However, chain validity alone doesn't establish *trust* - you must also trust the root issuer.

- If `--trusted-issuer` is provided, verification fails unless the root warrant's issuer matches one of the trusted keys.
- If `--trusted-issuer` is omitted, the chain is verified for internal consistency but the root issuer is not validated. This is useful for debugging but should not be used in production.
```bash
# Production: explicitly trust the control plane's key
$ tenuo verify \
    --warrant "$WARRANT" \
    --signature "$SIG" \
    --trusted-issuer ./control-plane.pub \
    "$PAYLOAD"

# Debugging: verify chain structure without asserting root trust
$ tenuo verify \
    --warrant "$WARRANT" \
    --signature "$SIG" \
    "$PAYLOAD"
# Warning: root issuer not verified
```

**Checks performed:**

1. Warrant structure valid
2. Warrant not expired (TTL)
3. Delegation chain signatures valid (each attenuator signed correctly)
4. Root issuer trusted (if `--trusted-issuer` provided)
5. Payload hash matches (SHA-256 of provided payload)
6. PoP signature valid
7. Signer is holder (signature key = warrant's holder key)

**Output (success):**
```
✅ VALID

Warrant:     wrt_8a7c...
Holder:      2b9x... (verified)
Expires:     in 45m
Tools:       [read_file]
Constraints: path=exact:/data/project-1/readme.md

Chain:       2 delegations
  [0] 8f4a... → 2b9x... (root, trusted)
  [1] 2b9x... → 7c3d... (attenuated)

PoP:         ✅ Signature valid, signer matches holder
```

**Output (failure):**
```
❌ INVALID: PoP signature does not match holder

Expected:    2b9x...
Signer:      9f8e...
```

**Output (untrusted root warning):**
```
⚠️  VALID (chain only)

Warning: root issuer not verified (no --trusted-issuer provided)

Warrant:     wrt_8a7c...
...
```

---

### `inspect`

Decode and pretty-print a warrant. Primary debugging tool.
```
tenuo inspect [OPTIONS] <WARRANT>
```

**Arguments:**

- `<WARRANT>` - Base64 warrant string. Use `-` to read from stdin.

**Options:**

| Flag | Description |
|------|-------------|
| `--json` | Output raw JSON structure |
| `--verify` | Verify internal signatures and TTL |
| `--chain` | Show full delegation chain |

**Default output:**
```
WARRANT: wrt_8a7c...
──────────────────────────────────────────────────
Status:      ✅ ACTIVE (expires in 45m)
Issuer:      8f4a...
Holder:      2b9x...
Tools:       [search, read_file]
Constraints:
  path:        pattern:/data/project-1/*
  max_results: range:1..100
──────────────────────────────────────────────────
```

**With `--chain`:**
```
DELEGATION CHAIN:
──────────────────────────────────────────────────
[0] ROOT
    Issuer:  8f4a... (control plane)
    Holder:  2b9x...
    Tools:   [search, read_file, write_file]
    TTL:     1h

[1] ATTENUATED
    Issuer:  2b9x... (agent)
    Holder:  7c3d... (worker)
    Tools:   [read_file]
    Added:   path=exact:/data/project-1/readme.md
    TTL:     10m
──────────────────────────────────────────────────
```

**Expired warrant:**
```
Status:      ❌ EXPIRED (2m ago)
```

---

### `extract`

Test extraction rules against a sample request (dry run). Useful for debugging gateway configurations.
```
tenuo extract --config <CONFIG> --request <JSON> --path <PATH> [OPTIONS]
```

**Required:**

| Flag | Description |
|------|-------------|
| `--config`, `-c` | Path to gateway configuration YAML file |
| `--request`, `-r` | Sample request JSON (inline or `@filename`) |
| `--path`, `-p` | Request path (e.g., `/api/v1/clusters/prod/scale`) |

**Options:**

| Flag | Description |
|------|-------------|
| `--method` | HTTP method (default: `POST`) |
| `--header`, `-H` | Additional headers as `key=value` pairs (repeatable) |
| `--query`, `-q` | Query parameters as `key=value` pairs (repeatable) |
| `--verbose`, `-v` | Show verbose extraction trace |
| `--output` | Output format: `text` (default) or `json` |

**Example:**
```bash
$ tenuo extract \
    --config ./gateway.yaml \
    --request '{"cluster": "staging-web", "replicas": 3}' \
    --path /api/v1/clusters/staging-web/scale \
    --method POST
```

---

### `validate-config`

Validate a gateway configuration file.
```
tenuo validate-config --config <CONFIG>
```

**Options:**

| Flag | Description |
|------|-------------|
| `--config`, `-c` | Path to gateway configuration YAML file |

**Example:**
```bash
$ tenuo validate-config --config ./gateway.yaml
✅ Configuration is valid.

Summary:
  Tools:  3
  Routes: 5
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Usage or logic error (bad arguments, constraint parse failure) |
| `2` | Verification failure (invalid signature, expired, scope violation) |

---

## Development Workflow

Complete lifecycle on a single machine:
```bash
# 1. Generate keys
tenuo keygen issuer
tenuo keygen agent
tenuo keygen worker

# 2. Issue root warrant (equivalent to control-plane issuance)
WARRANT=$(tenuo issue \
    --signing-key issuer.key \
    --holder agent.pub \
    --tool "read_file,write_file" \
    --constraint "path=pattern:/data/*" \
    --ttl 1h \
    --quiet)

# 3. Attenuate for worker (agent delegates narrower scope)
WORKER_WARRANT=$(echo "$WARRANT" | tenuo attenuate - \
    --signing-key agent.key \
    --holder worker.pub \
    --tool "read_file" \
    --constraint "path=exact:/data/readme.md" \
    --ttl 10m \
    --quiet)

# 4. Inspect the chain
echo "$WORKER_WARRANT" | tenuo inspect - --chain --verify

# 5. Worker signs a request
PAYLOAD='{"action":"read","path":"/data/readme.md"}'
SIGNATURE=$(tenuo sign \
    --key worker.key \
    --warrant "$WORKER_WARRANT" \
    --quiet \
    -- "$PAYLOAD")

# 6. Verify (equivalent to resource server verification)
tenuo verify \
    --warrant "$WORKER_WARRANT" \
    --signature "$SIGNATURE" \
    --trusted-issuer issuer.pub \
    -- "$PAYLOAD"
```

---

---

## Authorizer Binary

**Binary:** `tenuo-authorizer`

**Purpose:** Data plane authorization service for gateway integration (Envoy ext_authz, nginx auth_request, etc.).

### `serve`

Run Tenuo as an HTTP authorization service.
```
tenuo-authorizer serve --config <CONFIG> [OPTIONS]
```

**Required:**

| Flag | Description |
|------|-------------|
| `--config`, `-c` | Path to gateway configuration YAML file |

**Options:**

| Flag | Description |
|------|-------------|
| `--port`, `-p` | Port to listen on (default: `9090`) |
| `--bind`, `-b` | Bind address (default: `0.0.0.0`) |

**Global Options:**

| Flag | Env Var | Description |
|------|---------|-------------|
| `--trusted-keys` | `TENUO_TRUSTED_KEYS` | Comma-separated trusted public keys (hex) |
| `--revocation-list` | `TENUO_REVOCATION_LIST` | Path to signed revocation list (CBOR) |

**Behavior:**

1. Listens for HTTP requests on specified port
2. Extracts constraints from request based on config (path params, headers, body)
3. Reads warrant from `X-Tenuo-Warrant` header
4. Reads PoP signature from `X-Tenuo-PoP` header
5. Verifies warrant chain, constraints, and PoP
6. Returns `200 OK` (authorized) or `403 Forbidden` (unauthorized)

**Example:**
```bash
# Start authorizer with gateway config
$ tenuo-authorizer serve \
    --config ./gateway.yaml \
    --port 9090 \
    --trusted-keys "8f4a...control_plane_pubkey"

# Or using environment variables
$ TENUO_TRUSTED_KEYS="8f4a..." tenuo-authorizer serve \
    --config ./gateway.yaml
```

**Gateway Config Example:**
```yaml
settings:
  warrant_header: "X-Tenuo-Warrant"
  pop_header: "X-Tenuo-PoP"
  clock_tolerance_secs: 30

tools:
  read_file:
    constraints:
      path:
        source: path
        key: "filename"

routes:
  - pattern: "/files/{filename}"
    method: GET
    tool: read_file
```

See [Gateway Configuration](./gateway-config) for full configuration reference.

---

### `verify`

Verify and authorize a single warrant (for scripting/testing).
```
tenuo-authorizer verify --tool <TOOL> --pop <SIGNATURE> [OPTIONS]
```

**Required:**

| Flag | Description |
|------|-------------|
| `--tool`, `-t` | Tool name to authorize |
| `--pop` | Proof-of-possession signature (hex-encoded, 64 bytes) |

**Options:**

| Flag | Description |
|------|-------------|
| `--warrant`, `-w` | Warrant (base64, or `-` for stdin) |
| `--arg`, `-a` | Arguments in `key=value` format (repeatable) |
| `--output`, `-o` | Output format: `exit-code`, `json`, or `quiet` (default: `exit-code`) |

**Example:**
```bash
# First create a PoP signature
$ POP=$(tenuo sign --key worker.key --warrant "$WARRANT" --tool read_file --quiet -- '{"path":"/data/readme.md"}')

# Then verify with PoP
$ tenuo-authorizer verify \
    --warrant "$WARRANT" \
    --tool read_file \
    --pop "$POP" \
    --arg "path=/data/readme.md"
```

---

### `check`

Check if a warrant is structurally valid (no authorization, just verification).
```
tenuo-authorizer check --warrant <WARRANT>
```

**Example:**
```bash
$ tenuo-authorizer check --warrant "$WARRANT"
```

---

### `info`

Print authorizer configuration info.
```
tenuo-authorizer info
```

---

## Future Commands

### `revoke` (deferred)

Sign and publish revocation entries for the Signed Revocation List (SRL).
```
tenuo revoke --signing-key <KEY> --warrant-id <ID>
```

Not required for launch.
