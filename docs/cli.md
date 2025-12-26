---
title: CLI Reference
description: Tenuo command-line interface reference
---

# Tenuo CLI Reference

Developer utilities for inspecting warrants, analyzing logs, and initializing projects.

---

## Installation

The CLI is included with the Python package:

```bash
pip install tenuo
```

After installation, the `tenuo` command is available:

```bash
tenuo --help
```

**Alternative:** Run as a Python module:

```bash
python -m tenuo --help
```

---

## Commands

### `init`

Initialize a new Tenuo project for **local development**. Generates a root key and config file.

> 💡 **For local development.** Root keys (issuer keys) grant unlimited authority—in production, protect them with a secrets manager (Vault, K8s Secrets, cloud KMS).

```
tenuo init
```

**Creates:**
- `.env` with `TENUO_ROOT_KEY` (base64-encoded signing key)
- `tenuo_config.py` with basic configuration

**Example:**
```bash
$ tenuo init
🚀 Initializing Tenuo project (development mode)...
✅ Received root_key (ed25519) -> .env
✅ Created tenuo_config.py with sensible defaults

🎉 Ready! Next steps:
   tenuo mint --tool read_file --ttl 1h   # Create a test warrant
   tenuo decode <warrant>                 # Inspect it

💡 Tip: Root keys grant unlimited authority—protect them with a secrets manager in production.
```

---

### `mint`

Create a test warrant. Uses `TENUO_ROOT_KEY` from environment (set by `tenuo init`).
```
tenuo mint --tool <TOOL> [--tool <TOOL>...] [--ttl <TTL>]
```

**Required:**

| Flag | Description |
|------|-------------|
| `--tool`, `-t` | Tool to authorize (repeatable) |

**Options:**

| Flag | Description |
|------|-------------|
| `--ttl` | Time-to-live (default: `1h`). Examples: `1h`, `30m`, `300s` |

**Example:**
```bash
# Create warrant for read_file and search, valid for 1 hour
$ tenuo mint --tool read_file --tool search --ttl 1h
eyJ3YXJyYW50IjoiLi4uIn0=

# Pipe to decode to verify
$ tenuo mint --tool read_file | tenuo decode
```

---

### `tenuo decode`

Decode and inspect a warrant or warrant stack.

**Auto-detects** whether the input is a single warrant or a multi-warrant chain.

```bash
# Inspect a single warrant
tenuo decode <warrant_base64>

# Inspect a warrant chain (auto-detected)
tenuo decode <stack_base64>
```

**Output:**
```
Warrant ID: wrt_abc123
Issuer: pk_xyz...
Holder: pk_abc...
Tools: ["search", "read_file"]
TTL: 3600s (59m remaining)
Constraints:
  read_file.path: Pattern("/data/*")
```

**Example:**
```bash
$ tenuo decode eyJ3YXJyYW50IjoiLi4uIn0=
```

---

### `validate`

Check if a tool call would be authorized by a warrant.
```
tenuo validate <WARRANT> --tool <TOOL> [--args <JSON>]
```

**Arguments:**

- `<WARRANT>` - Base64-encoded warrant string

**Required:**

| Flag | Description |
|------|-------------|
| `--tool`, `-t` | Tool name to check |

**Options:**

| Flag | Description |
|------|-------------|
| `--args`, `-a` | Tool arguments as JSON (default: `{}`) |

**Example:**
```bash
# Check if read_file with path would be authorized
$ tenuo validate $WARRANT --tool read_file --args '{"path": "/data/report.txt"}'
Verifying warrant for tool: read_file
  Warrant ID: wrt_abc123
  Tools: read_file, search
  ✅ AUTHORIZED

# Check unauthorized path
$ tenuo validate $WARRANT --tool read_file --args '{"path": "/etc/passwd"}'
Verifying warrant for tool: read_file
  Warrant ID: wrt_abc123
  Tools: read_file, search
  ❌ DENIED: Arguments do not satisfy constraints
```

**Exit codes:**
- `0` - Authorized
- `1` - Denied or error

---

### `discover`

Analyze audit logs and generate capability definitions. Useful for migrating existing systems to Tenuo.
```
tenuo discover --input <LOG_FILE> [OPTIONS]
```

**Required:**

| Flag | Description |
|------|-------------|
| `--input`, `-i` | Path to audit log file (JSON lines format) |

**Options:**

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Output file (default: stdout) |
| `--format`, `-f` | Output format: `yaml` (default) or `python` |

**Log format:**

The audit log should be JSON lines with `tool`, `constraints`, and `event_type` fields:
```json
{"event_type": "authorization_check", "tool": "read_file", "constraints": {"path": "/data/report.txt"}}
{"event_type": "authorization_check", "tool": "read_file", "constraints": {"path": "/data/summary.txt"}}
{"event_type": "authorization_check", "tool": "search", "constraints": {"query": "weather NYC"}}
```

**Example:**
```bash
$ tenuo discover --input audit.log --format yaml

# Output:
capabilities:
  read_file:
    path: Pattern("/data/*")
  search:
    query: Pattern("*")
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (bad arguments, invalid warrant, etc.) |

---

## See Also

- [Python SDK](../tenuo-python/README.md) — Full programmatic API for warrant issuance, delegation, and verification
- [Quick Start](./quickstart.md) — Getting started with Tenuo
- [API Reference](./api-reference.md) — Complete Python API documentation
