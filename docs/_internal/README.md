# Design Documents (Internal)

> ⚠️ **Internal documentation** — Not for public consumption.
> 
> This directory (`docs/_internal/`) is excluded from the public website.
> For user-facing documentation, see the parent [`/docs`](..) directory.

---

## Contents

| Document | Description | Status |
|----------|-------------|--------|
| [full-spec.md](./full-spec.md) | Complete internal specification (v2.0 - current implementation) | ✅ Reference |
| [thi-spec.md](./thi-spec.md) | Tenuo Host Interface - stateful features (nonces, rate limits, revocation) | ⚠️ Conceptual (not planned) |
| [securegraph-spec.md](./securegraph-spec.md) | SecureGraph declarative policy engine | 📋 Design (future) |

---

## Implementation Status (v0.1)

### Core ✅
- Warrant model (execution warrants)
- Constraint types (Exact, Pattern, Range, OneOf, NotOneOf, Regex, Wildcard)
- Cryptographic chain verification
- Mandatory PoP with timestamp validation
- Monotonic attenuation
- Chain limits (MAX_DELEGATION_DEPTH = 16)

### Python SDK ✅
- Tiered API (`Capability` objects, `root_task`, `scoped_task`, `configure`)
- `@lockdown` decorator
- `protect_tools()` for LangChain
- `@tenuo_node` for LangGraph

### MCP Integration ✅
- `McpConfig` / `CompiledMcpConfig` (Rust + Python)
- Constraint extraction from MCP tool calls
- See `tenuo-python/examples/mcp_integration.py`

### CLI ✅
- `tenuo keygen`, `issue`, `attenuate`, `verify`, `inspect`
- `--diff` and `--preview` flags

---

## Future (v0.2+)

| Feature | Status | Notes |
|---------|--------|-------|
| SecureGraph | 📋 Design | Automatic attenuation for LangGraph |
| Trust Levels | 📋 Design | Enforcement opt-in (data model exists) |
| Multi-sig approvals | 📋 Planned | M-of-N for sensitive actions |
| Cascading revocation | 📋 Planned | Surgical or nuclear revocation |
| `tenuo-mcp` package | 📋 Planned | Standalone MCP server wrapper |
| Google A2A | 📋 Planned | Agent-to-Agent protocol integration |

---

## When to Use These

- **Implementing features** — Reference these for implementation details
- **Understanding design decisions** — These explain the "why"
- **Planning future work** — SecureGraph spec is the roadmap for v0.2

## When NOT to Use These

- **User documentation** — Use `/docs` instead
- **API reference** — Use `/docs/api-reference.md`
- **Getting started** — Use `/README.md`
