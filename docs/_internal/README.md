# Design Documents (Internal)

> ⚠️ **Internal documentation** — Not for public consumption.
> 
> This directory (`docs/_internal/`) is excluded from the public website.
> For user-facing documentation, see the parent [`/docs`](..) directory.

---

## Contents

| Document | Description | Status |
|----------|-------------|--------|
| [full-spec.md](./full-spec.md) | Complete internal specification - warrant model, constraints, wire format | ✅ Reference |
| [wire-format-spec.md](./wire-format-spec.md) | Wire format details for interoperability | ✅ Reference |
| [thi-spec.md](./thi-spec.md) | Tenuo Host Interface - stateful features (nonces, rate limits) | ⚠️ Conceptual |
| [securegraph-spec.md](./securegraph-spec.md) | SecureGraph - declarative attenuation for LangGraph | ⚠️ Conceptual |
| [environment-constraints.md](./environment-constraints.md) | Environment/Context constraints (IP, Time) via extensions | ⚠️ Conceptual |

---

## Implementation Status (v0.1.0-alpha.12)

### Core ✅
- Warrant model (execution + issuer warrants)
- Constraint types (Exact, Pattern, Range, OneOf, NotOneOf, Regex, Wildcard, CEL)
- Cryptographic chain verification
- Mandatory PoP with timestamp validation
- Monotonic attenuation
- Chain limits (MAX_DELEGATION_DEPTH = 16)
- Clearance levels (optional, enforcement opt-in)

### Python SDK ✅
- Tiered API (`Capability` objects, `mint`, `grant`, `configure`)
- `@guard` decorator
- `guard_tools()` for LangChain
- `@tenuo_node` for LangGraph
- `Clearance` with `custom()`, `level`, `meets()` API

### MCP Integration ✅
- `McpConfig` / `CompiledMcpConfig` (Rust + Python)
- Constraint extraction from MCP tool calls
- See `tenuo-python/examples/mcp_integration.py`

### CLI ✅
- `tenuo init`, `decode`, `mint`, `validate`
- Development helpers for key/warrant generation

---

## Completed (v0.1.0-alpha.12)
 
 | Feature | Status |
 |---------|--------|
 | Warrant convenience methods (`explain()`, `why_denied()`) | ✅ |
 | `BoundWarrant` with serialization guards | ✅ |
 | `grant_builder()` / `delegate()` API | ✅ |
 | Framework Integrations (FastAPI, LangChain, LangGraph) | ✅ |
 | `@guard` decorator | ✅ |
 | `KeyRegistry` for LangGraph | ✅ |
 | Testing utilities (`quick_mint`, assertions) | ✅ |

---

## Future (v0.2+)

| Feature | Status | Notes |
|---------|--------|-------|
| Multi-sig approvals | 📋 Planned | M-of-N for sensitive actions |
| Cascading revocation | 📋 Planned | Surgical or nuclear revocation |
| `tenuo-mcp` package | 📋 Planned | Standalone MCP server wrapper |
| Google A2A | 📋 Planned | Agent-to-Agent protocol integration |

---

## Document Descriptions

### full-spec.md (Reference)
Complete internal specification covering:
- Warrant model and wire format
- Constraint types and evaluation
- Cryptographic verification
- Clearance levels (optional)
- Delegation receipts

### wire-format-spec.md (Reference)
Wire format details for cross-language interoperability.

### thi-spec.md (Conceptual)
Stateful host interface features (not planned for implementation):
- Nonce-based replay prevention
- Per-key rate limiting
- Cascading revocation

### securegraph-spec.md (Conceptual)
Declarative attenuation for LangGraph (exploration only):
- Graph-level policies
- Node trust requirements

### environment-constraints.md (Conceptual)
Environment/Context constraints via `extensions`:
- **Context Pulling**: Integration injections context, Core remains pure
- **Strong Typing**: CIDR (IP) and TimeRange constraints
- **Fail Closed**: Secure fallback for missing providers

---

## When to Use These

- **Implementing features** — Reference these for implementation details
- **Understanding design decisions** — These explain the "why"
- **Historical context** — Conceptual docs show explored alternatives

## When NOT to Use These

- **User documentation** — Use `/docs` instead
- **API reference** — Use `/docs/api-reference.md`
- **Getting started** — Use `/README.md`
