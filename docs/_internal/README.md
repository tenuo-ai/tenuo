# Design Documents (Internal)

> ⚠️ **Internal documentation** — Not for public consumption.
> 
> This directory (`docs/_internal/`) is excluded from the public website.
> For user-facing documentation, see the parent [`/docs`](..) directory.

---

## Contents

| Document | Description | Status |
|----------|-------------|--------|
| [protocol-spec-v1.md](../spec/protocol-spec-v1.md) | Protocol specification - warrant model, semantics, verification | ✅ Reference |
| [wire-format-v1.md](../spec/wire-format-v1.md) | Wire format details for interoperability | ✅ Reference |
| [a2a-handshake.md](./a2a-handshake.md) | Unified Control Protocol (Registration & Renewal) | ⚠️ Conceptual |
| [thi-spec.md](./thi-spec.md) | Tenuo Host Interface - stateful features (nonces, rate limits) | ⚠️ Conceptual |
| [securegraph-spec.md](./securegraph-spec.md) | SecureGraph - declarative attenuation for LangGraph | ⚠️ Conceptual |
| [environment-constraints.md](./environment-constraints.md) | Environment/Context constraints (IP, Time) via extensions | ⚠️ Conceptual |

---

## Implementation Status (v0.1.0-beta.1)

### Core ✅
- Warrant model (execution + issuer warrants)
- Full constraint types (Pattern, Exact, Range, OneOf, NotOneOf, CIDR, UrlPattern, Regex, Wildcard, Contains, CEL)
- Cryptographic chain verification
- Mandatory PoP with timestamp validation
- Monotonic attenuation
- Chain limits (MAX_DELEGATION_DEPTH = 64)
- WarrantStack PEM chain encoding

### Python SDK ✅
- Ergonomic API (`Warrant.mint()`, `grant_builder()`, `@guard`)
- `guard_tools()` for LangChain
- `@tenuo_node` for LangGraph
- `KeyRegistry` for safe LangGraph checkpointing
- Async support

### Explorer ✅
- WASM-powered browser tool
- Visual Builder with 8+ constraint types
- Code Generator (Python/Rust)
- Delegation chain visualization

### CLI ✅
- `tenuo init`, `decode`, `mint`, `validate`
- PEM and base64 warrant support

---

## Completed (v0.1.0-beta.1)

| Feature | Status |
|---------|--------|
| Warrant convenience methods (`explain()`, `why_denied()`) | ✅ |
| `BoundWarrant` with serialization guards | ✅ |
| `grant_builder()` / `delegate()` API | ✅ |
| Framework Integrations (FastAPI, LangChain, LangGraph) | ✅ |
| `@guard` decorator | ✅ |
| `KeyRegistry` for LangGraph | ✅ |
| Explorer with Builder & Code Generator | ✅ |
| Full constraint types (CIDR, UrlPattern, Regex, etc.) | ✅ |

---

## Roadmap

| Feature | Target | Notes |
|---------|--------|-------|
| TypeScript/Node SDK | v0.2 | Help wanted! |
| Google A2A integration | v0.2 | Agent-to-Agent protocol |
| Multi-sig approvals | v0.2 | Partial now, notary in v0.2 |
| Distributed revocation | v0.3 | Cascading revocation service |
| Context-aware constraints | TBD | Spec under development |

---

## Document Descriptions

### protocol-spec-v1.md (Reference)
Complete protocol specification covering:
- Warrant model and semantics
- Constraint types and evaluation
- Cryptographic verification
- Clearance levels (optional)
- Delegation receipts
- Proof-of-Possession (PoP)

### wire-format-v1.md (Reference)
Wire format details for cross-language interoperability:
- CBOR serialization
- Envelope structure
- Canonical error codes
- HTTP/JSON-RPC mappings

### a2a-handshake.md (Experimental)
Unified Control Protocol for Agent-to-Agent interaction:
- **Zero-Touch Registration**: Handshake flow for new workers
- **Warrant Renewal**: Rotation protocol for expiring warrants
- **HD Key Provisioning**: Deterministic "Zero-Handshake" model (Method C)


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

- **User documentation** — Use [`/docs`](../) instead
- **API reference** — Use [`/docs/api-reference.md`](../api-reference.md)
- **Getting started** — Use [`/README.md`](../../README.md)
