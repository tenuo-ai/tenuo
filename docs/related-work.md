---
title: Related Work
description: How Tenuo relates to CaMeL, FIDES, and other AI agent security research
---

# Related Work

> How does Tenuo fit into the broader AI agent security landscape?

---

## CaMeL

**Paper**: [Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813) (Debenedetti et al., 2025)

CaMeL introduces a protective system layer around LLMs that secures agentic systems against prompt injection. Key ideas:

- **Capability tokens**: Explicit authorization for tool invocations
- **Control/data flow separation**: Untrusted data cannot impact program flow
- **P-LLM / Q-LLM architecture**: Privileged planner issues tokens to worker LLMs

**Tenuo implements CaMeL's capability token model:**

| CaMeL Concept | Tenuo Implementation |
|---------------|----------------------|
| Capability tokens | Warrants |
| Interpreter checks | Authorizer |
| P-LLM issues tokens | Root warrant (or issuer warrants) |
| Q-LLM holds tokens | Execution warrants |
| Token attenuation | Monotonic constraint narrowing |

CaMeL is the architecture. Tenuo is the authorization primitive.

---

## Microsoft FIDES

**Paper**: [Securing AI Agents with Information-Flow Control](https://arxiv.org/abs/2505.23643) (Costa et al., 2025)

FIDES uses information-flow control (IFC) to track data provenance through agent execution:

- **Taint tracking**: Labels data with confidentiality/integrity levels
- **Policy enforcement**: Prevents unauthorized data flows
- **Selective hiding**: Primitives for controlling information visibility

**Tenuo and FIDES solve different problems:**

| Concern | Solution |
|---------|----------|
| "Can this agent read `/etc/passwd`?" | **Tenuo** (action control) |
| "Did `/etc/passwd` contents leak to output?" | **FIDES** (data flow) |

Tenuo tracks **action flow** (what operations are authorized).  
FIDES tracks **data flow** (what information goes where).

### Complementary Approaches

A complete defense may use both:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Agent System                              │
│                                                                  │
│   ┌─────────────┐                      ┌─────────────────────┐  │
│   │   FIDES     │                      │      Tenuo          │  │
│   │             │                      │                     │  │
│   │  "Is this   │                      │  "Is this agent     │  │
│   │   data      │  ───────────────────▶│   allowed to call   │  │
│   │   tainted?" │                      │   this tool with    │  │
│   │             │                      │   these args?"      │  │
│   └─────────────┘                      └─────────────────────┘  │
│         │                                       │               │
│         ▼                                       ▼               │
│   Data flow policy                      Action authorization    │
│   (confidentiality)                     (capability tokens)     │
└─────────────────────────────────────────────────────────────────┘
```

**Example combined flow:**

1. Agent reads file → FIDES labels data as `confidential:internal`
2. Agent wants to send email → Tenuo checks warrant allows `send_email`
3. FIDES checks: can `confidential:internal` data flow to email recipient?
4. Both must approve for action to proceed

---

## Key Differences

| Aspect | Tenuo | FIDES |
|--------|-------|-------|
| **Focus** | Authorization (who can do what) | Information flow (where data goes) |
| **Model** | Capability tokens (warrants) | Taint labels (confidentiality/integrity) |
| **Enforcement** | Tool invocation time | Data propagation time |
| **Scope** | Per-task authority | Per-data-item provenance |
| **Overhead** | ~27μs verification | Depends on taint propagation |

---

## Prior Art

Tenuo builds on established capability-based authorization patterns:

| System | Contribution | Tenuo Difference |
|--------|--------------|------------------|
| [Macaroons](https://research.google/pubs/pub41892/) (Google, 2014) | Contextual caveats, attenuation | Tenuo adds PoP binding, AI-specific constraints |
| [Biscuit](https://www.biscuitsec.org/) (Clever Cloud) | Offline attenuation, Datalog authorization | Tenuo uses simpler constraint predicates |
| [UCAN](https://ucan.xyz/) (Fission) | Decentralized capability chains | Tenuo focused on centralized control plane model |

### Why Not Just Use Biscuit?

Biscuit is excellent. Both Tenuo and Biscuit support offline attenuation with similar mechanisms. Tenuo differs in:

1. **Threat model** — Designed specifically for AI agents processing untrusted input
2. **PoP binding** — Mandatory proof-of-possession (Biscuit has optional third-party caveats)
3. **Constraint types** — Purpose-built for tool authorization (Pattern, Range, OneOf)
4. **Authorization model** — Closed-form constraint predicates vs Datalog policies

If you need general-purpose capability tokens with flexible policy logic, consider Biscuit.  
If you need AI agent authorization with prompt injection defense, use Tenuo.

---

## Industry Approaches

| Vendor | Approach |
|--------|----------|
| Anthropic | Constitutional AI, RLHF alignment |
| OpenAI | System prompt isolation, function calling constraints |
| Google | Instruction hierarchy |

These focus on **model behavior**. Tenuo focuses on **authorization infrastructure**.

The approaches are complementary: model-level defenses reduce the likelihood of malicious intent; Tenuo limits the blast radius when defenses fail.

---

## Prompt Injection Defenses

| Approach | Description | Limitation |
|----------|-------------|------------|
| Input filtering | Detect/block malicious prompts | Evasion attacks |
| Output filtering | Detect/block harmful outputs | Post-hoc, reactive |
| Instruction hierarchy | System vs user prompt priority | Model-dependent |
| **Capability-based** | Limit what actions are possible | ✅ Tenuo's approach |

---

## Traditional Authorization Mapping

| System | Tenuo Analog |
|--------|--------------|
| OAuth scopes | Warrant constraints |
| RBAC roles | Issuer warrant pools |
| ABAC attributes | CEL expressions |
| Macaroons | Attenuated warrants |

---

## See Also

- [Concepts](./concepts) — Why Tenuo? Problem/solution overview
- [Protocol](./protocol) — How warrants work
- [Security](./security) — Detailed threat model
