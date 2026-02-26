---
title: "Agents Turn Sessions into Blank Checks"
description: "A technical thesis on warrant-based authorization for agentic systems"
layout: default
---

# Agents Turn Sessions into Blank Checks

### A technical thesis on warrant-based authorization for agentic systems

---

## Contents

1. [Overview](#overview)
2. [The Authorization Gap](#the-authorization-gap)
3. [Why Existing Infrastructure Fails](#why-existing-infrastructure-fails)
4. [Warrant-Based Authorization](#warrant-based-authorization)
5. [Architecture](#architecture)
6. [Constraint System](#constraint-system)
7. [Offline Verification vs. Centralized Enforcement](#offline-verification-vs-centralized-enforcement)
8. [Competitive Landscape](#competitive-landscape)
9. [Real-World Scenarios](#real-world-scenarios)
10. [Market Context](#market-context)
11. [Regulatory Convergence](#regulatory-convergence)
12. [Risks and Limitations](#risks-and-limitations)
13. [The Tenuo Thesis](#the-tenuo-thesis)

---

## Overview

AI agents are no longer conversational interfaces. They are autonomous systems that issue refunds, modify databases, delegate to sub-agents, and execute multi-step workflows, often completing entire chains of action in seconds.

This shift from conversation to action exposes an authorization gap that existing infrastructure was not designed to address. Authentication tells you *who* the agent is. Orchestration tells you *what workflow* the agent is executing. Neither provides the artifact that matters at execution time: cryptographic proof that this specific action, with these specific parameters, is the authorized continuation of a legitimate task.

Tenuo is cryptographic authorization infrastructure for agentic systems. It implements **warrant-based authorization**: signed, scoped, time-bound capability tokens that attenuate through delegation chains, verify offline in microseconds, and produce signed receipts for every action.

This document presents the problem, the architecture, and the thesis behind Tenuo.

---

## The Authorization Gap

### Why authorization worked before

The defining architectural pattern of the last decade was microservices: discrete services with fixed identities and predetermined permission sets. Static IAM worked because services did not reason, did not delegate, and did not act autonomously. A payment service called a database with a fixed credential set, and that credential set never changed mid-request.

Agentic workflows break every one of those assumptions. Agents spin up dynamically, delegate to sub-agents, invoke tools across system boundaries, and terminate, all within a single task. Authorization can no longer be static and identity-bound. It must be dynamic, scoped to the task, and enforced at execution time.

### How agents acquire authority today

The dominant pattern for agent authorization in production systems today is **session inheritance**. A human authenticates (OAuth, SSO, API key), establishing a session with some set of permissions. An AI agent operates within that session, inheriting all of its permissions for the session's entire lifetime.

This is how every major agent framework works by default. The agent receives a token or credential set at initialization. That credential set determines what the agent can do for the duration of the session. Not per-task. Not per-action.

The consequences:

| Property | Human session | Agent session |
|---|---|---|
| **Speed** | Seconds between actions | Milliseconds between actions |
| **Scope of action** | One task at a time | Parallel, multi-step workflows |
| **Intent legibility** | Clicks and form submissions | Opaque tool calls derived from probabilistic inference |
| **Delegation** | Explicit handoffs | Implicit sub-agent spawning |
| **Revocation window** | Minutes to hours | Actions complete before review is possible |

A human support agent clicking through a CRM operates within the same RBAC framework as an AI agent, but the attack surface is categorically different. The human takes 30 seconds to process a refund. The AI agent can process 50 refunds in that time. The human navigates a UI that constrains available actions. The AI agent has programmatic access to every tool in its registry.

Session-scoped credentials designed for human interaction become **ambient authority** when attached to an autonomous system. The agent doesn't need to escalate privileges. It already has them.

This is the **confused deputy problem** applied to AI agents. The agent holds legitimate authority. An adversarial input (or simply an ambiguous instruction) tricks it into exercising that authority in unintended ways. The deputy is confused, but its credentials are valid. Every action it takes is authenticated and authorized by the session.

The **temporal mismatch** compounds this. Credentials are scoped to a session that may last minutes or hours. The agent operates at millisecond speed. By the time a human could notice anomalous behavior, the agent has already completed the workflow. Authorization decisions made at session start cannot account for conditions that change during execution.

### The prompt injection multiplier

The authorization gap is a structural problem. Prompt injection makes it an urgent one.

When an agent can be induced to take unintended actions (through adversarial inputs in documents, emails, web pages, or user messages) the blast radius is determined entirely by the scope of authority the agent holds. If that scope is a session-level credential with broad permissions, the blast radius is everything the session can reach.

The structural failure is that **the authorization architecture provides no containment**. Any software can be exploited. A prompt injection against a session-scoped agent is equivalent to session hijacking, except easier, requiring no credential theft, and operating at machine speed.

**Memory poisoning** extends the attack surface beyond a single interaction. Adversarial content embedded in documents, emails, or tool outputs lodges in the agent's persistent context or retrieval store. The poisoned memory influences future, unrelated tasks, turning a single injection into a persistent compromise. The agent acts on corrupted context while every authorization check passes, because the credentials are valid and the actions fall within session scope. Without per-task, per-action authorization, there is no mechanism to contain the blast radius of a poisoned memory to the task that introduced it.

### The delegation chain problem

The authorization gap exists independently of adversarial scenarios. Even without prompt injection, delegation complexity alone requires structural containment. When Agent A delegates to Agent B:

1. What authority does B inherit?
2. Can B delegate further to Agent C?
3. Is there a cryptographic proof that C's authority descends from A's original grant?
4. Did permissions narrow at each hop, or could they have expanded?

OAuth tokens carry identity. They do not carry provenance. At the first hop, the token tells you *who* is acting. At the second hop, the token tells you who the delegate is, but not under what constraints they were delegated authority. By the third hop, the provenance is gone entirely. You have a valid token. You have no idea how the authority arrived there, whether it was supposed to narrow along the way, or whether this request has any relationship to the workflow that originally justified the access.

This is a structural limitation of the bearer token model, not a configuration gap that better policy can fix. OAuth, JWT, and API keys were designed for a world where a human authenticates and a service acts on their behalf. One hop. Multi-hop delegation, where agents spawn sub-agents that invoke tools that call external services, requires a primitive that carries provenance as a first-class property. Bearer tokens do not have this property and cannot be extended to have it without becoming something fundamentally different.

---

## Why Existing Infrastructure Fails

### Guardrails operate at the wrong layer

The standard approach to agent security, as documented in OpenAI's enterprise guide and most agent frameworks, consists of:

- **Relevance classifiers** that flag off-topic queries
- **Safety classifiers** that detect jailbreaks
- **PII filters** that redact personal information
- **Tool risk ratings** that escalate high-risk actions to humans
- **Regex-based validation** that pattern-matches dangerous inputs

These are perception-layer defenses. They attempt to determine, by analyzing the *content* of a request, whether that request should proceed. They are probabilistic by nature. Every classifier has a false negative rate. Every regex has an encoding bypass.

The authorization question is *"does this agent hold a valid, scoped, unexpired authorization for this specific action with these specific parameters?"* That question requires verification, not inference.

### Human escalation doesn't scale

"High-risk actions should trigger human oversight until confidence in the agent's reliability grows." This is OpenAI's recommendation for production deployments.

At agent velocity, human oversight is structurally impossible for real-time containment. An agent completes an entire workflow, including any violations, before a human reviewer can act. Human oversight remains valuable for audit, policy refinement, and exception handling. It is not a security boundary for autonomous systems operating at machine speed.

### Policy servers become bottlenecks

Traditional authorization evaluates policies at a central decision point. Agent A calls the policy server. The policy server checks A's roles, attributes, and context. This adds latency to every action and creates a single point of failure.

More critically, policy servers evaluate *identity and attributes*. They do not evaluate *provenance*. When Agent A delegates to Agent B, the policy server can check B's role. It cannot verify that B's authority was derived from A's grant, that constraints narrowed at each hop, or that this specific request is the legitimate continuation of a specific workflow.

Policy evaluation works for single-hop authorization. It does not extend to multi-hop delegation without bolting on provenance mechanisms that the policy model does not natively support.

### Time-of-check to time-of-use (TOCTOU)

Even when authorization is checked correctly, a gap exists between the check and the execution. In streaming architectures (OpenAI Agents SDK, LangChain), the agent plans a tool call, the system checks authorization, and then the agent executes. Between planning and execution, the call parameters can change. The agent may plan `transfer(amount=50)` and execute `transfer(amount=5000)` if the parameters are mutable between the check and the call.

This is TOCTOU applied to agent workflows. Traditional web applications mitigate TOCTOU through atomic transactions. Agent frameworks, where tool calls are constructed dynamically by a language model, have no equivalent atomicity guarantee. Authorization must be verified at the point of execution, not at the point of planning. Tenuo's enforcement layer checks the warrant against the *actual* parameters at call time, closing the TOCTOU window.

### String validation is a losing game

I documented this extensively in my analysis of [CVE-2025-66032](https://niyikiza.com/posts/cve-2025-66032/) (Claude Code command injection) and the [agent-tool trust boundary](https://niyikiza.com/posts/map-territory/). The core insight: validators and executors interpret the same bytes differently.

A regex-based path validator sees `../etc/passwd` and blocks it. It does not see `..%2Fetc%2Fpasswd` or `..%252Fetc%252Fpasswd` or symlinks that resolve outside the intended directory. The filesystem interprets all of these as the same path. The validator checks the map. The system executes in the territory.

This is why Tenuo's constraint system parses inputs semantically, the way the target system will interpret them, rather than pattern-matching strings. But constraints are the mechanism. The architectural insight is that **validation must be independent of the agent's behavior**. The agent is untrusted. Authorization must be verified externally, cryptographically, at the point of execution.

---

## Warrant-Based Authorization

### Definition

A **warrant** is a cryptographic authorization token with the following properties:

| Property | Description |
|---|---|
| **Issuer-signed** | Ed25519 signature by the authority that grants the capability |
| **Holder-bound** | Bound to a specific agent's public key; possession of the warrant alone is insufficient |
| **Capability-scoped** | Enumerates exactly which tools/actions are authorized |
| **Constraint-bearing** | Carries parameter constraints (value ranges, path prefixes, patterns) |
| **Time-limited** | Expires after a configurable TTL |
| **Attenuating** | Can be delegated, but delegated warrants can only narrow scope, never expand it |
| **Receipt-producing** | Every authorized action generates a signed receipt linking authorization to execution |

### Subtractive delegation

Warrants implement **subtractive delegation**: the principle that delegated authority can only be a subset of the delegator's authority.

```
Root Warrant (Alice, human)
├── capabilities: [read_crm, issue_refund, send_email]
├── constraints: {customer: "cus_123", refund_amount: ≤500}
├── ttl: 3600s
│
└── Delegated Warrant (Support Agent)
    ├── capabilities: [read_crm, issue_refund]  ← send_email removed
    ├── constraints: {customer: "cus_123", refund_amount: ≤100}  ← tightened
    ├── ttl: 300s  ← shortened
    │
    └── Sub-delegated Warrant (Refund Processor)
        ├── capabilities: [issue_refund]  ← read_crm removed
        ├── constraints: {customer: "cus_123", refund_amount: ≤100}
        └── ttl: 60s  ← shortened further
```

At each hop, capabilities can be removed but not added. Constraints can be tightened but not loosened. TTL can be shortened but not extended. The Rust core enforces this structurally. It will not sign a warrant that expands authority relative to its parent.

This is the same principle behind [Google's Macaroons](https://research.google/pubs/pub41892/) (2014), [Biscuit tokens](https://www.biscuitsec.org/) (Clever Cloud), and [UCAN](https://ucan.xyz/) (Fission). What Tenuo adds is the application of this primitive to the specific problem space of AI agent workflows: delegation at machine speed rather than human speed, constraints that encode business logic (not just resource paths), semantic parsing that matches target system interpretation, and audit trails that satisfy emerging Know Your Agent (KYA) requirements. The capability model is well-established. The agent-specific enforcement layer is what has been missing.

### Holder binding and Proof of Possession

Bearer tokens grant authority through possession. Whoever holds the token is authorized. This means interception equals compromise.

Warrants implement **Proof of Possession (PoP)**. Each warrant designates a specific agent public key as the authorized holder. When the agent presents a warrant, the verifier demands cryptographic proof: sign this challenge with the private key corresponding to the holder field. This is the same principle behind DPoP (RFC 9449) and mTLS-bound tokens, applied to agent authorization.

An attacker who intercepts a warrant in transit cannot use it. They have the authorization artifact but not the private key. The transaction is rejected. Unlike bearer tokens, where theft equals access, warrant theft without key compromise is useless.

PoP has a clear limitation: it does not help when the agent itself is compromised. A prompt injection that causes the legitimate agent to sign a malicious tool call will pass signature verification, because the signature is genuine. This is the design reason for tight, per-action constraints. The warrant limits what a compromised agent can do, not whether it can act.

### Receipts as first-class artifacts

Every authorized action produces a signed receipt:

```
Receipt {
    warrant_hash: SHA-256 of the authorizing warrant
    action: "issue_refund"
    parameters: {order_id: "12345", amount: 29.99}
    timestamp: 2026-02-18T10:32:01Z
    holder_signature: Ed25519 signature by the executing agent
    verifier_signature: Ed25519 signature by the enforcement point
}
```

A receipt is a cryptographic artifact, distinct from a log entry. A log entry is an assertion by your system that something happened. A receipt proves:

- **Who authorized**: the issuer signature chain traces back to a human approval
- **What was authorized**: the capability and constraint set in the warrant
- **What was executed**: the specific action and parameters
- **When**: timestamp bound to the warrant's validity window
- **By whom**: holder binding ties execution to a specific agent identity

This is the difference between [explaining your logging infrastructure during an investigation and handing over a signed chain of evidence](https://niyikiza.com/posts/hallucination-defense/). Logs describe. Receipts prove.


The enforcement layer produces signed receipts locally as part of the open-source core. Tenuo Cloud provides receipt storage, chain indexing, and compliance reporting.

---

## Architecture

Tenuo consists of three components:

### Rust Core

The authorization engine. Handles warrant minting, signature generation and verification, constraint evaluation, and delegation chain validation.

| Specification | Detail |
|---|---|
| **Signatures** | Ed25519 (RFC 8032) |
| **Encoding** | CBOR (RFC 8949) |
| **Hashing** | SHA-256 for chain linking |
| **Verification latency** | Microsecond-range (wire-level evaluation, stateless, no I/O) |
| **Wire format** | Specified with test vectors for cross-implementation consistency |

The core is deliberately minimal. It enforces cryptographic invariants: signature validity, monotonic attenuation, TTL bounds, holder binding. It does not handle routing, transport, tool invocation, or any application logic. The trusted computing base is small by design.

### Python SDK

Client library with framework integrations:

| Framework | Integration |
|---|---|
| OpenAI Agents SDK | Streaming TOCTOU defense, tool-level warrant enforcement |
| Google ADK | Native tool guard integration |
| LangChain / LangGraph | Middleware for chain-of-thought and multi-agent graphs |
| CrewAI | Task-scoped warrant lifecycle |
| AutoGen | Agent-to-agent delegation with attenuation |
| MCP | Secure client wrapping for Model Context Protocol servers |
| FastAPI | Request-scoped warrant verification middleware |

The SDK wraps the Rust core via PyO3. Five lines of code to protect an agent:

```python
from tenuo import configure, SigningKey, mint_sync, guard, Capability, Pattern

configure(issuer_key=SigningKey.generate(), dev_mode=True)

@guard(tool="send_email")
def send_email(to: str) -> str:
    return f"Sent to {to}"

with mint_sync(Capability("send_email", to=Pattern("*@company.com"))):
    send_email(to="alice@company.com")       # ✓ Authorized
    send_email(to="attacker@evil.com")        # ✗ Denied
```

### Approval Policies

Warrants define what an agent can do. Approval policies define when a human must confirm before execution proceeds. The approval layer sits between warrant authorization and tool execution: a warrant may permit a transfer up to $100K, but an approval policy requires human confirmation for amounts over $10K.

Every approval is cryptographically signed. There is no unsigned "approved=True" path. The approver's signing key produces a SignedApproval that binds to the exact (warrant, tool, arguments, holder) tuple via a SHA-256 request hash. The enforcement layer verifies the signature, hash, and approver key before allowing execution. Approvals are time-bound and scoped to a single action.

### Tenuo Cloud (Enterprise)

Authorization management for production deployments:

- Warrant lifecycle management and key rotation
- Policy-to-warrant mapping (import existing RBAC/ABAC policies as constraint templates)
- Audit console with delegation chain visualization
- Receipt storage and compliance reporting
- On-premises deployment for regulated industries

---

## Constraint System

Warrants carry typed constraints that are evaluated against action parameters at verification time. Each constraint type is designed for a specific attack surface:

| Constraint | Purpose | What it prevents |
|---|---|---|
| `Exact(value)` | Exact match | Parameter tampering |
| `OneOf(values)` | Enumerated set | Unapproved values (e.g., unauthorized trading symbols) |
| `Range(min, max)` | Numeric bounds | Amount manipulation, threshold evasion |
| `Pattern(glob)` | Glob matching | Recipient domain violations (e.g., `*@company.com`) |
| `Subpath(prefix)` | Path prefix with symlink resolution | Path traversal, directory escape |
| `UrlSafe(rules)` | Semantic URL parsing | SSRF, scheme injection, private IP access |
| `Shlex(allowlist)` | Shell tokenization | Command injection, operator chaining |

### Semantic parsing, not string matching

The critical design principle: **constraints parse inputs the way the target system will interpret them**.

`Subpath` does not regex-match path strings. It calls `os.path.realpath()` to resolve symlinks and relative components, then verifies the resolved path falls within the allowed prefix. This is [Layer 2 enforcement](https://niyikiza.com/posts/map-territory/): validation at the execution boundary, not the perception boundary.

`Shlex` does not regex-match shell commands. It tokenizes using the same algorithm the shell uses, then verifies the command and arguments against the allowlist. This is why it catches attacks that [bypassed Claude Code's allowlist](https://niyikiza.com/posts/cve-2025-66032/): parameter expansion, operator injection, and encoding tricks that regex-based validation cannot see.

`UrlSafe` parses URLs into components (scheme, host, port, path) rather than matching patterns. It catches SSRF vectors that string matching misses: DNS rebinding setups, encoded private IPs, scheme confusion.

---

## Offline Verification vs. Centralized Enforcement

This is an architectural decision with significant implications. Two models exist for enforcing authorization in agentic systems:

### Centralized model (gateway/proxy)

A central enforcement point (a gateway or authorization proxy) sits between agents and external systems. Agents present authorization artifacts to the gateway. The gateway holds real credentials, verifies authorization, and executes actions on behalf of agents.

**Advantages**: Agents never touch raw API keys. Centralized audit. Single enforcement point.

**Disadvantages**: Every agent action requires a round-trip to the gateway. The gateway is a single point of failure and a performance bottleneck. It does not survive async boundaries (queued workflows, event-driven architectures). Cross-organizational workflows require both parties to trust and connect to the same gateway. Latency scales with gateway load, not with verification complexity.

### Decentralized model (offline verification)

Authorization artifacts are self-contained and cryptographically verifiable. The tool or service that receives a warrant can verify it locally with only the issuer's public key. No callback. No central server in the critical path.

**Advantages**: Verification in the microsecond range regardless of system load. No single point of failure. Survives async boundaries: a warrant attached to a queued message is verifiable when the message is processed, minutes or hours later. Cross-organizational verification requires only published public keys, not shared infrastructure. Scales horizontally with zero coordination.

**Disadvantages**: Revocation requires either short TTLs (Tenuo's approach) or a revocation check (adds an online dependency). Credential management is distributed rather than centralized.

**Tenuo's position**: Offline verification with short TTLs. This follows the same design lineage as Macaroons, Biscuit, and UCAN. The latency and availability characteristics of offline verification are essential for agent-speed execution. Short TTLs (seconds to minutes) provide natural revocation windows without requiring online revocation infrastructure.

A centralized gateway can be layered on top of offline-verifiable warrants (Tenuo Cloud does this for enterprise key management and audit). The reverse, making a centralized gateway work offline, is architecturally impossible. Starting with the decentralized primitive provides strictly more deployment flexibility.

---

## Competitive Landscape

Authorization for agentic systems touches multiple existing infrastructure categories. Each solves a necessary part of the problem. The gap is at the intersection: multi-hop delegation with cryptographic constraint enforcement across organizational boundaries.

### Identity providers (Okta, Auth0, SPIFFE)

Establish and verify agent identity. Manage lifecycle, authentication, and policy-based access control. These are necessary foundations, and Tenuo assumes identity is already established. What identity providers do not provide is proof that a specific request carries authority that was delegated through a verifiable chain with constraints that accumulated at each hop.

### Orchestration platforms (OpenAI Agents SDK, LangChain, CrewAI)

Manage workflow execution, task routing, and multi-agent coordination patterns. Define what agents should do and in what order. Do not enforce authorization that persists across delegation hops or produce cryptographic audit trails for autonomous actions.

### Policy middleware (OPA, Cedar, custom RBAC)

Evaluate authorization rules at a central decision point. Effective for single-hop authorization where one agent calls one API. Do not extend to multi-hop delegation without supplemental provenance mechanisms. The policy can check each agent's permissions independently, but cannot verify the delegation lineage that connects them.

### Execution sandboxes (WASM sandboxes, Docker, gVisor)

Isolate the execution environment. Prevent container escape, filesystem access, and network exfiltration. Address a different threat model: a sandboxed agent with a broad credential set can still issue unauthorized refunds, access other tenants' data, or exfiltrate information through legitimate authorized channels. Sandboxing constrains *where* code runs. Warrants constrain *what actions are authorized*.

### Where Tenuo sits

Each of these layers answers a different question at a different point in the agent lifecycle:

| Layer | Question answered | When it's checked |
|---|---|---|
| Identity (Okta, Auth0, SPIFFE) | Who is this agent? | At connection |
| Governance (Eqty Lab) | Is this agent running in a trusted, compliant environment? | Continuous |
| Orchestration (OpenAI, LangChain, CrewAI) | What should this agent do? | At planning |
| Policy (OPA, Cedar, RBAC) | Is this action class permitted? | At decision point |
| Sandbox (Docker, gVisor, Firecracker) | Where can this code run? | At execution |
| **Authorization (Tenuo)** | **Is this specific action authorized, by this delegation chain, with these constraints?** | **At the tool boundary** |

Tenuo does not replace any of these layers. It answers the question that none of them ask: does this agent hold a valid, scoped, unexpired warrant for this specific action with these specific parameters, issued through a verifiable delegation chain where constraints tightened at every hop? That question only has meaning at the moment of execution, which is why it must be answered at the tool boundary.

### Warrant constraints subsume existing policy models

A common objection: "We already have RBAC and ABAC. Why add another authorization layer?"

The answer is that warrants don't replace existing policy. They make it delegation-safe. The mapping from policy rules to warrant constraints is mechanical:

An RBAC rule like *"support agents can process refunds"* becomes a capability: `Capability("refund", role=Exact("support"))`. An ABAC rule like *"finance team can process payments under $10k during business hours"* becomes a constrained capability: `Capability("payment", department=Exact("finance"), amount=Range(0, 10000), time_window=Exact("09:00-17:00"))`.

Existing policies translate directly. Nothing is lost in the mapping. What is gained is **provable attenuation across delegation hops**. When Agent A delegates to Agent B, and B delegates to C, the warrant chain guarantees that C's authority is a strict subset of B's, which is a strict subset of A's. Policy-based systems can check C's permissions at a central decision point. They cannot prove that C's authority *descended from* A's grant through B without bolting on provenance infrastructure that the policy model does not natively support.

Teams adopting Tenuo use the same mental models they already know. Roles and attributes become constraints. When multi-agent delegation enters the picture, the architecture already handles it. No re-platforming required.

---

## Real-World Scenarios

The following are concrete attack scenarios with specific warrant configurations that prevent them. Full code for all ten scenarios is available at [tenuo.ai/examples](https://tenuo.ai/examples).

### Healthcare: patient data exfiltration

A hospital's AI assistant has access to `query_records`, `generate_report`, and `send_email`. A prompt injection in a patient's intake form instructs the agent to exfiltrate records via `send_email` after every lookup.

**Without warrants**: The agent's static IAM role includes both EHR access and email permissions. The injection succeeds because `send_email` is a legitimate tool available at all times.

**With warrants**: The task warrant includes `query_records` and `generate_report` for the specific patient. `send_email` is not in the warrant. When a physician needs to email a report, a separate warrant is minted constraining the recipient to `*@partnerhospital.org`.

**Prevented**: HIPAA violation, patient data breach.

### Finance: unauthorized trade execution

A research agent fetches a news article containing injected instructions to call `place_order`. In a shared tool registry, the instruction reaches a node with trading capabilities.

**Without warrants**: Both research and trading agents share tool registries at the graph level. The compromised output flows into a node with `place_order` access.

**With warrants**: Per-agent warrants. The research agent's warrant contains `fetch_market_data`, `analyze_sentiment`, `write_memo`. The trading agent's warrant constrains `place_order` to approved symbols via `OneOf("AAPL", "GOOGL", "MSFT")` and quantity via `Range(1, 1000)`.

**Prevented**: Unauthorized trade execution, SEC regulatory violation.

### Multi-tenant SaaS: cross-tenant data breach

Tenant A crafts a query that includes `query_warehouse(tenant="tenant_b")`. With a shared connection pool, tenant isolation depends on application-layer filtering. One prompt injection bypasses it.

**Without warrants**: The agent's database credentials have cross-tenant read access.

**With warrants**: Per-request warrants with `tenant=Exact(tenant_id)`. The constraint is checked by the Rust core. Cross-tenant access is cryptographically impossible within the warrant's scope.

**Prevented**: Cross-tenant data breach, SOC 2 violation.

---

## Market Context

### The agent deployment wave

Agent deployments are accelerating from experimental to production faster than the security infrastructure can follow.

McKinsey's State of AI survey (2025) found 62% of organizations are at least experimenting with AI agents, with 23% already scaling agentic systems in production ([McKinsey](https://www.mckinsey.com/capabilities/quantumblack/our-insights/the-state-of-ai)). Deloitte's State of AI in the Enterprise report (3,235 leaders across 24 countries) projects agentic AI becoming nearly ubiquitous within two years, with 74% of companies using it at least moderately ([Deloitte](https://www.deloitte.com/us/en/what-we-do/capabilities/applied-artificial-intelligence/content/state-of-ai-in-the-enterprise.html)). Gartner projects 70% of AI applications will use multi-agent systems by 2028 ([Gartner](https://www.gartner.com/en/newsroom/press-releases/2025-06-11-gartner-predicts-that-guardian-agents-will-capture-10-15-percent-of-the-agentic-ai-market-by-2030)).

Multi-agent systems are where the authorization gap becomes critical. Delegation chains, shared tool registries, and cross-agent data flow create attack surfaces that single-agent architectures do not.

### The security gap is quantified

Deloitte found only 21% of companies have a mature governance model for autonomous agents, even as adoption accelerates ([Deloitte](https://www.deloitte.com/us/en/what-we-do/capabilities/applied-artificial-intelligence/content/state-of-ai-in-the-enterprise.html)). Gartner predicts 25% of enterprise cybersecurity incidents will involve AI agent misuse by 2028, and separately forecasts that over 40% of agentic AI projects will be canceled by end of 2027 due to escalating costs, unclear value, or **inadequate risk controls** ([Gartner](https://www.gartner.com/en/newsroom/press-releases/2025-06-11-gartner-predicts-that-guardian-agents-will-capture-10-15-percent-of-the-agentic-ai-market-by-2030)). NIST launched an [AI Agent Standards Initiative](https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure) in February 2026, explicitly identifying agent authorization, delegation, and audit as open problems requiring industry demonstration.

Authorization infrastructure is a prerequisite for agents reaching production.

### Authorization doesn't survive model hops

Production agent deployments already route across multiple model providers in the same workflow. LangChain's State of Agent Engineering survey reports 75%+ of production teams use multiple models to balance quality, latency, and cost. Google's [Agent-to-Agent (A2A) protocol](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/), now backed by over 150 organizations and hosted by the Linux Foundation, formalizes this as the standard architecture: client agents discover remote agents via Agent Cards, delegate tasks, and coordinate across organizational boundaries.

A2A solves discovery and communication. Its authentication model supports OpenAPI-compatible schemes (API keys, OAuth 2.0, OIDC) at the connection level. What A2A does not carry is per-task authorization provenance. When a client agent delegates a task to a remote agent, and that remote agent delegates further, the A2A protocol establishes who is communicating. It does not establish a cryptographic chain proving that each hop's authority descends from the original grant with constraints that tightened along the way.

This is the same gap at the protocol layer. MCP connects agents to tools. A2A connects agents to agents. Neither carries a portable authorization artifact that attenuates through the delegation chain. A warrant is that artifact. It can travel inside an A2A task payload or an MCP tool call, providing the authorization layer that both protocols assume exists but do not define.

### Infrastructure is converging on per-action boundaries

The infrastructure layer is already moving toward per-action isolation. Google's [Agent Sandbox](https://cloud.google.com/blog/products/containers-kubernetes/agentic-ai-on-kubernetes-and-gke) provisions gVisor containers per task on Kubernetes. [Docker Sandboxes](https://www.docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely/) run coding agents in dedicated microVMs with network isolation. [E2B](https://e2b.dev) spins up Firecracker microVMs in under 200ms for ephemeral agent execution. [Daytona](https://daytona.io) provisions sandboxes in sub-90ms for AI-generated code. Cloudflare runs ephemeral V8 isolates per request. [NVIDIA's AI Red Team](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/) published guidance recommending full kernel isolation (microVMs or Kata Containers) as the baseline for agentic workloads, explicitly stating that shared-kernel containers are insufficient.

The pattern is consistent: execution isolation is scoping down to the individual action. What none of these layers provide is *authorization* at the same granularity. A per-task sandbox can prevent container escape. It cannot verify that the action inside the sandbox was authorized by a legitimate delegation chain with constraints that narrowed at each hop. Isolation answers "where can this code run?" Authorization answers "should this action execute at all?"

---

## Regulatory Convergence

### Know Your Agent (KYA)

The concept of KYA (verifiable agent identity, provable authorization chains, and complete audit trails for every autonomous action) is moving from theoretical to required:

- **EU AI Act**: Requires human oversight and auditability for high-risk AI systems.
- **Visa and Mastercard**: Building agent trust frameworks for agentic commerce.
- **NIST**: AI Agent Standards Initiative with active RFIs for security (March 2026) and identity/authorization (April 2026).
- **Singapore IMDA**: Model AI Governance Framework for Agentic AI (Jan 2026) identifies dynamic agent authorization and recursive delegation as open gaps requiring new infrastructure.
- **OWASP**: MCP security guide (Feb 2026) defines signed tool manifests, capability-scoped tokens, and immutable audit trails as minimum requirements.
- **Financial services**: HIPAA audit requirements, SOC 2 compliance, SEC reporting, all converging on the need to demonstrate authorization provenance for autonomous actions.

Warrant chains provide native KYA compliance. The query *"who authorized what, under which constraints, through which delegation path, and when?"* is answered by the receipt chain. No log reconstruction. No forensic inference.

### Compliance as infrastructure

Organizations with queryable authorization chains will pass audits faster. This is a competitive advantage that compounds. Every warrant minted is a compliance artifact. Every receipt produced is audit evidence. The authorization infrastructure *is* the compliance infrastructure.

---

## Risks and Limitations

### What warrants do not solve

| Limitation | Why it exists | Mitigation |
|---|---|---|
| **Agent-level compromise** | A compromised agent acting within its authorized scope passes warrant checks. | Tight constraints bound the blast radius. Warrants limit damage even when the agent is compromised. |
| **Identity and authentication** | Warrants assume agent identity is already established. Tenuo is not a replacement for Okta, Auth0, or SPIFFE. | Tenuo operates as the layer between identity and execution. Integrates with existing identity infrastructure. |
| **Execution isolation** | Warrants authorize actions, not execution environments. A container escape bypasses the authorization boundary. | Sandboxing and authorization are complementary controls. Warrants constrain what actions are authorized; sandboxes constrain where code runs. |

### Market and technical risks

| Risk | If this happens | Our position |
|---|---|---|
| **Adoption timing** | Enterprises delay production agent deployments. Market for authorization infrastructure contracts. | Target companies where agents are already in production, not planning to be. Orchestration platforms and fintech agent teams are deploying today. |
| **Platform incumbents** | OpenAI, Anthropic, or hyperscalers build capability-based authorization natively. | Open-source core and 9 framework integrations make Tenuo a natural integration target. Incumbents will build for their own stack, not cross-platform. |
| **Regulatory uncertainty** | KYA requirements do not materialize. Compliance driver weakens. | Audit requirements for autonomous systems are increasing across EU AI Act, NIST, and financial regulators. The trend is acceleration, not retreat. |
| **Key management complexity** | Per-agent keys and rotation add operational burden relative to bearer tokens. | Tenuo Cloud handles key lifecycle for enterprise deployments. Short TTLs reduce the window of key compromise. |
| **Developer adoption** | Capability-based security learning curve slows adoption. | SDK provides secure defaults in five lines of code. Existing RBAC/ABAC mental models map directly to warrant constraints. |

---

## The Tenuo Thesis

**1. Authority must follow the task, not the session.**

Agents decompose tasks. IAM consolidates authority. The friction is structural. Warrants make authority task-scoped: broad at the source, narrower at each delegation, gone when the task ends.

**2. Security must be physics, not psychology.**

At agent velocity, policy servers become bottlenecks and probabilistic filters become bypass targets. Guardrails that depend on the agent interpreting instructions correctly are psychology. They work until the agent is confused, compromised, or adversarially manipulated. Constraints verified by Ed25519 signatures and semantic parsing are physics. They hold regardless of the agent's internal state. Warrants make RBAC/ABAC delegation-safe by turning policy into cryptographically verifiable proof.

**3. Offline verification is architecturally superior for agent-speed systems.**

Centralized gateways add latency, create single points of failure, and don't survive async boundaries. Self-contained, cryptographically verifiable warrants verify in microseconds, across organizational boundaries, through message queues, and without coordination.

**4. Receipts close the accountability gap.**

Logs describe. Receipts prove. When the regulator asks "prove this was authorized," signed warrant chains answer the question directly. Compliance becomes a byproduct of the authorization architecture, not a separate reporting effort.

**5. Authorization infrastructure is a prerequisite, not a roadmap item.**

Gartner predicts 40% of agentic AI projects will be canceled by 2027 due to escalating costs, unclear value, or inadequate risk controls. The projects that survive will be the ones that ship with authorization infrastructure from the start. Not because of compliance pressure alone, but because production agents without bounded authority are operationally untenable. The teams building that infrastructure now will define the patterns the industry adopts.

---

**Tenuo is open-source, MIT licensed.**

- **Core**: Rust. Ed25519, CBOR, SHA-256. Wire format spec with test vectors.
- **SDK**: Python. Integrations with OpenAI, Google ADK, LangChain, LangGraph, CrewAI, AutoGen, MCP, A2A, Temporal.
- **Verification**: Microsecond-range. Stateless. No I/O.

GitHub: [github.com/tenuo-ai/tenuo](https://github.com/tenuo-ai/tenuo)  
Install: `pip install tenuo`  
Talk to us: [tenuo.ai/contact](https://tenuo.ai/contact)

---

*Tenuo builds on decades of capability-based security research: [Macaroons](https://research.google/pubs/pub41892/) (Google, 2014), [Biscuit](https://www.biscuitsec.org/) (Clever Cloud), [UCAN](https://ucan.xyz/) (Fission), and recent work on agent security including [CaMeL](https://arxiv.org/abs/2503.18813) (Debenedetti et al., 2025). The ideas in this document evolved through the [Agentic Security series](https://niyikiza.com/posts/) on Vectors, starting in December 2025.*
