---
title: "Agents Turn Sessions into Blank Checks"
description: "A technical thesis on warrant-based authorization for agentic systems"
layout: default
---

# Agents Turn Sessions into Blank Checks

### A technical thesis on warrant-based authorization for agentic systems

---

## Overview

AI agents are moving from conversation to execution. They issue refunds, modify databases, invoke external tools, and delegate to sub-agents, often completing entire workflows in seconds.

That shift creates an authorization gap. Authentication tells you *who* the agent is. Orchestration tells you *what workflow* it is running. Neither proves, at execution time, that a specific action with specific parameters is the authorized continuation of a legitimate task.

Tenuo is authorization infrastructure for agentic systems. It implements **warrant-based authorization**: signed, scoped, time-bound capability artifacts that attenuate through delegation chains, verify offline at microsecond scale, and produce signed receipts for every action.

This thesis explains why existing authorization primitives are structurally insufficient for multi-agent systems, how warrants close that gap, and why this model aligns with real production patterns while strengthening enterprise security and compliance posture.

---

## The Authorization Gap

### Why authorization worked before

The defining architectural pattern of the last decade was microservices: discrete services with fixed identities and predetermined permission sets. Static IAM worked because services did not reason, did not delegate, and did not act autonomously. A payment service called a database with a fixed credential set, and its call graph was known at deploy time.

Agentic workflows challenge those assumptions. Agents spin up dynamically, delegate to sub-agents, invoke tools across system boundaries, and terminate, all within a single task. Authorization can no longer be static and identity-bound. It must be dynamic, scoped to the task, and enforced at execution time.

### How agents acquire authority today

The dominant production pattern today is **session inheritance**. A human authenticates (OAuth, SSO, API key), establishing a session with a permission set; the agent then inherits that authority for the run. In most frameworks, credentials are granted at initialization, not per task or per action.

The consequences (as common production patterns, not universal constants):

| Property | Human session | Agent session |
|---|---|---|
| **Speed** | Often seconds between actions | Often sub-second to seconds between actions |
| **Scope of action** | Usually one task/workflow at a time | Can run parallel, multi-step workflows |
| **Intent legibility** | UI actions are comparatively legible | Tool calls are less legible and often inference-derived |
| **Delegation** | Usually explicit handoffs | Often implicit delegation and sub-agent spawning |
| **Revocation window** | Human review may intervene mid-flow | Actions may complete before intervention is practical |

A human support rep and an AI agent may share the same RBAC role, but they do not operate at the same speed or under the same constraints. A human might process one refund every 30 seconds through a UI. An agent can execute many unrelated actions in that same interval with direct programmatic access to every exposed tool.

That is why session-scoped credentials become **ambient authority** in autonomous systems. The agent does not need to escalate privileges; it starts with broad authority and can apply it across rapidly changing contexts.

This is the **confused deputy problem** in agent form. The authority is legitimate, but adversarial or ambiguous inputs can redirect how it is exercised. Because the credentials remain valid, those actions still pass session-level checks.

### The prompt injection multiplier

Prompt injection turns this design weakness into an exploitation path. Blast radius is determined by the authority the agent already holds. With broad session scope, a successful injection or hallucination can trigger high-impact actions across that full scope, at machine speed and without credential theft.

**Memory poisoning** extends the problem beyond a single interaction. Malicious content can persist in memory or retrieval context and influence unrelated future tasks. Session-level checks still pass because credentials remain valid. Without per-task, per-action authorization, there is no mechanism to contain this persistence to the task that introduced it.

### The delegation chain problem

The authorization gap exists even without adversarial inputs. Delegation complexity alone requires explicit containment ([Tomasev et al., 2025](https://arxiv.org/abs/2602.11865)). When Agent A delegates to Agent B:

1. What authority does B inherit?
2. Can B delegate further to Agent C?
3. Is there a cryptographic proof that C's authority descends from A's original grant?
4. Did permissions narrow at each hop, or could they have expanded?

OAuth tokens carry identity, not provenance. At hop one, you know *who* is acting. At hop two, you know who the delegate is, but not the constraints of delegation. By hop three, you may still have a valid token but no reliable chain showing how authority arrived there, whether it narrowed at each step, or whether the request is a legitimate continuation of the original task.

This is a primitive mismatch, not a policy tuning problem. Bearer tokens (OAuth, JWT, API keys) answer *who currently holds the token*; they do not prove *how authority was delegated* across hops or whether it narrowed along the way. Multi-hop agent systems require first-class provenance and enforceable attenuation at every delegation step.

In short, the gap has two defining properties: lack of containment at execution time and loss of provenance across delegation chains. The next section evaluates why common security controls, while useful, do not fully address those properties.

---

## Why Existing Controls Are Necessary but Insufficient

The issue is not that current controls are ineffective; it is that they solve adjacent problems. For multi-agent authorization, the unresolved requirements are deterministic execution-time containment and verifiable delegation provenance.

### Guardrails operate at the wrong layer

Most production agent stacks layer multiple controls:

- **Relevance classifiers** that flag off-topic queries
- **Safety classifiers** that detect jailbreaks
- **PII filters** that redact personal information
- **Tool risk ratings** that escalate high-risk actions to humans
- **Regex-based validation** that pattern-matches dangerous inputs

These controls are useful, but they are primarily perception-layer defenses. They infer intent from content and outputs and are inherently probabilistic. They reduce risk, but they do not provide deterministic, task-scoped authorization at execution time.

### Human escalation doesn't scale

Human approval for high-risk actions is a sensible control and widely recommended in enterprise guidance.

The limitation is temporal. In many agent workflows, actions complete faster than a reviewer can evaluate intermediate steps. Human oversight remains critical for policy definition, exception handling, and auditability, but it cannot be the primary containment boundary for machine-speed autonomy.

### Policy servers alone are insufficient

Central policy engines (OPA, Cedar-based services, custom PDPs) are effective for role- and attribute-based decisions and remain important infrastructure.

The gap appears in delegated multi-agent execution. A policy server can evaluate identity, roles, and request context, but it does not natively carry delegation provenance across hops. Policy evaluation remains necessary, but for multi-hop delegation it must be paired with a verifiable authorization artifact that encodes provenance and attenuation.

### Time-of-check to time-of-use (TOCTOU)

Even with correct policy logic, a gap can exist between decision and execution. In streaming or tool-planning architectures, systems often check authorization on an intended call and execute later. If parameters remain mutable in between, the executed call can diverge from what was approved (for example, `transfer(amount=50)` becoming `transfer(amount=5000)`).

This is TOCTOU in agent workflows: authorization must bind to the actual call boundary, not just planning, and verify concrete parameters at execution.

### String validation is not semantic validation

We've documented this extensively in our analysis of [CVE-2025-66032](https://niyikiza.com/posts/cve-2025-66032/) (Claude Code command injection) and the [agent-tool trust boundary](https://niyikiza.com/posts/map-territory/). The core insight: validators and executors interpret the same bytes differently.

A regex-based path validator sees `../etc/passwd` and blocks it. It does not see `..%2Fetc%2Fpasswd` or `..%252Fetc%252Fpasswd` or symlinks that resolve outside the intended directory. The filesystem interprets all of these as the same path. The validator checks the map. The system executes in the territory.

This is why Tenuo's constraint system parses inputs semantically, the way the target system will interpret them, rather than relying on string patterns alone. The broader architectural point is that authorization must be evaluated independently of model behavior and enforced at execution time.

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
| **Receipt-producing** | Integrated enforcement points can emit signed receipts linking authorization to execution |

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

At each hop, capabilities can be removed but not added. Constraints can be tightened but not loosened. TTL can be shortened but not extended. **The Rust core enforces this as a cryptographic invariant: it will not sign a warrant that expands authority relative to its parent.**

This is the same principle behind [Google's Macaroons](https://research.google/pubs/pub41892/) (2014), [Biscuit tokens](https://www.biscuitsec.org/) (Clever Cloud), and [UCAN](https://ucan.xyz/) (Fission). What Tenuo adds is the application of this primitive to the specific problem space of AI agent workflows: delegation at machine speed rather than human speed, constraints that encode business logic (not just resource paths), semantic parsing that matches target system interpretation, and audit trails that satisfy emerging Know Your Agent (KYA) requirements. The capability model is well-established. The agent-specific enforcement layer is what has been missing.

### Holder binding and Proof of Possession

Bearer tokens grant authority through possession. Whoever holds the token is authorized. This means interception equals compromise.

Warrants implement **Proof of Possession (PoP)**. Each warrant designates a specific agent public key as the authorized holder. When the agent presents a warrant, the verifier demands cryptographic proof: sign this challenge with the private key corresponding to the holder field. This is the same principle behind DPoP (RFC 9449) and mTLS-bound tokens, applied to agent authorization. The difference: DPoP binds tokens to an HTTP client via a per-request JWT proof; Tenuo's PoP binds warrants to an agent identity key and covers non-HTTP contexts (message queues, workflow headers, inter-agent delegation) where DPoP has no mechanism.

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
    enforcement_signature: Ed25519 signature by the enforcement point
}
```

The enforcement point (the `@guard` decorator, FastAPI middleware, or Temporal interceptor) holds its own Ed25519 key pair, configured at deployment. Its signature attests that the warrant was verified and constraints were satisfied at execution time. The enforcement key is distributed as part of the deployment configuration, alongside the issuer's trusted root.

A receipt is a cryptographic artifact, distinct from a log entry. A log entry is an assertion by your system that something happened. A receipt proves:

- **Who authorized**: the issuer signature chain traces back to a human approval
- **What was authorized**: the capability and constraint set in the warrant
- **What was executed**: the specific action and parameters
- **When**: timestamp bound to the warrant's validity window
- **By whom**: holder binding ties execution to a specific agent identity

This is the difference between [explaining your logging infrastructure during an investigation and handing over a signed chain of evidence](https://niyikiza.com/posts/hallucination-defense/). Logs describe. Receipts prove.


The enforcement layer produces signed receipts. These records can be retained and indexed by whichever operational stack an organization uses for governance and compliance.

### Constraint enforcement at execution time

Warrants carry typed constraints evaluated against concrete action parameters at verification time. This is the containment boundary.
The constraint types below are illustrative, not exhaustive.

| Constraint | Purpose | Example risk addressed |
|---|---|---|
| `Exact` / `OneOf` | Fixed values and allowlists | Unauthorized symbols, recipients, operations |
| `Range` | Numeric bounds | Amount inflation and threshold abuse |
| `Subpath` | Canonicalized path boundaries | Traversal and symlink escape |
| `UrlSafe` | Parsed URL semantics | SSRF and private network targeting |
| `Shlex` | Shell tokenization semantics | Command injection and operator chaining |

The design principle is semantic enforcement, not string matching: inputs are interpreted the way the target system executes them, then checked against warrant constraints.

---

## Architecture

Tenuo is designed as a thin authorization layer that sits between identity/orchestration systems and execution boundaries.

At a conceptual level, it has three parts:

1. **Authorization core**: mints and verifies warrants, enforces attenuation invariants, and validates constraints at execution time.
2. **Application integration layer**: plugs into agent frameworks and service boundaries so checks happen where tool calls actually execute.
3. **Evidence and operations layer**: produces signed receipts and supports operational governance workflows required in production environments.

The key architectural principle is separation of concerns: identity proves who an actor is, orchestration decides what to attempt, and authorization verifies what is actually allowed at the execution boundary.

### Integration surface (public)

The integration layer is designed to fit existing agent and service stacks, including OpenAI Agents SDK, Google ADK, LangChain/LangGraph, CrewAI, AutoGen, Temporal, MCP, and A2A patterns. Deployment in Kubernetes follows sidecar or gateway enforcement patterns so authorization remains close to execution boundaries.

### Cloud and deployment model (high-level)

Tenuo Cloud provides managed operational capabilities around the core authorization model, including receipt storage and indexing, key and warrant lifecycle operations, policy-to-template mapping, and audit/compliance workflows. Teams with stricter requirements can deploy in self-managed or on-prem environments.

---

## Offline Verification vs. Centralized Enforcement

Two models exist for enforcing authorization in agentic systems:

### Centralized model (gateway/proxy)

A central enforcement point (a gateway or authorization proxy) sits between agents and external systems. Agents present authorization artifacts to the gateway. The gateway holds real credentials, verifies authorization, and executes actions on behalf of agents.

**Advantages**: Agents never touch raw API keys. Centralized audit. Single enforcement point.

**Disadvantages**: Every agent action requires a gateway round-trip, creating a bottleneck and single point of failure. It handles async and cross-organizational workflows less naturally, and latency scales with gateway load.

### Decentralized model (offline verification)

Authorization artifacts are self-contained and cryptographically verifiable. The tool or service that receives a warrant can verify it locally with only the issuer's public key. No callback. No central server in the critical path.

**Advantages**: Verification is local (microsecond range on typical hardware) without central authorization round-trips. There is no central enforcement SPOF. It survives async boundaries and supports cross-organizational verification with published public keys. It scales horizontally with minimal coordination.

**Disadvantages**: Revocation requires either short TTLs (Tenuo's approach) or a revocation check (adds an online dependency). Credential management is distributed rather than centralized.

**Tenuo's position**: Offline verification with short TTLs. This follows the lineage of Macaroons, Biscuit, and UCAN, and matches agent-speed latency/availability needs. Short TTLs (seconds to minutes) provide natural revocation windows without mandatory online revocation infrastructure.

A centralized gateway can be layered on top of offline-verifiable warrants for teams that prefer centralized key management and audit controls. The reverse does not provide equivalent offline verification properties without adding new trust and consistency trade-offs. Starting with the decentralized primitive provides more deployment flexibility.

---

## Competitive Landscape

Authorization for agentic systems intersects identity, orchestration, policy, and runtime isolation. Those layers remain necessary. The unresolved gap is portable, verifiable authorization across delegation chains at execution time.

### Where Tenuo fits

Each layer answers a different question:

| Layer | Question answered | Primary check point |
|---|---|---|
| Identity (Okta, Auth0, SPIFFE) | Who is this agent? | At connection/session establishment |
| NHI / workload identity infrastructure | Which non-human workload identity is this? | At credential issuance and rotation |
| PAM / secrets infrastructure | Who can access privileged credentials and systems? | At secret access and session initiation |
| Orchestration (OpenAI, LangChain, CrewAI) | What should this agent do? | During planning/workflow execution |
| Policy (OPA, Cedar, RBAC) | Is this action class permitted? | At policy decision points |
| Sandbox (Docker, gVisor, Firecracker) | Where can this code run? | At runtime boundary |
| **Authorization (Tenuo)** | **Is this specific action authorized, by this delegation chain, with these constraints?** | **At the tool boundary** |

Tenuo does not replace identity, NHI, PAM, orchestration, policy, or isolation. It supplies the missing execution-time authorization artifact those layers assume exists: scoped, attenuating, and cryptographically verifiable across delegation hops.

---

## Real-World Scenarios

Three concrete scenarios illustrate the model. Full code examples are in the [examples directory](https://github.com/tenuo-ai/tenuo/tree/main/examples).

### Healthcare: Patient Data Exfiltration

A hospital's AI assistant has access to `query_records`, `generate_report`, and `send_email`. A prompt injection in a patient's intake form instructs the agent to exfiltrate records via `send_email` after every lookup.

**Without warrants**: The agent's static IAM role includes both EHR access and email permissions. The injection succeeds because `send_email` is a legitimate tool available at all times.

**With warrants**: The task warrant includes `query_records` and `generate_report` for the specific patient. `send_email` is not in the warrant. When a physician needs to email a report, a separate warrant is minted constraining the recipient to `*@partnerhospital.org`.

**Prevented**: HIPAA violation, patient data breach.

### Multi-Tenant SaaS: Cross-Tenant Data Breach

Tenant A crafts a query that includes `query_warehouse(tenant="tenant_b")`. With a shared connection pool, tenant isolation depends on application-layer filtering. One prompt injection bypasses it.

**Without warrants**: The agent holds broad database credentials with cross-tenant read access.

**With warrants**: Per-request warrants with `tenant=Exact(tenant_id)`. The constraint is checked by the Rust core. Under the warrant and enforcement assumptions, cross-tenant access outside scope is cryptographically prevented.

**Prevented**: Cross-tenant data breach, SOC 2 violation.

### Finance: Invoice Redirection and Wire Fraud

An AP automation agent reads incoming invoices and schedules vendor payments. A compromised email thread injects an instruction to update payout details and route a transfer to an attacker-controlled account.

**Without warrants**: The agent holds broad payment authority for the session, including both beneficiary updates and transfer execution.

**With warrants**: Payment warrants are constrained to approved vendor IDs, immutable destination accounts, bounded currency/amount ranges, and short TTLs. Any mid-task beneficiary change requires a separate re-issuance or explicit approval warrant.

**Prevented**: Business email compromise-style payout diversion, unauthorized wire transfer, and downstream financial loss.

---

## Why Now

### Adoption is accelerating into multi-agent production

Agent deployments are moving from experimentation to production faster than authorization infrastructure is maturing. McKinsey reports 62% of organizations experimenting with agents and 23% already scaling them in production ([McKinsey](https://www.mckinsey.com/capabilities/quantumblack/our-insights/the-state-of-ai)).

### Risk controls are lagging deployment velocity

Deloitte reports only 21% of organizations have mature governance for autonomous agents ([Deloitte](https://www2.deloitte.com/us/en/about/press-room/state-of-ai-report-2026.html)). Gartner predicts over 40% of agentic AI projects will be canceled by the end of 2027 due to escalating costs, unclear value, or inadequate risk controls ([Gartner](https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-predicts-over-40-percent-of-agentic-ai-projects-will-be-canceled-by-end-of-2027)). OWASP's [Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) identifies risk classes consistent with this delegation and authorization gap framing.

### Protocol and infrastructure trends increase the need for portable authorization

MCP and A2A improve interoperability and orchestration, but they do not define delegation-safe authorization provenance across hops. At the same time, execution infrastructure is converging on per-action isolation (sandboxes, microVMs, ephemeral runtimes). This makes the missing layer explicit: isolation decides where code can run; authorization must decide whether an action is allowed.

### Compliance pressure is converging on provenance

Regulatory and industry guidance increasingly requires auditable, attributable autonomous actions. Warrant chains and signed receipts make this queryable by construction: who authorized what, under which constraints, through which delegation path, and when.

---

## Standards and Interoperability Path

Tenuo is designed as a standards-aligned extension to existing OAuth ecosystems, not a replacement for identity infrastructure. Authentication and session establishment remain with IdPs, OAuth servers, and workload identity systems. The missing layer is delegation-safe, execution-time authorization across multi-agent chains.

That direction is informed by the IETF Internet-Draft **Attenuating Authorization Tokens for Agentic Delegation Chains** ([draft-niyikiza-oauth-attenuating-agent-tokens-00](https://www.ietf.org/archive/id/draft-niyikiza-oauth-attenuating-agent-tokens-00.txt)). The draft defines OAuth-compatible attenuation semantics for multi-hop delegation. Tenuo's implementation aligns with these principles, but it is not presented as full conformance to the draft while the specification is still evolving.

The draft is accompanied by formal verification and implementation test work focused on attenuation monotonicity and chain-validation correctness, which helps make the security claims auditable rather than purely conceptual.

The core protocol invariants are:

- **Delegation authority linkage**: each derived token issuer is cryptographically tied to its parent holder.
- **Depth monotonicity**: delegation depth can only advance within configured bounds.
- **TTL monotonicity**: derived tokens cannot outlive their parent.
- **Capability monotonicity**: delegated authority can only narrow, never expand.
- **Cryptographic chain linkage**: each hop is bound to the previous token.
- **Proof of possession**: token presentation requires holder-key proof, not bearer possession alone.

This gives enterprises a pragmatic adoption path: deploy with today's OAuth and orchestration stack, while moving toward a verifiable authorization model that is interoperable, auditable, and suitable for standardization.

---

## Risks and Limitations

### What warrants do not solve

| Limitation | Why it exists | Mitigation |
|---|---|---|
| **Agent-level compromise** | A compromised agent acting within its authorized scope passes warrant checks. | Tight constraints bound the blast radius. Warrants limit damage even when the agent is compromised. |
| **Identity and authentication** | Warrants assume agent identity is already established. Tenuo is not a replacement for Okta, Auth0, or SPIFFE. | Tenuo operates as the layer between identity and execution. Integrates with existing identity infrastructure. |
| **Execution isolation** | Warrants authorize actions, not execution environments. A container escape bypasses the authorization boundary. | Sandboxing and authorization are complementary controls. Warrants constrain what actions are authorized; sandboxes constrain where code runs. |

---

## The Tenuo Thesis

**1. Authority must follow the task, not the session.**

Agents decompose tasks. IAM consolidates authority. The friction is structural. Warrants make authority task-scoped: broad at the source, narrower at each delegation, gone when the task ends.

**2. Deterministic enforcement is the foundation.**

At agent velocity, policy round-trips can become bottlenecks and probabilistic filters can be bypassed. Guardrails remain useful as risk-reduction layers, but they are not sufficient as the primary authorization boundary. Constraints verified by signatures and semantic parsing provide deterministic execution-time enforcement independent of model behavior. Warrants make RBAC/ABAC delegation-safe by turning policy into cryptographically verifiable proof.

**3. Offline verification is architecturally superior for agent-speed systems.**

Centralized gateways add latency, create single points of failure, and don't survive async boundaries. Self-contained, cryptographically verifiable warrants verify at microsecond scale, across organizational boundaries, through message queues, and without coordination.

**4. Receipts close the accountability gap.**

Logs describe. Receipts prove. When the regulator asks "prove this was authorized," signed warrant chains answer the question directly. Compliance becomes a byproduct of the authorization architecture, not a separate reporting effort.

**5. Authorization infrastructure is a prerequisite, not a roadmap item.**

Gartner predicts over 40% of agentic AI projects will be canceled by 2027 due to escalating costs, unclear value, or inadequate risk controls. Teams that treat authorization as foundational infrastructure, not a late add-on, are better positioned to scale safely. This is not only about compliance pressure; bounded authority is a core operational requirement for production agents. The teams building that infrastructure now will define the patterns the industry adopts.

---

*Tenuo builds on decades of capability-based security research: [Macaroons](https://research.google/pubs/pub41892/) (Google, 2014), [Biscuit](https://www.biscuitsec.org/) (Clever Cloud), [UCAN](https://ucan.xyz/) (Fission), and recent work on agent security including [CaMeL](https://arxiv.org/abs/2503.18813) (Debenedetti et al., 2025) and [Intelligent AI Delegation](https://arxiv.org/abs/2602.11865) (Tomasev et al., 2025). The ideas in this document evolved through the [Agentic Security series](https://niyikiza.com/categories/agentic-security/) on Vectors, starting in December 2025.*
