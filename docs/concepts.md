---
title: Why Tenuo
description: Why AI agents need task-scoped authorization, how Tenuo warrants work, and what they do and do not protect.
---

# Give agents authority for the task, not the lifetime of the process.

<p class="lede">AI agents can authenticate correctly, stay inside IAM policy and still take an action that does not belong to the task in front of them. Tenuo adds that missing boundary.</p>

## The gap between access and intent

Existing controls answer important questions. Identity proves who is acting. IAM and RBAC set the maximum that principal may do. Guardrails shape model behavior. Gateways decide which tools are reachable.

None of those controls, by itself, says what this agent may do **for this task**.

Consider a remediation agent handling incident `INC-812`. Its service account may be allowed to write every incident. The task only needs to update the severity and assign an owner on one incident for the next fifteen minutes. Both statements can be true:

- The principal is permitted to make the call.
- The call does not belong to this task.

That gap is where an incorrect plan, prompt injection or an over-broad delegation becomes a production action.

## Why teams hold agents back

The practical response is rational: keep agents read-only, add a human before every consequential step, or do not ship the workflow at all. The underlying authority is often:

- **Broader than the task.** One customer record requires access to a table, or one deployment requires permission across a service.
- **Longer-lived than the task.** A credential used for a fifteen-minute job remains valid after the job ends.
- **Passed downstream whole.** When one agent delegates, the next agent inherits the same access even when it needs less.

Tenuo does not ask teams to replace those controls. It uses them as the ceiling and narrows authority to the work being performed.

## What a warrant changes

A warrant is a signed, task-scoped authorization object. It names the permitted tools and arguments, who may use it, how long it lasts and whether it may be delegated.

<div class="concept-warrant">
  <div class="reveal-warrant" role="img" aria-label="Task warrant for incident INC-812 remediation, held by the remediation agent, permitting severity updates and owner assignment for fifteen minutes.">
    <div class="hw-hd"><span>Task warrant</span><span class="hw-id">wrt_8f21c4e0</span></div>
    <dl class="hw-body">
      <dt>task</dt><dd>INC-812 remediation</dd>
      <dt>holder</dt><dd>svc-remediation-agent<br><span class="hw-dim">key 4f2a&hellip;9c1e</span></dd>
      <dt>may</dt><dd class="hw-allow">incident.update_severity<br>incident.assign_owner</dd>
      <dt>expires</dt><dd>in 14m 38s</dd>
      <dt>depth</dt><dd>0 <span class="hw-dim">&middot; max 2</span></dd>
    </dl>
    <div class="hw-ft"><span class="logo" style="--logo:url(/images/brand/mark.svg)" aria-hidden="true"></span>Ed25519 &middot; checked before every call</div>
  </div>
</div>

Five properties make the boundary useful in production:

1. **Task-bound:** only the actions, resources, limits and lifetime the task requires.
2. **Holder-bound:** bound to the intended agent's key, so copying the warrant is not enough to use it.
3. **Delegation-safe:** downstream authority can narrow, but it cannot widen.
4. **Independently verifiable:** checked where the action runs without trusting the agent that requested it.
5. **Auditable by default:** every authorization decision can produce a signed receipt.

The agent keeps its long-lived identity. Authority arrives with the task and expires with it.

## How each action is checked

1. A trusted issuer creates a warrant for the task.
2. The agent presents it when calling a tool.
3. Tenuo verifies the signature, expiration, holder proof, tool permission and argument constraints locally.
4. An allowed call reaches the tool. Anything outside the warrant is denied before execution.

Verification is local and stateless, so the Tenuo Cloud control plane is not in the path of an action. When work moves to another agent, delegation creates a narrower child warrant with a cryptographically verifiable lineage.

## How Tenuo fits with existing controls

Tenuo does not replace identity, IAM, policy engines or the credentials used to reach a target system. Those controls establish who is acting, the maximum authority available and how access is delivered. Tenuo narrows that authority to the task.

| Existing control | What it answers | How Tenuo works with it |
|---|---|---|
| Identity and authentication | Who is acting? | Binds task authority to its intended holder, so a copied warrant is not enough to use it. |
| IAM, RBAC and application authorization | What may this principal do at most? | Issues narrower, task-specific authority within that ceiling without changing the principal's permissions. |
| Policy engines | Under what conditions should authority be available? | Keeps policy as the ceiling and carries the task's authority to the enforcement point. |
| OAuth, JIT and short-lived credentials | How does this principal reach the target system? | Keeps that access path and adds task provenance, holder binding and narrowing delegation. |

For deployment boundaries and bypass resistance, see [Enforcement architecture](./enforcement).

## A real failure of task authority

In April 2026, a coding agent at PocketOS was working in staging when it found a token with blanket authority across its hosting provider's API. It chose volume deletion as a fix for a credential error. Nine seconds later, the production database and every backup were gone.

The agent was authenticated, and the token permitted the call. The missing boundary was the task: managing a staging credential did not require deleting a production volume.

[Read the incident, control by control &rarr;](/faq/pocketos-incident)

---

## Core invariants

Tenuo enforces these invariants:

1. **Mandatory proof of possession:** warrant use requires proof that the caller holds the corresponding private key.
2. **Task-scoped authority:** authority is carried by warrants, not inherited from process identity.
3. **Stateless verification:** checks run locally at authorization time.
4. **Monotonic attenuation:** child scope is a subset of parent scope.
5. **Self-contained tokens:** warrants carry the data needed for verification.
6. **Fail-closed constraints:** unknown constraint types are rejected; unknown arguments are rejected in constrained mode unless explicitly allowed.

## Threat Model

### What Tenuo Protects Against

- Prompt injection impact via least privilege
- Confused deputy behavior (tool misuse outside scope)
- Warrant theft without private key (PoP binding)
- Stale authority (TTL expiration)
- Privilege escalation in delegation chains
- Replay outside the PoP validity window

### What Tenuo Does Not Protect Against

These are threats that Tenuo's authorization layer alone does not cover. Each one has a deployment-level mitigation:

| Threat | In-Process | Sidecar/Gateway | Mitigation |
|--------|------------|-----------------|------------|
| Agent process compromise (RCE) | Not covered (attacker shares the trust boundary) | Covered (enforcement runs in a separate process; compromised agent cannot bypass it) | Deploy sidecar or gateway enforcement |
| Malicious tool implementation | Not covered at any layer (Tenuo verifies authorization, not tool correctness) | Same | Code review, sandboxing, tool isolation |
| Compromised root issuer | Not covered (a compromised issuer can mint arbitrary warrants) | Same | Secure the control plane; rotate keys; use short-lived root warrants |
| Traffic bypassing enforcement | Not covered if raw tool endpoints are exposed | Covered (network policy routes all traffic through the sidecar/gateway) | Network controls, service mesh, deny direct tool access |

The in-process model is sufficient for trusted single-process deployments. For stronger isolation, add a sidecar or gateway so that enforcement survives agent compromise. See [Enforcement Architecture](./enforcement) for deployment patterns.

---

## Key Concepts

### Warrants

A warrant is a self-contained capability token specifying tools, argument constraints, holder, expiration, and signatures.

```
WARRANT
  id: "wrt_abc123"          (display format; wire is UUID)
  tools: ["search", "read_file"]
  constraints:
    path: Pattern("/data/project-alpha/*")
    max_results: Range(min=1, max=100)
  ttl_seconds: 300
  holder: <public_key>
  signature: <issuer_signature>
```

### Proof-of-Possession (PoP)

Warrants are bound to keypairs. A stolen warrant token alone is insufficient; the caller must produce a valid PoP signature with the holder private key.

### Warrant Types

| Type | Can Execute? | Can Delegate? | Typical Use |
|------|--------------|---------------|-------------|
| Execution | Yes | Yes (if `depth < max_depth`) | Workers, execution nodes |
| Issuer | No | Yes (if `depth < max_depth`) | Planners, orchestrators, issuer services |

When `depth >= max_depth`, the warrant is terminal and cannot delegate further.

### Monotonic Attenuation

Delegation can only narrow:

| Dimension | Rule |
|-----------|------|
| Tools | Child tools must be a subset of parent tools |
| Constraints | Child constraints must be tighter or equivalent |
| TTL | Child cannot outlive parent |
| Depth | `max_depth` can only decrease |

### Stateless Verification

Authorization is performed where the action is requested. No central online decision service is required at request time.

### Zero-Touch Provisioning

Verifiers do not need per-worker onboarding. They trust one or more configured root issuer public keys and validate warrant chains from those roots.

- **Authorizer config**: needs trusted root issuer public key(s)
- **Worker identity**: carried in the warrant holder field
- **Trust flow**: root issuer trusts delegator, delegator trusts worker

This supports elastic worker scaling without provisioning each worker identity into the verifier.

---

## Deployment Models

Tenuo can enforce at multiple points, and every model verifies the same warrant semantics.

| Model | Where It Runs | Additional Coverage | Trust Boundary |
|-------|---------------|---------------------|----------------|
| In-Process | Inside agent runtime | Fastest integration, framework-native checks | Agent process |
| Sidecar | Separate container in same pod | Agent process compromise (RCE) | Pod network |
| Gateway | Ingress or service mesh (`ext_authz`) | Centralized multi-service policy | Gateway |
| MCP Proxy | Between agent and MCP server | Unauthorized MCP tool access | Proxy |
| A2A | Between agents | Bounded inter-agent delegation | Receiving agent |

Models compose for defense in depth. For deployment diagrams and operational guidance, see [Enforcement Architecture](./enforcement).

## Constraint Layer

Warrants constrain arguments, not only tool names:

```python
url = UrlSafe(allow_domains=["api.github.com"], deny_domains=["*.evil.com"])
path = Subpath("/data/reports")
cmd = Shlex(allow=["npm", "docker"])
model = OneOf(["gpt-4o", "gpt-4o-mini"])
max_tokens = Range(0, 1000)
```

Built-in constraints cover values, ranges, paths, URLs, shells, CIDRs, regex, and composable logic (`All`, `AnyOf`, `Not`). Delegation must tighten constraints, and unrecognized constraint types fail closed.

See [Constraints](./constraints) for the complete reference.

---

## How Tenuo compares

| | Tenuo | Token-Based IAM | LLM Guardrails |
|---|-------|-----------------|----------------|
| Granularity | Per-tool and per-argument | Per-identity | Per-prompt |
| Delegation | Monotonic, cryptographically chained | Static roles | Not applicable |
| Authorization latency | Local and stateless | Auth service dependency | LLM inference dependency |
| Tamper resistance | Signature + PoP | Bearer-token style risk | No cryptographic enforcement |
| Auditability | Cryptographic delegation lineage | Log-based | Limited |
| Runtime targets | Native and WASM | Usually server-only | Usually server-only |

Stateless verification improves horizontal scalability. Shared Rust core plus WASM support enables consistent behavior across server, edge, and browser-capable runtimes.

---

## Relationship to CaMeL

Tenuo implements the capability enforcement primitive described in [Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813) (CaMeL).

| CaMeL Concept | Tenuo Implementation |
|---------------|----------------------|
| Capability token | Warrant |
| Interpreter check | Authorizer |
| Planner-issued authority | Issuer or root warrant |
| Worker-held authority | Execution warrant |

CaMeL is the architecture; Tenuo is the authorization primitive.

See [Related Work](./related-work) for comparisons with FIDES, Biscuit, Macaroons, UCAN, and delegation-focused work.

## Relationship to IETF AATs

The [Attenuating Authorization Tokens](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/01/) Internet-Draft standardizes OAuth-oriented **task-scoped tokens**, **holder-driven attenuation**, and **offline chain verification** for agent delegation. The approach is conceptually aligned with warrants (tool constraints, monotonic narrowing, PoP at enforcement). For a readable walkthrough and mapping to agent-security gaps, see the [AAT draft summary](./aat-ietf-summary).

## Scope Boundaries

### Tenuo Owns

- Warrant format and verification
- Constraint evaluation
- Attenuation enforcement
- Delegation chain validation
- PoP verification

### Tenuo Does Not Own

- Task decomposition or orchestration strategy
- Data-flow/taint tracking
- Authentication and user identity systems
- Business logic inside tools
- Prompt attack detection models

---

## Summary

Tenuo binds authority to tasks, verifies warrants locally, requires proof-of-possession, and enforces monotonic attenuation across delegation chains. It limits the blast radius of prompt injection and confused deputy failures by making unauthorized tool actions cryptographically non-executable.

**Identity is long-lived; authority is short-lived and task-scoped.**

## Next Steps

- [Quick Start](/quickstart/): Installation, first warrant, choosing your integration
- [AI Agent Patterns](./ai-agents): P-LLM/Q-LLM, prompt injection containment
- [Enforcement Architecture](./enforcement): Deployment models and proxy configurations
- [Constraints](./constraints): Full constraint catalog, argument extraction, gateway config
- [Security](./security): Operational security, key management, best practices
- [API Reference](./api-reference): Python SDK, CLI, and performance benchmarks
- [Protocol Specification](./spec/protocol-spec-v1): Wire format and verification semantics
- [Related Work](./related-work): Research context and comparisons
- [AAT draft summary](./aat-ietf-summary): IETF attenuating OAuth tokens for agents (vs. warrants)
