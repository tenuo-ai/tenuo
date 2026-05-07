# Tenuo and the OWASP Top 10 for Agentic Applications (2026)

This document maps **[OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)** (ASI01–ASI10) to what **Tenuo** provides at the **tool execution boundary**, and what remains **outside** that layer (model safety, memory/RAG, supply-chain vetting, etc.).

It is a technical mapping for architects and security reviewers, not a claim of product certification against OWASP.

**Attribution:** Risk IDs and titles follow the OWASP Gen AI Security Project publication (Version 2026, December 2025), licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/legalcode).

**Related:** [Tenuo and the EU AI Act](./eu-act.md) · [Thesis / framing](./thesis.md)

---

## How to read the coverage labels

| Label | Meaning |
| --- | --- |
| **Strong** | Tenuo’s defaults (warrants, constraints, PoP where enabled, audit hooks) directly address a major part of the risk at enforcement time. |
| **Partial** | Tenuo narrows blast radius or improves observability, but the risk still needs model-, UX-, or infrastructure-level controls. |
| **Limited** | Mostly organizational, lifecycle, or subsystem concerns; Tenuo is ancillary or not applicable. |

---

## Summary matrix

| ID | OWASP risk | Tenuo coverage | Notes |
| --- | --- | --- | --- |
| ASI01 | Agent Goal Hijack | Partial | Warrants bound **what tools may run with which arguments**; they do not fully align model “goals” with human intent. |
| ASI02 | Tool Misuse and Exploitation | Strong | Least-privilege **capabilities**, argument **constraints**, TTL, delegation monotonicity; enforcement regardless of how the model phrased the request. |
| ASI03 | Identity and Privilege Abuse | Strong | **Holder** binding, optional **PoP**, issuer chain and attenuation rules reduce ambient credentials and confused-deputy patterns at the tool boundary. |
| ASI04 | Agentic Supply Chain Vulnerabilities | Limited | SBOM, dependency pinning, plugin vetting are **deployment practices**; Tenuo can constrain what compromised components are allowed to **invoke**. |
| ASI05 | Unexpected Code Execution (RCE) | Partial | Tool allowlists and command/sandbox constraints reduce arbitrary execution paths; **does not** patch interpreters or kernel isolation by itself. |
| ASI06 | Memory & Context Poisoning | Limited | **Not** a memory/RAG integrity layer; poisoned context may still steer the model until execution is denied by lack of capability. |
| ASI07 | Insecure Inter-Agent Communication | Partial | **Warrant stacks**, consistent headers, and verification APIs help **authenticate** delegation between actors; transport security is still TLS/mTLS policy. |
| ASI08 | Cascading Failures | Partial | TTL, revocation, and explicit capability boundaries limit **how far** a bad step propagates; resilience patterns (circuit breakers, quotas) are separate. |
| ASI09 | Human-Agent Trust Exploitation | Limited | UX, approvals workflows, and disclosure are mostly **product/process**; Tenuo supports **approval gates** and evidence for oversight where integrated. |
| ASI10 | Rogue Agents | Partial | Short-lived warrants, revocation, and cryptographic verification limit persistence of compromised agents’ authority; **endpoint compromise** still requires IR and identity hygiene. |

---

## ASI01: Agent Goal Hijack

**Risk:** Adversarial or ambiguous instructions cause the agent to pursue unintended objectives while appearing compliant.

**Tenuo:** **Partial.** Execution warrants constrain **authorized effects** (tools and arguments). A hijacked planner may still waste cycles or leak data *within* an authorized envelope unless constraints are tight and monitoring catches abuse patterns.

**Also use:** Instruction hierarchy, output filtering, task decomposition with human checkpoints, monitoring for goal drift.

---

## ASI02: Tool Misuse and Exploitation

**Risk:** The agent invokes legitimate tools in harmful ways (path traversal, SSRF, shell injection, excessive API calls).

**Tenuo:** **Strong.** Constraints (`Subpath`, `UrlSafe`, `Shlex`, `Pattern`, `Range`, etc.) and strict validation modes bind arguments **before** side effects; violations produce denials and auditable signals.

**Also use:** Rate limits, egress controls, safe API design, least-privilege cloud IAM wrapped behind narrow tools.

---

## ASI03: Identity and Privilege Abuse

**Risk:** Stolen tokens, confused deputy, or excessive persistence let an agent act beyond the user’s or tenant’s intent.

**Tenuo:** **Strong.** Task-scoped warrants, explicit **holders**, optional **proof-of-possession**, and delegation rules reduce “one token does everything” deployments.

**Also use:** Hardware-backed keys for high-risk holders, rotation, separate issuer vs worker identities, zero-trust networking.

---

## ASI04: Agentic Supply Chain Vulnerabilities

**Risk:** Malicious or vulnerable plugins, prompts packages, models, or integrations undermine the whole agent.

**Tenuo:** **Limited.** Tenuo does not verify vendor SBOMs or model weights; it **limits what a compromised worker can call** if policies are tight.

**Also use:** Signed artifacts, dependency review, sandboxed installs, pin versions, monitor for shadow MCP servers.

---

## ASI05: Unexpected Code Execution (RCE)

**Risk:** Natural language or tool output triggers unintended code paths (e.g., shell meta-characters, unsafe eval).

**Tenuo:** **Partial.** Narrow tool surfaces and structured constraints shrink exploitable grammar; **full** mitigation needs secure runtimes (containers, WASM, no `eval`), patched libraries.

**Also use:** Separate “run untrusted code” tools with heavy sandboxing and no overlap with data-plane tools.

---

## ASI06: Memory & Context Poisoning

**Risk:** Long-term memory, RAG corpora, or cross-session context are poisoned to manipulate future actions.

**Tenuo:** **Limited.** Warrants do not authenticate retrieval sources or sanitize embeddings; they enforce **actions**.

**Also use:** Corpus integrity, retrieval provenance, freshness checks, isolation per tenant/session.

---

## ASI07: Insecure Inter-Agent Communication

**Risk:** Agents exchange insufficiently authenticated trust or capabilities (A2A, MCP, custom RPC).

**Tenuo:** **Partial.** Verifiable **warrant stacks** and consistent authorization headers improve **cryptographic traceability** of delegated authority between components.

**Also use:** mTLS, audience-bound tokens, message signing, schema validation for inter-agent protocols.

---

## ASI08: Cascading Failures

**Risk:** One bad step or misconfiguration causes multi-step workflows to fail open or amplify damage.

**Tenuo:** **Partial.** Automatic expiry and revocation **contain** how long bad authority lasts; explicit capability matrices reduce accidental “super-agent” configs.

**Also use:** Idempotency, retries with caps, blast-radius isolation per workflow, SLOs on authorization paths.

---

## ASI09: Human-Agent Trust Exploitation

**Risk:** Users over-trust agent outputs or approvals are rubber-stamped.

**Tenuo:** **Limited.** Technical enforcement complements but does not replace UX, training, and governance.

**Also use:** Risk-tiered approvals, dual control for irreversible tools, clear disclosure of warrant scope in operator UIs.

---

## ASI10: Rogue Agents

**Risk:** Compromised, impersonated, or malicious autonomous agents operate with stolen or excessive privileges.

**Tenuo:** **Partial.** Short TTLs, revocation, PoP, and audit receipts reduce **duration** and **repudiation** of abuse; compromised endpoints still need detection and containment.

**Also use:** Device posture, workload identity, EDR, segregated environments for agent runners.

---

## References

- OWASP Gen AI Security Project, [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Tenuo and the EU AI Act](./eu-act.md)
- [Related work](./related-work.md)
