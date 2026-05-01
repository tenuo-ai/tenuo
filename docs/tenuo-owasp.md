# Tenuo against the OWASP Top 10 for Agentic Applications

The [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) defines the most critical risks facing autonomous AI systems. This page maps Tenuo's coverage against each item, with a comparison to what the agent-security category actually ships today.

## Tenuo in 30 seconds

Tenuo is a deterministic authorization layer for AI agents. Before any tool call executes, the agent presents a cryptographically signed warrant: a task-scoped capability token specifying which tools, with which arguments, for how long. The warrant either authorizes the action or rejects it locally, in tens of microseconds, with a signed receipt. Verification is offline.

If your threat model includes prompt injection, agent compromise, or any failure mode that produces damage through unauthorized tool calls, Tenuo bounds the damage at the action boundary, regardless of upstream cause.

## How to read this document

- **Doing a security review or vendor evaluation:** start with [Coverage at a glance](#coverage-at-a-glance) and [Where Tenuo fits in an agent security stack](#where-tenuo-fits-in-an-agent-security-stack).
- **Building an RFP requirement matrix:** jump to the per-risk sections (each has *How Tenuo helps*, *Comparison*, and *What Tenuo does not do*).
- **Threat-modeling your agent deployment:** start with [Why one layer covers many risks](#why-one-layer-covers-many-risks), then [Tenuo's own assumptions](#tenuos-own-assumptions) before per-risk sections.

## Contents

- [Tenuo's own assumptions](#tenuos-own-assumptions)
- [ASI01 Agent Goal Hijack](#asi01-agent-goal-hijack)
- [ASI02 Tool Misuse & Exploitation](#asi02-tool-misuse--exploitation)
- [ASI03 Identity & Privilege Abuse](#asi03-identity--privilege-abuse)
- [ASI04 Agentic Supply Chain Vulnerabilities](#asi04-agentic-supply-chain-vulnerabilities)
- [ASI05 Unexpected Code Execution (RCE)](#asi05-unexpected-code-execution-rce)
- [ASI06 Memory & Context Poisoning](#asi06-memory--context-poisoning)
- [ASI07 Insecure Inter-Agent Communication](#asi07-insecure-inter-agent-communication)
- [ASI08 Cascading Failures](#asi08-cascading-failures)
- [ASI09 Human-Agent Trust Exploitation](#asi09-human-agent-trust-exploitation)
- [ASI10 Rogue Agents](#asi10-rogue-agents)
- [Where Tenuo fits in an agent security stack](#where-tenuo-fits-in-an-agent-security-stack)

## Why one layer covers many risks

Every failure mode in the OWASP list produces damage through agent actions. Tenuo constrains agent actions regardless of *why* they were attempted. An agent that has been hijacked, poisoned, supply-chain-compromised, or has gone rogue is bounded by the same mechanism, because the mechanism operates on what the agent does rather than on its inferred state.

That property is what makes Tenuo relevant across the list. The sections below focus on the part of the mechanism that matters most for each risk: a constraint type, a delegation property, or the receipt artifact that gives investigators evidence after the fact.

## Audit as part of enforcement

Every authorization decision is a cryptographically signed receipt: every allow, every deny, every human approval. The audit trail comes from enforcement itself rather than a separate logging system, which keeps it complete and tamper-evident. Each section below highlights the forensic angle that matters for that risk; the underlying mechanism is the same.

---

## Coverage at a glance

We use three labels in this document. Each is defended by the corresponding section.

- **Prevented:** Tenuo's mechanism rules out the failure mode within its scope.
- **Contained:** The failure can occur upstream of Tenuo, for example in the model, in memory, or in a compromised dependency, but Tenuo bounds the resulting damage.
- **Partial:** Some attack vectors are covered; others belong in a complementary layer.

| Risk | Name | Tenuo coverage | Mechanism |
|------|------|----------------|-----------|
| ASI01 | Agent Goal Hijack | **Contained** | Action-boundary warrant check |
| ASI02 | Tool Misuse & Exploitation | **Prevented** (argument-level), **Contained** (logic-level) | Argument constraints |
| ASI03 | Identity & Privilege Abuse | **Prevented** | Holder binding + monotonic attenuation |
| ASI04 | Agentic Supply Chain Vulnerabilities | **Contained** | Action-boundary warrant check |
| ASI05 | Unexpected Code Execution (RCE) | **Partial** | Execution-tool authorization + argument constraints; no sandboxing |
| ASI06 | Memory & Context Poisoning | **Contained** | Action-boundary warrant check |
| ASI07 | Insecure Inter-Agent Communication | **Prevented** | Cryptographic chain verification |
| ASI08 | Cascading Failures | **Prevented** | Monotonic attenuation across hops |
| ASI09 | Human-Agent Trust Exploitation | **Contained** | Cryptographic approval artifacts |
| ASI10 | Rogue Agents | **Contained** | Action-boundary warrant check |

The pattern is consistent: Tenuo prevents failures tied to authority and delegation, contains failures that originate upstream of authorization, and is partial where execution isolation belongs in a sandbox.

---

## Tenuo's own assumptions

The sections below describe what Tenuo prevents or contains. Security reviewers also need to know what Tenuo itself assumes, requires, and what fails if those assumptions break.

**Trust anchors.** Verification depends on the configured trust anchors: the public keys of authorized warrant issuers (your control plane, Tenuo Cloud, or both). If an issuer's signing key is compromised, all warrants signed by it are forgeable until the trust anchor is rotated. Trust anchor rotation is supported and audit-logged; key custody for issuers is the most important operational responsibility.

**Holder key custody.** Holders' private keys must be stored securely. A compromised holder key allows an attacker to sign valid Proof-of-Possession signatures for any warrant the holder legitimately holds, until those warrants expire. Tenuo recommends standard secret-management practices (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, KMS-backed signing) and supports rotation through warrant TTL. Short TTLs bound the impact of an undetected key compromise.

**Integration discipline.** Tenuo enforces at the integration boundary you wire it into. If a tool dispatch happens outside a Tenuo-aware path (raw API call, untracked subprocess, custom client without the wrapper), the warrant is not checked on that path. Tenuo's guarantee is uniform when every tool dispatch flows through a supported integration: OpenAI (`GuardBuilder`), Anthropic, LangChain / LangGraph, CrewAI, MCP (`SecureMCPClient` / `SecureMCPServer`), Temporal (`TenuoTemporalPlugin`), A2A, FastAPI dependency. New integrations should preserve the same enforcement-at-dispatch property.

**Fail-closed by default.** If verification cannot proceed (trust anchor unconfigured, signature malformed, warrant deserialization fails), Tenuo refuses to authorize. Misconfiguration produces denials, not silent bypass. The denial is logged with a structured reason so the misconfiguration is observable, not hidden.

**No central authority required at decision time.** Verification is offline against the configured trust anchors and the warrant's chain of signatures. A network partition between the agent and Tenuo Cloud (or your own issuance service) does not prevent verification of warrants already issued. Issuance, revocation list updates, and approval signing do require connectivity to the relevant control plane; verification does not.

**Revocation latency is bounded by your refresh cadence.** Tenuo supports revocation through Signed Revocation Lists (SRL). Verifiers fetch the SRL on a configurable cadence; until the next refresh, a revoked warrant remains technically valid. Short warrant TTLs are the primary defense against revocation latency; the SRL is a secondary mechanism for emergencies. Plan TTL and SRL cadence together.

**Cryptographic primitives.** Tenuo uses Ed25519 for signing and SHA-256 / BLAKE3 for argument digests. The cryptographic invariants and threat model are documented in [/security](/security).

If your environment requires additional guarantees (FIPS-validated cryptography, hardware-backed key custody, air-gapped issuance), those are deployment-time decisions and we work with customers on them directly. The open-source core supports the building blocks; the hardening profile depends on your environment.

---

## ASI01, Agent Goal Hijack

*Contained*

Attackers manipulate agent instructions, objectives, or decision pathways through prompt injection, deceptive tool outputs, malicious artifacts, forged agent-to-agent messages, or poisoned external data.

### How Tenuo helps

A successful prompt injection still has to produce a tool call. The damage from EchoLeak-style exfiltration, unauthorized financial transfers, and forged internal communications flows through tool calls the warrant either authorizes or rejects. The hijack may succeed at the model layer; the damage does not, provided the warrant is task-scoped. Containment does not depend on detecting the attack.

### Comparison

Prompt-injection detection (Lakera, Pillar Security, Prompt Security) addresses the manipulation itself, with detection rates that vary by attack type. Tenuo addresses the action that results. These are complementary: detection is probabilistic and depends on recognizing the attack; containment is deterministic and does not.

### What Tenuo does not do

Tenuo does not detect or block the injection. The model still processes the malicious input. Pair with a detection tool if your threat model requires both prevention and containment.

---

## ASI02, Tool Misuse & Exploitation

*Prevented at the argument level; contained at the logic level*

Agents misuse legitimate tools due to prompt manipulation, misalignment, or unsafe delegation. A valid tool, called with valid-looking arguments, used for something it was never intended to do.

### How Tenuo helps

Tenuo is most differentiated at the argument layer. RBAC and tool-list approaches authorize tool *names*, leaving argument misuse undefended. The tool is legitimate, the call is authorized at the name level, but the argument turns a benign read into data exfiltration or a benign write into infrastructure deletion. Tenuo enforces at the argument level, with eleven constraint types built around one principle: the constraint evaluator must parse arguments using the same semantics as the target system. Any gap between "constraint parser" and "target parser" is an attack surface.

Five of the eleven illustrate the principle:

- `Subpath(...)`: path containment with normalization for traversal and encoding edge cases.
- `UrlSafe(...)`: SSRF protection covering IPv6, link-local, and DNS rebinding.
- `Shlex(...)`: shell-aware argument parsing for command strings, with conservative rejection of shell metacharacter patterns.
- `Range(...)`: numeric bounds.
- `Pattern(...)`: glob matching with consistent escape rules.

```python
from tenuo.openai import GuardBuilder, Subpath, Range, UrlSafe

client = (GuardBuilder(openai.OpenAI())
    .allow("read_file", path=Subpath("/data/customers"))   # No traversal.
    .allow("fetch_url", url=UrlSafe())                     # No SSRF.
    .allow("transfer", amount=Range(max=1000))             # Value cap.
    .build())
```

### Why an `if` statement is not equivalent

```python
# Naive: looks fine, ships, gets bypassed.
def read_file(path: str) -> str:
    if not path.startswith("/data/customers"):
        raise PermissionError
    return open(path).read()

read_file("/data/customers/../../etc/passwd")
# Passes the prefix check. Reads /etc/passwd. The agent never had to
# break out of the call; the parser disagreement was the whole bypass.
```

```python
# Tenuo: the constraint applies containment-aware path checking.
.allow("read_file", path=Subpath("/data/customers"))
# Same call: denied with a signed receipt naming Subpath as the
# violated constraint. The agent cannot smuggle traversal past it.
```

The same shape applies to shell commands (`Shlex` applies shell-aware parsing and fails closed on shell metacharacter patterns), URLs (`UrlSafe` rejects `http://169.254.169.254` and its many encodings), and globs. Hand-rolled checks are one parser-disagreement away from being a bypass primitive. See [CVE-2025-66032](https://niyikiza.com/posts/cve-2025-66032/) for a published example: the tool's argument parser disagreed with the shell's, letting an injection slip past the constraint.

### Comparison

Most agent-security tools address tool misuse through prompt-injection detection, hoping to catch it at the input layer. Tenuo addresses it at the tool boundary, which catches misuse regardless of whether it came from injection, hallucination, or misaligned planning.

### What Tenuo does not do

Tenuo does not inspect the *semantics* of a call beyond the warrant constraints. If the warrant authorizes a valid but ultimately harmful action, Tenuo does not detect harm beyond the constraints. The right move is to narrow the warrant, not to ask Tenuo to second-guess it.

---

## ASI03, Identity & Privilege Abuse

*Prevented*

Attackers exploit inherited credentials, cached tokens, delegated permissions, or agent-to-agent trust boundaries. The agent holds more authority than it needs for the task, and an attacker steers it into exercising that excess authority.

### How Tenuo helps

ASI03 is the reason Tenuo exists. Conventional agents hold session-level credentials scoped to a user or service account, which means a single prompt can pivot the agent into exercising authority that was never relevant to the task. Tenuo replaces session authority with task-scoped warrants, with three properties that address this risk directly:

1. **Holder binding.** A warrant presented without the corresponding private key is rejected at signature verification. Stolen warrants are unusable; replay is bounded by TTL.
2. **Monotonic attenuation.** Authority narrows at every delegation hop. A compromised agent cannot expand its own scope or its children's; the broadening attempt fails at signing time, before the warrant exists. There is no runtime check to skip.
3. **Cryptographically chained delegation.** Every link is independently verifiable. An auditor can prove which agent authorized which other agent to do what, from the trust anchor down.

```python
from tenuo import mint_sync, Capability
from datetime import timedelta

# Orchestrator holds broad authority. When delegating, it derives a
# narrower warrant for the worker:
with mint_sync(
    Capability("lookup_customer", customer_id="CUST-4718"),
    ttl=timedelta(seconds=60),
):
    result = worker_agent.run("Fetch CUST-4718 and summarize")
# Worker cannot look up CUST-4719. Cannot extend TTL. Cannot escalate.
# Every decision produces a signed audit receipt.
```

### Comparison

Traditional IAM (Okta, Auth0, AWS IAM) handles workload identity but not task-level delegation or attenuation. Non-Human Identity vendors (Astrix, Entro, Clutch) track machine credentials but do not bound what the credential holder can do for a specific task. SPIFFE/SPIRE handles workload identity attestation but not capability attenuation. Tenuo is the delegation-and-attenuation layer that identity systems lack.

### Standards connection

The delegation and attenuation semantics are being standardized as [draft-niyikiza-oauth-attenuating-agent-tokens](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/) in the IETF OAuth Working Group.

---

## ASI04, Agentic Supply Chain Vulnerabilities

*Contained*

Compromised tools, descriptors, models, or agent personas influence execution. MCP tool poisoning, dynamic component discovery without provenance, and runtime composition of third-party agents.

### How Tenuo helps

Tenuo does not verify the integrity of components. It bounds what a compromised component can accomplish. The [GitHub MCP cross-repository data leakage](https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/) attack works precisely because the agent's GitHub token has authority over every accessible repository. A poisoned instruction can pivot the agent from reading a public issue to exfiltrating a private one. A warrant scoped to a single repo for a single task breaks the attack chain because the poisoned instruction produces a tool call the warrant did not authorize.

```python
from tenuo.openai import GuardBuilder, Pattern

# Worker is scoped to a single public repo for this task.
client = (GuardBuilder(openai.OpenAI())
    .allow("github_read",   repo=Pattern("acme/public-docs"))
    .allow("github_search", repo=Pattern("acme/public-docs"))
    .build())
# A poisoned MCP tool description that coerces the agent into
# `github_read(repo="acme/secrets")` produces a tool call denied at
# the enforcement point with a signed receipt of the attempt.
```

### Comparison

Supply-chain tools such as signed registries, descriptor verification, SBOM, Sigstore, in-toto, SLSA, and Anchore address provenance: knowing what component you are running. Tenuo addresses impact: bounding what any component can do once it is running. These are complementary in defense-in-depth.

### What Tenuo does not do

Tenuo does not verify the integrity of a tool's description, its implementation, or its runtime behavior. Pair with supply-chain integrity tools if your threat model requires provenance verification.

---

## ASI05, Unexpected Code Execution (RCE)

*Partial*

Agents generate or execute attacker-controlled code, often through natural-language instructions that unlock dangerous execution paths (AutoGPT-style RCE, MCP server command injection, coding-agent hooks).

Tenuo's coverage here is partial. ASI05 is largely about agent-invoked execution paths: agents generating, modifying, installing, or running code and commands because untrusted instructions, repository content, package metadata, or tool output steered them there. Tenuo can restrict whether the agent may invoke execution-capable tools at all, which commands or wrappers are in scope, and what argument, path, URL, and TTL constraints apply. It does not make authorized code execution safe once execution begins. Runtime isolation still belongs in a sandbox.

### What Tenuo does

Where an execution tool is exposed to an agent, Tenuo checks the authorization boundary around that tool: whether the agent may call `run_shell`, `npm_install`, `run_tests`, or `execute_code`; whether the command or wrapper is allowlisted; and whether arguments satisfy constraints such as `Shlex`, `Subpath`, `UrlSafe`, and `Range`. `Shlex` applies shell-aware parsing for command arguments and fails closed on shell metacharacter patterns that naive string matching often misses. This prevents a recurring class of agent RCE-via-argument attacks. Argument injection has been observed in multiple agent RCE disclosures in 2025 and 2026 (see [CVE-2025-66032](https://niyikiza.com/posts/cve-2025-66032/) for a published example).

```python
from tenuo.openai import GuardBuilder, Shlex, Subpath

client = (GuardBuilder(openai.OpenAI())
    .allow("run_shell", cmd=Shlex("pytest"), cwd=Subpath("/workspace/project-a"))
    .build())
# `pytest` is the only permitted command. Shell metacharacters in any
# argument are rejected. Execution outside /workspace/project-a is denied.
```

### What Tenuo does not do

Tenuo does not sandbox execution or prove that authorized code is safe. A warrant can allow `run_tests` only in `/workspace/project-a` with a bounded timeout, but a malicious `pytest` plugin, package postinstall script, Makefile, compiler plugin, or sandbox escape can still execute inside that authorized runtime. OS-level sandboxing, container isolation, and kernel-level syscall filtering (Anthropic's Sandbox Runtime Tool, gVisor, Firecracker, microVMs) are the appropriate layer for execution isolation.

### Comparison

Sandboxing addresses runtime isolation after execution begins. Tenuo addresses the authorization boundary before execution reaches the runtime: whether execution-capable tools may be invoked, under which command, path, URL, argument, and task constraints. They compose cleanly because they operate at different layers of the stack.

---

## ASI06, Memory & Context Poisoning

*Contained*

Persistent corruption of stored agent memory, retrievable context, or long-term reasoning state. Poisoned context influences future sessions and reasoning paths after the initial interaction.

### How Tenuo helps

Memory poisoning matters because it causes the agent to take actions it would not otherwise take. Those actions still face the warrant at the tool boundary. Containment is uniform across recent and historical poisoning, because enforcement is deterministic at the action boundary rather than behavioral at the model layer.

The forensic angle matters here especially. Memory poisoning is often discovered long after the event, and reconstruction depends on records. A pattern of denied attempts against a specific tool over time is often the first observable signal that memory has been compromised. That signal is visible directly in the receipt log without instrumenting the model.

### Comparison

Memory-validation and RAG-integrity tools (Pillar Security, Lakera, projects in the OWASP AI Exchange) address poisoning at the source. Detection in this category is an emerging vendor area where the threat models are still being refined. Tenuo addresses the impact directly, which complements detection wherever detection is partial or late.

### What Tenuo does not do

Tenuo does not detect poisoned memory, validate RAG content, or check context integrity. Pair with memory-validation tools if your threat model requires detection of the poisoning itself.

---

## ASI07, Insecure Inter-Agent Communication

*Prevented*

Spoofed or forged agent-to-agent messages misdirect clusters. A malicious or compromised agent impersonates a trusted counterpart to escalate, redirect, or exfiltrate.

### How Tenuo helps

Warrants are cryptographically signed capability tokens bound to a holder key. Inter-agent delegation requires the receiving agent to present a warrant derived from its sender's, signed by keys the receiver is configured to trust. Chain verification is offline and cryptographic, so:

- A spoofed agent cannot present a warrant it does not hold (signature check fails).
- A compromised agent cannot derive a warrant that exceeds what it received (monotonicity fails at signing time).
- Every hop is verifiable from the trust anchor's public key alone, with no live authority server in the request path.

Verification is local, in tens of microseconds in our benchmarks (a modern x86 core, default warrant size, single-capability check; methodology in [Performance Benchmarks](/api-reference#performance-benchmarks)), with no network call to a central authority at decision time. In multi-agent deployments where agents cross network, organizational, or trust boundaries, this matters because authority can flow across the boundary without the boundary needing to be live or reachable at each decision. See the [A2A integration docs](/integrations/a2a) for the full API.

### What Tenuo does not do

TLS secures the transport; Tenuo secures the authority presented over that transport. A misconfigured trust anchor (trusting the wrong issuer) or a compromised holder key breaks the guarantee. See [Tenuo's own assumptions](#tenuos-own-assumptions) for the full list.

### Comparison

Most inter-agent protocols rely on TLS for transport security and assume that agents are trustworthy at the application layer. Adjacent capability-token systems include Macaroons (Google, 2014), Biscuit (Cloudflare/Tarides), GNAP (IETF), RFC 9396 RAR (IETF, 2023), and SPIFFE/SPIRE for workload identity without attenuation. Tenuo's distinct position is cryptographically chained delegation with offline verification at the action boundary, argument-level constraints, and semantics designed for agent topologies. We are not aware of another system that combines all four properties at once.

---

## ASI08, Cascading Failures

*Prevented*

Failures in one agent propagate to others. A compromised or malfunctioning component induces dependent agents to produce bad outputs, repeat failures, or escalate in ways their designers did not anticipate.

### How Tenuo helps

> The cascade grows not because the failure spreads on its own, but because the authority that carries the failure was unbounded to begin with.

Cascades expand when each agent in the chain operates with authority broader than it needs. A bad input at the top triggers actions whose scope grows as the failure propagates, because each agent holds session-level authority that its children inherit.

Monotonic attenuation is the structural defense. A derived warrant cannot exceed its parent; every delegation step narrows authority; a failure introduced at any point cannot cause downstream agents to exercise authority the chain did not already permit. Cascades are bounded by the shape of the chain rather than by real-time intervention. Short TTLs prevent persistence past the warrant's expiry.

### Comparison

Anomaly detection and rate limiting at the observability layer (Datadog, Splunk, Honeycomb) detect cascades after they begin. They do not prevent expansion by themselves. Tenuo limits how far authority can spread, regardless of whether detection fires in time.

### What Tenuo does not do

Tenuo does not detect cascades in real time and does not circuit-break on anomaly signals. Pair with behavioral monitoring for early detection. Tenuo bounds the cascade; observability tells you it is happening.

---

## ASI09, Human-Agent Trust Exploitation

*Contained; approval forgery and repudiation prevented*

Attackers exploit the trust humans place in agent outputs. Deceptive summaries, plausible misstatements, social engineering through agent-mediated channels. Humans approve actions based on misleading presentation.

### How Tenuo helps

Tenuo supports cryptographic human approvals through its guards mechanism. When an action requires human authorization, the approval is not a log entry or an API call. It is a cryptographic artifact binding a specific tool call to a specific human's key, verifiable offline and recorded as a signed receipt. The artifact survives database tampering, log loss, and post-hoc dispute.

Three properties the deployed baseline lacks:

1. **Forensics by signature.** If a human approves something they shouldn't have, investigators do not reconstruct from logs. They verify the approval signature. The artifact names exactly which tool call was approved, by which key, at which timestamp.
2. **Per-human accountability.** Approvals are tied to specific keys rather than shared accounts. There is no ambiguity about which human authorized a specific action.
3. **Non-repudiation:** the cryptographic property that a signer cannot credibly deny having authorized an action. A human cannot disclaim an approval signed by their key.

### Comparison

The deployed baseline for ASI09 is presentation-layer controls: output grounding, source attribution, confidence indicators, and UI patterns that highlight high-risk actions, such as Anthropic's tool-use UX, OpenAI Operator, and vendor-built approval UIs. These help humans make better decisions but produce no cryptographic artifact when the human is deceived. Tenuo adds that artifact, which gives reviewers evidence of exactly what was approved even when the human judgment was manipulated.

### What Tenuo does not do

Tenuo does not prevent the deception itself. If an agent presents misleading information to a human, Tenuo does not detect the misleading framing. Output grounding and presentation-layer controls are the right complementary layer.

---

## ASI10, Rogue Agents

*Contained*

Agents diverge from intended behavior without active attacker control, through misalignment, emergent goal-seeking, or deliberate deception by the agent itself.

### How Tenuo helps

From Tenuo's perspective, containment does not require knowing *why* the agent diverged. The same scoped warrant limits a careless agent, a malicious agent, and a confused one. For rogue behavior, the useful signal is often in the receipt log: repeated denied attempts against capabilities outside the agent's task scope can surface earlier than behavioral monitoring.

### Comparison

The realistic baseline for ASI10 is behavioral monitoring, anomaly detection, drift metrics, and alignment research. Behavioral monitoring detects rogue patterns after the agent has already acted; alignment is a long-term prevention approach. Tenuo provides containment at the action boundary, bounding the action before damage rather than after detection.

### What Tenuo does not do

Tenuo does not detect rogue behavior and does not distinguish a rogue tool call from a legitimate one within warrant scope. Pair with behavioral monitoring to identify the divergence; Tenuo bounds what a rogue agent can do while detection works.

---

## Where Tenuo fits in an agent security stack

Serious deployments need prevention controls at each layer and a containment layer that applies across all of them.

| Failure origin | Per-layer prevention | What Tenuo adds |
|----------------|---------------------|-----------------|
| Prompt injection | Prompt-injection detection | **Contained:** bounds the resulting action |
| Tool misuse | (no comparable layer) | **Prevented** at argument level |
| Credential abuse | NHI management, IAM, SPIFFE | **Prevented:** attenuation, holder binding |
| Supply chain | Signed registries, SBOM | **Contained:** bounds the resulting action |
| Code execution | Sandboxing, containers | **Partial:** execution-tool authorization and argument constraints; no sandboxing |
| Memory poisoning | Context validation | **Contained:** bounds the resulting action |
| Inter-agent spoofing | (no comparable layer) | **Prevented:** cryptographic identity + chain |
| Cascading failures | Anomaly detection | **Prevented:** monotonic attenuation |
| Human trust exploitation | Output grounding, UI patterns | **Contained:** cryptographic approvals and non-repudiation |
| Rogue agents | Behavioral monitoring | **Contained:** bounds the resulting action |

Tenuo is the authorization layer that sits underneath everything else. Per-layer controls prevent specific failure modes; Tenuo bounds the damage when those controls miss. Agent failures become dangerous through actions; Tenuo constrains actions. Every decision produces a signed audit receipt, giving you forensic coverage across the framework.

Pair Tenuo with row-specific prevention controls.

---

## Try Tenuo against your OWASP posture

The open-source core is MIT-licensed and installs with `pip install tenuo`. The framework integrations (OpenAI, LangChain, LangGraph, CrewAI, Temporal, MCP, A2A, and more) use the same warrant semantics.

```bash
pip install tenuo
```

[GitHub](https://github.com/tenuo-ai/tenuo) | [Quickstart](/quickstart) | [Try it in Colab](https://colab.research.google.com/github/tenuo-ai/tenuo/blob/main/notebooks/tenuo_demo.ipynb)

Deploying agents in production? Tenuo Cloud adds managed warrant issuance, revocation workflows, multi-tenant isolation, and compliance-grade audit export. [Talk to us](https://tenuo.ai/early-access.html).

---

## References

- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), the authoritative framework this page maps against.
- [draft-niyikiza-oauth-attenuating-agent-tokens](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/), Tenuo's delegation and attenuation semantics, in the IETF OAuth Working Group.
- [Tenuo security model](/security), threat model, cryptographic guarantees, and invariants.
- [Constraint reference](/constraints), all eleven constraint types with semantics and examples.
- [Claude Code CVE-2025-66032: Why Allowlists Aren't Enough](https://niyikiza.com/posts/cve-2025-66032/), on parser differentials and why string validation cannot secure command execution.
