# Tenuo against the OWASP Top 10 for Agentic Applications

**Reference framework:** [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (Version 2026, December 2025), OWASP Gen AI Security Project.

This page maps each listed risk to **Tenuo's mechanisms**, notes where complementary controls belong, and contrasts that with typical patterns in agent-security tooling.

---

## Scope and mechanism

Before a tool runs, Tenuo checks a cryptographically signed **warrant**: a task-scoped capability token that names allowed tools, **argument constraints**, and **TTL**. The authorization decision is **offline-verifiable** against configured trust anchors; typical verification is tens of microseconds per check. Each allow, deny, or human approval yields a **signed receipt**, so audit evidence is produced by enforcement rather than by a separate logging pipeline.

Most concrete harm from OWASP-style failures appears as **tool calls**. Tenuo constrains *what* executes, not *why* the model proposed it—so prompt injection, poisoned memory, supply-chain influence, and misaligned planning all encounter the same boundary. The sections below highlight which part of the mechanism matters most per risk (constraints, delegation chain, receipts).

For a spoken overview of this model, see [Unprompted 2025: cryptographic authorization for AI agents](https://www.youtube.com/watch?v=bw928cFShK4).

## How to read this document

- **Orientation:** [Coverage at a glance](#coverage-at-a-glance) and [Where Tenuo fits in an agent security stack](#where-tenuo-fits-in-an-agent-security-stack).
- **Per-risk detail:** ASI01–ASI10 use consistent headings (*How Tenuo helps*, *Comparison*, *Complementary controls* where relevant).
- **Boundary conditions:** [Tenuo's own assumptions](#tenuos-own-assumptions) lists trust anchors, holder custody, integration discipline, and cryptographic choices.

## Contents

- [Scope and mechanism](#scope-and-mechanism)
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

---

## Coverage at a glance

We use three labels in this document. Each is defined in the corresponding section.

- **Prevented:** Tenuo's mechanism rules out the failure mode within its scope.
- **Contained:** The failure can occur upstream of Tenuo (model, memory, compromised dependency), but Tenuo bounds the resulting damage at the tool boundary.
- **Partial:** Some attack vectors are covered; others belong in a complementary layer (notably sandboxing for ASI05).

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

**Prevented** applies to authority and delegation mechanics. 
**Contained** means upstream failure is still possible but unauthorized tools/arguments are blocked. **Partial** for ASI05 reflects that sandboxing and runtime isolation remain necessary.

---

## Tenuo's own assumptions

The sections below describe what Tenuo prevents or contains. These are the **boundary conditions**—what must hold for those guarantees to apply, and what breaks them if violated.

**Trust anchors.** Verification depends on the configured trust anchors: the public keys of authorized warrant issuers (your control plane, Tenuo Cloud, or both). If an issuer's signing key is compromised, all warrants signed by it are forgeable until the trust anchor is rotated. Trust anchor rotation is supported and audit-logged; key custody for issuers is the most important operational responsibility.

**Holder key custody.** Holders' private keys must be stored securely. A compromised holder key allows an attacker to sign valid Proof-of-Possession signatures for any warrant the holder legitimately holds, until those warrants expire. Tenuo recommends standard secret-management practices (enterprise vaults, cloud secret managers, KMS-backed signing) and supports rotation through warrant TTL. Short TTLs bound the impact of an undetected key compromise.

**Integration discipline.** Tenuo enforces at the integration boundary you wire it into. If a tool dispatch happens outside a Tenuo-aware path (raw API call, untracked subprocess, custom client without the wrapper), the warrant is not checked on that path. Tenuo's guarantee is uniform when every tool dispatch flows through a supported integration: OpenAI (`GuardBuilder`), LangChain / LangGraph, CrewAI, MCP (`SecureMCPClient` / `SecureMCPServer`), Temporal (`TenuoTemporalPlugin`), A2A, FastAPI dependency. New integrations should preserve the same enforcement-at-dispatch property.

**Fail-closed by default.** If verification cannot proceed (trust anchor unconfigured, signature malformed, warrant deserialization fails), Tenuo refuses to authorize. Misconfiguration produces denials, not silent bypass. The denial is logged with a structured reason so the misconfiguration is observable, not hidden.

**No central authority required at decision time.** Verification is offline against the configured trust anchors and the warrant's chain of signatures. A network partition between the agent and Tenuo Cloud (or your own issuance service) does not prevent verification of warrants already issued. Issuance, revocation list updates, and approval signing do require connectivity to the relevant control plane; verification does not.

**Revocation latency is bounded by your refresh cadence.** Tenuo supports revocation through Signed Revocation Lists (SRL). Verifiers fetch the SRL on a configurable cadence; until the next refresh, a revoked warrant remains technically valid. Short warrant TTLs are the primary defense against revocation latency; the SRL is a secondary mechanism for emergencies. Plan TTL and SRL cadence together.

**Cryptographic primitives.** Tenuo uses Ed25519 for signing and SHA-256 / BLAKE3 for argument digests. The cryptographic invariants and threat model are documented in [/security](https://tenuo.ai/security).

**Hardening profiles.** FIPS-validated cryptography, hardware-backed issuance, or air-gapped control planes layer on the open-source primitives documented in [/security](https://tenuo.ai/security)—they are deployment choices, not gaps in the core threat model.

---

## ASI01, Agent Goal Hijack

*Contained*

Attackers manipulate agent instructions, objectives, or decision pathways through prompt injection, deceptive tool outputs, malicious artifacts, forged agent-to-agent messages, or poisoned external data.

### How Tenuo helps

A successful prompt injection still has to produce a tool call. The damage from EchoLeak-style exfiltration, unauthorized financial transfers, and forged internal communications flows through tool calls the warrant either authorizes or rejects. The hijack may succeed at the model layer; the damage does not, provided the warrant is task-scoped. Containment does not depend on detecting the attack.

Every enforcement decision is recorded as a cryptographically signed receipt. If a hijack attempts an unauthorized action, the denial is logged with the attempted tool call, the holder identity, and a timestamp—giving incident responders a forensic record of what was tried and where it was blocked.

### Example

```python
from tenuo.openai import GuardBuilder, Pattern

client = (GuardBuilder(openai.OpenAI())
    .allow("send_email", to=Pattern("*@company.com"))
    .build())
# A hijacked call to attacker@evil.com is denied at the enforcement point.
# The denial is recorded as a signed receipt.
```

### Comparison

Commercial prompt-injection detection tools address the manipulation itself, with effectiveness that varies by attack type. Tenuo addresses the action that results. The two are complementary: detection is probabilistic and depends on recognizing the attack; containment at dispatch is deterministic and does not.

### Complementary controls

Model-layer detection can shrink how often injections fire; **dispatch containment is deterministic either way**. Add detection when your threat model wants both fewer attempts and bounded outcomes.

---

## ASI02, Tool Misuse & Exploitation

*Prevented at the argument level; contained at the logic level*

Agents misuse legitimate tools due to prompt manipulation, misalignment, or unsafe delegation. A valid tool, called with valid-looking arguments, used for something it was never intended to do.

### How Tenuo helps

Tenuo is most differentiated at the argument layer. RBAC and tool-list approaches authorize tool *names*, leaving argument misuse undefended. The tool is legitimate, the call is authorized at the name level, but the argument turns a benign read into data exfiltration or a benign write into infrastructure deletion. Tenuo enforces at the argument level, with a constraint library built around one principle: the constraint evaluator must parse arguments using the same semantics as the target system. Any gap between "constraint parser" and "target parser" is an attack surface.

Five examples illustrate the principle:

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

The same shape applies to shell commands (`Shlex`), URLs (`UrlSafe`), and globs. Hand-rolled checks are one parser-disagreement away from being a bypass primitive. See [CVE-2025-66032](https://niyikiza.com/posts/cve-2025-66032/) for a published example: the tool's argument parser disagreed with the shell's, letting an injection slip past the constraint.

### Comparison

Most agent-security tools address tool misuse through prompt-injection detection, hoping to catch it at the input layer. Tenuo addresses it at the tool boundary, which catches misuse regardless of whether it came from injection, hallucination, or misaligned planning.

### Complementary controls

**Semantic risk** inside warrant scope is a policy exercise: narrow capabilities, gate high-impact tools, and review workflows—Tenuo enforces the declaration precisely rather than inferring business intent from arguments.

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

Traditional enterprise IAM and cloud identity services handle workload identity but not task-level delegation or attenuation. Non-human identity (NHI) products typically track machine credentials but do not structurally bound what the credential holder may do for a specific task. SPIFFE/SPIRE handles workload identity attestation but not capability attenuation. Tenuo supplies the delegation-and-attenuation layer those stacks omit.

### Standards connection

The delegation and attenuation semantics are being standardized as [draft-niyikiza-oauth-attenuating-agent-tokens](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/) in the IETF OAuth Working Group.

### Complementary controls

**Holder lifecycle** (provisioning, rotation, vault storage) stays with your IdP and secret-management stack. TTL and custody practices bound the impact of a stolen holder key—see [Tenuo's own assumptions](#tenuos-own-assumptions).

---

## ASI04, Agentic Supply Chain Vulnerabilities

*Contained*

Compromised tools, descriptors, models, or agent personas influence execution. MCP tool poisoning, dynamic component discovery without provenance, and runtime composition of third-party agents.

### How Tenuo helps

Even when provenance is uncertain, **damage still flows through tool calls**—and warrants cap what those calls can do. The [GitHub MCP cross-repository data leakage](https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/) attack works because the agent's GitHub token spans every reachable repo; a poisoned instruction pivots from a public issue read to private-repo exfiltration. Scope the warrant to one repo for one task and the same poisoned instruction hits the enforcement wall instead.

Receipts matter for post-incident work: the audit trail shows which tool calls the compromised component produced and which were denied—in signed evidence rather than reconstructed logs.

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

Supply-chain tools such as signed registries, descriptor verification, SBOM, Sigstore, in-toto, SLSA, and container/image attestation products address provenance: knowing what component you are running. Tenuo addresses impact: bounding what any component can do once it is running. These are complementary in defense-in-depth.

### Complementary controls

**Provenance stacks**—signed descriptors, SBOM, Sigstore, image attestation—tell you *what* ran. Tenuo tells you what it was **allowed** to do. Combine them when you need both integrity proof and blast-radius caps.

---

## ASI05, Unexpected Code Execution (RCE)

*Partial*

Agents generate or execute attacker-controlled code, often through natural-language instructions that unlock dangerous execution paths (AutoGPT-style RCE, MCP server command injection, coding-agent hooks).

ASI05 spans **invocation policy** (whether and how execution-capable tools fire) and **runtime isolation** once code runs. Tenuo owns the first: agents steered by prompts, repos, packages, or tool output still meet warrants before `run_shell`, `npm_install`, `pytest`, or similar paths execute. Sandboxes, containers, and syscall filtering own safety **inside** an authorized execution.

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

### Complementary controls

**After the warrant allows execution**, runtime isolation carries safety against malicious plugins, install hooks, build steps, and escapes. Layer OS sandboxes, containers, syscall filters, or microVM runtimes beneath authorized calls—Tenuo already filtered *whether* and *how* those calls were admitted.

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

Memory-validation and RAG-integrity tooling (including community efforts such as the OWASP AI Exchange) address poisoning at the source; mature commercial coverage is still uneven. Tenuo addresses downstream impact at tool dispatch, which complements source-side detection when it is partial or late.

### Complementary controls

**Memory and RAG integrity tools** catch poisoning at the source when available. Tenuo caps **downstream actions** either way—poisoned context still has to pass the warrant to do harm.

---

## ASI07, Insecure Inter-Agent Communication

*Prevented*

Spoofed or forged agent-to-agent messages misdirect clusters. A malicious or compromised agent impersonates a trusted counterpart to escalate, redirect, or exfiltrate.

### How Tenuo helps

Warrants are cryptographically signed capability tokens bound to a holder key. Inter-agent delegation requires the receiving agent to present a warrant derived from its sender's, signed by keys the receiver is configured to trust. Chain verification is offline and cryptographic, so:

- A spoofed agent cannot present a warrant it does not hold (signature check fails).
- A compromised agent cannot derive a warrant that exceeds what it received (monotonicity fails at signing time).
- Every hop is verifiable from the trust anchor's public key alone, with no live authority server in the request path.

Verification is local, in tens of microseconds in our benchmarks (a modern x86 core, default warrant size, single-capability check; methodology in [Performance Benchmarks](https://tenuo.ai/api-reference#performance-benchmarks)), with no network call to a central authority at decision time. In multi-agent deployments where agents cross network, organizational, or trust boundaries, this matters because authority can flow across the boundary without the boundary needing to be live or reachable at each decision. See the [A2A integration docs](https://tenuo.ai/integrations/a2a) for the full API.

### Example

```python
from tenuo.a2a import A2AServerBuilder, A2AClient

server = (A2AServerBuilder()
    .name("Search Agent")
    .key(my_key)
    .trust(orchestrator_key)    # Only accepts warrants from this issuer.
    .build())

# Client requests a warrant, presents it, signs the task.
# Server verifies the chain offline and enforces constraints.
warrant = await client.request_warrant(
    signing_key=worker_key,
    capabilities={"search": {}}
)
result = await client.send_task(
    skill="search",
    warrant=warrant,
    signing_key=worker_key
)
```

### Complementary controls

**TLS** protects the channel; **warrants** authenticate the capability payload. Misconfigured trust anchors or compromised holder keys break the chain—see [Tenuo's own assumptions](#tenuos-own-assumptions).

### Comparison

Most inter-agent protocols rely on TLS for transport security and assume that agents are trustworthy at the application layer. Adjacent capability-token systems include Macaroons, Biscuit, GNAP, RFC 9396 RAR, and SPIFFE/SPIRE for workload identity without attenuation. Chained delegation with offline verification, argument-level constraints, and multi-agent semantics is **still rare as a single package** in production agent stacks—that gap is what Tenuo targets.

---

## ASI08, Cascading Failures

*Prevented*

Failures in one agent propagate to others. A compromised or malfunctioning component induces dependent agents to produce bad outputs, repeat failures, or escalate in ways their designers did not anticipate.

### How Tenuo helps

> The cascade grows not because the failure spreads on its own, but because the authority that carries the failure was unbounded to begin with.

Cascades expand when each agent in the chain operates with authority broader than it needs. A bad input at the top triggers actions whose scope grows as the failure propagates, because each agent holds session-level authority that its children inherit.

Monotonic attenuation is the structural defense. A derived warrant cannot exceed its parent; every delegation step narrows authority; a failure introduced at any point cannot cause downstream agents to exercise authority the chain did not already permit. Cascades are bounded by the shape of the chain rather than by real-time intervention. Short TTLs prevent persistence past the warrant's expiry.

### Comparison

Anomaly detection and rate limiting in observability stacks detect cascades after they begin. They do not prevent expansion by themselves. Tenuo limits how far authority can spread, regardless of whether detection fires in time.

### Complementary controls

**Observability** (rate limits, anomaly detection, circuit breakers) surfaces cascades in flight. **Monotonic attenuation** caps how far authority propagates regardless—detection and structural bounds compose cleanly.

---

## ASI09, Human-Agent Trust Exploitation

*Contained; approval forgery and repudiation prevented*

Attackers exploit the trust humans place in agent outputs. Deceptive summaries, plausible misstatements, social engineering through agent-mediated channels. Humans approve actions based on misleading presentation.

### How Tenuo helps

Tenuo supports cryptographic human approvals through its guards mechanism. When an action requires human authorization, the approval is not a log entry or an API call. It is a cryptographic artifact binding a specific tool call to a specific human's key, verifiable offline and recorded as a signed receipt. The artifact survives database tampering, log loss, and post-hoc dispute.

Three properties the deployed baseline lacks:

1. **Forensics by signature.** If a human approves something they shouldn't have, investigators do not reconstruct from logs. They verify the approval signature. The artifact names exactly which tool call was approved, by which key, at which timestamp.
2. **Per-human accountability.** Approvals are tied to specific keys rather than shared accounts. There is no ambiguity about which human authorized a specific action.
3. **Non-repudiation.** The cryptographic property that a signer cannot credibly deny having authorized an action. A human cannot disclaim an approval signed by their key.

### Comparison

The usual baseline for ASI09 is presentation-layer controls: output grounding, source attribution, confidence indicators, and UI patterns that highlight high-risk actions in hosted chat and agent products. Those patterns improve decisions but typically produce no cryptographic artifact when the human is deceived. Tenuo adds a verifiable approval binding where integrated, which gives reviewers evidence of exactly what was approved even when judgment was manipulated.

### Complementary controls

**Grounding, attribution, and UX patterns** steer humans before approval. Where integration exists, Tenuo adds **cryptographically bound approvals**—reviewers get tamper-evident proof of what they authorized even when framing was misleading.

---

## ASI10, Rogue Agents

*Contained*

Agents diverge from intended behavior without active attacker control, through misalignment, emergent goal-seeking, or deliberate deception by the agent itself.

### How Tenuo helps

From Tenuo's perspective, containment does not require knowing *why* the agent diverged. The same scoped warrant limits unintended, malicious, or confused behavior at the tool boundary. For rogue behavior, a useful signal is often in the receipt log: repeated denials for capabilities outside the task scope can appear before behavioral analytics flag drift.

### Comparison

The realistic baseline for ASI10 is behavioral monitoring, anomaly detection, drift metrics, and alignment research. Behavioral monitoring detects rogue patterns after the agent has already acted; alignment is a long-term prevention approach. Tenuo provides containment at the action boundary, bounding the action before damage rather than after detection.

### Complementary controls

**Behavioral monitoring and drift metrics** flag misalignment early. Within warrant scope, calls look the same to enforcement—by design—while **scoped capabilities** keep rogue agents from expanding blast radius during investigation.

---

## Where Tenuo fits in an agent security stack

Defense in depth typically stacks prevention controls per failure mode with enforcement at the tool boundary.

| Failure origin | Per-layer prevention | What Tenuo adds |
|----------------|---------------------|-----------------|
| Prompt injection | Prompt-injection detection | **Contained:** bounds the resulting action |
| Tool misuse | Sparse native argument enforcement | **Prevented** at argument level |
| Credential abuse | NHI management, IAM, SPIFFE | **Prevented:** attenuation, holder binding |
| Supply chain | Signed registries, SBOM | **Contained:** bounds the resulting action |
| Code execution | Sandboxing, containers | **Partial:** execution-tool authorization and argument constraints; no sandboxing |
| Memory poisoning | Context validation | **Contained:** bounds the resulting action |
| Inter-agent spoofing | TLS + implicit trust at app layer | **Prevented:** cryptographic identity + chain |
| Cascading failures | Anomaly detection | **Prevented:** monotonic attenuation |
| Human trust exploitation | Output grounding, UI patterns | **Contained:** cryptographic approvals and non-repudiation |
| Rogue agents | Behavioral monitoring | **Contained:** bounds the resulting action |

Per-layer controls target specific failure modes; authorization at tool dispatch bounds effects when those controls miss. Every decision in the table — allow, deny, or approval — also produces a signed receipt, so forensic coverage is a byproduct of enforcement rather than a separate concern.

---

## References

- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), the authoritative framework this page maps against.
- [Tenuo on GitHub](https://github.com/tenuo-ai/tenuo)
- [Quickstart](https://tenuo.ai/quickstart)
- [Demo notebook (Colab)](https://colab.research.google.com/github/tenuo-ai/tenuo/blob/main/notebooks/tenuo_demo.ipynb)
- [Unprompted 2025 talk on cryptographic authorization for AI agents](https://www.youtube.com/watch?v=bw928cFShK4)
- [draft-niyikiza-oauth-attenuating-agent-tokens](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/), delegation and attenuation semantics in the IETF OAuth Working Group.
- [Tenuo security model](https://tenuo.ai/security), threat model, cryptographic guarantees, and invariants.
- [Constraint reference](https://tenuo.ai/constraints), constraint types with semantics and examples.
- [Claude Code CVE-2025-66032: Why Allowlists Aren't Enough](https://niyikiza.com/posts/cve-2025-66032/), parser differentials and command execution.
- [Tenuo and the EU AI Act](./eu-act.md)
