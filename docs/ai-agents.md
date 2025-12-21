# AI Agent Security Patterns

This document describes how Tenuo's warrant system applies to AI agent security patterns, with particular focus on multi-agent architectures and prompt injection defense. We aim to be precise about what Tenuo provides and what additional measures are needed for comprehensive AI safety.

## Table of Contents

1. [Security Model Foundations](#security-model-foundations)
2. [The P-LLM / Q-LLM Pattern](#the-p-llm--q-llm-pattern)
3. [What Tenuo Provides](#what-tenuo-provides)
4. [What Tenuo Does Not Provide](#what-tenuo-does-not-provide)
5. [Defense Against Prompt Injection](#defense-against-prompt-injection)
6. [Multi-Agent Orchestration](#multi-agent-orchestration)
7. [Recommendations for Complete Security](#recommendations-for-complete-security)
8. [References](#references)

---

## Security Model Foundations

Tenuo implements a **capability-based security model** [1] for AI agent tool authorization. The key principles:

### Principle of Least Authority (POLA)

Every agent receives only the minimum capabilities needed for its specific task. This follows from Saltzer and Schroeder's principle of least privilege [2], extended to the capability model.

```python
# Instead of granting broad access:
# ❌ agent.grant_all_file_access()

# Grant specific, scoped capabilities:
# ✅ 
warrant = (parent.attenuate()
    .capability("read_file", {"path": Pattern("/data/reports/*.pdf")})
    .ttl(60)
    .holder(agent_kp.public_key)
    .delegate(orchestrator_kp))
```

### Capability Attenuation (Monotonicity)

Authority can only **decrease** through delegation, never increase. This is the monotonicity property [3]:

```
∀ child, parent: capabilities(child) ⊆ capabilities(parent)
```

This prevents privilege escalation attacks where a compromised agent attempts to expand its authority.

### Confused Deputy Prevention

Warrants solve the **confused deputy problem** [4] by binding authorization to cryptographic identity. A tool server verifies:

1. The warrant authorizes the requested operation
2. The caller possesses the private key matching the warrant's holder
3. The warrant chain is cryptographically valid

This prevents an attacker from using a legitimate agent as a "confused deputy" to perform unauthorized actions.

---

## The P-LLM / Q-LLM Pattern

The P-LLM (Planner) / Q-LLM (Query/Executor) pattern separates reasoning from execution [5]:

| Component | Role | Capabilities |
|-----------|------|--------------|
| **P-LLM** (Planner) | Reasons about tasks, creates execution plans | Cannot execute tools |
| **Q-LLM** (Executor) | Executes specific tool calls | Cannot autonomously decide what to do |

### Security Rationale

This separation provides **defense in depth**:

1. **If P-LLM is compromised** (e.g., via prompt injection): It can only issue warrants within its authority bounds. It cannot directly execute harmful actions.

2. **If Q-LLM is compromised**: It can only execute operations allowed by the warrants it receives. It cannot expand its own authority.

3. **Neither has full autonomy**: Successful attack requires compromising both components or the communication channel.

### Tenuo Implementation

```python
# P-LLM: Holds an issuer warrant (cannot execute)
issuer_warrant = Warrant.issue_issuer(
    issuable_tools=["search", "read_file"],
    trust_ceiling=TrustLevel.Internal,
    keypair=planner_kp,
    ttl_seconds=3600,
)

# P-LLM creates execution warrant for Q-LLM
exec_warrant = (issuer_warrant.issue_execution()
    .tool("search")
    .capability("search", {
        "query": Pattern("quarterly report*"),
        "max_results": Range.max_value(10)
    })
    .holder(q_llm_kp.public_key)  # Must be different from planner!
    .ttl(60)
    .intent("Search for Q3 quarterly reports")
    .issue(planner_kp))

# Q-LLM executes with the warrant
# Tool server verifies: caller_key == exec_warrant.holder
```

### Self-Issuance Prevention

Tenuo **cryptographically enforces** that P-LLM cannot grant execution capabilities to itself:

```python
# This FAILS with SelfIssuanceProhibited error:
bad_warrant = (issuer_warrant.issue_execution()
    .holder(planner_kp.public_key)  # Same as issuer warrant holder!
    .issue(planner_kp))
# Error: "issuer cannot grant execution warrants to themselves"
```

This enforcement is critical for the P-LLM/Q-LLM pattern—without it, a compromised planner could bypass the separation.

---

## What Tenuo Provides

### Authorization Layer (Strong Guarantees)

| Property | Enforcement | Cryptographic? |
|----------|-------------|----------------|
| P-LLM cannot execute tools | Issuer warrants have no execution capability | ✅ Yes |
| Self-issuance blocked | `holder != issuer.holder` check | ✅ Yes |
| Capability bounds | Constraints on tool parameters | ✅ Yes |
| Monotonicity | Child ⊆ Parent for all dimensions | ✅ Yes |
| Holder verification | Proof-of-possession via signatures | ✅ Yes |
| Time bounds | TTL enforced at verification | ✅ Yes |
| Audit trail | Delegation receipts, chain verification | ✅ Yes |
| Structural information flow | Egress filtering via URL/endpoint constraints | ✅ Yes |

### Trust Boundaries

Tenuo establishes explicit trust boundaries between agents:

```
┌─────────────────────────────────────────────────────────┐
│ Control Plane (TrustLevel.System)                       │
│ - Issues root warrants                                  │
│ - Can revoke any warrant in hierarchy                   │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼ Delegates with TrustLevel.Privileged
┌─────────────────────────────────────────────────────────┐
│ Orchestrator (P-LLM)                                    │
│ - Holds issuer warrant                                  │
│ - Can issue execution warrants to workers               │
│ - Cannot execute tools directly                         │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼ Issues with TrustLevel.Internal
┌─────────────────────────────────────────────────────────┐
│ Worker (Q-LLM)                                          │
│ - Holds execution warrant                               │
│ - Can execute specific tools within constraints         │
│ - Cannot delegate further (terminal)                    │
└─────────────────────────────────────────────────────────┘
```

---

## What Tenuo Does Not Provide

### Semantic Intent Verification

Tenuo's `intent` field is **informational only**, not enforced:

```python
warrant = (issuer.issue_execution()
    .intent("Search for public financial reports")  # Logged, not enforced
    .capability("search", {"query": Pattern("*")})
    .holder(worker_kp.public_key)
    .issue(planner_kp))

# Q-LLM could search for anything matching Pattern("*")
# even if it violates the stated intent
```

**Gap**: Tenuo verifies *syntactic* constraints (pattern matching), not *semantic* intent.

### Content-Based Data Loss Prevention

Tenuo provides **structural** information flow control (where data can go) but not **content-based** inspection (what data contains):

```python
# ✅ Tenuo CAN do: Structural/Topological Control
#    Constraint: UrlPattern("https://api.company.com/*")
#    Effect: Agent cannot send data to evil.com (egress filtering)

# ❌ Tenuo CANNOT do: Content Inspection
#    Tenuo doesn't scan: "Is this response leaking PII?"
#    Tenuo doesn't detect: Secrets embedded in API payloads
```

**What Tenuo provides:**
- URL/endpoint constraints prevent exfiltration to unauthorized destinations
- Path constraints limit file access topology
- Parameter constraints bound what operations can do

**What Tenuo doesn't provide:**
- PII/secret detection in payloads
- Semantic analysis of data sensitivity
- Content classification

**Gap**: Content-based DLP requires inspection layers; Tenuo provides the structural controls.

**Complementary Approaches**: Tenuo focuses on **action authorization** (what operations can be performed). For **data flow control** (tracking what information flows where), see complementary approaches:

- [FIDES](https://arxiv.org/abs/2410.01738) [7] - Information flow tracking for LLM agents using taint propagation
- Content-based DLP systems - Scan payloads for PII, secrets, and sensitive patterns

These approaches can be layered with Tenuo: Tenuo controls the structural boundaries, while FIDES-style tracking monitors what data crosses those boundaries.

### Reasoning Verification

Tenuo does not verify that Q-LLM's actions follow P-LLM's reasoning:

```python
# P-LLM plan: "Search for Q3 reports, summarize findings"
# 
# Warrant grants: search capability
# 
# Q-LLM could: Search for unrelated content within the constraint bounds
# 
# Tenuo cannot verify: Did Q-LLM follow the plan's intent?
```

**Gap**: Plan compliance requires runtime supervision, not just authorization.

### Single-Use Enforcement

Warrants can be used multiple times within their TTL:

```python
# Same warrant, multiple uses:
result1 = tool_server.call("search", {"query": "report"}, warrant)
result2 = tool_server.call("search", {"query": "secrets"}, warrant)  # Also allowed!
```

**Gap**: For single-use semantics, implement revocation-after-use at application layer.

### Collusion Prevention

If P-LLM and Q-LLM are controlled by the same adversary, separation provides no security:

```python
# Adversary controls both:
# - P-LLM: Issues maximally permissive warrants
# - Q-LLM: Executes malicious actions within those bounds
#
# Tenuo cannot detect: Coordinated malicious behavior
```

**Gap**: Collusion detection requires behavioral analysis, not authorization.

---

## Defense Against Prompt Injection

Prompt injection [6] is a critical threat to LLM-based agents. Tenuo provides **containment**, not prevention.

### Threat Model

```
User Input
    │
    ▼
┌─────────────────┐
│ LLM Agent       │ ← Prompt injection payload
│ (compromised)   │
└─────────────────┘
    │
    ▼ Attempts tool calls
┌─────────────────┐
│ Tool Server     │ ← Tenuo verification happens HERE
│ + Tenuo         │
└─────────────────┘
```

### What Tenuo Contains

Even if an LLM agent is fully compromised via prompt injection:

| Attack | Tenuo Response |
|--------|----------------|
| Call unauthorized tool | ❌ Blocked (not in warrant) |
| Exceed parameter bounds | ❌ Blocked (constraint violation) |
| Escalate privileges | ❌ Blocked (monotonicity) |
| Use expired warrant | ❌ Blocked (TTL check) |
| Impersonate another agent | ❌ Blocked (PoP verification) |
| Access after revocation | ❌ Blocked (revocation check) |

### What Tenuo Cannot Contain

| Attack | Why Tenuo Cannot Help |
|--------|----------------------|
| Malicious actions within bounds | Authorized by warrant |
| Data exfiltration via allowed tools | Output not controlled |
| Social engineering via responses | Outside tool authorization |
| Persistent compromise | Tenuo is stateless per-request |

### Defense in Depth Recommendation

Tenuo should be **one layer** in a comprehensive defense:

```
┌─────────────────────────────────────────────────────────┐
│ Layer 1: Input Sanitization                             │
│ - Filter known injection patterns                       │
│ - Separate user input from system prompts               │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 2: Tenuo Authorization                            │
│ - Scoped warrants (POLA)                                │
│ - Cryptographic verification                            │
│ - Self-issuance prevention                              │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 3: Output Monitoring                              │
│ - Anomaly detection                                     │
│ - Sensitive data leak prevention                        │
│ - Rate limiting                                         │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 4: Human Oversight                                │
│ - Approval for sensitive operations                     │
│ - Audit log review                                      │
│ - Kill switches                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Multi-Agent Orchestration

Complex AI systems involve multiple agents with different roles. Tenuo supports this via delegation chains.

### Hierarchical Delegation

```python
# Root authority
root_warrant = Warrant.issue(
    keypair=system_kp,
    capabilities={
        "read_file": {"path": Pattern("/data/*")},
        "write_file": {"path": Pattern("/data/output/*")},
        "search": {"max_results": Range.max_value(1000)},
    },
    ttl_seconds=3600,
)

# Orchestrator receives delegated authority
orchestrator_warrant = (root_warrant.attenuate()
    .capability("read_file", {"path": Pattern("/data/reports/*")})
    .capability("search", {"max_results": Range.max_value(100)})
    .holder(orchestrator_kp.public_key)
    .ttl(1800)
    .delegate(system_kp))

# Orchestrator further delegates to specialized workers
researcher_warrant = (orchestrator_warrant.attenuate()
    .capability("search", {"max_results": Range.max_value(10)})
    .holder(researcher_kp.public_key)
    .ttl(300)
    .terminal()  # Cannot delegate further
    .delegate(orchestrator_kp))
```

### Trust Level Propagation

```python
# Trust levels decrease through the hierarchy
root:         TrustLevel.System
orchestrator: TrustLevel.Privileged  # Demoted
worker:       TrustLevel.Internal    # Further demoted
external_api: TrustLevel.External    # Untrusted boundary
```

### Cross-Agent Communication

When Agent A needs Agent B to perform a sub-task:

```python
# Agent A attenuates its warrant for Agent B
subtask_warrant = (agent_a_warrant.attenuate()
    .capability("specific_tool", {"param": Exact("value")})
    .holder(agent_b_kp.public_key)
    .ttl(60)
    .intent("Perform subtask X for parent task Y")
    .delegate(agent_a_kp))

# Agent B receives warrant and executes
# Agent B cannot exceed Agent A's authority (monotonicity)
```

---

## Recommendations for Complete Security

### Minimum Viable Security

For basic P-LLM/Q-LLM deployment:

1. **Use Tenuo warrants** for all tool authorization
2. **Set appropriate TTLs** (minutes, not hours)
3. **Make worker warrants terminal** (prevent further delegation)
4. **Log all authorization decisions** (allow and deny)

### Enhanced Security

For production deployments:

1. **Human-in-the-loop** for sensitive operations
   ```python
   if not warrant.trust_level or warrant.trust_level < TrustLevel.Privileged:
       require_human_approval(operation)
   ```

2. **Output monitoring** for data exfiltration
   ```python
   result = tool_server.call(tool, params, warrant)
   if contains_sensitive_data(result):
       audit_log.alert(result, warrant)
   ```

3. **Behavioral anomaly detection**
   ```python
   if request_pattern_anomalous(agent_id, recent_requests):
       revoke_warrants(agent_id)
   ```

4. **Single-use warrants** for critical operations
   ```python
   def execute_critical(warrant):
       result = tool_server.call(..., warrant)
       revocation_service.revoke(warrant.id)
       return result
   ```

### What Tenuo Cannot Replace

| Requirement | Solution |
|-------------|----------|
| Prevent prompt injection | Input sanitization, prompt hardening |
| Verify semantic intent | Plan verification, LLM-as-judge |
| Content-based DLP (PII/secrets) | Content inspection, classification engines |
| Detect collusion | Behavioral analysis |
| Ensure correctness | Output validation, testing |

---

## References

[1] Dennis, J. B., & Van Horn, E. C. (1966). "Programming semantics for multiprogrammed computations." *Communications of the ACM*, 9(3), 143-155.

[2] Saltzer, J. H., & Schroeder, M. D. (1975). "The protection of information in computer systems." *Proceedings of the IEEE*, 63(9), 1278-1308.

[3] Miller, M. S. (2006). "Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control." PhD dissertation, Johns Hopkins University.

[4] Hardy, N. (1988). "The Confused Deputy: (or why capabilities might have been invented)." *ACM SIGOPS Operating Systems Review*, 22(4), 36-38.

[5] Debenedetti, E., et al. (2025). "CaMeL: Capability-based Sandboxing for Agentic AI." *arXiv preprint arXiv:2503.00813*. Microsoft Research.

[6] Perez, F., & Ribeiro, I. (2022). "Ignore This Title and HackAPrompt: Exposing Systemic Vulnerabilities of LLMs through a Global Scale Prompt Hacking Competition." *arXiv preprint arXiv:2311.16119*.

[7] Piet, J., et al. (2024). "FIDES: A Framework for Information Flow Tracking in LLM Agents." *arXiv preprint arXiv:2410.01738*.
