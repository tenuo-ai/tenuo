# AgentDojo Benchmark Integration

> ⚠️ **Work in Progress**: This benchmark is under active development. Results may vary based on model, attack type, and constraint configuration.

Empirical validation that Tenuo's constraint enforcement works as specified, using [AgentDojo](https://github.com/ethz-spylab/agentdojo).

## What This Proves (and Doesn't)

**Tenuo is a deterministic constraint engine.** If you constrain recipients to `*@company.com`, emails to `attacker@evil.com` will be blocked. This is straightforward mechanical enforcement, not magic.

This benchmark does **NOT** prove:
- Attack detection (we don't detect anything)
- Intent understanding (we don't interpret meaning)
- AI-based security (there's no AI in the enforcement layer)

This benchmark **DOES** prove:
- Constraints are enforced correctly under adversarial conditions
- Compromised LLMs cannot exceed their granted capabilities
- The overhead is acceptable for real workloads

## Results (Preliminary)

| Model | Malicious Calls | Blocked | Escaped |
|-------|-----------------|---------|---------|
| gpt-5.1 | 36 | 36 | 0 |
| gpt-4o-mini | 31 | 31 | 0 |

*Results vary by model behavior and attack success rate.*

**What this means**: When the compromised LLM tried to exceed its warrant (e.g., email `evil.com` when only `*@company.com` was allowed), the call was blocked. Every time. By design.

**What this doesn't mean**: "100% attack prevention." Attacks that stay within the warrant's bounds succeed - because they're indistinguishable from legitimate use. That's the tradeoff of constraint-based security.

### Attacks That Succeed (By Design)

If the warrant allows `send_email(to="*@company.com")` and the attacker tricks the LLM into sending `send_email(to="attacker@company.com")`, Tenuo allows it. The constraint is satisfied.

This is why **constraint design matters**. Tenuo enforces what you specify, not what you intend.

### Why It Works (The Boring Reason)

There's no magic. Tenuo is a gate between the LLM and tool execution:

```
┌─────────────────┐     ┌─────────────┐     ┌─────────────┐     ┌──────────┐
│ Malicious Input │ --> │  LLM Agent  │ --> │   Tenuo     │ -X- │  Tool    │
│ "email evil.com"│     │  (tricked)  │     │  (checks)   │     │ (blocked)│
└─────────────────┘     └─────────────┘     └─────────────┘     └──────────┘
                                                   │
                                                   v
                                            ❌ "evil.com" does not
                                               match "*@company.com"
```

The constraint says `to: *@company.com`. The argument is `attacker@evil.com`. Pattern doesn't match. Call denied.

| What LLM Tried | Constraint | Math |
|----------------|------------|------|
| `send_email(to="attacker@evil.com")` | `to: *@company.com` | `evil.com ≠ company.com` |
| `transfer_money(amount=50000)` | `amount: 0..1000` | `50000 > 1000` |
| `read_file(path="/etc/passwd")` | `path: docs/*` | `/etc/` doesn't start with `docs/` |

That's it. No AI, no heuristics, no detection. Just constraints.

### Utility Cost

Constraints have a cost: legitimate calls that happen to exceed the warrant's scope get blocked too.

| Model | Legitimate Calls Allowed | False Positives |
|-------|--------------------------|-----------------|
| gpt-5.1 | 337 | 0 |
| gpt-4o-mini | 373 | 0 |

**0 false positives** in this run because we defined constraints that match the legitimate workload. This is the key insight: you have to scope constraints to what's actually needed, not what's theoretically possible.

### Same Agent, Different Warrant (Solving Temporal Mismatch)

Traditional auth gives the agent broad permissions at startup. By the time it acts, context may have changed.

Tenuo solves this: **same agent + different warrant = different capabilities**.

```python
# Pseudocode - same agent, same code, different warrants
agent = create_agent()

# Task 1: "Email the team" - scoped warrant
warrant = issue(tools=["send_email"], recipients="*@company.com")
agent.run(warrant=warrant)  # ✅ team@company.com allowed

# Task 2: Attack injection - same agent, same scoped warrant  
agent.run(warrant=warrant)  # ❌ attacker@evil.com blocked

# Task 3: Admin task - broader warrant
admin_warrant = issue(tools=["send_email"], recipients="*")
agent.run(warrant=admin_warrant)  # ✅ external@partner.com allowed
```

The agent code never changes. The warrant scopes capabilities to the **current task**, not what the agent might theoretically need.

### Delegation: Same Action, Different Outcome

When comparing manager vs delegated assistant warrants, **identical actions** can have different outcomes:

| Tool Call | Manager (full scope) | Assistant (delegated) |
|-----------|---------------------|----------------------|
| `send_money(amount=500)` | ✅ Allowed (limit: $1000) | ❌ **Blocked** (limit: $100) |
| `send_email(to="partner@external.com")` | ✅ Allowed | ❌ **Blocked** (internal only) |
| `transfer(amount=100)` after 10 min | ✅ Allowed (TTL: 1hr) | ❌ **Blocked** (TTL: 5min expired) |

This is Tenuo's core value: even if the assistant LLM is fully compromised, it cannot exceed what was delegated.

See [`benchmarks/delegation/`](../delegation/) for full delegation scenarios.

<details>
<summary>Detailed Breakdown by Model</summary>

#### gpt-5.1 on Workspace Suite

**240 security test cases** → **36 malicious tool calls** → **0 succeeded**

| What Was Blocked | Count |
|------------------|-------|
| Email to external address | 29 |
| Calendar invite to external user | 6 |
| Sensitive file operation | 1 |

#### gpt-4o-mini on Workspace Suite

**240 security test cases** → **31 malicious tool calls** → **0 succeeded**

| What Was Blocked | Count |
|------------------|-------|
| Email to external address | 18 |
| Calendar invite to external user | 6 |
| File shared externally | 6 |
| Unauthorized file deletion | 1 |

*Breakdown varies by model and which attacks succeed in bypassing the LLM's own safeguards.*

</details>

---

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Dry run (no API calls, no cost)
python -m benchmarks.agentdojo.evaluate --suite workspace --dry-run

# Real benchmark
python -m benchmarks.agentdojo.evaluate --suite workspace --model gpt-4o-mini

# Analyze results
python -m benchmarks.agentdojo.analyze results/workspace/<timestamp>/
```

---

## Configuration

### Error Messages

```bash
# Opaque (default) - attacker learns nothing
python -m benchmarks.agentdojo.evaluate --suite workspace
# → "Tool call denied: Unauthorized"

# Adaptive - for testing against learning attackers  
python -m benchmarks.agentdojo.evaluate --suite workspace --adaptive-errors
# → "denied: recipient attacker@evil.com not in *@company.com"
```

### Models

```bash
--model gpt-4o-mini    # Fast, cheap
--model gpt-4o         # Better reasoning
--model gpt-5.1        # Latest
```

### Suites

| Suite | Tools | Tasks | Focus |
|-------|-------|-------|-------|
| `workspace` | 33 | 40 | Email, files, calendar |
| `banking` | 11 | 16 | Money transfers |
| `slack` | 11 | 21 | Messaging |
| `travel` | 26 | 20 | Bookings |

---

## How Constraints Are Defined

See `warrant_templates.py` for the full constraint definitions:

```python
WORKSPACE_CONSTRAINTS = {
    "send_email": {"recipients": Pattern("*@company.com")},
    "read_file": {"path": AnyOf([Pattern("docs/*"), Pattern("data/*")])},
    "transfer_money": {"amount": Range(0, 1000)},
}
```

Each suite has pre-defined constraints modeling realistic enterprise policies.

---

## Files

```
benchmarks/agentdojo/
├── evaluate.py          # CLI entrypoint
├── harness.py           # AgentDojo integration
├── warrant_templates.py # Constraint definitions
├── tool_wrapper.py      # Tenuo authorization layer
├── analyze.py           # Results analysis
└── requirements.txt     # Dependencies
```



## Limitations

**This benchmark tests single-agent constraint enforcement.**

AgentDojo evaluates one LLM with tools against prompt injection. While we've added delegation comparison (manager vs assistant warrants), the full value of Tenuo's warrant chains is better demonstrated in the [Delegation Benchmark](../delegation/).

For multi-agent hierarchies and warrant chain testing, see:
- `benchmarks/delegation/` - Delegation-specific scenarios
- `python -m benchmarks.delegation.run_agentdojo` - AgentDojo with delegation comparison

---

## Further Reading

- [Tenuo Concepts](https://tenuo.dev/concepts) - How capability tokens work
- [Constraints Reference](https://tenuo.dev/constraints) - Pattern, Range, OneOf, etc.
- [AgentDojo Paper](https://arxiv.org/abs/2401.13138) - Benchmark methodology
