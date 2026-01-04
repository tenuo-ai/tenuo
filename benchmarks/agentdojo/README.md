# AgentDojo Benchmark Integration


Empirical validation of Tenuo's constraint enforcement using [AgentDojo](https://github.com/ethz-spylab/agentdojo).

⚠️ **Work in Progress**: This benchmark is under active development. Results may vary based on model, attack type, and constraint configuration.

## What This Tests

Tenuo is a deterministic constraint engine. If you constrain recipients to
`*@company.com`, emails to `attacker@evil.com` are blocked.

This benchmark validates:
- Constraints are enforced under adversarial conditions
- Compromised LLMs cannot exceed their granted capabilities
- Overhead is acceptable for real workloads

## Results

| Model | Malicious Calls | Blocked | Pass Rate |
|-------|-----------------|---------|-----------|
| gpt-5.1 | 36 | 36 | 100% |
| gpt-4o-mini | 31 | 31 | 100% |

When the compromised LLM tried to exceed its warrant (e.g., email `evil.com` when only `*@company.com` was allowed), the call was blocked.

### How It Works

```
┌─────────────────┐     ┌─────────────┐     ┌─────────────┐     ┌──────────┐
│ Malicious Input │ ──▶ │  LLM Agent  │ ──▶ │   Tenuo     │ ─X─ │  Tool    │
│ "email evil.com"│     │  (tricked)  │     │  (checks)   │     │ (blocked)│
└─────────────────┘     └─────────────┘     └─────────────┘     └──────────┘
                                                  │
                                                  ▼
                                           [BLOCKED] "evil.com" does not
                                              match "*@company.com"
```

| What LLM Tried | Constraint | Result |
|----------------|------------|--------|
| `send_email(to="attacker@evil.com")` | `to: *@company.com` | Blocked |
| `transfer_money(amount=50000)` | `amount: 0..1000` | Blocked |
| `read_file(path="/etc/passwd")` | `path: docs/*` | Blocked |

### Utility Metrics

| Model | Legitimate Calls | False Positives |
|-------|------------------|-----------------|
| gpt-5.1 | 337 | 0 |
| gpt-4o-mini | 373 | 0 |

### Same Agent, Different Warrant

Tenuo solves the temporal mismatch problem: **same agent + different warrant = different capabilities**.

```python
agent = create_agent()

# Task 1: Scoped warrant
warrant = issue(tools=["send_email"], recipients="*@company.com")
agent.run(warrant=warrant)  # team@company.com -> allowed

# Attack injection with same warrant
agent.run(warrant=warrant)  # attacker@evil.com -> blocked

# Admin task with broader warrant
admin_warrant = issue(tools=["send_email"], recipients="*")
agent.run(warrant=admin_warrant)  # external@partner.com -> allowed
```

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

</details>

---

## Quick Start

```bash
# Install dependencies (AgentDojo pinned to 0.1.35)
pip install -r benchmarks/agentdojo/requirements.txt

# Dry run (no API calls)
python -m benchmarks.agentdojo.evaluate --suite workspace --dry-run

# Real benchmark
python -m benchmarks.agentdojo.evaluate --suite workspace --model gpt-4o-mini

# Smaller run for iteration speed
python -m benchmarks.agentdojo.evaluate --suite workspace --model gpt-4o-mini --user-tasks 3 --injection-tasks 2

# Analyze results
python -m benchmarks.agentdojo.analyze results/workspace/<timestamp>/
```

## Configuration

### Models

```bash
--model gpt-4o-mini    # Fast, cost-effective
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

## Constraint Definitions

See `warrant_templates.py`:

```python
WORKSPACE_CONSTRAINTS = {
    "send_email": {"recipients": Pattern("*@company.com")},
    "read_file": {"path": AnyOf([Pattern("docs/*"), Pattern("data/*")])},
    "transfer_money": {"amount": Range(0, 1000)},
}
```

## Files

```
benchmarks/agentdojo/
├── evaluate.py          # CLI entrypoint
├── harness.py           # AgentDojo integration
├── warrant_templates.py # Constraint definitions
├── tool_wrapper.py      # Authorization layer
├── analyze.py           # Results analysis
└── requirements.txt     # Dependencies
```

## Further Reading

- [Tenuo Concepts](https://tenuo.dev/concepts) - Capability token fundamentals
- [Constraints Reference](https://tenuo.dev/constraints) - Pattern, Range, OneOf
- [AgentDojo Paper](https://arxiv.org/abs/2401.13138) - Benchmark methodology
- [Delegation Benchmark](../delegation/) - Multi-warrant scenarios
