# Delegation Benchmark

Benchmarks for Tenuo's constraint enforcement and multi-agent delegation scenarios.

## Overview

This benchmark validates that warrant constraints are correctly enforced by testing identical tool calls against warrants with varying permissions.

**Core Insight**: The agent code remains constant. The warrant determines what's allowed.

For cryptographic property tests (forgery resistance, key separation, etc.), see `benchmarks/cryptographic/`.

## Test Suites

### 1. Constraint Scenarios (`scenarios.py`)

Unit tests for constraint enforcement:

| Scenario | Description | Tests |
|----------|-------------|-------|
| `temporal_scoping` | Same agent, different warrants per task | 8 |
| `range_limit` | Numeric range boundary enforcement | 5 |
| `pattern_match` | Glob pattern constraint enforcement | 5 |
| `tool_scoping` | Tool authorization verification | 5 |

### 2. LLM Multi-Agent Scenarios (`llm_scenarios.py`)

Real LLM multi-agent scenarios with prompt injection attacks:

| Scenario | Description |
|----------|-------------|
| `MultiAgentDelegationScenario` | Manager delegates to assistant, injection targets assistant |
| `DelegationChainScenario` | Org -> Manager -> Assistant -> Bot with escalation attempts |

## Running the Benchmarks

```bash
# Constraint scenario tests
python -m benchmarks.delegation.evaluate --all

# Single scenario
python -m benchmarks.delegation.evaluate --scenario temporal_scoping

# LLM delegation scenarios (requires OpenAI API key)
python -m benchmarks.delegation.run_llm --model gpt-4o-mini

# Save results
python -m benchmarks.delegation.evaluate --all --output results/delegation/
```

## Example: Temporal Scoping

Same agent, different outcomes based on warrant:

```python
agent = create_agent()

# Task 1: Internal email warrant
internal_warrant = Warrant.mint_builder()
    .capability("send_email", {"to": Pattern("*@company.com")})
    .mint(issuer_key)
agent.run(warrant=internal_warrant)
# team@company.com -> Allowed
# attacker@evil.com -> Blocked

# Task 2: External email warrant  
external_warrant = Warrant.mint_builder()
    .capability("send_email", {"to": Pattern("*")})
    .mint(issuer_key)
agent.run(warrant=external_warrant)
# partner@external.com -> Allowed
```

## Example: Same Action, Different Outcome

| Tool Call | Small Limit ($100) | Large Limit ($10k) |
|-----------|--------------------|--------------------|
| `transfer(amount=50)` | Allowed | Allowed |
| `transfer(amount=500)` | Blocked | Allowed |
| `transfer(amount=50000)` | Blocked | Blocked |

## Metrics

| Metric | Description |
|--------|-------------|
| Pass Rate | Percentage of tests where actual = expected |
| Attacks Blocked | Out-of-scope actions correctly denied |
| False Positives | Legitimate actions incorrectly denied |
| False Negatives | Attack actions incorrectly allowed |

## Files

```
benchmarks/delegation/
├── scenarios.py             # Constraint enforcement scenarios
├── llm_scenarios.py         # LLM multi-agent scenarios
├── harness.py               # Test harness
├── evaluate.py              # CLI entrypoint
├── run_llm.py               # LLM scenario runner
├── agentdojo_integration.py # AgentDojo integration
└── README.md                # This file
```

## Related

- `benchmarks/cryptographic/` - Forgery resistance, key separation, delegation monotonicity
- `benchmarks/agentdojo/` - AgentDojo prompt injection benchmark with Tenuo
