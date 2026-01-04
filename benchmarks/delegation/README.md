# Delegation Benchmark

Benchmark for Tenuo's constraint enforcement across different warrant scopes.

## Overview

This benchmark validates that warrant constraints are correctly enforced by testing identical tool calls against warrants with varying permissions.

**Core Insight**: The agent code remains constant. The warrant determines what's allowed.

## Scenarios

| Scenario | Description | Tests |
|----------|-------------|-------|
| `temporal_scoping` | Same agent, different warrants per task | 8 |
| `range_limit` | Numeric range boundary enforcement | 5 |
| `pattern_match` | Glob pattern constraint enforcement | 5 |
| `tool_scoping` | Tool authorization verification | 5 |

### Temporal Scoping

Demonstrates that capabilities are determined by the warrant, not the agent code:

```python
# Same agent, different outcomes based on warrant
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

### Same Action, Different Outcome

| Tool Call | Small Limit Warrant | Large Limit Warrant |
|-----------|---------------------|---------------------|
| `transfer(amount=50)` | Allowed | Allowed |
| `transfer(amount=500)` | Blocked | Allowed |
| `transfer(amount=50000)` | Blocked | Blocked |

## Running the Benchmark

```bash
# Run single scenario
python -m benchmarks.delegation.evaluate --scenario temporal_scoping

# Run all scenarios
python -m benchmarks.delegation.evaluate --all

# Save results
python -m benchmarks.delegation.evaluate --all --output results/delegation/
```

## Results

| Metric | Value |
|--------|-------|
| Total Tests | 23 |
| Pass Rate | 100% |
| Attacks Blocked | 11 |
| False Positives | 0 |
| False Negatives | 0 |
| Avg Auth Time | 0.04 ms |

## Metrics

| Metric | Description |
|--------|-------------|
| Pass Rate | Percentage of tests where actual = expected |
| Attacks Blocked | Out-of-scope actions correctly denied |
| False Positives | Legitimate actions incorrectly denied |
| False Negatives | Attack actions incorrectly allowed |

## Design Notes

These scenarios test single-warrant constraint enforcement. Each scenario creates independent warrants with different constraint configurations and verifies that:

1. Actions within scope are allowed
2. Actions exceeding scope are blocked
3. Wrong tools are rejected
4. Pattern matching works correctly
5. Range boundaries are enforced

## Files

```
benchmarks/delegation/
├── evaluate.py      # CLI entrypoint
├── harness.py       # Test harness
├── scenarios.py     # Scenario definitions
└── __init__.py      # Package exports
```

## Further Reading

- [Tenuo Concepts](https://tenuo.dev/concepts) - Capability token fundamentals
- [Constraints Reference](https://tenuo.dev/constraints) - Pattern, Range, AnyOf constraints
