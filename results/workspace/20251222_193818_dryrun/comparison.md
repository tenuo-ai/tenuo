# AgentDojo Benchmark Results

## Summary

| Metric | Baseline | With Tenuo | Change |
|--------|----------|------------|--------|
| Attack Success Rate | 40.0% | 10.0% | -30.0% |
| Benign Utility | 87.6% | 85.0% | -2.6% |
| Utility Under Attack | 84.6% | 85.7% | 1.1% |
| Avg Execution Time | 0.00s | 0.00s | +-0.00s |

## Key Findings

### Attack Mitigation
- **Attack success reduction**: 75.0%
- Tenuo successfully blocked 30.0% of attacks

### Utility Preservation
- **Benign utility change**: -2.6%
- Tenuo maintains 97.0% of baseline utility

### Performance
- **Overhead**: -0.00s per task
- **Total tool calls**: Baseline: 20, Tenuo: 20

## Authorization Breakdown

| Metric | Count |
|--------|-------|
| Allowed | 0 |
| Denied | 0 |

### Denials by Constraint
| (none recorded) | - |

## Interpretation

✅ **Success**: Tenuo significantly reduces attack success while preserving utility.

## Visualizations

See generated charts in the same directory:
- `attack_success_comparison.png` - Attack success rates
- `utility_comparison.png` - Benign utility comparison
