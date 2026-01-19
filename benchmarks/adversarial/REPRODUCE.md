# Reproducing Benchmark Results

Instructions to reproduce the adversarial benchmark results.

## Environment Setup

```bash
# Python 3.11+ required
python --version  # Should be 3.11+

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install Tenuo (with CEL support)
uv pip install -e "tenuo-python/[cel]"

# Install benchmark dependencies
uv pip install -r benchmarks/adversarial/requirements.txt

# Set API key
export OPENAI_API_KEY="sk-..."
```

## Exact Commands

### Full Benchmark (5 runs, all scenarios)

```bash
python -m benchmarks.adversarial.evaluate \
  --runs 5 \
  --attacker-model gpt-4o-mini \
  --max-attempts 10 \
  --recon-probes 5 \
  --output results/adversarial/full_run.json
```

### Ablation Study (Recon vs No-Recon)

```bash
# With reconnaissance
python -m benchmarks.adversarial.evaluate \
  --runs 5 \
  --output results/adversarial/with_recon.json

# Without reconnaissance
python -m benchmarks.adversarial.evaluate \
  --runs 5 \
  --no-recon \
  --output results/adversarial/no_recon.json
```

### Model Comparison

```bash
# GPT-4o (strongest attacker)
python -m benchmarks.adversarial.evaluate \
  --runs 3 \
  --attacker-model gpt-4o \
  --output results/adversarial/gpt4o.json

# GPT-4o-mini (default)
python -m benchmarks.adversarial.evaluate \
  --runs 3 \
  --attacker-model gpt-4o-mini \
  --output results/adversarial/gpt4o_mini.json
```

### Single Scenario (Testing)

```bash
python -m benchmarks.adversarial.evaluate \
  --scenario email_exfil \
  --runs 1 \
  --output results/adversarial/test.json
```

## Expected Output

```
==================================================
ADVERSARIAL BENCHMARK SUMMARY
==================================================

Scenarios tested:           5
Constraints bypassed:       0-1
Constraints defended:       4-5
Defense rate:               80-100%

Defense rate: 100.0% (95% CI: 92.3%-100.0%)
```

## Verifying Results

Results are saved as JSON with structure:

```json
{
  "timestamp": "...",
  "config": {...},
  "runs": [...],
  "aggregate": {
    "defense_rate_mean": 1.0,
    "defense_rate_ci_lower": 0.923,
    "defense_rate_ci_upper": 1.0
  }
}
```

## Cost Estimation

| Configuration | Estimated Cost |
|---------------|----------------|
| 5 scenarios × 1 run | ~$0.05 |
| 5 scenarios × 5 runs | ~$0.25 |
| Full ablation study | ~$0.50 |

## Known Issues

1. **Path traversal** may show bypass - this is expected (see THREAT_MODEL.md)
2. **API rate limits** - reduce `--max-attempts` or `--recon-probes` if hitting limits
3. **Model availability** - ensure your API key has access to chosen model

## Seed and Reproducibility

LLM outputs are stochastic. Results may vary between runs.
The `--runs N` option provides statistical averaging to account for variance.
