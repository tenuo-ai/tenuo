# Running AgentDojo Benchmarks

## Prerequisites

```bash
# Install with benchmark dependencies
pip install -e ".[benchmark]"

# Set API key
export OPENAI_API_KEY="your-key-here"
```

## Running Tests

### H0₂: Security-Utility Tradeoff

Tests whether Tenuo blocks attacks while maintaining utility.

```bash
python -m benchmarks.agentdojo.hypotheses \
  --suite workspace \
  --test security-utility \
  --model gpt-3.5-turbo-0125 \
  --user-tasks 5 \
  --attack-type important_instructions
```

**Parameters:**
- `--suite`: Task suite (workspace, banking, travel, slack)
- `--test`: Test type (security-utility, defense-in-depth, attenuation-depth, all)
- `--model`: LLM model to use
- `--user-tasks`: Number of user tasks to test (default: all)
- `--attack-type`: Attack type (important_instructions, fixed_jailbreak, injecagent, direct)

### Test with Different Models

#### OpenAI Models
```bash
# GPT-4
python -m benchmarks.agentdojo.hypotheses \
  --suite workspace \
  --test security-utility \
  --model gpt-4-turbo-preview

# GPT-3.5
python -m benchmarks.agentdojo.hypotheses \
  --suite workspace \
  --test security-utility \
  --model gpt-3.5-turbo-0125
```

#### Groq (Open Source Models)
```bash
export GROQ_API_KEY="your-groq-key"

python -m benchmarks.agentdojo.hypotheses \
  --suite workspace \
  --test security-utility \
  --model llama-3.3-70b-versatile \
  --api-key $GROQ_API_KEY \
  --base-url https://api.groq.com/openai/v1
```

**Available Groq models:**
- `llama-3.3-70b-versatile`
- `llama-3.1-8b-instant`
- `openai/gpt-oss-20b`

**Note:** Groq has aggressive rate limits on free tier (200k tokens/day). Tests may be incomplete.

## Results Location

Results are saved to:
```
results/hypotheses/h0_security_utility_TIMESTAMP/
├── baseline_benign/      # Phase 1: Benign tasks without Tenuo
├── tenuo_benign/         # Phase 2: Benign tasks with Tenuo
├── baseline_attacks/     # Phase 3: Attack scenarios without Tenuo
├── tenuo_attacks/        # Phase 4: Attack scenarios with Tenuo
└── summary.json          # Test summary statistics
```

Each result file contains:
- Full conversation history
- Tool calls and responses
- Utility score (task completed successfully?)
- Security score (attack executed?)

## Analyzing Results

### View Summary
```bash
cat results/hypotheses/h0_security_utility_TIMESTAMP/summary.json
```

### Count Attack Successes
```python
import json
from pathlib import Path

results_dir = Path("results/hypotheses/h0_security_utility_TIMESTAMP")

# Baseline attacks
baseline = results_dir / "baseline_attacks/baseline-pipeline-MODEL/workspace"
for user_task in baseline.iterdir():
    if user_task.is_dir() and "user_task" in user_task.name:
        attack_dir = user_task / "fixed_jailbreak"
        for result in attack_dir.glob("*.json"):
            data = json.load(open(result))
            if data.get("security") == True:
                print(f"Attack succeeded: {user_task.name}/{result.stem}")
```

## Test Output

### Phase Descriptions

**Phase 1: Baseline Benign**
- Tests whether agent can complete legitimate tasks without Tenuo
- Establishes baseline utility

**Phase 2: Tenuo Benign**
- Tests whether agent can complete same tasks with Tenuo enabled
- Measures if Tenuo blocks legitimate operations (false positives)

**Phase 3: Baseline Attacks**
- Tests whether agent executes injected malicious commands without Tenuo
- Establishes baseline security vulnerability

**Phase 4: Tenuo Attacks**
- Tests whether agent executes injected malicious commands with Tenuo
- Measures if Tenuo blocks attacks (true positives)

### Success Criteria

**Perfect Security:**
- Phase 3: Some attacks succeed (proves vulnerability exists)
- Phase 4: Zero attacks succeed (proves Tenuo blocks them)

**Maintained Utility:**
- Phase 1: Tasks succeed (proves agent is capable)
- Phase 2: Same tasks succeed (proves Tenuo doesn't harm utility)

## Troubleshooting

### Rate Limits
```
Error: 429 - Rate limit exceeded
```
**Solution:** Use a paid OpenAI tier or wait for rate limit to reset.

### Tool Calling Errors
```
Error: 400 - Failed to call a function
```
**Solution:** Some models (Llama on Groq) don't support OpenAI function calling properly. Use GPT models or try a different provider.

### Out of Memory
```
Error: CUDA out of memory
```
**Solution:** Use a smaller model or reduce `--user-tasks` and `--injection-tasks` counts.

## Quick Test (5 minutes)

To verify everything works:

```bash
python -m benchmarks.agentdojo.hypotheses \
  --suite workspace \
  --test security-utility \
  --model gpt-3.5-turbo-0125 \
  --user-tasks 2 \
  --attack-type important_instructions
```

This runs a subset of tests (2 user tasks × 6 injection tasks = 12 attack scenarios) and completes in ~5 minutes.

## Full Test (~1 hour)

For complete results:

```bash
python -m benchmarks.agentdojo.hypotheses \
  --suite workspace \
  --test security-utility \
  --model gpt-3.5-turbo-0125
```

This runs all workspace tasks (33 user tasks × 6 injection tasks = 198 scenarios) and takes ~1 hour.
