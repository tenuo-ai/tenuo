# Running AgentDojo Benchmarks with Real LLM

## Prerequisites

### 1. Install AgentDojo
```bash
uv pip install agentdojo
```

### 2. Set up OpenAI API Key
```bash
export OPENAI_API_KEY="sk-..."
```

Or add to your shell profile:
```bash
echo 'export OPENAI_API_KEY="sk-..."' >> ~/.zshrc
source ~/.zshrc
```

### 3. Install Tenuo
```bash
cd /path/to/tenuo
uv pip install -e tenuo-python
```

---

## Running Benchmarks

### Quick Test (Single Suite)
```bash
cd /path/to/tenuo

# Run workspace suite with comparison
python -m benchmarks.agentdojo.evaluate \
    --suite workspace \
    --compare \
    --tasks user_task_0,user_task_1,user_task_2
```

### Full Suite Comparison
```bash
# Workspace suite (email, files, calendar)
python -m benchmarks.agentdojo.evaluate \
    --suite workspace \
    --compare

# Banking suite (money transfers)
python -m benchmarks.agentdojo.evaluate \
    --suite banking \
    --compare

# Slack suite (messaging)
python -m benchmarks.agentdojo.evaluate \
    --suite slack \
    --compare

# Travel suite (bookings)
python -m benchmarks.agentdojo.evaluate \
    --suite travel \
    --compare
```

### Baseline Only (No Tenuo)
```bash
python -m benchmarks.agentdojo.evaluate \
    --suite workspace \
    --baseline-only
```

### Tenuo Only
```bash
python -m benchmarks.agentdojo.evaluate \
    --suite workspace \
    --with-tenuo
```

---

## Analyzing Results

After running benchmarks, analyze the results:

```bash
# Find the latest results directory
ls -lt benchmarks/agentdojo/results/workspace/

# Analyze specific run
python -m benchmarks.agentdojo.analyze \
    benchmarks/agentdojo/results/workspace/20241222_193000/
```

This generates:
- `comparison.md` - Detailed report
- `attack_success_comparison.png` - Chart
- `utility_comparison.png` - Chart

---

## Expected Output

### During Run
```
Running AgentDojo benchmark: workspace
Model: gpt-4o-2024-05-13
Tasks: user_task_0,user_task_1,user_task_2
Attacks: Yes
Dry run: No
Output: benchmarks/agentdojo/results/workspace/20241222_193000

Running baseline (no Tenuo)...
Baseline: 6 results

Running with Tenuo protection...
With Tenuo: 6 results
Authorization: 45 allowed, 12 denied

Quick Summary:
--------------------------------------------------
Attack Success Rate:
  Baseline: 60.0%
  With Tenuo: 5.0%
  Reduction: 91.7%

Benign Utility:
  Baseline: 95.0%
  With Tenuo: 92.0%
  Change: -3.0%

Attacks Blocked By Constraint:
  send_email.to: 5
  transfer_money.amount: 4
  read_file.path: 3
```

---

## Cost Estimation

### Per Task
- **Baseline**: ~$0.02 (1 LLM call)
- **With Tenuo**: ~$0.02 (1 LLM call)
- **Comparison**: ~$0.04 (2 LLM calls)

### Per Suite (10 tasks, with attacks)
- **Comparison**: ~$0.80 (20 LLM calls)

### All 5 Suites
- **Full comparison**: ~$4.00

---

## Tips

### Start Small
```bash
# Test with 1 task first
python -m benchmarks.agentdojo.evaluate \
    --suite workspace \
    --compare \
    --tasks user_task_0
```

### Use Dry Run First
```bash
# Verify everything works without API calls
python -m benchmarks.agentdojo.evaluate \
    --suite workspace \
    --compare \
    --dry-run
```

### Run Overnight
```bash
# Run all suites (takes ~30 minutes)
for suite in workspace banking slack travel; do
    python -m benchmarks.agentdojo.evaluate \
        --suite $suite \
        --compare
done
```

---

## Troubleshooting

### "AgentDojo not installed"
```bash
uv pip install agentdojo
```

### "OpenAI API key not found"
```bash
export OPENAI_API_KEY="sk-..."
```

### "Module not found: tenuo"
```bash
cd /path/to/tenuo
uv pip install -e tenuo-python
```

### Rate Limits
If you hit OpenAI rate limits, add delays:
```python
# In evaluate.py, add after each task:
import time
time.sleep(1)  # 1 second between tasks
```

---

## Next Steps

1. **Run dry-run test**: Verify setup
2. **Run single task**: Test with real LLM
3. **Run single suite**: Get initial results
4. **Analyze results**: Check metrics
5. **Run all suites**: Full benchmark
6. **Generate report**: Share findings
