# Running Benchmarks in Small Chunks

To avoid OpenAI API rate limits, you can run benchmarks in several ways:

## Option 1: Single Task at a Time (Manual)

Run one task, wait, then run the next:

```bash
# Task 0
OPENAI_API_KEY=$OPENAI_API_KEY python -m benchmarks.agentdojo.evaluate \
  --suite workspace --compare --tasks user_task_0

# Wait 30 seconds
sleep 30

# Task 1
OPENAI_API_KEY=$OPENAI_API_KEY python -m benchmarks.agentdojo.evaluate \
  --suite workspace --compare --tasks user_task_1
```

## Option 2: Bash Script (Automated)

Use the provided batch script:

```bash
cd /Users/aimable/Development/tenuo

# Run all tasks with 30s delay between each
./benchmarks/agentdojo/run_batch.sh workspace 30

# Or with custom delay (60s)
./benchmarks/agentdojo/run_batch.sh workspace 60
```

## Option 3: Python Script (Best Control)

Use the Python batch runner for better error handling:

```bash
cd /Users/aimable/Development/tenuo

# Run all tasks with default settings (30s delay)
python benchmarks/agentdojo/run_batch.py --suite workspace

# Custom delays
python benchmarks/agentdojo/run_batch.py \
  --suite workspace \
  --delay 45 \
  --rate-limit-delay 180

# Run specific tasks only
python benchmarks/agentdojo/run_batch.py \
  --suite workspace \
  --tasks user_task_0 user_task_1 user_task_3
```

### Python Script Options

- `--suite`: Which suite to run (workspace, banking, travel, slack)
- `--delay`: Seconds to wait between tasks (default: 30)
- `--rate-limit-delay`: Extra seconds to wait after rate limit (default: 120)
- `--tasks`: Specific tasks to run (default: all)

## Option 4: No Attacks (Faster)

Run without attacks to reduce API calls:

```bash
python -m benchmarks.agentdojo.evaluate \
  --suite workspace \
  --compare \
  --no-attacks
```

This runs only benign tasks, which uses ~50% fewer API calls.

## Recommended Strategy

For a full workspace suite (40 tasks):

1. **Start with 3-5 tasks** to test:
   ```bash
   python benchmarks/agentdojo/run_batch.py \
     --tasks user_task_0 user_task_1 user_task_3 \
     --delay 60
   ```

2. **If successful, run in batches of 10**:
   ```bash
   # Batch 1
   python benchmarks/agentdojo/run_batch.py \
     --tasks user_task_0 user_task_1 user_task_3 user_task_4 user_task_5 \
            user_task_6 user_task_7 user_task_8 user_task_9 user_task_10
   
   # Wait 5 minutes
   sleep 300
   
   # Batch 2
   python benchmarks/agentdojo/run_batch.py \
     --tasks user_task_11 user_task_12 ...
   ```

3. **Or run overnight** with long delays:
   ```bash
   python benchmarks/agentdojo/run_batch.py \
     --delay 120 \
     --rate-limit-delay 300
   ```

## Rate Limit Info

OpenAI rate limits (as of Dec 2025):
- **Tier 1**: 30,000 TPM (tokens per minute)
- **Tier 2**: 450,000 TPM
- **Tier 3**: 10,000,000 TPM

Each task with attacks uses ~2,000-5,000 tokens, so:
- Tier 1: ~6-15 tasks per minute
- With 30s delay: ~2 tasks per minute (safe for Tier 1)
- With 60s delay: ~1 task per minute (very safe)

## Monitoring Progress

Results are saved incrementally, so you can check progress:

```bash
# See what's been completed
ls -la results/workspace/

# Check latest results
cat results/workspace/*/authorization_metrics.json
```
