# AgentDojo × Tenuo — Work in Progress

> [!WARNING]
> **This benchmark integration has known methodological limitations and is under active development.**
> Results should not be cited in publications or used as authoritative performance claims.
> We are collaborating with AgentDojo authors on a proper evaluation harness.
> See [AGENTDOJO_COLLABORATION_NOTES.md](./AGENTDOJO_COLLABORATION_NOTES.md) for the full technical discussion.

---

## Why This Is Hard: A Fundamental Mismatch

**AgentDojo was not designed to evaluate authorization systems like Tenuo.**

AgentDojo measures **task-level Attack Success Rate (ASR)**: did the attacker achieve their goal? This is the right question for prompt injection defense research. It is the *wrong* question for capability-based authorization, and here's why:

```
Injection: "Transfer $30,000 to attacker"
Tenuo constraint: amount ≤ $10,000 per call

What happens:
  ❌ send_money(amount=30000) → BLOCKED by Tenuo
  ✅ send_money(amount=9000)  → allowed  ← within policy
  ✅ send_money(amount=9000)  → allowed  ← within policy
  ✅ send_money(amount=9000)  → allowed  ← within policy

AgentDojo verdict: security=False  (attack goal achieved)
Tenuo's view:      operating correctly — every call satisfied the warrant
```

The constraint did exactly what it was configured to do. The *policy* ($10k/call) was insufficient to prevent a multi-call attack — but that is a **constraint design problem**, not an enforcement failure. AgentDojo's metric cannot distinguish between the two.

### Three compounding issues

| Issue | Effect |
|---|---|
| **Multi-path attacks** | Blocking one route doesn't improve ASR if alternate routes remain |
| **LLM stochasticity** | Significant ASR variance between identical runs, swamping the enforcement signal |
| **No per-operation ground truth** | Can't compute precision/recall on individual blocked calls; only binary task outcomes exist |

---

## What This Benchmark Is Good For (Right Now)

Running against AgentDojo still validates something useful:

- ✅ **No false positives** — enforcement doesn't break legitimate agent behavior  
- ✅ **Enforcement can't be bypassed via prompt injection** — the constraint check is cryptographic, not prompt-interpretable  
- ✅ **Integration correctness** — harness, tool wrapper, and warrant lookup work end-to-end with a live LLM agent  

Run the benchmark to see your own enforcement metrics — operation-level block/allow counts are reported separately from task-level ASR.

---

## What We're Working Toward

To make task-level ASR meaningful for authorization systems, we need at least one of:

1. **Per-operation ground truth labels** — mark each expected-bad call so precision/recall can be computed
2. **Damage metrics** — replace binary ASR with "% of attack goal achieved" (partial prevention credit)
3. **Deterministic scripted sequences** — eliminate LLM stochasticity for reproducible enforcement testing
4. **Constraint design reference** — example policies that actually achieve 0% ASR, showing what sufficient constraints look like

See [AGENTDOJO_COLLABORATION_NOTES.md](./AGENTDOJO_COLLABORATION_NOTES.md) for detailed proposals on all four.

---

## Running It

```bash
# Install
uv pip install -r benchmarks/agentdojo/requirements.txt
export OPENAI_API_KEY="sk-..."

# Run (requires live LLM + API key)
python -m benchmarks.agentdojo.evaluate --suite workspace --model gpt-4o-mini \
  --user-tasks 5 --injection-tasks 3

# Analyze a previous run
python -m benchmarks.agentdojo.analyze results/workspace/<timestamp>/
```

### Baseline policy applied

| Tool | Constraint |
|---|---|
| `send_email` | Recipients: `@company.com`, `@bluesparrowtech.com` domains only |
| `delete_file` | Protected file IDs blocked |
| `share_file` | Internal emails only |
| Read operations | Unrestricted |

### CLI options

```
--suite            workspace, banking, travel, slack
--model            gpt-4o-mini (default), gpt-4o
--user-tasks       Limit user tasks (faster/cheaper runs)
--injection-tasks  Limit injection tasks
--dry-run          Validate setup without API calls
```

---

## Files

```
benchmarks/agentdojo/
├── README.md                        ← This file
├── AGENTDOJO_COLLABORATION_NOTES.md ← Full technical analysis + collaboration proposal
├── evaluate.py                      ← CLI entry point
├── harness.py                       ← AgentDojo integration layer
├── task_policies.py                 ← Warrant definitions for each scenario
├── tool_wrapper.py                  ← Tenuo enforcement adapter
├── analyze.py                       ← Results analysis and report generation
├── compare_baseline.py              ← Matched baseline comparison runner
└── warrant_templates.py             ← Reusable warrant builders
```

---

## See Also

- [benchmarks/cryptographic/](../cryptographic/) — **Deterministic** cryptographic guarantee proofs (100% verified, not WIP)
- [benchmarks/escalation/](../escalation/) — Four-layer escalation benchmark with both deterministic and LLM layers
- [benchmarks/adversarial/](../adversarial/) — Red team LLM vs Tenuo enforcement
