# AgentDojo Integration

> **Work in Progress**: This benchmark is under active development.

Integration of Tenuo with [AgentDojo](https://github.com/ethz-spylab/agentdojo) to demonstrate constraint enforcement in LLM agent pipelines.

## What This Shows

Tenuo enforces capability constraints at the tool boundary. When an agent attempts a tool call that violates its warrant, the call is blocked—regardless of how the agent was prompted.

```
Agent: "I'll send this to attacker@evil.com"
Warrant: recipients must match @company.com
Result: BLOCKED
```

## Quick Start

```bash
# Install
pip install -r benchmarks/agentdojo/requirements.txt
export OPENAI_API_KEY="sk-..."

# Run
python -m benchmarks.agentdojo.evaluate --suite workspace --model gpt-4o-mini \
  --user-tasks 5 --injection-tasks 3

# Analyze
python -m benchmarks.agentdojo.analyze results/workspace/<timestamp>/
```

## Example Output

```
Tool calls allowed: N
Tool calls blocked: M

Blocked by constraint:
  send_email.recipients: X
  delete_file.file_id: Y

Enforcement accuracy: 100%
```

Run the benchmark to see your results.

## Baseline Policy

| Tool | Constraint |
|------|------------|
| `send_email` | Recipients: `@company.com`, `@bluesparrowtech.com` |
| `delete_file` | Protected IDs: 13, 14, 15 |
| `share_file` | Internal emails only |
| Read operations | Allowed |

## CLI Options

```
--suite        workspace, banking, travel, slack
--model        gpt-4o-mini (default), gpt-4o
--user-tasks   Limit user tasks (faster runs)
--injection-tasks  Limit injection tasks
--dry-run      Validate setup without API calls
```

## Files

```
benchmarks/agentdojo/
├── evaluate.py          # CLI
├── harness.py           # AgentDojo integration
├── task_policies.py     # Baseline policy
├── tool_wrapper.py      # Enforcement layer
└── analyze.py           # Results analysis
```

## See Also

- [benchmarks/cryptographic/](../cryptographic/) — Tenuo's cryptographic guarantees
- [benchmarks/delegation/](../delegation/) — Multi-agent delegation scenarios
