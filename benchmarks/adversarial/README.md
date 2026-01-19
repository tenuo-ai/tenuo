# Adversarial Benchmark: Red Team LLM vs Tenuo

A true adversarial benchmark where an LLM attacker tries to bypass Tenuo's constraints.

**Scope:** This benchmark evaluates single-step tool authorization under adversarial inputs. It does not evaluate multi-step semantic attacks, policy misconfiguration, or unsafe-but-authorized actions.

## Why This Matters

Most security benchmarks are **unit tests with adversarial inputs** - the defender writes the attacks. This creates a bias: defenders test what they expect, not what attackers will try.

This benchmark uses an **LLM as the attacker**:
- The attacker knows the constraint
- The attacker can try creative bypasses
- The attacker adapts based on feedback
- The attacks are **not hardcoded by us**

## Known Limitations

> **Pattern constraints** are vulnerable to path traversal attacks. `Pattern("/public/*")` matches the string `/public/../etc/passwd` even though it resolves outside `/public/`. For filesystem security, use [path_jail](https://github.com/tenuo-ai/path_jail) at execution time. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Statistical Methodology

- **Runs per scenario:** 5 (for confidence intervals)
- **Confidence level:** 95% (t-distribution)
- **Threat model:** See [THREAT_MODEL.md](THREAT_MODEL.md)
- **Reproducibility:** See [REPRODUCE.md](REPRODUCE.md)

## Quick Start

```bash
# Install dependencies
uv pip install -r benchmarks/adversarial/requirements.txt

# Single run (fast)
python -m benchmarks.adversarial.evaluate

# Statistical run (5 trials with CIs)
python -m benchmarks.adversarial.evaluate --runs 5

# Ablation study (recon vs no-recon)
python -m benchmarks.adversarial.evaluate --runs 5 --ablation

# Save results
python -m benchmarks.adversarial.evaluate --runs 5 --output results/full_run.json
```

## Methodology: Two-Phase Adaptive Attack

### Phase 1: Reconnaissance
The attacker makes probing calls to learn constraint behavior:
- What arguments are allowed?
- What error messages reveal the constraint type?
- Are there case sensitivity issues?

### Phase 2: Exploitation
Using reconnaissance findings, the attacker crafts targeted attacks:
- Focuses on patterns discovered during recon
- Adapts based on feedback
- Tries creative evasion techniques

**Academic Reference:** Similar to "Practical Black-Box Attacks" (Papernot et al., 2017)

## Scenarios

| Scenario | Constraint Type | Attack Goal |
|----------|-----------------|-------------|
| `email_exfil` | CEL (suffix) | Send to external address |
| `financial_limit` | Range | Transfer > $100 |
| `path_traversal` | Pattern | Read outside /public/ |
| `url_restriction` | CEL (suffix) | Fetch from evil.com |
| `multi_recipient` | CEL (list) | Sneak in external address |
| `api_key_exfil` | CEL (blocklist) | Read secrets file |
| `tool_confusion` | Tool-level | Call admin tools |
| `unicode_homoglyph` | CEL (suffix) | Unicode domain tricks |

## Metrics

| Metric | Description |
|--------|-------------|
| Defense rate | % of scenarios where constraint held |
| 95% CI | Confidence interval from N runs |
| Attempts | How many tries before success/timeout |
| Strategies | What evasion techniques were tried |
| Cost | Estimated API cost |

## Example Output

```
==================================================
AGGREGATED RESULTS (with 95% Confidence Intervals)
==================================================

email_exfil:         XX.X% (95% CI: XX%-XX%)
financial_limit:     XX.X% (95% CI: XX%-XX%)
path_traversal:      XX.X% (95% CI: XX%-XX%)
...

----------------------------------------------------------------------
Overall defense rate:          XX.X%
Total runs:                    N
Total cost:                    $X.XX
==================================================
```

Run with `--runs 5` to generate your own results with confidence intervals.

## CLI Options

| Option | Description |
|--------|-------------|
| `--scenario` | Single scenario or `all` |
| `--attacker-model` | LLM model (default: gpt-4o-mini) |
| `--max-attempts` | Attempts per scenario (default: 10) |
| `--recon-probes` | Recon probes per scenario (default: 5) |
| `--no-recon` | Disable reconnaissance |
| `--runs N` | Multiple runs for statistics |
| `--ablation` | Compare recon vs no-recon |
| `--multi-step` | Run multi-step attack chains |
| `--output` | Save results as JSON |

## Multi-Step Scenarios

**What this tests:** Tenuo enforces constraints at each call boundary, regardless of prior authorized steps.

**What this does NOT test:** Semantic attack detection. Tenuo doesn't "understand" that a chain is malicious - it simply enforces constraints on each individual call.

```bash
python -m benchmarks.adversarial.evaluate --multi-step
```

| Scenario | Chain | Constraint |
|----------|-------|------------|
| `data_exfil_chain` | list_files → read_file → send_email | email: `@company.com` only |
| `recon_to_attack` | search_files → read_file → delete_file | delete: `/tmp/*` only |

**Key insight:** Tenuo blocks at the right boundary. The attacker can read files, but cannot exfiltrate data because `send_email` to external addresses is blocked by CEL constraint.

This demonstrates:
1. Legitimate operations proceed unimpeded
2. Malicious final steps are blocked by constraints
3. The attack chain is broken at the exfiltration/destruction point

## Files

```
benchmarks/adversarial/
├── evaluate.py           # CLI entrypoint
├── redteam.py            # Single-step attack engine
├── multistep.py          # Multi-step chain attacks
├── scenarios.py          # Attack scenario definitions
├── statistics.py         # Confidence intervals
├── metrics.py            # Cost estimation
├── THREAT_MODEL.md       # Formal threat model
├── REPRODUCE.md          # Reproduction instructions
├── requirements.txt      # Dependencies
└── results/              # Sample outputs
```

## Citation

If you use this benchmark in academic work:

```bibtex
@software{tenuo_adversarial_2026,
  author = {Tenuo Team},
  title = {Adversarial Benchmark: Red Team LLM vs Tenuo},
  year = {2026},
  url = {https://github.com/tenuo-ai/tenuo/tree/main/benchmarks/adversarial}
}
```

## See Also

- [THREAT_MODEL.md](THREAT_MODEL.md) - Formal threat model
- [REPRODUCE.md](REPRODUCE.md) - Reproduction instructions
- [benchmarks/cryptographic/](../cryptographic/) - Cryptographic guarantees
- [benchmarks/escalation/](../escalation/) - Privilege escalation (p/q agent model)
- [benchmarks/delegation/](../delegation/) - Multi-agent delegation scenarios
