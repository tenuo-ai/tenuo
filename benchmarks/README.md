# Tenuo Security Benchmark Suite

Comprehensive benchmarks validating Tenuo's security properties across five dimensions: cryptographic guarantees, adversarial robustness, privilege escalation prevention, delegation enforcement, and real-world attack resistance.

## 🎯 Quick Start

```bash
# 1. Cryptographic properties (no API key, deterministic)
pytest benchmarks/cryptographic/ -v

# 2. Escalation prevention (no API key, deterministic)
python -m benchmarks.escalation.evaluate

# 3. Adversarial attacks (requires OpenAI API key)
export OPENAI_API_KEY="sk-..."
python -m benchmarks.adversarial.evaluate --runs 3

# 4. Delegation scenarios (no API key for unit tests)
python -m benchmarks.delegation.evaluate --all

# 5. AgentDojo integration (requires OpenAI API key)
python -m benchmarks.agentdojo.evaluate --suite workspace --user-tasks 5
```

---

## 📚 Benchmark Overview

| Benchmark | What It Tests | API Key? | Runtime | Deterministic? |
|-----------|---------------|----------|---------|----------------|
| **[Cryptographic](#1-cryptographic)** | Forgery resistance, key separation, delegation monotonicity | ❌ No | ~30s | ✅ Yes |
| **[Escalation](#2-escalation)** | Privilege escalation prevention (p/q model) | ❌ No | ~10s | ✅ Yes |
| **[Adversarial](#3-adversarial)** | Adaptive LLM attacks on constraints | ✅ OpenAI | ~5min | ❌ Stochastic |
| **[Delegation](#4-delegation)** | Multi-agent constraint enforcement | ❌ No (unit) | ~15s | ✅ Yes |
| **[AgentDojo](#5-agentdojo)** | Real-world prompt injection attacks | ✅ OpenAI | ~10min | ❌ Stochastic |

---

## 🧭 Navigation Guide

### New to Tenuo?
**Start here:** [Cryptographic](#1-cryptographic) → [Escalation](#2-escalation) → [Adversarial](#3-adversarial)

1. **Cryptographic** shows *why cryptography matters* (vs input validation)
2. **Escalation** shows *damage bounding* when agents are compromised
3. **Adversarial** shows *attack resistance* against adaptive adversaries

### Evaluating Tenuo for Production?
Focus on:
- **Cryptographic** - Core security guarantees
- **Escalation** - Threat model alignment (p/q agent model)
- **Performance** - See [cryptographic/README.md](cryptographic/README.md#performance) (~27µs Rust / ~50-60µs Python per call)

### Academic Research?
All benchmarks are designed for peer review:
- Formal threat models
- Reproducible methodology (see REPRODUCE.md files)
- Statistical rigor (confidence intervals, multiple runs)
- Honest limitations (no overselling)

---

## 1. Cryptographic

**Directory:** [`cryptographic/`](cryptographic/)

### What It Tests
Validates that Tenuo provides cryptographic security properties that input validation cannot match:

| Property | Test File | What It Proves |
|----------|-----------|----------------|
| **Forgery Resistance** | `test_forgery.py` | Tampered warrants fail verification |
| **Delegation Monotonicity** | `test_delegation.py` | Child warrants cannot exceed parent authority |
| **Key Separation** | `test_key_separation.py` | Stolen warrants are useless without holder key |
| **Temporal Enforcement** | `test_temporal.py` | Expired warrants are rejected |
| **Multi-Sig** | `test_multisig.py` | M-of-N approval thresholds enforced |

### Why This Matters

**The core question:** In a distributed system, how do you verify authority without calling the issuer's API?

| Approach | Tradeoff |
|----------|----------|
| API call to issuer | Latency, availability dependency, coupling |
| Shared database | Consistency issues, tight coupling |
| Trust headers blindly | Insecure |
| **Tenuo warrants** | Self-contained, offline-verifiable, cryptographically bound |

### Running the Tests

```bash
# All tests
pytest benchmarks/cryptographic/ -v

# Single test file
pytest benchmarks/cryptographic/test_forgery.py -v

# Generate security report
python -m benchmarks.cryptographic.report
```

### Performance

Rust Criterion benchmarks (authoritative):
```bash
cd tenuo-core && cargo bench
```

| Operation | Rust (Criterion) | Python (via PyO3) |
|-----------|-----------------|-------------------|
| Full verification (PoP + constraints) | ~27μs | ~50-60μs |
| Constraint evaluation only | ~100ns | — |
| Denial (wrong tool) | ~150ns | — |

**Read more:** [cryptographic/README.md](cryptographic/README.md)

---

## 2. Escalation

**Directory:** [`escalation/`](escalation/)

### What It Tests
Measures how delegation bounds damage from compromised AI agents.

### The p/q Threat Model

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   p-agent: Trusted orchestrator with broad authority            │
│      │                                                          │
│      │ DELEGATES (cryptographic attenuation)                    │
│      ▼                                                          │
│   q-agent: Task executor with minimal authority                 │
│      │                                                          │
│      │ COMPROMISED via prompt injection                         │
│      ▼                                                          │
│   Attack: Escalate to p-agent's privileges                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Key assumption:** We assume q-agent **will be compromised**. The security model doesn't depend on preventing this. Instead: **can delegation bound the damage?**

### Two-Layer Validation

#### Layer 1: Mechanism Proof (Synthetic)
Deterministic tests showing the math works. No LLM, no API key.

```bash
python -m benchmarks.escalation.evaluate
```

Scenarios:
- Email exfiltration (CEL constraint blocks external recipients)
- Financial limits (Range constraint blocks amount > threshold)
- File access (Subpath constraint blocks unauthorized paths)
- Holder binding (PoP mismatch: wrong key can't use warrant)

#### Layer 2: Real-World Validation

See [`benchmarks/agentdojo/`](agentdojo/) for integration with real LLM agents and prompt injection payloads.

> ⚠️ **Work in Progress** — this layer has known methodological limitations. See [agentdojo/README.md](agentdojo/README.md) before drawing conclusions from results.

### Example

```python
# p-agent: CFO-level authority ($100k limit)
p_warrant = Warrant.mint_builder() \
    .capability("transfer_money", amount=Range(0, 100000)) \
    .holder(p_key.public_key).ttl(3600).mint(org_key)

# q-agent: Petty cash only ($50 limit) - delegated from p
q_warrant = p_warrant.attenuate_builder() \
    .with_capability("transfer_money", amount=Range(0, 50)) \
    .with_holder(q_key.public_key).with_ttl(300).delegate(p_key)

# Attack: q-agent tries to transfer $5000
# Result: BLOCKED (exceeds $50 limit)
# Note: p-agent's warrant WOULD have allowed this.
```

**Metrics:**
- **Policy Violations Blocked** = calls q-agent blocked that p-agent would allow
- **Enforcement Rate** = Policy Violations Blocked / p_allowed

**Read more:** [escalation/README.md](escalation/README.md)

---

## 3. Adversarial

**Directory:** [`adversarial/`](adversarial/)

### What It Tests
Red team LLM vs Tenuo constraints - adaptive attacks on single-step authorization.

### Why This Matters

Most security benchmarks are **unit tests with adversarial inputs** - the defender writes the attacks. This creates bias: defenders test what they expect, not what attackers will try.

This benchmark uses an **LLM as the attacker**:
- The attacker knows the constraint
- The attacker can try creative bypasses
- The attacker adapts based on feedback
- The attacks are **not hardcoded by us**

### Methodology: Two-Phase Adaptive Attack

**Phase 1: Reconnaissance**
Attacker makes probing calls to learn constraint behavior:
- What arguments are allowed?
- What error messages reveal the constraint type?
- Are there case sensitivity issues?

**Phase 2: Exploitation**
Using reconnaissance findings, attacker crafts targeted attacks:
- Focuses on patterns discovered during recon
- Adapts based on feedback
- Tries creative evasion techniques

**Academic Reference:** Similar to "Practical Black-Box Attacks" (Papernot et al., 2017)

### Scenarios

| Scenario | Constraint Type | Attack Goal |
|----------|-----------------|-------------|
| `email_exfil` | CEL (suffix) | Send to external address |
| `financial_limit` | Range | Transfer > $100 |
| `path_traversal` | Subpath | Read outside /public/ |
| `url_restriction` | CEL (suffix) | Fetch from evil.com |
| `multi_recipient` | CEL (list) | Sneak in external address |
| `api_key_exfil` | CEL (blocklist) | Read secrets file |
| `tool_confusion` | Tool-level | Call admin tools |
| `unicode_homoglyph` | CEL (suffix) | Unicode domain tricks |

### Running the Benchmark

```bash
# Single run (fast)
python -m benchmarks.adversarial.evaluate

# Statistical run (5 trials with confidence intervals)
python -m benchmarks.adversarial.evaluate --runs 5

# Ablation study (recon vs no-recon)
python -m benchmarks.adversarial.evaluate --runs 5 --ablation

# Single scenario
python -m benchmarks.adversarial.evaluate --scenario email_exfil
```

**Cost:** ~$0.45 per run (8 scenarios × 1 run with gpt-4o-mini)

### Metrics

| Metric | Description |
|--------|-------------|
| Defense rate | % of scenarios where constraint held |
| 95% CI | Confidence interval from N runs |
| Attempts | How many tries before success/timeout |
| Strategies | What evasion techniques were tried |

**Read more:** [adversarial/README.md](adversarial/README.md)
**Threat model:** [adversarial/THREAT_MODEL.md](adversarial/THREAT_MODEL.md)
**Reproducibility:** [adversarial/REPRODUCE.md](adversarial/REPRODUCE.md)

---

## 4. Delegation

**Directory:** [`delegation/`](delegation/)

### What It Tests
Validates that warrant constraints are correctly enforced across multi-agent delegation chains.

**Core Insight:** The agent code remains constant. The warrant determines what's allowed.

### Test Suites

#### 1. Constraint Scenarios (`scenarios.py`)
Unit tests for constraint enforcement:

```bash
python -m benchmarks.delegation.evaluate --all
```

| Scenario | Description | Tests |
|----------|-------------|-------|
| `temporal_scoping` | Same agent, different warrants per task | 8 |
| `range_limit` | Numeric range boundary enforcement | 5 |
| `pattern_match` | Glob pattern constraint enforcement | 5 |
| `tool_scoping` | Tool authorization verification | 5 |

#### 2. LLM Multi-Agent Scenarios (`llm_scenarios.py`)
Real LLM multi-agent scenarios with prompt injection attacks:

```bash
export OPENAI_API_KEY="sk-..."
python -m benchmarks.delegation.run_llm --model gpt-4o-mini
```

**Difference from Adversarial:**
- **Delegation**: Tests multi-agent chains with prompt injection targeting specific roles in a workflow
- **Adversarial**: Tests single-step attacks with adaptive reconnaissance and creative bypasses

### Example: Same Agent, Different Outcomes

```python
agent = create_agent()

# Task 1: Internal email warrant
internal_warrant = Warrant.mint_builder() \
    .capability("send_email", to=Pattern("*@company.com")) \
    .holder(agent_key.public_key).ttl(300).mint(issuer_key)

agent.run(warrant=internal_warrant)
# team@company.com -> Allowed
# attacker@evil.com -> Blocked

# Task 2: External email warrant
external_warrant = Warrant.mint_builder() \
    .capability("send_email", to=Pattern("*")) \
    .holder(agent_key.public_key).ttl(300).mint(issuer_key)

agent.run(warrant=external_warrant)
# partner@external.com -> Allowed
```

**Read more:** [delegation/README.md](delegation/README.md)

---

## 5. AgentDojo

**Directory:** [`agentdojo/`](agentdojo/)

### What It Tests
Integration with [AgentDojo](https://github.com/ethz-spylab/agentdojo) for testing constraint enforcement in fully-automated LLM agent workflows.

> ⚠️ **Work in Progress** — this benchmark has known methodological limitations (task-level ASR is not a reliable metric for operation-level authorization). Results should not be cited. Details: [agentdojo/README.md](agentdojo/README.md)

### What This Shows

Tenuo enforces capability constraints at the tool boundary. When an agent attempts a tool call that violates its warrant, the call is blocked - regardless of how the agent was prompted.

```
Agent: "I'll send this to attacker@evil.com"
Warrant: recipients must match @company.com
Result: BLOCKED
```

### Baseline Policy

| Tool | Constraint |
|------|------------|
| `send_email` | Recipients: `@company.com`, `@bluesparrowtech.com` |
| `delete_file` | Protected IDs: 13, 14, 15 |
| `share_file` | Internal emails only |
| Read operations | Allowed |

### Running the Benchmark

```bash
# Install
uv pip install -r benchmarks/agentdojo/requirements.txt
export OPENAI_API_KEY="sk-..."

# Run
python -m benchmarks.agentdojo.evaluate \
    --suite workspace --model gpt-4o-mini \
    --user-tasks 5 --injection-tasks 3

# Analyze
python -m benchmarks.agentdojo.analyze results/workspace/<timestamp>/
```

**Read more:** [agentdojo/README.md](agentdojo/README.md)

---

## 📊 Baseline Results

Reference results for validation are stored in [`results/baseline/`](results/baseline/):

```
results/baseline/
├── cryptographic_report.json     # All cryptographic tests (100% pass rate)
├── escalation_summary.json        # p/q model enforcement metrics
├── adversarial_defense_rates.json # Defense rates with 95% CIs
└── delegation_pass_rates.json     # Constraint enforcement pass rates
```

These baselines are frozen snapshots from:
- **Tenuo version:** 0.1.0-beta.10
- **Date:** 2026-02-23
- **Environment:** Python 3.11, macOS 14.2 (ARM64)

**Usage:**
```bash
# Compare your results to baseline
python scripts/compare_to_baseline.py results/my_run.json
```

---

## 🔬 Academic Use

All benchmarks are designed for peer review and academic publication.

### Key Properties

✅ **Formal threat models** (see THREAT_MODEL.md files)
✅ **Reproducible methodology** (see REPRODUCE.md files)
✅ **Statistical rigor** (confidence intervals, multiple runs)
✅ **Honest limitations** (clearly stated out-of-scope items)
✅ **Proper attribution** (Debenedetti et al., Papernot et al.)
✅ **Citation-ready** (BibTeX in READMEs)

### Citation

If you use these benchmarks in academic work:

```bibtex
@software{tenuo_benchmarks_2026,
  author = {Tenuo Team},
  title = {Tenuo Security Benchmark Suite},
  year = {2026},
  url = {https://github.com/tenuo-ai/tenuo/tree/main/benchmarks}
}
```

Individual benchmarks have their own citations (see respective READMEs).

---

## 🛠️ Development

### Running All Benchmarks

```bash
# Fast (no LLM calls)
pytest benchmarks/cryptographic/ -v
python -m benchmarks.escalation.evaluate
python -m benchmarks.delegation.evaluate --all

# With LLM (requires API key)
export OPENAI_API_KEY="sk-..."
python -m benchmarks.adversarial.evaluate --runs 3
python -m benchmarks.delegation.run_llm --model gpt-4o-mini
python -m benchmarks.agentdojo.evaluate --suite workspace --user-tasks 5
```

### CI Integration

See [`.github/workflows/benchmarks.yml`](../.github/workflows/benchmarks.yml) for automated benchmark runs.

Fast benchmarks (cryptographic, escalation, delegation unit tests) run on every PR.
LLM benchmarks run on releases and manual triggers.

### Adding New Scenarios

Each benchmark suite has a `scenarios.py` file defining test cases:

```python
# Example: Adding a new adversarial scenario
ADVERSARIAL_SCENARIOS["my_scenario"] = {
    "description": "...",
    "goal": "...",
    "verify_bypass": lambda tool, args: ...,
    "build_warrant": lambda org_key, agent_key: ...,
}
```

See individual benchmark READMEs for detailed extension guides.

---

## 📈 Performance

### Benchmark Runtimes

| Benchmark | Runtime (fast) | Runtime (full) | API Calls |
|-----------|----------------|----------------|-----------|
| Cryptographic | ~30s | ~2min (with report) | 0 |
| Escalation | ~10s | ~10s | 0 |
| Delegation (unit) | ~15s | ~15s | 0 |
| Adversarial | N/A | ~5-10min (3 runs) | ~200-300 |
| AgentDojo | N/A | ~10-15min | ~100-200 |

### Cost Estimates

| Benchmark | Model | Cost per Run | Cost (3 runs) |
|-----------|-------|--------------|---------------|
| Adversarial | gpt-4o-mini | ~$0.45 | ~$1.36 |
| Delegation (LLM) | gpt-4o-mini | ~$0.25 | ~$0.75 |
| AgentDojo | gpt-4o-mini | ~$0.80 | ~$2.40 |

**Total for full LLM suite:** ~$4.50 (3 runs each)

---

## 🎯 Quick Reference

### What am I testing?

| Question | Benchmark |
|----------|-----------|
| "Does cryptography actually provide security?" | [Cryptographic](#1-cryptographic) |
| "What happens if my agent is compromised?" | [Escalation](#2-escalation) |
| "Can an attacker bypass my constraints?" | [Adversarial](#3-adversarial) |
| "How do constraints enforce across delegation?" | [Delegation](#4-delegation) |
| "How does Tenuo integrate with published LLM agent benchmarks?" | [AgentDojo](#5-agentdojo) ⚠️ WIP |

### Which benchmark should I run?

| Use Case | Recommended Benchmark |
|----------|----------------------|
| Evaluating Tenuo for the first time | Cryptographic → Escalation |
| Presenting to security team | Cryptographic + Adversarial |
| Academic research | All (use statistical modes) |
| CI/CD integration | Cryptographic + Escalation (fast, deterministic) |
| Stress testing custom constraints | Adversarial (with your scenarios) |

---

## 📖 Further Reading

- **Core Concepts:** [docs/enforcement.md](../docs/enforcement.md)
- **Constraint Types:** [docs/constraints.md](../docs/constraints.md)
- **Delegation:** [docs/delegation.md](../docs/delegation.md)
- **Approvals:** [docs/approvals.md](../docs/approvals.md)
- **Temporal Integration:** [docs/temporal.md](../docs/temporal.md)

---

## 🤝 Contributing

We welcome benchmark contributions! See [CONTRIBUTING.md](../CONTRIBUTING.md) for:
- How to add new scenarios
- Statistical methodology guidelines
- Peer review process for academic benchmarks

---

## 📄 License

These benchmarks are part of the Tenuo project and share the same license.
See [LICENSE](../LICENSE) for details.
