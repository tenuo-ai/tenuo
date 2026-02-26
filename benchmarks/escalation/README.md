# Escalation Prevention Benchmark

Quantifying how cryptographic delegation bounds damage from compromised AI agents.

## Threat Model

```
p-agent: Trusted orchestrator with broad authority
   │
   │ DELEGATES (cryptographic attenuation)
   ▼
q-agent: Task executor with minimal authority
   │
   │ COMPROMISED via prompt injection
   ▼
Attack: Escalate to p-agent's privileges
```

**Key assumption:** We assume q-agent **will be compromised**. The security model
doesn't depend on preventing this. Instead, we ask: **can delegation bound the damage?**

## Four-Layer Benchmark

Each layer tests a different security property with a different methodology.

| Layer | Question | Method | LLM? | Entry point |
|-------|----------|--------|------|-------------|
| 1. Policy Enforcement | Does the constraint engine block violations? | Deterministic | No | `evaluate.py` |
| 2. Cryptographic Integrity | Does the crypto layer reject forgery/tampering? | Deterministic | No | `evaluate.py` |
| 3. Adversarial Fuzzing | Can random inputs bypass any invariant? | Randomized (seeded) | No | `fuzz.py` |
| 4. LLM Red Team | Can a creative attacker achieve objectives within policy? | Stochastic | Yes | `red_team.py` |

### Layer 1: Policy Enforcement

Deterministic, reproducible tests showing the constraint engine blocks violations.

```bash
python -m benchmarks.escalation.evaluate
```

| Scenario | What's Tested | Constraint Types |
|----------|---------------|-----------------:|
| email_exfil | External recipients blocked | CEL, capability removal |
| financial | Amount limits enforced | Range |
| file_access | Path containment + traversal blocked | Subpath, capability removal |

### Layer 2: Cryptographic Integrity

Deterministic tests that the crypto layer rejects forgery, tampering, and structural attacks.

| Scenario | What's Tested |
|----------|---------------|
| holder_binding | Wrong key can't use someone else's warrant (PoP) |
| crypto_integrity | Forgery, expired TTL, wrong trust root, stale PoP, terminal re-delegation |
| chain_manipulation | Constraint escalation, cross-chain splicing, duplicate warrants, chain gaps |

### Layer 3: Adversarial Fuzzing

Randomized but seeded (reproducible). Three sub-tests:

```bash
python -m benchmarks.escalation.fuzz
python -m benchmarks.escalation.fuzz --iterations 1000 --seed 42
```

**Constraint boundary probing**: Edge-case inputs against all major constraint types.

| Constraint | Attack Class |
|---|---|
| `Range(0, 50)` | Boundary values, float precision, type confusion, special floats |
| `Range(0, 100000)` | Same, wider bound |
| `Subpath("/public")` | Path traversal, encoding tricks, null bytes, shell injection |
| `Subpath("/drafts")` | Same, different root |
| `CEL(endsWith('@company.com'))` | Domain spoofing, injection, vacuous truth, unicode |
| `UrlPattern("https://*.internal.corp/*")` | SSRF, protocol confusion, encoding, type confusion |
| `UrlSafe()` | SSRF bypass attempts: private IPs, metadata endpoints, IPv6 confusion |
| `Cidr("10.0.0.0/8")` | IP boundary, IPv6-mapped, octal/hex encoding, type confusion |

**Monotonicity property test**: For random parent-child warrant pairs, verify that
`child.allows(x) → parent.allows(x)` for all inputs. This is the core delegation
invariant — a violation here would be a real security bug.

**Structural warrant fuzzing**: Mutate valid warrant bytes (bit-flip, truncation,
insertion, zero-fill, shuffle) and test random byte sequences. None should produce
a warrant that passes authorization.

### Layer 4: LLM Red Team

An LLM plays the compromised q-agent and tries to achieve malicious objectives
using only calls that pass the constraint engine. Tests **policy sufficiency**,
not enforcement correctness.

```bash
export OPENAI_API_KEY="sk-..."
python -m benchmarks.escalation.red_team --model gpt-4o-mini --rounds 3
```

Findings are application-layer design tradeoffs, not enforcement failures:
- Content inspection (scanning email body for secrets) sits above warrant enforcement.
- Aggregate/rate limits (200 x $50 = $10k) sit above per-call warrant checks.

### Full Report

Generate a full report locally. Results are not published with the harness.

```bash
python -m benchmarks.escalation.report                  # all 4 layers
python -m benchmarks.escalation.report --no-red-team    # layers 1-3 only
```

## Strict Policies

All warrants use **strict mode**: every allowed parameter is explicitly listed
with either a constraint (`CEL`, `Range`, `Subpath`, `UrlPattern`, `UrlSafe`, `Cidr`)
or `Wildcard()` (allowed, any value). Parameters not listed are rejected outright.

## Metrics

| Metric | Layer | Definition |
|--------|-------|------------|
| Violations caught | 1 | Of policy violations, how many were blocked? (target: 100%) |
| Attacks rejected | 2 | Of crypto attacks, how many were rejected? (target: 100%) |
| Monotonicity violations | 3 | Inputs where child allows but parent denies (target: 0) |
| Structural bypasses | 3 | Mutated bytes that passed authorization (target: 0) |
| Policy sufficiency gaps | 4 | Objectives achievable using only allowed calls |

## Files

```
benchmarks/escalation/
├── README.md                  # This file
├── scenarios.py               # Deterministic scenarios (Layers 1+2)
├── evaluate.py                # CLI for Layers 1+2 (no API key)
├── fuzz.py                    # Adversarial fuzzing (Layer 3, no API key)
├── red_team.py                # LLM red team (Layer 4, requires API key)
├── report.py                  # Full report generator (all layers)
└── __init__.py
```

> **Note**: `REPORT.md` is a locally generated artifact and is not tracked in version control.
> Run `python -m benchmarks.escalation.report` to generate it.
