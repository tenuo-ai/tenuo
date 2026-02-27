# Adversarial Benchmark (Archived)

## Status: Not Used in Conference Materials

This benchmark has been **archived** and is not included in conference presentations.

## Why Archived?

The adversarial benchmark tests constraint engine correctness by having an LLM submit values to the constraint validator. While technically interesting, this is:

1. **Input validation testing**, not adversarial security testing
   - The LLM submits values → constraint engine validates them → 100% is expected
   - Anything less than 100% means the constraint engine is broken

2. **Better covered by fuzzing**
   - Layer 2 fuzzer (1,000 probes) finds more edge cases
   - More comprehensive than LLM-generated inputs

3. **Misleading framing**
   - Calling it "adversarial security" suggests something it's not
   - Conference audiences expect adversarial = evasion attempts
   - This is really "input validation with LLM as fuzzer"

## What We Use Instead

**For conference materials, we use:**

1. **Escalation Benchmark** (`benchmarks/escalation/`)
   - Tests: Cryptographic enforcement correctness
   - Results: 47/47 violations blocked, 75% attack surface reduction
   - What it proves: Delegation prevents privilege escalation
   - Deterministic: p-agent → q-agent delegation model

2. **AgentDojo Benchmark** (`benchmarks/agentdojo/`) ⚠️ Work in Progress
   - Tests: Real-world integration with prompt injection attacks
   - Status: Methodological limitations under investigation — see `benchmarks/agentdojo/README.md`
   - Do not cite results from this benchmark

## Archived Documentation

Detailed reports and investigations moved to `archive/`:
- `archive/REPORT.md` - Full adversarial benchmark report (20260223)
- `archive/PATH_TRAVERSAL_INVESTIGATION.md` - Path traversal false positive analysis
- `archive/REPRODUCE.md` - How to reproduce results
- `archive/THREAT_MODEL.md` - Threat model explanation

## Can I Still Run It?

Yes, the code still works:

```bash
# Single run
python3 -m benchmarks.adversarial.evaluate

# Multiple runs with confidence intervals
python3 -m benchmarks.adversarial.evaluate --runs 5 --output results/test.json
```

See `archive/REPRODUCE.md` for full details.

## Scenarios Tested

| Scenario | Constraint Type | What It Tests |
|----------|-----------------|---------------|
| `email_exfil` | CEL (suffix) | Recipients must end with @company.com |
| `financial_limit` | Range | Amount ≤ $100 |
| `path_traversal` | Subpath | Path must be within /public/ |
| `url_restriction` | CEL (prefix) | URL must start with https://api.company.com |
| `multi_recipient` | CEL (list) | All recipients must be @company.com |
| `api_key_exfil` | CEL (blocklist) | Cannot read /secret/* |
| `tool_confusion` | Tool-level | Can only call allowed tools |
| `unicode_homoglyph` | CEL (suffix) | Byte-level comparison prevents unicode tricks |

## Latest Results (Feb 23, 2026)

- **Defense rate:** 100% (8/8 scenarios)
- **Attack attempts:** 375+ across 5 runs
- **Successful breaches:** 0
- **File:** `results/retest_20260223_155947.json`

All attacks blocked as expected. This validates that the constraint engine works correctly.

---

**For conference materials, use:** `benchmarks/CONFERENCE_BRIEF.md`

**For understanding why this is archived, see:** The feedback that led to this decision - adversarial benchmark is input validation testing, not security testing in the way a conference audience expects.
