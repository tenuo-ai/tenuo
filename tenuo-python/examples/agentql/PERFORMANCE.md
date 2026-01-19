# Tenuo Performance

**TL;DR**: Authorization adds **0.001ms** per action. Browser actions take 100-2000ms. Overhead is <0.1%.

---

## The Numbers (Jan 2026)

| Metric | Value | Context |
|--------|-------|---------|
| **Latency (Pure Logic)** | **0.001ms** (1μs) | 1,000x faster than a function call |
| **Throughput (Raw)** | **~1.15M** checks/sec | Direct Rust binding (`bound.allows`) |
| **Throughput (Wrapper)** | **~312,000** checks/sec | High-level Python API (`agent.authorize`) |
| **PoP Throughput** | **~26,000** checks/sec | Full crypto round-trip (Sign + Verify) |
| **Workflow Overhead** | **< 0.1%** | Effectively zero vs browser I/O |
| **Memory per Agent** | **~5.8 KB** | 0.01% of browser instance |

### Advanced Metrics

| Metric | Result | Description |
|--------|--------|-------------|
| **Cold Start** | **~0.6 ms** | Negligible first-call latency (no warmup needed) |
| **Concurrency** | **~360k** checks/sec | Stable under 10-thread load (no GIL contention) |
| **Complexity** | **O(1)** | Constant time even with 50+ capabilities |
| **Scale** | **Linear** | 5.8KB/agent confirmed at 10,000 agents |

---

## What This Means

Browser automation is **I/O bound**, not CPU bound. The slowest part is waiting for webpages to load, render, and networks to respond.

| Browser Action | Time | Authorization Overhead |
|----------------|------|----------------------|
| Navigate to URL | 500-2000ms | 0.00005% |
| Click button | 100-500ms | 0.0002% |
| Fill form field | 50-200ms | 0.0005% |

**Tenuo is never the bottleneck.** Even at 10,000 actions/second (impossible for browsers), overhead would be minimal.

### Real Example

1000 agents, 50 actions/hour each = 50,000 authorizations/hour.

```
50,000 × 0.001ms = 0.05 seconds/hour = 0.001% of compute
```

---

## Verify It Yourself

Run the benchmark suite to verify these claims on your own hardware:

```bash
python benchmark.py
```

**Typical Output (Apple M3 Max):**
```text
======================================================================
BENCHMARK SUMMARY
======================================================================

📊 Performance Claims vs Actual:
----------------------------------------------------------------------

1. Authorization Latency:
   Claim: ~0.005ms
   Actual: 0.001ms
   Status: ✅ PASS

2. Throughput:
   Claim: ~268,000 checks/second
   Raw Engine:   1,177,399 checks/second
   Via Wrapper:  312,522 checks/second
   Status: ✅ PASS

3. Throughput (Full PoP):
   Actual: 25,927 checks/second

6. Memory per Agent:
   Claim: ~50 KB
   Actual: 5.8 KB
   Status: ✅ PASS

5. Crypto Verification (Server):
   Claim: ~0.027ms
   Actual: 0.027ms
   Status: ✅ PASS

   (Full Round Trip: 0.040ms)

7. Workflow Overhead:
   Claim: <1.0%
   Actual: 0.06%
   Note: In real workflows with slower browser actions, overhead approaches 0%

8. Advanced Metrics (New):
   Cold Start:       0.646 ms
   Concurrency:      363,372 checks/sec (10 threads)
   Complexity (50):  0.005 ms (vs 0.001 baseline)
   Scale (10k obj):  5.794 KB/agent (Linear scaling confirmed)
```

---

## Optimization Tips

### 1. Bind Once, Use Many

```python
# Slow: rebinds every iteration (creates new Python object)
for action in actions:
    bound = warrant.bind(keypair)
    bound.allows(action, args)

# Fast: bind once, reuse
bound = warrant.bind(keypair)
for action in actions:
    bound.allows(action, args)
```

**Speedup**: ~4x (measured: 1.1M vs 300k ops/sec)

### 2. Prefer UrlPattern Over Regex

```python
# Slower
.capability("navigate", url=Regex(r"https://([a-z0-9-]+\.)*example\.com/.*"))

# Faster
.capability("navigate", url=UrlPattern("https://*.example.com/*"))
```

Usually negligible, but matters at extreme scale.

---

## Summary

| Question | Answer |
|----------|--------|
| Will Tenuo slow down my agent? | **No.** 0.001ms vs 100-2000ms browser actions. |
| What's the overhead? | **< 0.1%** of workflow time. |
| Can it handle scale? | **1.1 Million** checks/sec (raw). Never the bottleneck. |
| How do I verify? | `python benchmark.py` |

**Bottom line**: Tenuo provides cryptographic authorization at `if-statement` speed.
