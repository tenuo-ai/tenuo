# Map vs Territory: Blog Demos

Interactive demos for the blog post **"The Map is not the Territory: The Agent-Tool Trust Boundary"**.

## Quick Start

```bash
# Core demo (no dependencies required)
cd tenuo-python/examples/blog_demos/map_territory
python streaming_toctou.py

# Full demo suite (simulated attacks)
pip install tenuo path-jail url-jail proc-jail
python map_vs_territory.py

# Real LLM demo (requires OpenAI API key)
pip install openai tenuo
export OPENAI_API_KEY=sk-...
python map_vs_territory.py --openai

# Prompt injection demo (most impactful!)
python map_vs_territory.py --inject
```

## Demos

### 1. `map_vs_territory.py` — Attack Scenarios

Interactive menu showing how attacks exploit the gap between validation (the Map) and execution (the Territory).

**Scenarios:**
1. **Path Traversal** — URL encoding bypass (`..%2f`) — *like CVE-2024-3571*
2. **SSRF** — Decimal IP + redirect attack — *like CVE-2025-2828, CVE-2024-0243*
3. **Command Injection** — Newline injection (no semicolon needed)
4. **Homoglyph** — Cyrillic `і` vs Latin `i` (visually identical, different bytes)
5. **Symlink Escape** — Layer 1.5 passes, Layer 2 catches — *like CVE-2025-3046*

**Output:**
```
┌───────────────────────────────────────────────────────────────┐
│  ATTACK: Path Traversal (URL Encoding Bypass)                │
└───────────────────────────────────────────────────────────────┘

  Input: read_file("/data/foo%2f..%2f..%2fetc/passwd")

  [Layer 1   ] Regex: checking for '..' and prefix
  [Layer 1   ] ✅ PASS — Starts with "/data/", no ".."
  ⚠️  Attack passes Layer 1

  [Layer 1.5 ] Subpath: URL decode, normalize, check containment
  [          ] URL decode: "/data/foo%2f..%2f..%2fetc/passwd" → "/data/foo/../etc/passwd"
  [          ] Normalize:  → "/etc/passwd"
  [Layer 1.5 ] ❌ BLOCKED — Normalizes to "/etc/passwd" — escapes /data
  🛡️  Attack blocked at Layer 1.5
```

**Dependencies:**
- `tenuo` — Layer 1.5 (semantic validation)
- `path-jail` — Layer 2 (filesystem guards)
- `url-jail` — Layer 2 (network guards)
- `proc-jail` — Layer 2 (process execution guards)

The demo degrades gracefully — shows what it can with what's installed.

**`--openai` mode:** Real LLM demo that:
1. Asks GPT-4o-mini to read `/etc/passwd`
2. **Unprotected:** Executes the tool call → shows actual file contents 😱
3. **With Tenuo:** `Subpath("/data")` blocks the tool call → attack prevented

**`--inject` mode:** Path traversal demo (shows Tenuo's real value!):
1. Attack path: `/data/../etc/passwd`
2. **Naive check:** `startswith('/data/')` → passes! 💀
3. **Tenuo Subpath:** normalizes first → `/etc/passwd` → BLOCKED 🛡️

This demo proves why you need semantic validation, not if-statements.

```bash
python map_vs_territory.py --inject  # No API key needed for core demo
```

### 2. `streaming_toctou.py` — TOCTOU Vulnerability

Demonstrates Time-of-Check-to-Time-of-Use vulnerabilities in LLM tool calls.

**Two modes:**
```bash
# Streaming TOCTOU (partial JSON)
python streaming_toctou.py

# Filesystem TOCTOU (symlink race)
python streaming_toctou.py --race
```

**Default mode** shows how validating partial JSON leads to TOCTOU.

**Race mode** shows the filesystem race window:
- Layer 1.5 validates the path string ✓
- Attacker swaps symlink in the race window
- Kernel opens the wrong file
- Layer 2 (path_jail) catches this at execution time

**Simulated mode output:**

```
┌───────────────────────────────────────────────────────────────┐
│  VULNERABLE: Validate-As-You-Go                              │
└───────────────────────────────────────────────────────────────┘

  [Buffer  ] {"path": "/data/report.txt"}
  [VALIDATE] JSON complete! Checking: "/data/report.txt"
  [VALIDATE] ✅ PASS — starts with /data/
  [EXECUTE ] 🚀 read_file("/data/report.txt") — TRIGGERED

            ...but more tokens are still arriving...

  [Buffer  ] {"path": "/data/report.txt/../../../etc/passwd"}

  ─────────────────────────────────────────────────────────────
  [RESULT  ] 💀 ATTACK SUCCEEDED
  
            Validated: "/data/report.txt"
            Executed:  "/data/report.txt/../../../etc/passwd"
            Opened:    "/etc/passwd"
  ─────────────────────────────────────────────────────────────
```

Includes:
- Side-by-side comparison diagram
- The code fix (buffer-verify-emit pattern)
- Tenuo's actual implementation (`GuardedCompletions._guard_stream()`)

## Key Insights

1. **Layer 1 (Regex)** validates syntax. Attackers encode semantics differently.
2. **Layer 1.5 (Tenuo)** validates semantics. But it's still the Map — doesn't see symlinks or DNS.
3. **Layer 2 (Jails)** validates reality. Touches the actual filesystem/network at execution time.

**The streaming insight:** Never validate partial tool arguments. Buffer the complete JSON. Verify. Only then execute.

## Learn More

- [Blog Post](https://niyikiza.com/posts/map-territory/)
- [Tenuo GitHub](https://github.com/tenuo-ai/tenuo)
- [path-jail](https://github.com/tenuo-ai/path-jail)
- [url-jail](https://github.com/tenuo-ai/url-jail)
- [proc-jail](https://github.com/tenuo-ai/proc-jail)
