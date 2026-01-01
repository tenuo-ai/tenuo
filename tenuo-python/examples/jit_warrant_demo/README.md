# Just-in-Time Warrant Demo

> **Orchestrator-Worker Pattern with Multi-Sig Human Approval**

This demo showcases production-realistic patterns for AI agent security:

1. **Orchestrator** analyzes tasks and proposes capabilities (via LLM)
2. **Control Plane** validates against security policy
3. **Human** cryptographically signs approval
4. **Workers** receive attenuated (subset) warrants
5. **Execution** with Proof-of-Possession on every call

## Prerequisites

```bash
pip install tenuo rich  # rich is optional but recommended for beautiful output
```

For real LLM mode (optional):
- [LM Studio](https://lmstudio.ai/) running locally with a model loaded

## Quick Start

```bash
# Full demo (basic flow)
python demo.py --simulate --auto-approve

# Full demo with delegation + temporal mismatch demos
python demo.py --simulate --auto-approve --delegation

# With LM Studio (real LLM reasoning)
python demo.py --auto-approve --delegation
```

### What You'll See

```
┏━━━━━━━━━━━━━ 🔐 APPROVAL REQUIRED ━━━━━━━━━━━━━┓
┃ Task: Summarize this URL: https://docs.python.org
┃ Requested Capabilities:
┃  • fetch_url (url constraint enforced)
┃  • summarize (no constraints)
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
✅ MULTI-SIG APPROVAL COMPLETE
✅ AUTHORIZED (PoP Verified + 2 multi-sig approvals)
⛔ BLOCKED: Tool 'http_request' not in warrant
```

## Security Concepts Demonstrated

### 1. Multi-Sig Human Approval

Both system AND human must cryptographically approve before authorization succeeds.

This demo uses Tenuo's real `Approval` class:
- Each approver creates a signed `Approval` object bound to a specific request
- Approvals are passed to `Authorizer.authorize()` for verification
- Both approvals must be valid (not expired) and correctly signed

```python
from tenuo import Approval

# System creates its approval
system_approval = Approval.create(
    warrant=warrant,
    tool="fetch_url",
    args={"url": "https://docs.python.org"},
    keypair=system_key,
    external_id="control_plane@system",
    provider="policy-engine",
    ttl_secs=300,
)

# Human reviews and creates their approval
human_approval = Approval.create(
    warrant=warrant,
    tool="fetch_url",
    args={"url": "https://docs.python.org"},
    keypair=human_key,
    external_id="reviewer@company.com",
    provider="human-review",
    ttl_secs=300,
    reason="Approved for scheduled task"
)

# Both approvals passed to authorization
authorizer.authorize(warrant, tool, args, signature, 
                     approvals=[system_approval, human_approval])
```

```
┌─────────────────────────────────────────────────────────────┐
│ System Approval                                             │
│  ✓ Policy check passed                                      │
│  ✓ System signed with key: PublicKey(886417b3...)           │
├─────────────────────────────────────────────────────────────┤
│ Human Approval                                              │
│  ✓ Security Reviewer reviewed the proposal                  │
│  ✓ Cryptographically signed with key: PublicKey(6e0b7468...)│
└─────────────────────────────────────────────────────────────┘
```

### 2. Attenuation (Least Privilege Delegation)

Orchestrator delegates SUBSETS of its authority to specialized workers.

```
Orchestrator Warrant: fetch_url(docs.python.org), summarize
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         ┌─────────┐    ┌──────────┐    ┌──────────┐
         │ Fetcher │    │Summarizer│    │  Writer  │
         │fetch_url│    │summarize │    │write_file│
         │ (1 URL) │    │  only    │    │ /tmp/*   │
         └─────────┘    └──────────┘    └──────────┘

Each worker can ONLY use its specific capability.
Fetcher cannot summarize. Summarizer cannot fetch.
```

### 3. Temporal Mismatch

What happens when a valid warrant becomes stale due to changing requirements.

```
T0 (Earlier): Worker received warrant for Python 3.11 docs
              fetch_url(https://docs.python.org/3.11/*)

T1 (Now):     Current task requires Python 3.12 docs
              https://docs.python.org/3.12/whatsnew

T2 (Problem): Worker's warrant doesn't match!
              • fetch_url(3.12/whatsnew) -> ⛔ BLOCKED
              • fetch_url(3.11/whatsnew) -> ✅ AUTHORIZED (still valid!)
```

**Solution**: Short TTLs + Just-in-Time minting ensure warrants match current requirements.

### 4. Monotonicity Enforcement

Authority can only DECREASE through delegation, never increase.

```
Orchestrator has:     fetch_url(docs.python.org)
Attempts to delegate: fetch_url(admin.internal.corp/secrets)
Result:               ⛔ BLOCKED - Monotonicity violation
```

You CANNOT:
- Grant capabilities you don't have
- Relax constraints
- Extend TTL beyond parent

### 5. Proof-of-Possession (PoP)

Every tool call is cryptographically signed with the agent's private key.

```
Agent calls: fetch_url(url="https://docs.python.org")
             │
             ▼
┌─────────────────────────────────────────────────┐
│ 1. Sign intent with private key (PoP)           │
│ 2. Verify signature matches warrant holder      │
│ 3. Check constraints (url in allowed list)      │
│ 4. Execute or block                             │
└─────────────────────────────────────────────────┘
```

Even if someone steals the warrant, they can't use it without the private key.

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                     CONTROL PLANE + HUMAN                          │
│  System Key: Signs policy-validated proposals                      │
│  Human Key:  Signs reviewed proposals (multi-sig)                  │
└───────────────────────────┬────────────────────────────────────────┘
                            │ Multi-Sig Warrant
                            ▼
┌────────────────────────────────────────────────────────────────────┐
│                       ORCHESTRATOR                                  │
│  - Analyzes task (LLM reasoning)                                   │
│  - Receives multi-sig warrant                                      │
│  - Delegates ATTENUATED warrants to workers                        │
└─────────────┬──────────────────────────────────┬───────────────────┘
              │                                  │
              ▼                                  ▼
     ┌─────────────────┐                ┌─────────────────┐
     │  Fetcher Worker │                │Summarizer Worker│
     │  fetch_url only │                │  summarize only │
     │  (specific URL) │                │                 │
     └─────────────────┘                └─────────────────┘
```

## Demo Flags

| Flag | Description |
|------|-------------|
| `--simulate` | Run without LLM (pattern matching) |
| `--auto-approve` | Skip interactive human approval prompt |
| `--delegation` | Show attenuation + temporal mismatch demos |
| `--no-attack` | Skip prompt injection simulation |
| `--slow N` | Add N-second pauses between steps (for presentations) |
| `--task "..."` | Custom task (include URLs) |

## Key Security Properties

| Property | How It's Enforced |
|----------|-------------------|
| Multi-Sig | System AND human must sign |
| Least Privilege | Workers get attenuated subsets |
| Monotonicity | Can't grant what you don't have |
| Temporal Safety | Short TTLs + JIT minting |
| PoP Binding | Agent proves key possession |
| Attack Containment | Even compromised LLM bound by warrant |
