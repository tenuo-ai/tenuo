# CrewAI Integration Demos

**These demos show where prompt-based guardrails fail and capability-based authorization holds.**

Demos showing Tenuo's value for CrewAI multi-agent systems.

## Which demo should I run?

| Goal | Demo | Why | Prerequisites |
|------|------|-----|---------------|
| **Quick first look** | `demo_simple.py` | Deterministic, no API key needed | None |
| **Sales/presentation** | `demo_simple.py --slow` | Reliable pacing, guaranteed output | None |
| **Real LLM behavior** | `demo_live.py` | Actual CrewAI agent with indirect injection | OPENAI_API_KEY |
| **All attack vectors** | `research_team_demo.py --attacks` | Comprehensive security scenarios | None (simulation mode) |
| **Full hierarchical delegation** | `research_team_demo.py` | Multi-agent architecture with attenuation | None (simulation mode) |
| **Production integration** | `research_team_demo.py --live` | Real CrewAI workflow with Tenuo | OPENAI_API_KEY |

**Recommendation for first-time users:** Start with `demo_simple.py`, then try `demo_live.py` if you have an API key.

## demo_simple.py (210 lines)

Deterministic demo with real CrewAI components. Uses `guard.protect(tool)` public API.

```bash
python demo_simple.py              # Protected
python demo_simple.py --unprotected  # No protection
python demo_simple.py --slow       # Slower for recording
```

**Part 1: Delegation with Attenuation**
- Manager has `/data/*` access via protected tool
- Researcher gets attenuated warrant (`/data/papers/*` only)
- Same tool, different warrants - attenuation blocks escalation

**Part 2: Prompt Injection via CrewAI**
- CrewAI tool wrapper receives the call
- Tenuo intercepts at authorization layer
- Detailed DENY output shows attempted vs allowed paths

## demo_live.py (177 lines)

Real LLM demo with CrewAI agent. Uses `guard.protect(tool)` public API.

```bash
export OPENAI_API_KEY="sk-..."
python demo_live.py              # Protected
python demo_live.py --unprotected  # See attack succeed
python demo_live.py --quiet      # Less verbose output
```

**Features:**
- Subtle injection: config file references `credentials_file` outside safe directory
- Task is "validate deployment" - doesn't ask for credentials explicitly
- Professional audit output with attempted/allowed/decision details

**Caveat:** LLM behavior varies. Use `demo_simple.py` for guaranteed demonstration.

## research_team_demo.py (923 lines)

Full-featured demo with multiple attack scenarios.

```bash
python research_team_demo.py         # Simulation mode
python research_team_demo.py --live  # Real LLM
```

## Key Insight

```
Traditional: Hope the LLM refuses malicious requests.
Tenuo: Enforce constraints regardless of what the LLM decides.

The warrant is the source of truth, not the prompt.
```

## Additional APIs (Not Shown in Demos)

These demos focus on security scenarios. For additional integration patterns, see the [full documentation](../../docs/crewai.md):

- **GuardedCrew**: Policy-based protection for entire crews
- **@guarded_step**: Decorator for protecting CrewAI Flow steps
- **WarrantDelegator**: Explicit delegation API (shown in research_team_demo.py)

Quick example:
```python
from tenuo.crewai import GuardedCrew

crew = (GuardedCrew(agents=[...], tasks=[...])
    .policy({"Researcher": ["read_file", "search"]})
    .constraints({"Researcher": {"read_file": {"path": Subpath("/data")}}})
    .build())
```
