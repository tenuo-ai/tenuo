# Tenuo CrewAI Examples

**These demos show where prompt-based guardrails fail and capability-based authorization holds.**

This directory contains integration examples and security demos for Tenuo's CrewAI integration using the native hooks API (v2.0).

## Integration Examples

Learn how to use Tenuo's APIs with these focused examples:

### quickstart.py

Basic constraint-based protection using `GuardBuilder` and the hooks API.

```bash
python quickstart.py
```

**Demonstrates:**
- Creating guards with the builder pattern
- Using semantic constraints (Subpath, Pattern, Range, Wildcard)
- Handling denied tool calls
- Guard introspection and validation
- Hooks API usage (`guard.register()`)

### hierarchical_delegation.py

Warrant-based delegation for hierarchical crews using `WarrantDelegator`.

```bash
python hierarchical_delegation.py
```

**Demonstrates:**
- Creating warrants for manager agents
- Delegating narrowed authority to worker agents
- Attenuation-only delegation (scope can only narrow)
- Escalation prevention
- Hooks-based authorization at the framework level

### guarded_crew.py (146 lines)

Policy-based protection for entire crews using `GuardedCrew`.

```bash
python guarded_crew.py
```

**Demonstrates:**
- Defining role-based policies (who can use what)
- Applying per-tool constraints (how they can use it)
- Strict mode to catch unguarded tool calls
- Audit logging for all authorization decisions
- Fail-closed behavior with `on_denial("raise")`

### guarded_flow.py (41 lines)

Step-level protection for CrewAI Flows using `@guarded_step` decorator.

```bash
python guarded_flow.py
```

**Demonstrates:**
- Protecting individual Flow steps
- Setting TTLs per step
- Step-specific constraints
- Strict mode enforcement

---

## Security Demos

See Tenuo in action preventing real attacks:

### demo_simple.py (216 lines)

Deterministic demo showing prompt injection defense and delegation attenuation.

```bash
python demo_simple.py              # Protected
python demo_simple.py --unprotected  # No protection (see attack succeed)
python demo_simple.py --slow       # Slower pacing for presentations
```

**Part 1: Delegation with Attenuation**
- Manager has `/data/*` access
- Researcher gets attenuated warrant (`/data/papers/*` only)
- Attenuation prevents privilege escalation

**Part 2: Prompt Injection Defense**
- Malicious content in data file attempts path traversal
- Tenuo blocks unauthorized file access
- Detailed audit output shows attempted vs allowed paths

**Part 3: Escalation Prevention**
- Researcher attempts to widen scope via delegation
- Cryptographic enforcement prevents escalation

### demo_live.py (201 lines)

Real LLM demo with CrewAI agent and indirect injection attack.

```bash
export OPENAI_API_KEY="sk-..."
python demo_live.py              # Protected
python demo_live.py --unprotected  # See attack succeed
python demo_live.py --quiet      # Less verbose output
```

**Attack scenario:**
- Config file contains subtle injection: references `credentials_file` outside safe directory
- Agent task is "validate deployment configuration"
- LLM follows the reference and attempts to read credentials
- Tenuo blocks the unauthorized access

**Note:** LLM behavior varies. Use `demo_simple.py` for guaranteed demonstration.

### research_team_demo.py (939 lines)

Comprehensive demo with multiple attack vectors and multi-agent delegation.

```bash
python research_team_demo.py         # Simulation mode
python research_team_demo.py --live  # Real LLM mode
python research_team_demo.py --attacks  # Show all attack scenarios
```

**Attack scenarios:**
- SSRF: Attempts to access AWS metadata endpoint
- Path traversal: Tries to read `/etc/passwd`
- Privilege escalation: Worker attempts to access manager resources
- Data exfiltration: Unauthorized file access

**Multi-agent architecture:**
- Manager delegates to Researcher and Analyst
- Each agent has narrowed warrant scope
- Demonstrates hierarchical delegation chains

---

## Quick Start

```python
from tenuo.crewai import GuardBuilder, Subpath

# Create guard with constraints
guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .on_denial("raise")
    .build())

# Register as global hook - ALL tool calls go through authorization
guard.register()

# Use tools directly - hooks intercept all calls
agent = Agent(
    role="Researcher",
    tools=[read_file_tool],  # No wrapping needed
)

# Run crew
crew.kickoff()

# Cleanup
guard.unregister()
```

## Key Concept

```
Traditional approach: Hope the LLM refuses malicious requests
Tenuo approach: Cryptographically enforce constraints

The warrant is the source of truth, not the prompt.
```

## See Also

- [Full CrewAI Documentation](../../docs/crewai.md)
- [API Reference](../../docs/api.md)
