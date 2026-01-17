# Tenuo × AgentQL Security Demo

An educational demonstration of how Tenuo provides cryptographic authorization and least-privilege enforcement for browser agents.

This demo explores a general security pattern for browser agents and uses AgentQL as a concrete, representative example.

## What This Demonstrates

### Core Security Patterns

1. **Confused Deputy Attack Prevention** (ACT 3)
   - Shows how prompt injection cannot bypass authorization
   - Demonstrates "Layer 2" security (cryptographic enforcement) vs "Layer 1" (prompt engineering)

2. **Multi-Agent Delegation with Attenuation** (ACT 4)
   - Visualizes warrant provenance chains
   - Shows cryptographic privilege narrowing
   - Demonstrates that privilege escalation is mathematically impossible

3. **Capability-Based Authorization** (Throughout)
   - Actions are authorized against cryptographic warrants
   - Every action is logged with full warrant chain
   - Compromised agents have limited "blast radius"

## Quick Start

### Option 1: Mock Demo (Recommended for First Time)

```bash
# Run the demo (uses mock AgentQL, no API keys needed)
python demo.py

# Expected output:
# - ACT 1: Warrant visualization with chain depth
# - ACT 2: Authorized actions (navigate, fill, click)
# - ACT 3: Blocked "Confused Deputy" attacks (simulated)
# - ACT 4: Multi-agent delegation with provenance chain
```

**Pro**: Fast, deterministic, free, works offline  
**Con**: Simulated LLM behavior (not as compelling)

### Option 2: Real LLM Demo (Recommended)

This demo uses real AI agents (via OpenAI or Anthropic) and real browser automation (via Playwright/AgentQL).

**1. Setup Environment**

```bash
# Install dependencies
pip install agentql playwright openai anthropic

# Install Tenuo (local development)
pip install -e ../../../

# Install Playwright browsers
playwright install
```

**2. Set API Keys**

```bash
export OPENAI_API_KEY="sk-..."       # Required for OpenAI
# OR
export ANTHROPIC_API_KEY="sk-ant-.." # Required for Anthropic
```

**3. Run**

```bash
# Run all scenarios
python demo_llm.py

# Run specific scenarios
python demo_llm.py --simple       # Part 1: Basic Prompt Injection
python demo_llm.py --delegation   # Part 2: Multi-Agent Delegation
python demo_llm.py --dlp          # Part 3: Data Loss Prevention
python demo_llm.py --advanced     # Run all advanced scenarios

# Use Claude (Anthropic)
python demo_llm.py --anthropic --advanced
```

**Pro**: Shows REAL attacks being blocked in real-time (much more compelling)  
**Con**: Requires API key, costs a few cents (~$0.02 per run), non-deterministic

**Recommendation**: 
- **Learning**: Start with mock demo to understand concepts
- **Quick demo**: `python demo_llm.py --simple` for 5-minute presentation
- **Security deep dive**: `python demo_llm.py` for full sophisticated attack scenarios
- **Conference talk**: Run full LLM demo to show realistic attacks

### LLM Demo Scenarios

The `demo_llm.py` includes both simple and advanced attack scenarios:

**Simple Scenario** (Part 1):
- Direct prompt injection with "IGNORE INSTRUCTIONS"
- Shows the core concept clearly
- ~5 minutes

**Advanced Scenarios** (Part 2):
1. **Indirect Injection**: Attack embedded in page content ("System Alert" popup)
2. **Social Engineering**: Multi-step escalation building trust
3. **Multi-Agent Delegation**: "Orchestrator" delegates attenuated rights to "Intern"
4. **Data Loss Prevention (DLP)**: Preventing PII exfiltration via `query()`

These advanced scenarios show why prompt engineering alone cannot solve AI security.

## Files

| File | Purpose |
|------|---------|
| `demo_llm.py` | **Entrypoint**: Real LLM demo with all scenarios |
| `wrapper.py` | Security wrapper implementing Tenuo authorization |
| `demo.py` | Mock demo (Offline / No API Key) |
| `mock_agentql.py` | Mock backend for offline demo |
| `README.md` | This file - complete documentation |

## Key Concepts

### Warrants

Cryptographically signed authorization tokens that grant specific capabilities:

```python
warrant = (Warrant.mint_builder()
    .capability("navigate", url=UrlPattern("https://example.com/*"))
    .capability("fill", element=OneOf(["search_box"]))
    .capability("click", element=OneOf(["submit_button"]))
    .holder(agent_keypair.public_key)
    .ttl(3600)
    .mint(user_keypair)
)
```

### Delegation & Attenuation

Agents can delegate warrants with reduced privileges:

```python
# Parent: Can navigate *.example.com, fill anything, click anything
parent_warrant = Warrant.create(...)

# Child: Can only navigate search.example.com, fill search_box, cannot click
child_warrant = (parent_warrant.grant_builder()
    .capability("navigate", url=UrlPattern("https://search.example.com/*"))
    .capability("fill", element=OneOf(["search_box"]))
    # Note: 'click' capability removed
    .grant(parent_keypair)
)
```

**Key Property:** Privilege escalation is mathematically impossible due to cryptographic signature chains.

### Provenance Chains

The demo visualizes trust flow:

```
📜 Warrant Provenance Chain:

   🔑 ROOT: User → Orchestrator
          Can: navigate, fill, click
          TTL: 3600 seconds

      ↓ L1: Orchestrator → Worker
            Can: fill, navigate
            TTL: 1800 seconds
```

## Security Properties

1. **Confused Deputy Prevention**: Agent cannot be tricked into exceeding authorization
2. **Privilege Attenuation**: Capabilities only decrease in delegation chains
3. **Blast Radius Limitation**: Compromised agents have minimal impact
4. **Audit Trail**: Every action logged with full provenance
5. **Time-Bounded Access**: Warrants expire automatically

## Integration Pattern

This demo shows how to integrate Tenuo with browser automation libraries:

1. **Wrapper Pattern** (`SecureProxy`, `SecureLocatorProxy`)
   - Intercepts method calls transparently
   - Authorizes actions against warrants
   - Preserves semantic context (element labels)

2. **Method Mapping** (`METHOD_TO_CAPABILITY`)
   - Maps library-specific methods to Tenuo capabilities
   - Extensible configuration for different APIs

3. **Audit Logging** (`AuditEntry`)
   - Automatic logging of all authorization decisions
   - Includes timestamp, action, target, and result

## Semantic Labels

The demo includes a note on semantic label-based policies:

```python
# Instead of brittle CSS selectors:
capabilities = {
    "fill": Constraint.pattern(["div > span:nth-child(3)"])  # ← Breaks on DOM changes
}

# Use semantic labels:
capabilities = {
    "fill": Constraint.enum(["search_box"])  # ← Stable, human-readable
}
```

**Benefits:**
- Policies survive DOM restructuring
- Human-readable security policies
- Better audit logs

## Testing

See [`TESTING.md`](./TESTING.md) for instructions on:
- Running with real AgentQL
- Verifying API compatibility
- Common issues and fixes

## Learn More

- **Tenuo Documentation**: [tenuo.dev](https://tenuo.dev)
- **Wire Format Spec**: [`docs/spec/wire-format-v1.md`](../../../docs/spec/wire-format-v1.md)
- **Other Integrations**: OpenAI, LangChain, LangGraph, MCP, Google ADK

## License

This demo is part of the Tenuo open-source project.
