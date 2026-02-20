# Google ADK Integration

Tenuo provides first-class support for [Google's Agent Development Kit (ADK)](https://github.com/google/adk-toolkit), enabling warrant-based authorization and constraint validation for ADK agents.

---

## Which Pattern Should I Use?

**Answer these questions:**

1. **Are your tools running in the same process as the agent?**
   - Yes -> Tier 1 (GuardBuilder with inline constraints)
   - No -> Tier 2 (Warrant + Proof-of-Possession)

2. **Do you need protection against insider threats or code tampering?**
   - Yes -> Tier 2 (constraints in cryptographic warrant)
   - No -> Tier 1 is sufficient

3. **Do you need to delegate tasks to other agents?**
   - Yes -> Tier 2 + [A2A integration](./a2a.md)
   - No -> ADK integration only

**TL;DR:** Start with Tier 1. Move to Tier 2 when you need crypto.

---

## Installation

```bash
uv pip install "tenuo[google_adk]"
```

---

## Quick Start

### Tier 1: With Constraints (5 minutes)

Use the **builder pattern** for semantic constraints that block attacks:

```python
from google.adk.agents import Agent
from tenuo.google_adk import GuardBuilder
from tenuo.constraints import Subpath, UrlSafe

# Build guard with inline constraints
guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .allow("web_search", url=UrlSafe(allow_domains=["*.google.com"]))
    .build())

# Create agent with guard
agent = Agent(
    name="assistant",
    tools=guard.filter_tools([read_file, web_search]),
    before_tool_callback=guard.before_tool,
)
```

**What gets blocked:**
- `read_file("/etc/passwd")` - path traversal outside `/data`
- `web_search(url="http://169.254.169.254/")` - SSRF to AWS metadata
- `delete_file(...)` - tool not in `.allow()` list
- Any argument not explicitly constrained (Zero Trust)

**Simple allowlist only?** Use `protect_agent()` for basic protection without constraints:

```python
from tenuo.google_adk import protect_agent

agent = protect_agent(my_agent, allow=["search", "read_file"])
```

---

## Tier 2: Warrants (Production)

When you need cryptographic proof that constraints haven't been tampered with:

```python
from google.adk.agents import Agent
from tenuo.google_adk import GuardBuilder
from tenuo import SigningKey, Warrant
from tenuo.constraints import Subpath

# Agent's signing key (proves possession)
agent_key = SigningKey.generate()

# Control plane issues warrant with constraints
warrant = (Warrant.mint_builder()
    .capability("read_file", path=Subpath("/data"))
    .capability("web_search")
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_plane_key))

# Build guard from warrant
guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .build())

agent = Agent(
    name="assistant",
    tools=guard.filter_tools([read_file, web_search]),
    before_tool_callback=guard.before_tool,
)
```

**Why Tier 2?** Constraints live in the warrant (signed by control plane), not in your code. Even if an attacker modifies your Python, they can't change what the warrant allows.

---

## Skill Mapping (When Names Don't Match)

If your tool function name differs from the warrant skill name:

```python
# Warrant has skill "read_file", but your function is named "read_file_tool"
guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .map_skill("read_file_tool", "read_file")  # tool_name -> skill_name
    .build())
```

**Helpful error messages:** When a tool isn't found, Tenuo suggests fixes:

```
ToolAuthorizationError: Tool 'read_file_tool' not found in warrant

Warrant has skills: ['read_file', 'web_search']
Did you mean 'read_file'?

Fix: Add skill mapping to your GuardBuilder:
  .map_skill("read_file_tool", "read_file")
```

---

## Tier 1 Security Model

### What Tier 1 Protects Against

**Trust Boundary**: Code access

Tier 1 enforces constraints at runtime, protecting against:

| Threat | Protection | Example |
|--------|------------|---------|
| **Prompt Injection** | Strong | Attacker manipulates LLM to call `read_file("/etc/passwd")` - blocked by `Subpath("/data")` |
| **LLM Hallucinations** | Strong | Model invents tool call with invalid args - blocked by constraints |
| **SSRF Attempts** | Strong | LLM tries `http://169.254.169.254/` - blocked by `UrlSafe()` |
| **Path Traversal** | Strong | `../../../etc/passwd` - normalized and blocked by `Subpath` |
| **Development Bugs** | Strong | Accidental misconfiguration caught before production |

**Key Insight**: Tier 1 is effective because **constraints are outside the LLM's control**. Even if an attacker fully manipulates the prompt, they cannot bypass Python-enforced guardrails.

### What Tier 1 Does NOT Protect Against

| Threat | Protection | Why Not |
|--------|------------|---------|
| **Insider Threats** | None | Developer can modify code to bypass guards |
| **Container Compromise** | None | Attacker with code execution can disable guards |
| **Tampering** | None | No cryptographic proof of enforcement |
| **Multi-Process Delegation** | Limited | Downstream service must trust caller's honesty |

**Example Bypass**:
```python
# Production code with guard
guard = GuardBuilder().with_warrant(warrant, key).build()

# Insider threat: Just don't use the guard
agent = Agent(tools=[...])  # Bypassed
```

### When to Use Tier 1

**Good for**:
- Single-process agents (LLM and tools in same Python runtime)
- Trusted execution environment (your laptop, internal servers)
- Prototyping and development
- Defense against external attackers (via prompt injection)

**Not suitable for**:
- Untrusted execution environment (shared infrastructure)
- Zero-trust security model
- Compliance requirements for audit trails
- Multi-process systems with untrusted intermediaries

### When to Upgrade to Tier 2

Upgrade when you need:

1. **Cryptographic Proof**: Verifiable evidence of what was authorized
2. **Delegation Chains**: Multi-agent systems where agents delegate to each other
3. **Untrusted Callers**: Cannot trust calling agent to honestly report tool calls
4. **Audit Requirements**: Need non-repudiable logs of authorization decisions

**Tier 2 adds**:
- Warrant signatures (cryptographic authorization)
- Proof-of-Possession (PoP) per tool call
- Tamper-evident audit trail
- Cross-process verification

**Migration is simple**:
```python
# Tier 1
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

# Tier 2 (add warrant + signing key)
guard = GuardBuilder().with_warrant(warrant, signing_key).build()
```

### Bottom Line

Tier 1 stops prompt injection, LLM hallucinations, and SSRF attacks. It enforces constraints at runtime within a single Python process.

Tier 2 adds cryptographic verification for distributed systems and untrusted execution environments.

**Choose based on your threat model:**
- Single-process, trusted execution: Tier 1
- Multi-process, delegation, or untrusted execution: Tier 2

---

## Closed-World Constraints (Zero Trust)

> [!IMPORTANT]
> **Tenuo enforces Zero Trust for arguments.**
> Once you add **any** constraint to a tool, Tenuo switches to a "closed-world" model for that tool.
>
> This means **ANY argument not explicitly listed in your constraints will be REJECTED**.
> Tenuo does not silently ignore extra arguments—it blocks them to prevent "shadow argument" attacks.
>
> ```python
> # ❌ Blocks call with 'timeout' arg because it's unknown
> guard = GuardBuilder().allow("api_call", url=UrlSafe()).build()
>
> # ✅ Explicitly allow unknown args (less secure)
> guard = GuardBuilder().allow("api_call", url=UrlSafe(), _allow_unknown=True).build()
>
> # ✅ Or allow specific field with Wildcard
> from tenuo.constraints import Wildcard
> guard = GuardBuilder().allow("api_call", url=UrlSafe(), timeout=Wildcard()).build()
> ```

---

## Constraint Types

Tenuo provides production-ready constraints for common attack vectors:

### Subpath: Secure Path Containment

`Subpath` blocks path traversal attacks that `Pattern` cannot catch:

```python
from tenuo.constraints import Subpath

# Secure: Normalizes paths before checking
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

# Blocks: /data/../etc/passwd → normalizes to /etc/passwd → outside /data
# Blocks: /data/./../../etc/passwd → same
# Allows: /data/reports/file.txt → inside /data
```

### UrlSafe: SSRF Protection

`UrlSafe` blocks Server-Side Request Forgery (SSRF) attempts:

```python
from tenuo.constraints import UrlSafe

# Block private IPs, localhost, cloud metadata
guard = GuardBuilder().allow("fetch", url=UrlSafe()).build()

# Blocks: http://169.254.169.254/ (AWS metadata)
# Blocks: http://127.0.0.1/ (localhost)
# Blocks: http://10.0.0.1/ (private network)
# Blocks: http://2130706433/ (decimal IP encoding)

# With domain allowlist
strict = UrlSafe(allow_domains=["api.example.com", "*.googleapis.com"])
# Allows: https://api.example.com/v1
# Allows: https://storage.googleapis.com/bucket
# Blocks: https://evil.com/
```

### Pattern: Glob Matching

Simple glob-style matching for strings:

```python
from tenuo.constraints import Pattern

# Email domain restriction
guard = GuardBuilder().allow("send_email", to=Pattern("*@company.com")).build()

# Query filtering
guard = GuardBuilder().allow("search", query=Pattern("product:*")).build()
```

### Range: Numeric Bounds

Enforce min/max values for numeric arguments:

```python
from tenuo.constraints import Range

guard = GuardBuilder().allow("set_volume", level=Range(0, 100)).build()
guard = GuardBuilder().allow("api_call", timeout=Range(1, 60)).build()
```

### OneOf: Enumerated Values

Restrict to specific allowed values:

```python
from tenuo.constraints import OneOf

guard = GuardBuilder().allow(
    "set_mode",
    mode=OneOf(["read-only", "read-write", "admin"])
).build()
```

---

## Integration Patterns

### Tool Filtering

`filter_tools()` removes unauthorized tools before agent creation:

```python
all_tools = [read_file, write_file, delete_file, web_search]

# Only read_file and web_search will be visible to the agent
filtered = guard.filter_tools(all_tools)

agent = Agent(
    name="assistant",
    tools=filtered,  # Reduced tool set
    before_tool_callback=guard.before_tool,
)
```

**Why filter?** Don't waste tokens showing tools the LLM can't use.

### ScopedWarrant (Multi-Agent Isolation)

When multiple agents share the same session, use `ScopedWarrant` to prevent cross-agent warrant leaks:

```python
from tenuo.google_adk import TenuoPlugin, ScopedWarrant

# At agent creation time, scope the warrant
plugin = TenuoPlugin(warrant_key="my_warrant")
scoped = ScopedWarrant(warrant, agent_name="research_agent")

# Store in session state
session_state["my_warrant"] =scoped

# Before each turn, plugin validates the warrant belongs to this agent
agent = Agent(
    name="research_agent",
    before_agent_callback=plugin.before_agent_callback,
)
```

### Argument Remapping

Map ADK tool argument names to warrant constraint names:

```python
guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .map_skill("read_file_tool", "read_file", file_path="path")
    .build())

# Tool called with {"file_path": "/data/report.txt"}
# Validated against warrant's "path" constraint
```

### Denial Handling

Control what happens when a tool call is denied:

```python
# Raise exception (stops execution)
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).on_denial("raise").build()

# Return error dict (agent sees denial reason)
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).on_denial("return").build()

# Silent skip (not recommended - can confuse LLM)
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).on_denial("skip").build()
```

### Error Handling

Google ADK integration uses custom exceptions (`ToolAuthorizationError`, `MissingSigningKeyError`) for API consistency. However, the underlying Tenuo authorization still uses canonical wire codes internally:

```python
from tenuo.google_adk import GuardBuilder, ToolAuthorizationError

guard = (GuardBuilder()
    .allow("transfer", amount=Range(0, 1000))
    .on_denial("raise")
    .build())

try:
    guard.check("transfer", {"amount": 5000})
except ToolAuthorizationError as e:
    print(f"Tool denied: {e}")
    print(f"Tool: {e.tool_name}")
    print(f"Args: {e.tool_args}")
    # For programmatic handling, parse the error message
    # or use on_denial("return") mode for structured responses
```

**Structured Error Mode:**

Using `on_denial("return")` provides structured error responses:

```python
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

result = guard.check("read_file", {"path": "/etc/passwd"})
# {
#   "authorized": False,
#   "reason": "Constraint 'path' failed: not contained in /data",
#   "tool": "read_file",
#   "details": {...}
# }
```

**Note**: Google ADK is designed as a higher-level wrapper with ADK-specific error handling. For direct access to Tenuo's canonical wire codes (1000-2199), use the `tenuo.langchain` integration or raw `Warrant.authorize()` calls.

---

## Audit Logging

Every tool call decision is logged with context:

```python
def audit_callback(event):
    print(f"[AUDIT] {event.decision} tool={event.tool_name} agent={event.agent_name}")
    # Send to your logging system

guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .audit_callback(audit_callback)
    .build())
```

**Event fields**:
- `decision`: "allowed" or "denied"
- `tool_name`: Name of the tool
- `agent_name`: From ToolContext (if available)
- `arguments`: Tool arguments
- `session_id`: Unique session identifier
- `timestamp`: When the decision was made

---

## Builder API Reference

### `.allow(tool_name, **constraints)`

Allow a tool with optional constraints (Tier 1):

```python
guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .allow("search", query=Pattern("*"))
    .build())
```

### `.with_warrant(warrant, signing_key)`

Use cryptographic warrant (Tier 2):

```python
guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .build())
```

### `.map_skill(tool_name, skill_name, **arg_mappings)`

Map tool/argument names to warrant skills:

```python
guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .map_skill("read_file_tool", "read_file", file_path="path")
    .build())
```

### `.on_denial(mode)`

Control denial behavior (`"raise"`, `"return"`, `"skip"`):

```python
guard = GuardBuilder().allow("read_file").on_denial("raise").build()
```

### `.audit_callback(callback)`

Register audit logging callback:

```python
def log_audit(event):
    logger.info(f"{event.decision}: {event.tool_name}")

guard = GuardBuilder().allow("read_file").audit_callback(log_audit).build()
```

---

## Advanced: Dynamic Warrants

For per-request warrants (e.g., user-specific capabilities):

```python
# Configure guard to look up warrant from session state
guard = (GuardBuilder()
    .with_warrant_key("user_warrant")  # Key in ToolContext.session_state
    .build())

# At runtime, inject user-specific warrant
def handle_request(user_id):
    warrant = issue_warrant_for_user(user_id)
    session_state["user_warrant"] = warrant
    
    # Agent uses the injected warrant
    agent.run(...)
```

---

## Tier 1 vs Tier 2 Comparison

| Feature | Tier 1 (Direct) | Tier 2 (Warrant + PoP) |
|---------|-----------------|------------------------|
| **Setup** | `.allow()` builder | Warrant issuance + signing key |
| **Cryptographic proof** | ❌ No | ✅ Yes (Ed25519 signatures) |
| **Protection against insider threats** | ❌ No | ✅ Yes |
| **Multi-agent delegation** | ❌ No | ✅ Yes (attenuation chains) |
| **Audit trail** | ✅ Events only | ✅ Cryptographic receipts |
| **Performance** | Fast (no crypto) | Slightly slower (signature checks) |
| **Use case** | Prototyping, single-process | Production, distributed agents |

---

## Examples

**Tier 1 - Research Agent**:
```python
from google.adk.agents import Agent
from tenuo.google_adk import GuardBuilder
from tenuo.constraints import Subpath, UrlSafe

guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/research/papers"))
    .allow("web_search", url=UrlSafe(allow_domains=["*.arxiv.org", "*.scholar.google.com"]))
    .build())

agent = Agent(
    name="research_agent",
    tools=guard.filter_tools([read_file, web_search]),
    before_tool_callback=guard.before_tool,
)
```

**Tier 2 - Multi-Agent System**:
```python
from google.adk.agents import Agent
from tenuo.google_adk import GuardBuilder, TenuoPlugin, ScopedWarrant
from tenuo import SigningKey, Warrant
from tenuo.constraints import Subpath

# Control plane issues warrants
orchestrator_key = SigningKey.generate()
researcher_key = SigningKey.generate()

researcher_warrant = (Warrant.mint_builder()
    .capability("read_file", path=Subpath("/research"))
    .capability("web_search")
    .holder(researcher_key.public_key)
    .ttl(3600)
    .mint(orchestrator_key))

# Create scoped warrant for session isolation
plugin = TenuoPlugin(warrant_key="agent_warrant")
scoped = ScopedWarrant(researcher_warrant, "researcher")

# Build guard
guard = (GuardBuilder()
    .with_warrant(researcher_warrant, researcher_key)
    .build())

# Create agent
researcher = Agent(
    name="researcher",
    tools=guard.filter_tools([read_file, web_search]),
    before_tool_callback=guard.before_tool,
    before_agent_callback=plugin.before_agent_callback,
)

# Run with scoped warrant in session state
session_state = {"agent_warrant": scoped}
# ... use session_state in agent execution
```

---

## MCP Tools with ADK

ADK agents can use [Model Context Protocol (MCP)](https://modelcontextprotocol.io) tools with Tenuo authorization. MCP provides a standard protocol for AI agents to access tools like filesystems, databases, and APIs.

### Pattern: ADK Agent + MCP Tools

```python
from google.adk.agents import Agent
from tenuo.mcp import SecureMCPClient
from tenuo import configure, mint, Capability, Subpath, SigningKey

# Configure Tenuo
key = SigningKey.generate()
configure(issuer_key=key)

# Connect to MCP server with automatic tool discovery
async with SecureMCPClient("python", ["mcp_server.py"], register_config=True) as mcp:
    # Get protected MCP tools
    mcp_tools = mcp.tools

    # Create ADK agent with MCP tools
    agent = Agent(
        name="assistant",
        tools=[mcp_tools["read_file"], mcp_tools["search"]],
    )

    # Execute with warrant scoping
    async with mint(Capability("read_file", path=Subpath("/data"))):
        result = await agent.run("Read the configuration file")
```

### Example: Research Agent with MCP

See [`examples/mcp/`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/mcp) for complete examples:
- **`langchain_mcp_demo.py`** - LangChain + MCP integration (similar pattern applies to ADK)
- **`mcp_a2a_delegation.py`** - Multi-agent system with MCP tools via A2A
- **`crewai_mcp_demo.py`** - CrewAI crew workflow with MCP tools

**When to use ADK + MCP:**
- Agent needs standardized tool access (filesystem, databases, APIs)
- Tools exposed via MCP protocol from other services
- Want automatic tool discovery and protection
- Need to constrain MCP tool arguments (paths, URLs, etc.)

**See also:** [MCP Integration Guide](./mcp.md) for complete MCP documentation.

---

## Multi-Agent Systems with A2A

For systems where ADK agents delegate tasks to other agents, use [Tenuo's A2A integration](./a2a.md) for warrant-based authorization across agent boundaries.

### Example: Incident Response with A2A

See [`examples/google_adk_a2a_incident/`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/google_adk_a2a_incident) for a complete multi-agent system:

**Architecture:**
```
Control Plane
     │
     ├─→ Analyst Agent (ADK + A2A server)
     │   - Reads logs (Subpath constraint)
     │   - Queries threat DB
     │   - Can delegate block_ip to Responder
     │
     └─→ Responder Agent (ADK + A2A server)
         - Blocks IPs (Cidr constraint)
         - Quarantines users
```

**Key Features:**
- **Multi-process**: Agents run as separate Python processes communicating via HTTP
- **Warrant attenuation**: Analyst narrows privileges when delegating to Responder
- **Real A2A calls**: Demonstrates production architecture with network communication
- **Attack scenarios**: Shows prompt injection, warrant replay, and privilege escalation attempts

**Run the demo:**
```bash
cd tenuo-python/examples/google_adk_a2a_incident
python demo_distributed.py               # Full demo with real HTTP
python demo_distributed.py --no-services # Simulation mode
```

**What it demonstrates:**
1. **Detection Phase**: Detector analyzes logs for suspicious activity
2. **Investigation Phase**: Analyst queries threat DB via A2A
3. **Response Phase**: Analyst delegates to Responder with attenuated warrant
4. **Attack Defense**:
   - Prompt injection tries to block entire Internet → blocked by Exact constraint
   - Forged warrant → blocked by signature verification
   - Privilege escalation → blocked by monotonicity checks

### When to Use ADK + A2A

**Use A2A when:**
- Multiple ADK agents delegate tasks to each other
- Agents run in separate processes/services
- Need cryptographic proof of delegation
- Cross-organizational boundaries

**Use ADK alone when:**
- Single ADK agent with local tools
- All tools in same process
- No delegation needed

**Pattern:**
```python
# Orchestrator agent (ADK + A2A client)
from google.adk.agents import Agent
from tenuo.google_adk import GuardBuilder
from tenuo.a2a import A2AClient

# Guard for orchestrator's own tools
guard = GuardBuilder().with_warrant(orchestrator_warrant, key).build()

orchestrator = Agent(
    name="orchestrator",
    tools=guard.filter_tools([local_tool1, local_tool2]),
    before_tool_callback=guard.before_tool,
)

# Delegate to worker via A2A
async def delegate_to_worker(task):
    task_warrant = (
        orchestrator_warrant.grant_builder()
        .holder(worker_key.public_key)
        .capability("analyze")
        .ttl(300)
        .grant(key)
    )

    client = A2AClient("https://worker.example.com")
    return await client.send_task(
        warrant=task_warrant,
        skill="analyze",
        arguments={"data": task},
        signing_key=key,
    )
```

---

## Developer Tools

Tenuo provides debugging and visualization utilities in `tenuo.google_adk`.

### Denial Explanations and Hints

```python
from tenuo.google_adk import GuardBuilder, explain_denial

guard = GuardBuilder().with_warrant(warrant, signing_key).build()

result = guard.before_tool(tool, args, tool_context)
if result:
    explain_denial(result)  # Colored output with recovery hints
```

Output includes error details and actionable suggestions like:
- Constraint violations with examples of valid values
- "Did you mean?" suggestions for mismatched tool names
- Available skills in warrant

### Warrant Visualization

```python
from tenuo.google_adk import visualize_warrant

visualize_warrant(my_warrant)  # ASCII table with capabilities
```

Shows warrant ID, expiry, skills, and constraints in readable format.

### Auto-Detect Skill Mappings

```python
from tenuo.google_adk import suggest_skill_mapping

suggestions = suggest_skill_mapping(
    tools=[read_file_tool, web_search_api],
    warrant=my_warrant,
    verbose=True  # Prints analysis
)
# Returns: {"read_file_tool": "read_file", "web_search_api": "web_search"}

# Review then apply:
guard = GuardBuilder().skill_map(suggestions).build()
```

> [!CAUTION]
> Review suggestions before use - incorrect mappings could grant unintended access.

### Development Modes

```python
# Development: Log denials but don't block
dev_guard = GuardBuilder().on_denial("log").build()

# Production: Raise exceptions (default)
prod_guard = GuardBuilder().on_denial("raise").build()

# Testing: Dry run mode (requires direct constructor)
test_guard = TenuoGuard(
    warrant=warrant,
    signing_key=key,
    dry_run=True,  # Logs with "DRY RUN", never blocks
)
```

### Chain Multiple Callbacks

```python
from tenuo.google_adk import chain_callbacks

agent = Agent(
    tools=[...],
    before_tool_callback=chain_callbacks(
        guard.before_tool,     # Authorization
        rate_limiter.check,    # Rate limiting
        audit_logger,          # Logging
    ),
)
```

---

---

## Advanced: Decorator Pattern

For simple tools with static constraints, use the `@guard_tool` decorator:

```python
from tenuo.google_adk import guard_tool, GuardBuilder
from tenuo.constraints import Subpath

@guard_tool(path=Subpath("/data"))
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()

# Extract constraints from decorated tools
guard = GuardBuilder.from_tools([read_file]).build()
```

> [!WARNING]
> **Decorator Limitations**
> - Static only (can't change per-user)
> - Not for Tier 2 (no crypto at decoration time)
> - Can't decorate third-party tools
>
> **Use GuardBuilder for**: Production, dynamic authorization, Tier 2

---

## See Also

- [Constraints Reference](./constraints.md) - Full list of available constraints
- [Security Model](./security.md) - Threat model and mitigations
- [OpenAI Integration](./openai.md) - Similar integration for OpenAI SDK
- [A2A Integration](./a2a.md) - Multi-agent task delegation
- [API Reference](./api-reference.md) - Complete Python API docs
