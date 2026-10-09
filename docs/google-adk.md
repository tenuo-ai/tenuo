# ADK Integration

Tenuo provides first-class support for [Google's Agent Development Kit (ADK)](https://github.com/google/adk-toolkit), enabling warrant-based authorization and constraint validation for ADK agents.

---

## Which Pattern Should I Use?

**Answer these questions:**

1. **Do you need application-owned local policy checks?**
   - Yes -> Tier 1. Trusted application code enforces tool allowlists and argument constraints, including in production.
   - A separate verifier must check issuer, holder, or delegation -> Tier 2 (question 2).

2. **Do you need independently verifiable issuer authority, holder proof, or delegation?**
   - Yes -> Tier 2. The verifier checks issuer, holder, and narrowing delegation locally, in one process or across many.

3. **Do you need to delegate tasks to other agents?**
   - Yes -> Tier 2 + [A2A integration](./a2a.md)
   - No -> ADK integration only

**TL;DR:** Tier 1 rejects out-of-policy calls in trusted code. Tier 2 adds signed, holder-bound authority an independent verifier can check. Run the check on the path that performs the effect.

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

# Define your ADK tools (FunctionTool, or plain functions with docstrings)
def read_file(path: str) -> str:
    """Read a file at the given path."""
    ...

def web_search(url: str) -> str:
    """Search the web at the given URL."""
    ...

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

**Why Tier 2?** The issuer signs the authority envelope, and delegation can only narrow it. An independent verifier rejects a widened warrant. Your own issuer or a control plane can mint it. Changing the agent's Python cannot produce a broader warrant that verifier will accept. Run the verifier in the component that holds the resource.

`TenuoGuard(require_pop=False)` selects Tier 1 checks. A warrant on that path supplies the constraints. Issuer, holder, and delegation signatures are checked when `require_pop` stays at its default, `True`.

### Human Approval

Define gates and approvers on the warrant, then pass `.on_approval()`. See [Human Approvals](approvals.md) for the full guide.

```python
from tenuo.approval import cli_prompt

guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .on_approval(cli_prompt(approver_key=approver_key))
    .build())
```

### Delegated warrants

A leaf minted by a delegator is denied when the guard trusts only the original issuer. Pass the parents as `warrant_chain` (root first, excluding the leaf) and set `with_trusted_roots` to that issuer.

```python
from tenuo import Pattern, SigningKey, Warrant
from tenuo.google_adk import GuardBuilder

root_key = SigningKey.generate()
mid_key = SigningKey.generate()
leaf_key = SigningKey.generate()

parent = (Warrant.mint_builder()
    .holder(mid_key.public_key)
    .capability("search", query=Pattern("*"))
    .ttl(600)
    .mint(root_key))
leaf = (parent.grant_builder()
    .holder(leaf_key.public_key)
    .capability("search", query=Pattern("customers:*"))
    .ttl(300)
    .grant(mid_key))

guard = (GuardBuilder()
    .with_warrant(leaf, leaf_key, warrant_chain=[parent])
    .with_trusted_roots([root_key.public_key])
    .build())
```

`customers:acme` is allowed. `employees:x` is denied by the leaf's narrower pattern. The same call without `warrant_chain` is denied because the leaf's issuer is `mid_key`, not `root_key`.

`TenuoPlugin` takes the same `warrant_chain` and `trusted_roots` arguments. Register it on the Runner:

```python
from google.adk.runners import InMemoryRunner
from tenuo.google_adk import TenuoPlugin

plugin = TenuoPlugin(
    warrant=leaf,
    signing_key=leaf_key,
    trusted_roots=[root_key.public_key],
    warrant_chain=[parent],
)
runner = InMemoryRunner(agent=agent, app_name="research", plugins=[plugin])
```

---

## Skill Mapping (When Names Don't Match)

If your tool function name differs from the warrant skill name:

```python
# Warrant has skill "read_file", but your function is named "read_file_tool"
guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .map_skill("read_file_tool", "read_file")  # tool name -> warrant skill
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

**Trust boundary:** the model proposes calls; trusted application code enforces policy before dispatch.

Tier 1 provides deterministic allowlist and argument checks, not another prompt asking the model to behave. Calls that violate the configured policy are blocked on the guarded path, whether they originated from prompt injection, a model mistake, or application logic.

| Attempt | Enforced check | Example |
|---------|----------------|---------|
| Out-of-policy tool call | Tool allowlist and argument constraints | A model-selected recipient outside the permitted set is rejected |
| Invalid or unexpected arguments | Configured constraints and closed-world argument checking | An unlisted argument is rejected |
| Disallowed URL | URL constraints | `UrlSafe()` rejects a literal metadata-service URL such as `http://169.254.169.254/` |
| Path traversal | Path constraints | `Subpath("/data")` rejects traversal outside the permitted root |

**Why this matters:** the policy lives in trusted code, outside the model. A fully manipulated prompt still cannot get an out-of-policy call through the guard. Tighten the policy for actions that are allowed and still harmful. Symlinks, URL redirects, DNS resolution, and shell behavior need a control at the resource too.

### Where Tier 2 and placement take over

| Need | What covers it |
|------|----------------|
| **Forged or widened authority** | Tier 2: issuer signature, holder proof, and delegation that can only narrow |
| **A service that must check the caller** | Tier 2: local verification against trusted roots |
| **Proof of the allow or deny decision** | Tier 2 signed receipts, when configured. Tier 1 still emits audit events |
| **A caller that can skip this callback** | The same tier, running in the component that performs the effect |

The callback runs only where you register it. An agent built without it skips the check:

```python
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()
agent = Agent(tools=[...])  # this agent has no before_tool_callback
```

### When to Use Tier 1

**Good for**:

- Production agents whose trusted code holds the tool and argument policy.
- Rejecting model-chosen calls outside that policy, including calls from a manipulated prompt.
- A local check beside network and credential controls.

### When to Upgrade to Tier 2

Upgrade when you need:

1. **Cryptographic Proof**: Verifiable evidence of what was authorized
2. **Delegation Chains**: Multi-agent systems where agents delegate to each other
3. **Untrusted Callers**: Cannot trust calling agent to honestly report tool calls
4. **Audit Requirements**: Need verifiable authority and, with receipt signing configured, signed records of authorization decisions

**Tier 2 adds**:
- The same tool allowlists and argument constraints, carried in the warrant
- Warrant signatures (cryptographic authorization)
- Proof-of-Possession (PoP) per tool call
- Cross-process verification against independently configured trusted roots
- Signed receipts of the authority presented and the verifier's decision, including denials, when receipt signing is configured

A warrant is proof of the scope that was issued. A signed receipt is proof of what the verifier decided. Your own issuer can mint the warrant. Completion of the downstream effect is a separate record.

**Migration is simple**:
```python
# Tier 1
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

# Tier 2 (add warrant + signing key)
guard = GuardBuilder().with_warrant(warrant, signing_key).build()
```

### Bottom Line

**Tier 1 rejects out-of-policy calls in trusted code. Tier 2 keeps those checks and adds signed authority.** The prompt cannot widen a Tier 1 policy. An independent verifier accepts a Tier 2 warrant only when the issuer, the holder, and any narrowing delegation all check out.

- Use Tier 1 when trusted application code owns the policy.
- Use Tier 2 when the component that performs the effect must verify issuer-granted, holder-bound authority, including across agents or processes.
- When the agent can skip an in-process callback, run that same check in the component that performs the effect, outside the agent's control.

---

## Closed-World Constraints (Zero Trust)

> [!IMPORTANT]
> **Tenuo enforces Zero Trust for arguments.**
> Once you add **any** constraint to a tool, Tenuo switches to a "closed-world" model for that tool.
>
> This means **ANY argument not explicitly listed in your constraints will be REJECTED**.
> Tenuo does not silently ignore extra arguments --it blocks them to prevent "shadow argument" attacks.
>
> ```python
> # Blocks call with 'timeout' arg because it's unknown
> guard = GuardBuilder().allow("api_call", url=UrlSafe()).build()
>
> # Explicitly allow unknown args (less secure)
> guard = GuardBuilder().allow("api_call", url=UrlSafe(), _allow_unknown=True).build()
>
> # Or allow specific field with Wildcard
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

# Blocks: /data/../etc/passwd -- normalizes to /etc/passwd -- outside /data
# Blocks: /data/./../../etc/passwd -- same
# Allows: /data/reports/file.txt -- inside /data
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
from google.adk.runners import InMemoryRunner
from tenuo.google_adk import ScopedWarrant, TenuoPlugin

plugin = TenuoPlugin(
    warrant_key="my_warrant",
    signing_key=agent_key,
    trusted_roots=[issuer_key.public_key],
)
runner = InMemoryRunner(agent=agent, app_name="research", plugins=[plugin])

session = await runner.session_service.create_session(
    app_name="research",
    user_id="u",
    state={"my_warrant": ScopedWarrant(warrant, "research_agent")},
)
```

Register `TenuoPlugin` on the Runner. Assigning `before_agent_callback` on the `Agent` does not install the plugin. The plugin drops a `ScopedWarrant` when `callback_context.agent_name` does not match.

### Argument Remapping

The keyword is the warrant constraint. The value is the tool argument:

```python
guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .map_skill("read_file_tool", "read_file", path="file_path")
    .build())

# The keyword is the warrant constraint name. The value is the tool argument.
# A call with {"file_path": "/data/report.txt"} is checked against "path".
# The tool still receives file_path. Prefer .allow("read_file", file_path=...)
# when the tool's own argument name is the one you want to constrain.
```

### Denial Handling

Control what happens when a tool call is denied:

```python
# Raise exception (stops execution)
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).on_denial("raise").build()

# Return error dict (default - agent sees denial reason and can adapt)
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).on_denial("return").build()
```

### Error Handling

The ADK integration uses `ToolAuthorizationError` and `MissingSigningKeyError`. Authorization goes through the `before_tool` callback on the agent, or through `TenuoPlugin` on the Runner. There is no standalone `guard.check()` method.

**With `on_denial("raise")`**, the `before_tool` callback raises `ToolAuthorizationError`:

```python
from tenuo.google_adk import GuardBuilder, ToolAuthorizationError

guard = (GuardBuilder()
    .allow("transfer", amount=Range(0, 1000))
    .on_denial("raise")
    .build())

agent = Agent(
    name="banker",
    tools=guard.filter_tools([transfer]),
    before_tool_callback=guard.before_tool,
)

# When the LLM calls transfer(amount=5000), the before_tool callback raises:
# ToolAuthorizationError with .tool_name, .tool_args attributes
```

**With `on_denial("return")` (default)**, the callback returns a structured error dict that the LLM sees as the tool result:

```python
guard = GuardBuilder().allow("read_file", path=Subpath("/data")).on_denial("return").build()

# When the LLM calls read_file(path="/etc/passwd"), before_tool returns:
# {
#   "error": "authorization_denied",
#   "message": "Authorization denied: Argument 'path' violates constraint",
#   "details": "...",
#   "hints": [...]
# }
```

**Note**: This integration uses ADK-specific errors. For Tenuo's canonical wire codes (1000-2199), use the `tenuo.langchain` integration or `Warrant` authorization directly.

---

## Audit Logging

Every tool call decision is logged with context:

```python
guard = (GuardBuilder()
    .allow("read_file", path=Subpath("/data"))
    .audit_log("audit.jsonl")  # File path or file-like object
    .build())
```

**Event fields** (JSON lines written to the audit log):
- `event`: `"tool_allowed"`, `"tool_denied"`, or `"tool_dry_run_denied"`
- `tool`: Name of the tool
- `args`: Tool arguments (values truncated to 100 chars)
- `warrant`: Warrant ID and issuer (if available)
- `timestamp`: ISO 8601 timestamp

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
    .map_skill("read_file_tool", "read_file", path="file_path")
    .build())
```

### `.on_denial(mode)`

Control denial behavior (`"raise"` or `"return"`):

```python
guard = GuardBuilder().allow("read_file").on_denial("raise").build()
```

### `.audit_log(log)`

Set audit log destination (file path or file-like object):

```python
guard = GuardBuilder().allow("read_file").audit_log("audit.jsonl").build()
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
| **Cryptographic proof** | No | Yes (Ed25519 signatures) |
| **Policy checks** | Allowlists and argument constraints | The same checks, carried in the signed warrant |
| **Issuer and holder verification** | Local policy only | Yes, with trusted roots and valid PoP |
| **If the agent can skip this process** | Run the policy check on the effect path | Run signature checks on the effect path |
| **Multi-agent delegation** | Each agent enforces its own policy | Attenuation chains an independent verifier can check |
| **Audit trail** | Allow and deny audit events | Signed receipts of the authorization decision, when configured |
| **Performance** | Local, no signature checks | Local signature checks, no runtime network call |
| **Use case** | Application-owned local policy | Verifiable delegated authority, distributed enforcement |

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

**Tier 2 - Runner plugin**:
```python
from google.adk.agents import Agent
from google.adk.runners import InMemoryRunner
from tenuo.google_adk import TenuoPlugin
from tenuo import SigningKey, Warrant
from tenuo.constraints import Subpath

orchestrator_key = SigningKey.generate()
researcher_key = SigningKey.generate()

researcher_warrant = (Warrant.mint_builder()
    .capability("read_file", path=Subpath("/research"))
    .capability("web_search")
    .holder(researcher_key.public_key)
    .ttl(3600)
    .mint(orchestrator_key))

plugin = TenuoPlugin(
    warrant=researcher_warrant,
    signing_key=researcher_key,
    trusted_roots=[orchestrator_key.public_key],
)
researcher = Agent(name="researcher", tools=[read_file, web_search])
runner = InMemoryRunner(agent=researcher, app_name="research", plugins=[plugin])
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
   - Prompt injection tries to block entire Internet -- blocked by Exact constraint
   - Forged warrant -- blocked by signature verification
   - Privilege escalation -- blocked by monotonicity checks

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
builder = GuardBuilder()
for tool_name, skill_name in suggestions.items():
    builder = builder.map_skill(tool_name, skill_name)
guard = builder.build()
```

> [!CAUTION]
> Review suggestions before use - incorrect mappings could grant unintended access.

### Development Modes

```python
# Development: Log denials but don't block (dry run via builder)
dev_guard = GuardBuilder().dry_run().on_denial("return").build()

# Production: Raise exceptions on denial
prod_guard = GuardBuilder().on_denial("raise").build()

# Production: Return structured error (default)
default_guard = GuardBuilder().on_denial("return").build()

# Testing: Dry run mode (via direct constructor)
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
