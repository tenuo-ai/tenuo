---
name: tenuo-warrant
description: Create tenuo warrants (capability tokens) for AI agents from natural language descriptions. Use this skill whenever someone wants to authorize an agent, create a warrant, set up agent permissions, add tenuo to a project, or describe what an AI agent should be allowed to do. Also trigger when you see tenuo imports, warrant-related code, or the user mentions capabilities, constraints, delegation, or attenuation in the context of agent authorization.
---

# Tenuo Warrant Creator

Help developers create tenuo warrants by translating natural language intent into capability tokens with the right constraints. Warrants are a new authorization primitive — most developers haven't seen them before — so this skill bridges the gap between "I want my agent to do X" and the actual warrant code.

**Announce at start:** "I'm using the tenuo-warrant skill to help you create a warrant for your agent."

## The Core Idea

A warrant is like an API key that can only get weaker. Once created, it can be delegated to sub-agents with fewer permissions (attenuation), but never more. Think of it as a capability token with built-in least-privilege enforcement.

For developers familiar with other auth systems:
- **OAuth**: Warrants are like scopes, but scopes are static strings — warrants carry semantic constraints (e.g., "files under /data" not just "files:read")
- **IAM**: Warrants are like IAM policies attached to a session token, but they're cryptographically chained so each delegation provably narrows scope
- **RBAC**: Instead of roles with fixed permissions, warrants carry exactly the permissions needed, bound to a specific agent and expiration

## Flow

### Phase 1: Discover Context

Before asking questions, scan the codebase:

1. **Check for existing tenuo usage** — search for `import tenuo`, `from tenuo`, `tenuo_cloud`, `Warrant`, `SigningKey` in Python files
2. **Detect AI frameworks** — look for imports from `openai`, `langchain`, `crewai`, `autogen`, `google.adk`, `temporalio`, `mcp`, `a2a` in Python files and `requirements.txt`/`pyproject.toml`
3. **Check for tenuo-cloud** — look for `tenuo_cloud` imports, `tc_` prefixed env vars, or `AsyncTenuoCloudClient`

This tells you whether this is a greenfield integration or a retrofit, and which framework integration to generate code for.

### Phase 2: Persona Check

Ask: **"Before we start — are you a developer building agent integrations, a platform engineer setting up infrastructure, or a security engineer reviewing permissions?"**

- **Developer** → continue with this skill
- **Security engineer** → suggest `/tenuo-audit` instead ("That skill is designed for reviewing and explaining existing warrants — it'll frame everything in IAM/RBAC terms you're used to")
- **Platform engineer** → continue, but note the sidecar + policy file workflow is coming soon. For now, help them create warrants via the SDK

### Phase 3: Natural Language Intake

Ask the developer to describe what their agent needs to do in plain language. Encourage them to be specific about:
- What tools/actions the agent should have
- What data or systems it accesses
- Any boundaries (file paths, URLs, environments)
- How long it should be valid

**Example prompt:** "Describe what your agent needs to be authorized to do. Be as specific as you can — for example: 'My agent needs to read files under /data/reports, call the GitHub API to create issues, and run for at most 30 minutes.'"

### Phase 4: Draft the Warrant

Take the natural language description and produce a draft warrant spec. For each capability and constraint, explain what you chose and why using this mapping:

| What they said | Constraint you pick | Why this one |
|---|---|---|
| "files in /path" or "read from /dir" | `Subpath("/path")` | Prevents path traversal — `../../etc/passwd` gets blocked. Like an S3 bucket policy with resource path. |
| "call API at X" or "hit endpoint X" | `All([UrlSafe(), UrlPattern("X")])` | UrlSafe blocks private IPs and cloud metadata endpoints (SSRF protection). UrlPattern restricts to the specific API. Like an API gateway allowlist. |
| "search the web" or "fetch URLs" or any network access | `UrlSafe()` (at minimum) | Any capability that touches the network MUST have UrlSafe() — even if no specific URL pattern is needed. Without it, the agent could hit internal services or cloud metadata endpoints (SSRF). Like requiring a VPC endpoint policy. |
| "run for N minutes/hours" | `.ttl(seconds)` | Warrant expires automatically. No revocation needed for short-lived tasks. Like a session timeout. |
| "only these tools" | Explicit capability list | Closed set — anything not listed is denied. Like OAuth scopes. |
| "values between X and Y" | `Range(min, max)` | Numeric bounds on arguments. Like input validation rules. |
| "shell commands, but only..." | `Shlex(allow=["cmd1", "cmd2"])` | Shell injection protection — only allowed commands pass. Like a sudoers allowlist. |
| "only in production" or "staging only" | `OneOf(["prod"])` | Enum constraint. Like environment-scoped IAM roles. |
| "IP range 10.0.0.0/8" | `Cidr("10.0.0.0/8")` | Network range constraint. Like a security group or firewall rule. |
| "custom rule: if X then Y" | `CEL("expression")` | Arbitrary evaluation logic. Like an OPA/Rego policy. Needs human review. |
| "files matching *.json" | `Pattern("*.json")` | Glob pattern matching. Supports delegation narrowing (unlike Regex). |
| "exactly this value" | `Exact("value")` | Literal match only. Like an enum with one option. |
| "match pattern [regex]" | `Regex("pattern")` | Regex match. **Cannot be narrowed during delegation** — prefer `Pattern` if the warrant will be delegated further. |

**Present the draft like this:**

```
Here's what I'm proposing for your warrant:

📋 Capabilities:
  • read_file — with path constrained to Subpath("/data/reports")
    "Your agent can read any file under /data/reports, but path traversal
     attacks are blocked. ../../etc/passwd → denied."

  • create_issue — with url constrained to All([UrlSafe(), UrlPattern("https://api.github.com/*")])
    "Can call GitHub's API, but SSRF is blocked — no reaching internal
     services or cloud metadata endpoints."

⏱ TTL: 1800 seconds (30 minutes)
🔗 Max delegation depth: 3 (agent → sub-agent → sub-sub-agent)
```

### Phase 5: Validate Each Mapping

Walk through each constraint and ask for confirmation:

"I interpreted 'read files under /data/reports' as a `Subpath("/data/reports")` constraint. This means:
- ✅ `/data/reports/q4.csv` — allowed
- ✅ `/data/reports/2024/summary.txt` — allowed
- ❌ `/data/reports/../../etc/passwd` — blocked (traversal)
- ❌ `/data/other/file.txt` — blocked (outside scope)

Does that match what you intended?"

Fill gaps with targeted questions:
- "You mentioned API access — should the agent be able to write (POST/PUT) or just read (GET)?"
- "Should the agent be able to delegate this warrant to sub-agents? If so, how deep?"
- "Any time limit on how long this authorization should last?"

**Safety check — always verify:** Any capability that involves network access (fetching URLs, calling APIs, web search, webhooks) MUST have `UrlSafe()` applied, even if no specific URL pattern is needed. This prevents SSRF attacks where the agent could reach internal services, cloud metadata endpoints (169.254.169.254), or localhost. If a network-facing capability is missing UrlSafe(), flag it and add it. This is the single most common constraint omission.

### Phase 6: Explain the Full Warrant

Present a complete plain-language summary:

```
📋 Warrant Summary

This warrant authorizes the holder to:
  ✓ Read files under /data/reports (path traversal protected)
  ✓ Call https://api.github.com/* (SSRF protected)
  ✗ Cannot write files
  ✗ Cannot access any other network endpoints
  ✗ Cannot delegate beyond depth 3

⏱ Expires in 30 minutes
🔒 Proof-of-possession required (warrant is useless without the holder's private key)

Blast radius (if compromised):
  An attacker with this warrant could read files under /data/reports
  and create GitHub issues. They cannot write to the filesystem, access
  other APIs, or escalate privileges. The warrant expires in 30 minutes
  and requires the private key to use.

In familiar terms:
  • IAM: Allow s3:GetObject on arn:aws:s3:::data/reports/*,
         Allow execute-api:Invoke on github-api/issues/*
  • OAuth: Scopes: files:read:reports, github:issues:write. Expires: 1800s
  • RBAC: Role: report-reader-github-issuer, Namespace: agent-pool
```

### Phase 7: Closed-World Mode

If any constraints were added, explain the trust cliff:

"Because you added constraints, tenuo is now in **closed-world mode** for those capabilities. This means any argument you *didn't* explicitly constrain will be **rejected by default**. This is a security feature — it prevents unexpected argument values from slipping through.

If there are arguments you want to leave unconstrained, I'll add `Wildcard()` for those. You can also opt out of closed-world entirely with `_allow_unknown=True`, but that's not recommended for production."

### Phase 8: Choose Minting Source

Ask: **"Where should this warrant come from?"**

- **Open-source (local keys)**: "You'll generate a signing key locally and mint the warrant in your code. Good for development, self-hosted deployments, and teams managing their own key material."
- **Tenuo Cloud**: "The warrant gets minted by tenuo cloud's KMS. Your code requests it via a trigger, and if your service account is authorized, cloud issues it. Good for production, teams that want managed key infrastructure, and approval workflows."

### Phase 9: Generate Code

Based on the chosen source and detected framework, generate the integration code.

**Open-source example:**
```python
from tenuo import (
    SigningKey, Warrant, Capability,
    Subpath, UrlSafe, UrlPattern, All
)

# Generate keys (in production, load from secure storage)
issuer_key = SigningKey.generate()
agent_key = SigningKey.generate()

# Mint the warrant
warrant = (Warrant.mint_builder()
    .capability(Capability("read_file", path=Subpath("/data/reports")))
    .capability(Capability("create_issue",
        url=All([UrlSafe(), UrlPattern("https://api.github.com/*")])))
    .ttl(1800)
    .max_depth(3)
    .holder(agent_key.public_key())
    .mint(issuer_key))

# Serialize for transmission to the agent
warrant_str = warrant.serialize()
```

**Cloud example:**
```python
from tenuo_cloud import AsyncTenuoCloudClient

client = AsyncTenuoCloudClient(api_key="tc_...")
warrant = await client.fire_trigger(
    trigger_id="trg_...",
    event_data={
        "file_path": "/data/reports",
        "api_host": "api.github.com"
    },
    initiator={"sub": "service-account@example.com"}
)
```

**With framework integration (e.g., OpenAI GuardBuilder):**
```python
from tenuo.openai import GuardBuilder, Subpath, UrlSafe, UrlPattern, All

client = (GuardBuilder(openai.OpenAI())
    .allow("read_file", path=Subpath("/data/reports"))
    .allow("create_issue",
        url=All([UrlSafe(), UrlPattern("https://api.github.com/*")]))
    .on_denial("raise")
    .build())
```

**With context managers (scoped tasks):**
```python
from tenuo import mint, Capability, Subpath, UrlSafe, UrlPattern, All

async with mint(
    Capability("read_file", path=Subpath("/data/reports")),
    Capability("create_issue",
        url=All([UrlSafe(), UrlPattern("https://api.github.com/*")])),
):
    result = await agent.run(task)
```

### Phase 10: Explain Delegation

After generating the code, explain how delegation works for sub-agents:

"This warrant is for your first agent. When it spawns sub-agents, it creates narrower copies using `warrant.grant_builder()`. Each hop can only remove capabilities or tighten constraints — never add.

```python
# Agent delegates to a sub-agent with narrower permissions
child_warrant = (parent_warrant.grant_builder()
    .capability(Capability("read_file",
        path=Subpath("/data/reports/2024")))  # narrower path
    .ttl(300)  # shorter TTL
    .terminal()  # no further delegation
    .holder(worker_key.public_key())
    .grant(agent_signing_key))
```

The chain is capped at depth 64, but set `max_depth` to the actual depth your chain needs (e.g., 3 for orchestrator → worker → sub-worker). Excess headroom is unnecessary risk."

For cloud users, also explain:

"With tenuo cloud, your orchestrator can request warrants from the cloud based on templates/triggers instead of attenuating locally. If the orchestrator's service account is authorized, tenuo cloud mints the warrant via KMS — root key material never touches your application code."

After completing, suggest: "Want a security review of this warrant? Use `/tenuo-audit` to get a blast radius assessment and risk analysis."

## Important Constraints Behavior

### Composing Multiple Constraints on One Argument

Use `All([...])` to combine constraints on the same argument:
```python
Capability("call_api", url=All([UrlSafe(), UrlPattern("https://api.stripe.com/*")]))
```

### Attenuation Compatibility

Not all constraints can be narrowed during delegation:
- **Narrowable**: `Pattern`, `Subpath`, `Range`, `OneOf`, `Exact`, `Cidr`, `UrlPattern`
- **Not narrowable**: `Regex` (can only be kept identical or replaced with `Exact`)
- **Composites**: `All`, `AnyOf`, `Not` follow their component constraints

When a developer picks `Regex`, warn them about the delegation limitation and suggest `Pattern` if the warrant will be delegated.

## Key API Reference

When generating code, use these exact patterns from the tenuo Python SDK:

**Minting:** `Warrant.mint_builder()` → chain `.capability()`, `.ttl()`, `.max_depth()`, `.holder(pubkey)` → `.mint(signing_key)`

**Granting:** `warrant.grant_builder()` → chain `.capability()`, `.ttl()`, `.terminal()`, `.holder(pubkey)` → `.grant(signing_key)`

**Scoped tasks:** `async with mint(Capability(...), ...):` and `async with grant(Capability(...)):` for nested delegation

**GuardBuilder:** `GuardBuilder(client).allow("tool", arg=Constraint).on_denial("raise").build()`

**@guard decorator:** `@guard` on functions, with `warrant_scope(w)` and `key_scope(k)` context managers

**Imports:** `from tenuo import SigningKey, Warrant, Capability, Subpath, UrlSafe, UrlPattern, Pattern, Range, OneOf, Exact, Shlex, Cidr, All, Wildcard`
