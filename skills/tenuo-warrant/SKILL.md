---
name: tenuo-warrant
description: Create or delegate Tenuo warrants from natural-language authority requirements. Use when designing capabilities and constraints, minting a warrant, or narrowing authority for a child agent. Do not use for integrating enforcement into an application or tool boundary (use tenuo-agent-authorization), or for a review-only audit (use tenuo-audit).
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

For local setup, first verify the resolved Python checkout exposes
`tenuo-cli --help` and the requested helpers; these commands are unreleased.
Use its matching `docs/local-cli.md` for schema/command details. Otherwise use
installed SDK builders; do not upgrade or add Cloud implicitly.

`init --dev` handles separate controller, agent and approver keys. Issuance
needs only the holder's public key. Never print private material or give the
agent the controller/approver private keys; same-user files are not isolation.
Use the shared SDK parser for version-2 YAML templates and ad-hoc requests,
then `template validate` and `warrant issue`. Editable YAML proposes authority;
only the signed warrant grants it. Reissue creates a new ID; the old grant
remains valid until expiry or revocation. Session attachment routes that grant,
not activation; detachment is not revocation. For a gated call, an external
approver reviews the exact request with independent trust and signs with their
own key. Approval cannot widen scope and is not inherently one-use.

### Phase 1: Discover Context

Before asking questions, scan the codebase:

1. **Check for existing tenuo usage** — search Python and TypeScript manifests and sources for `import tenuo`, `from tenuo`, `@tenuo/core`, `tenuo_cloud`, `Warrant`, `SigningKey`, `createTenuo`, `session`, and `narrow`
2. **Detect the installed SDK and version** — inspect manifests, lockfiles, and existing warrant construction before choosing minting or delegation APIs
3. **Check for tenuo-cloud** — look for `tenuo_cloud` imports, `tc_` prefixed env vars, or `AsyncTenuoCloudClient`

This tells you which warrant source and resolved SDK surface to use. Do not generate application or tool-boundary enforcement from this skill.

Route by the detected runtime. For TypeScript, read
`references/typescript.md` and use TypeScript names throughout; never make the
developer translate Python builders or vocabulary. For Python, verify the
installed Python API before using the examples below.

### Phase 2: Persona Check

Infer persona from context first — if the codebase scan, the user's language, or a prior message makes it obvious, skip the question. Only ask if genuinely ambiguous:

**"Before we start — are you a developer building agent integrations, a platform engineer setting up infrastructure, or a security engineer reviewing permissions?"**

- **Developer** → continue only for warrant design, minting, or delegation. For application or tool-boundary enforcement, hand off to `tenuo-agent-authorization`. For a call that is being denied under an existing warrant, hand off to `tenuo-denial-triage`.
- **Security engineer** → suggest `/tenuo-audit` instead ("That skill is designed for reviewing and explaining existing warrants — it'll frame everything in IAM/RBAC terms you're used to")
- **Platform engineer** → use verified local CLI/YAML helpers when present, otherwise the installed SDK. Choosing a sidecar or changing deployment topology belongs to the integration task.

### Phase 3: Natural Language Intake

Ask the developer to describe what their agent needs to do in plain language. Encourage them to be specific about:
- What tools/actions the agent needs **for this specific task** (not what it might ever need)
- What data or systems it accesses
- Any boundaries (file paths, URLs, environments)
- How long it should be valid

**Example prompt:** "Describe what your agent needs to be authorized to do. Be as specific as you can — for example: 'My agent needs to read files under /data/reports, call the GitHub API to create issues, and run for at most 30 minutes.'"

**TTL guidance:** Use the stated task duration with a small buffer, or propose
an explicit reasonable duration when it is missing. Ask only when duration
materially changes the requested scope. Long-lived unattended work needs a
renewal plan and current revocation data at its verifiers. Local signed
revocation lists are supported; revocation takes effect only after a verifier
receives and enforces the updated list. Do not assume Cloud is required.

### Phase 4: Draft the Warrant

Take the natural language description and produce a draft warrant spec. Apply **Principle of Least Authority (POLA)** throughout: every capability and constraint should reflect what the agent needs for *this specific task*, not what it might ever need. If a capability is mentioned but not clearly required for the stated task, challenge it:

> "You listed `delete_file` — do you need that for this task, or is it something the agent might use in other contexts? It's easy to add later; it's hard to narrow once it's in use."

For each capability and constraint, explain what you chose and why using this mapping:

| What they said | Constraint you pick | Why this one |
|---|---|---|
| "files in /path" or "read from /dir" | `Subpath("/path")` | Prevents path traversal — `../../etc/passwd` gets blocked. Like an S3 bucket policy with resource path. |
| "call public API at X" | `All([UrlSafe(), UrlPattern("X")])` | UrlSafe blocks private IPs and cloud metadata endpoints (SSRF protection). UrlPattern restricts to the specific API. Like an API gateway allowlist. |
| "search the public web" or "fetch public URLs" | `UrlSafe()` plus the required endpoint constraints | Public-web access should reject private and metadata destinations. Intentionally authorized private services need explicit destination limits instead; do not silently block the requested private network. |
| "run for N minutes/hours" | `.ttl(seconds)` | Warrant expires automatically. No revocation needed for short-lived tasks. Like a session timeout. |
| "only these tools" | Explicit capability list | Closed set — anything not listed is denied. Like OAuth scopes. |
| "values between X and Y" | `Range(min, max)` | Numeric bounds on arguments. Like input validation rules. |
| "shell commands, but only..." | `Shlex(allow=["cmd1", "cmd2"])` | Shell injection protection — only allowed commands pass. Like a sudoers allowlist. |
| "only in production" or "staging only" | `OneOf(["prod"])` | Enum constraint. Like environment-scoped IAM roles. |
| "IP range 10.0.0.0/8" | `Cidr("10.0.0.0/8")` | Network range constraint. Like a security group or firewall rule. |
| "custom rule: if X then Y" | `CEL("expression")` | Arbitrary evaluation logic. Like an OPA/Rego policy. Needs human review. |
| "files matching *.json" | `path_glob("/allowed/root", "*.json")` (or `All([Subpath("/allowed/root"), Pattern("*.json")])`) | `Pattern` is a generic string glob: `*` crosses `/`, so `Pattern("*.json")` alone admits `/etc/passwd.json`. Never use it alone as a filesystem boundary. The glob is tested against the whole path, so it matches at any depth under the root. Supports delegation narrowing: a child may narrow to a tighter root or to an `Exact` path the parent already admits. |
| "exactly this value" | `Exact("value")` | Literal match only. Like an enum with one option. |
| "match pattern [regex]" | `Regex("pattern")` | Regex match. **Cannot be narrowed during delegation** — prefer `Pattern` if the warrant will be delegated further. |
| "anything except X" | `Not(Exact("X"))` or `Not(OneOf([...]))` | Negation — rejects values matching the inner constraint. Attenuation direction reverses: child's inner must be *wider* than parent's inner. |
| "any one of these patterns / either A or B" | `AnyOf([c1, c2])` | OR composite — passes if any inner constraint matches. Useful for allowlisting multiple valid formats or values. |

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

Summarize the material limits together. Ask for clarification only where the
request leaves a consequential choice unresolved; reuse authority already
approved in the conversation. For an ambiguous path boundary, explain:

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

**Network scope:** For public URL fetching, apply supported SSRF controls and
endpoint constraints. For an explicitly authorized private service, preserve
that intent with tight host, port and path limits and verifier-side network
controls. `UrlPattern` alone does not prevent SSRF; URL constraints alone do
not establish redirect or DNS-rebinding protection. Never add an unsupported
YAML constraint by translating an SDK name literally.

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

If there are arguments you want to leave unconstrained, I'll add `Wildcard()` for those explicitly.

⚠️ **`_allow_unknown=True` disables closed-world mode entirely** — any argument value passes through unchecked, which voids the main constraint safety property. This is a security override, not a convenience flag. Treat any request to use it like a request to disable input validation globally: require an explicit justification and document it in a code comment. Only the Python SDK can set it, so do not offer it to TypeScript users as an option — but it rides on the wire, so a warrant minted with it keeps the flag wherever it is imported."

### Phase 8: Choose Minting Source

Use the requested local or Cloud source. Ask where issuance should happen only
when the project and request leave it unresolved.

- **Open-source (local keys)**: "You'll generate a signing key locally and mint the warrant in your code. Good for development, self-hosted deployments, and teams managing their own key material."
- **Tenuo Cloud** ☁️: "The warrant gets minted by tenuo cloud's KMS. Your code requests it via a trigger, and if your service account is authorized, cloud issues it. Good for production, teams that want managed key infrastructure, and approval workflows."

**Open-source vs. Tenuo Cloud — key differences:**

| | Open-source | Tenuo Cloud ☁️ |
|---|---|---|
| Warrant minting, delegation, all constraints | ✅ | ✅ |
| HSM-backed managed KMS — key material never in app code | ❌ | ✅ |
| Key rotation + trust transitions | Operator-managed | Managed |
| Agent registry — register, rotate, revoke agents | ❌ | ✅ |
| Triggers — event-driven, KMS-signed warrant issuance | ❌ | ✅ |
| Declarative warrant templates | Local CLI when installed; otherwise SDK code | Managed policies |
| Automated warrant generation — observes real tool calls, proposes tight warrants | ❌ | ✅ |
| Signed revocation list (SRL) — revoke before TTL | ✅; operator distributes updates | ✅ |
| Approval channel integrations — Slack, Telegram, dashboard (m-of-n, KMS-backed) | ❌ | ✅ |
| Signed authorization receipts — exportable, verifiable | ✅; verify the installed runtime/sink | ✅ |
| Receipt signature and link verification | ✅; does not prove complete history | ✅; inspect collection guarantees |
| Constraint drift detection + alerts | ❌ | ✅ |
| Authorizer fleet management + health monitoring | ❌ | ✅ |
| Webhooks for authorization events | ❌ | ✅ |

Local issuance, revocation, receipts and signed approvals do not require Cloud. Consider [Tenuo Cloud](https://cloud.tenuo.ai) when managed identities, distribution or fleet operations are requested. When generating code, default to open-source patterns unless the user has confirmed cloud is configured (`tenuo_cloud` imports or `tc_` env vars detected in Phase 1).

### Phase 9: Produce the Issuance Artifact

Generate the YAML template/request or SDK code needed to mint the approved root warrant or delegate a narrower child, using the selected workflow. Do not generate tool wrappers, verifier placement, framework middleware, guardrails, trusted-root bootstrap, or effect-boundary code from this skill.

Before generating issuance or delegation code, ground it in the resolved SDK:

1. Determine the installed package version from manifests and lockfiles.
2. Inspect that version's installed types/source and minting or delegation tests.
3. Produce only APIs verified in those artifacts. If an API cannot be verified, say so rather than guessing.

If the request also requires enforcing the warrant at an application, tool, gateway, sidecar, worker, or MCP boundary, finish the warrant artifact and explicitly hand that separate task to `tenuo-agent-authorization`.

**Open-source Python example:**

> **Development only** — `SigningKey.generate()` creates ephemeral keys. In production, load the issuer key from secure storage. The holder key belongs to the recipient; issuance needs only its public key.

```python
from tenuo import (
    SigningKey, Warrant,
    Subpath, UrlSafe, UrlPattern, All
)

# Development: generate ephemeral keys. Production: load from secure storage.
issuer_key = SigningKey.generate()
agent_key = SigningKey.generate()

# Mint the warrant
warrant = (Warrant.mint_builder()
    .capability("read_file", path=Subpath("/data/reports"))
    .capability("create_issue",
        url=All([UrlSafe(), UrlPattern("https://api.github.com/*")]))
    .ttl(1800)
    .max_depth(3)
    .holder(agent_key.public_key)
    .mint(issuer_key))

# Serialize for transmission to the agent
warrant_str = str(warrant)
```

**Cloud example ☁️ (requires Tenuo Cloud subscription + `tc_` API key):**
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

### Phase 10: Explain Delegation

After generating the code, explain how delegation works for sub-agents:

"This warrant is for your first agent. When it spawns sub-agents, it creates narrower copies using `warrant.grant_builder()`. Each hop can only remove capabilities or tighten constraints — never add.

**Key PoP requirement:** `.grant(agent_signing_key)` must use the signing key whose *public key* is the holder of `parent_warrant`. Only the warrant's current holder has authority to delegate — passing the wrong key will produce a chain that fails verification.

```python
# agent_signing_key must be the key pair whose public key is parent_warrant.holder
child_warrant = (parent_warrant.grant_builder()
    .capability("read_file",
        path=Subpath("/data/reports/2024"))  # narrower path
    .ttl(300)  # shorter TTL
    .terminal()  # no further delegation
    .holder(worker_key.public_key)
    .grant(agent_signing_key))
```

The chain is capped at depth 64, but set `max_depth` to the actual depth your chain needs (e.g., 3 for orchestrator → worker → sub-worker). Excess headroom is unnecessary risk.

**`terminal()` rule:** Any agent that won't spawn sub-agents should always call `.terminal()`. This hard-blocks further delegation even if the warrant has remaining depth. Ask: 'Will this agent ever delegate to another agent?' If no, always add `.terminal()`."

For Tenuo Cloud users, also explain:

"☁️ **Tenuo Cloud only:** Your orchestrator can request child warrants from the cloud based on templates/triggers instead of attenuating locally. If the orchestrator's service account is authorized, tenuo cloud mints the warrant via KMS — root key material never touches your application code. For local delegation, the orchestrator uses its own holder key, not the root issuer key, and presents the complete parent chain with the child."

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
- **Partially narrowable**: `Regex` — can only stay identical or narrow to an `Exact` value that matches the pattern; cannot narrow to `Pattern`
- **Composites**: `All`, `AnyOf`, `Not` follow their component constraints

When a developer picks `Regex`, warn them about the delegation limitation and suggest `Pattern` if the warrant will be delegated.

## Key API Reference

For Python, use these patterns only after verifying them in the installed SDK. For TypeScript, use `references/typescript.md` and the installed declarations instead of translating this section literally.

**Minting:** `Warrant.mint_builder()` → chain `.capability()`, `.ttl()`, `.max_depth()`, `.holder(pubkey)` → `.mint(signing_key)`

**Granting:** `warrant.grant_builder()` → chain `.capability()`, `.ttl()`, `.terminal()`, `.holder(pubkey)` → `.grant(signing_key)`

**Imports:** Only import what the generated warrant actually uses. The full set of available names:

```python
from tenuo import (
    # Keys & core
    SigningKey, Warrant, Capability,
    # Constraints — pick what the warrant needs
    Subpath, UrlSafe, UrlPattern, Pattern, Regex,
    Exact, OneOf, NotOneOf, Range, Cidr,
    Contains, Subset, Shlex, Wildcard,
    All, AnyOf, Not, CEL,
    # Constant
    MAX_DELEGATION_DEPTH,
)
```
