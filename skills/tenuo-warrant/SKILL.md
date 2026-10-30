---
name: tenuo-warrant
description: Create or delegate Tenuo warrants from natural-language authority requirements. Use when designing capabilities and constraints, minting a warrant, or narrowing authority for a child agent. Do not use for integrating enforcement into an application or tool boundary (use tenuo-agent-authorization), or for a review-only audit (use tenuo-audit).
---

# Tenuo Warrant Creator

Help developers create tenuo warrants by translating natural language intent into capability tokens with the right constraints. Warrants are a new authorization primitive — most developers haven't seen them before — so this skill bridges the gap between "I want my agent to do X" and the actual warrant code.

**Announce at start:** "I'm using the tenuo-warrant skill to help you create a warrant for your agent."

## The Core Idea

A warrant grants task authority to a holder key. The holder can delegate a narrower child: for example, a controller permits payments for an approved invoice up to $500, and a worker receives a $250 ceiling for the same invoice and bank account. A fooled worker cannot widen its signed authority at a verifier enforcing the complete chain. The parent remains usable; delegation does not revoke it.

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

Resolve the actual imported package/source before choosing an API. Installed
source and lockfile resolution outrank the matching immutable release, which
outranks current main and open PR context. Main is usable as implementation
guidance only for a project running that checkout or an explicitly requested
unreleased evaluation. An open PR may invalidate a recommendation without
making its replacement API available. Do not treat this skill's examples as
evidence that an API exists in the target runtime.

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
- **Review-only request** → use `tenuo-audit` if available. A security engineer asking to create authority still belongs here; route by the requested work, not job title.
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

> "Does this task require `delete_file`? Omit it unless needed. A replacement grant does not revoke an already issued broader grant."

For each capability and constraint, explain what you chose and why using this mapping:

| What they said | Constraint you pick | Why this one |
|---|---|---|
| "files in /path" or "read from /dir" | `Subpath("/path")` | Constrains path strings. Filesystem enforcement must also handle symlinks, canonicalization and races at the actual open. |
| "call public API at X" | `All([UrlSafe(), UrlPattern("X")])` | UrlSafe rejects unsafe destination values and UrlPattern restricts the requested API. Verify DNS and redirect enforcement in the fetcher separately. |
| "search the public web" or "fetch public URLs" | `UrlSafe()` plus the required endpoint constraints | Public-web access should reject private and metadata destinations. Intentionally authorized private services need explicit destination limits instead; do not silently block the requested private network. |
| "run for N minutes/hours" | `.ttl(seconds)` | Warrant expires automatically. No revocation needed for short-lived tasks. Like a session timeout. |
| "only these tools" | Explicit capability list | Closed set — anything not listed is denied. Like OAuth scopes. |
| "values between X and Y" | `Range(min, max)` | Numeric bounds on arguments. Like input validation rules. |
| "shell commands, but only..." | `Shlex(allow=["cmd1", "cmd2"])` | Restricts binary names and shell syntax; it does not constrain flags, interpreter code, binary resolution or tool semantics. Verify the installed evaluator and prefer structured executable/argument boundaries. |
| "only in production" or "staging only" | `OneOf(["prod"])` | Enum constraint. Like environment-scoped IAM roles. |
| "IP range 10.0.0.0/8" | `Cidr("10.0.0.0/8")` | Network range constraint. Like a security group or firewall rule. |
| "custom rule: if X then Y" | `CEL("expression")` | Arbitrary evaluation logic. Like an OPA/Rego policy. Needs human review. |
| "files matching *.json" | `path_glob("/allowed/root", "*.json")` (or `All([Subpath("/allowed/root"), Pattern("*.json")])`) | `Pattern` is a generic string glob: `*` crosses `/`, so `Pattern("*.json")` alone admits `/etc/passwd.json`. Never use it alone as a filesystem boundary. The glob is tested against the whole path, so it matches at any depth under the root. Supports delegation narrowing: a child may narrow to a tighter root or to an `Exact` path the parent already admits. |
| "exactly this value" | `Exact("value")` | Literal match only. Like an enum with one option. |
| "match pattern [regex]" | `Regex("pattern")` | Can stay identical or narrow to an admitted `Exact` value; arbitrary regex-language containment is unsupported. |
| "anything except X" | `Not(Exact("X"))` or `Not(OneOf([...]))` | Negation — rejects values matching the inner constraint. Attenuation direction reverses: child's inner must be *wider* than parent's inner. |
| "any one of these patterns / either A or B" | `AnyOf([c1, c2])` | OR composite — passes if any inner constraint matches. Useful for allowlisting multiple valid formats or values. |

**YAML templates, when the target has `tenuo-cli`** (unreleased; confirm with
`tenuo-cli --help` and its matching `docs/local-cli.md`). The same constraints in
template syntax:

| YAML | Means |
|---|---|
| `order_id: A-1001` | exactly that value (a `*` in a plain string is literal; use `pattern`) |
| `env: [staging, prod]` | one of these values (integers allowed where the parser accepts them) |
| `amount_cents: 1..12000`, `..50`, `1..` | a numeric range |
| `query: any` | any value |
| `{subpath: /data}`, `{pattern: '*.md'}`, `{regex: '^d-'}`, `{url_pattern: 'https://api.example.com/*'}` | the constructors above |
| `{optional: 1..600}` | may be left out; if sent, must match (only where the installed parser supports it) |

Every listed argument is required and unlisted arguments are refused, so an
argument a framework sends only sometimes (Hermes `terminal.workdir`,
`read_file.offset`) is the most common first denial: wrap it in `optional`. Where
the CLI is available, draft from what the agent actually did: `tenuo-cli mode
observe`, run it, `tenuo-cli calls summary`; check the draft with `tenuo-cli
warrant review --file T.yaml --json` if the installed CLI has it; then issue.

**Present the draft like this:**

```
Here's what I'm proposing for your warrant:

📋 Capabilities:
  • read_file — with path constrained to Subpath("/data/reports")
    "Your agent can read any file under /data/reports, but path traversal
     attacks are blocked. ../../etc/passwd → denied."

  • create_issue — with url constrained to All([UrlSafe(), UrlPattern("https://api.github.com/*")])
    "Restricts requested URL values to GitHub and rejects unsafe literals.
     The fetcher must still enforce redirects and resolved destinations."

⏱ TTL: 1800 seconds (30 minutes)
🔗 Delegation: worker child is terminal; inspect the installed parent depth ceiling
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
  ✓ Call https://api.github.com/* (destination constrained; network enforcement still required)
  ✗ Cannot write files
  ✗ Cannot access any other network endpoints
  ✗ Worker child cannot delegate further

⏱ Expires in 30 minutes
🔒 Proof-of-possession required (warrant is useless without the holder's private key)

Authority at a correctly enforcing boundary (not a process-compromise claim):
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

**`_allow_unknown=True` permits additional, unlisted arguments for that capability; explicitly declared constraints still apply.** It widens the input surface and requires an explicit reason. Prefer named constraints or deliberate `Wildcard()` fields. The flag travels on the wire, so review externally minted warrants as well. Do not invent a TypeScript setter or assume a diagnostic exposes this flag; inspect the installed minting and verification APIs."

### Phase 8: Choose Minting Source

Use the requested local or Cloud source. For a new setup, default to the local
SDK or supported CLI; explain Cloud when managed issuance is useful or migration
is requested. Preserve an existing verified Cloud issuance path. Ask only when
issuance ownership is a material unresolved choice.

- **Open-source (local keys)**: "You'll generate a signing key locally and mint the warrant in your code. Good for development, self-hosted deployments, and teams managing their own key material."
- **Tenuo Cloud**: "Managed issuance can move issuer-key operations, templates and trigger policy to the service. Resolve the installed client and service contract before generating requests. Local verification still belongs at the effect boundary."

| Choice | Issuance responsibility | Check before generating an artifact |
|---|---|---|
| Local SDK / supported CLI | Application or operator owns issuer keys and trusted task inputs | Installed builder/parser, key ownership, root trust and distribution |
| Cloud management | Service owns configured issuance policy and issuer-key operations | Installed client/service, template and trigger schema, requester permissions, holder binding and returned grant |

Local deployments can be production deployments. Cloud is an optional management
choice, not a stronger effect verifier by itself. Managed feature availability,
approval channels, receipt delivery and revocation freshness need verification
against the actual service; do not promise a product-wide feature list.

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
from tenuo import Exact, Range, SigningKey, Warrant

issuer = SigningKey.generate()       # development controller only
agent = SigningKey.generate()        # agent owns this key; issuer needs its public key
worker = SigningKey.generate()

# These values come from the approved invoice, not model-produced payment details.
parent = (Warrant.mint_builder()
    .capability("pay_invoice", invoice_id=Exact("inv-123"),
                bank_account=Exact("approved-bank"), amount_cents=Range(1, 50000))
    .ttl(600).holder(agent.public_key).mint(issuer))
child = (parent.grant_builder()
    .capability("pay_invoice", invoice_id=Exact("inv-123"),
                bank_account=Exact("approved-bank"), amount_cents=Range(1, 25000))
    .ttl(300).terminal().holder(worker.public_key).grant(agent))
chain = [parent.to_base64(), child.to_base64()]  # public root-to-leaf transport
```

The receiving verifier must trust `issuer.public_key`, receive the complete
chain, and require the worker's proof over the exact effect arguments.
This snippet issues authority; it does not install enforcement or prove an
allowed/denied effect. It has no cumulative budget, single-use guarantee or
idempotency. Keep the parent and agent key away from the worker.

Released Python 0.3.2's high-level `MintBuilder` has neither `max_depth()` nor
`terminal()`. Do not emit either call on that builder. Its default root maximum
is 64; `GrantBuilder.terminal()` limits the child. If the task needs a tighter
root ceiling, verify a supported lower-level builder in the installed SDK and
show its actual resulting depth rather than inventing a setter.

**Cloud issuance:** Resolve the installed Cloud SDK and matching server API,
then inspect the configured template/trigger and initiator policy. Do not assume
`AsyncTenuoCloudClient.fire_trigger()` exists: it is absent from the reviewed
Cloud main client. Use a verified issuance API or clearly mark the missing
client support. Do not call private transport methods or silently substitute a
new root grant for attenuation of an existing parent.

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

Core caps delegation at depth 64. Roots are depth 0, so orchestrator → worker → sub-worker is depth 2. Request only the necessary ceiling where the installed builder exposes it; do not confuse the delegation count with the number of nodes.

**`terminal()` rule:** Use `.terminal()` on a supported grant builder for a worker that will not delegate. Do not emit it on the released high-level mint builder, where it is absent."

For Tenuo Cloud users, also explain:

"Cloud-managed issuance may mint a new root grant from a configured template/trigger; it is not automatically a child of the orchestrator's existing warrant. Verify that relationship before calling it delegation. Local attenuation uses the parent holder key, keeps root issuer key material out of the agent, and transports the complete parent chain with the child."

After completing, suggest: "Want a security review of this warrant? Use `/tenuo-audit` to get a blast radius assessment and risk analysis."

## Important Constraints Behavior

### Composing Multiple Constraints on One Argument

Use `All([...])` to combine constraints on the same argument:
```python
Warrant.mint_builder().capability(
    "call_api", url=All([UrlSafe(), UrlPattern("https://api.stripe.com/*")]))
```

### Attenuation Compatibility

Not all constraints can be narrowed during delegation:
- **Narrowable**: `Pattern`, `Subpath`, `Range`, `OneOf`, `Exact`, `Cidr`, `UrlPattern`
- **Partially narrowable**: `Regex` — can only stay identical or narrow to an `Exact` value that matches the pattern; cannot narrow to `Pattern`
- **Composites**: `All`, `AnyOf`, `Not` follow their component constraints

When a developer picks `Regex`, warn them about the delegation limitation and suggest `Pattern` if the warrant will be delegated.

## Key API Reference

For Python, use these patterns only after verifying them in the installed SDK. For TypeScript, use `references/typescript.md` and the installed declarations instead of translating this section literally.

**Minting:** `Warrant.mint_builder()` → chain `.capability()`, `.ttl()`, `.holder(pubkey)` → `.mint(signing_key)`

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
