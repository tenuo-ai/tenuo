---
name: tenuo-audit
description: Audit, explain, or compare existing Tenuo warrants and delegation chains. Use for review-only requests about effective authority, blast radius, chain validity, or authorization risk. Do not use to implement enforcement in an application or tool boundary (use tenuo-agent-authorization).
---

# Tenuo Warrant Auditor

For local inspection, first check the resolved Python checkout exposes the
unreleased `tenuo-cli` commands. Use its matching `docs/local-cli.md` for exact
options. `warrant show` decodes; `warrant verify` separately checks signatures,
trust, expiry and the installed signed revocation list. `warrant list` inventories
local files, not all issued grants. `audit list` and `audit verify` inspect
signed decisions, not proof of completed effects or complete history. Never
print private keys while inspecting identity, approvals or authority.

Help developers and security reviewers understand what tenuo warrants authorize, assess blast radius, review delegation chains, and flag security risks — all explained in the access control language they already know.

**Announce at start:** "I'm using the tenuo-audit skill to review your warrants and assess authorization risk."

## How Warrants Map to Familiar Concepts

Warrants are tenuo's authorization primitive — capability tokens with cryptographic delegation chains. If you're coming from traditional access control, here's the translation:

| Tenuo | IAM | RBAC | OAuth |
|---|---|---|---|
| Warrant | Session-scoped IAM policy | Role binding with TTL | Access token with scopes |
| Capability | IAM action (s3:GetObject) | Permission | Scope (files:read) |
| Constraint | IAM condition (StringLike) | N/A (RBAC lacks this) | N/A (OAuth lacks this) |
| Attenuation | Cannot escalate (no privilege widening) | Cannot add permissions to inherited role | Cannot widen scopes on refresh |
| Proof-of-Possession | Like mTLS — token bound to key | N/A (RBAC is bearer) | DPoP (RFC 9449) |
| TTL | Session duration | N/A (roles are permanent) | Token expiry |
| Delegation chain | AssumeRole chain | Role inheritance | Token exchange (RFC 8693) |
| Closed-world mode | Default deny policy | Implicit deny | N/A |

The key difference: warrants carry **semantic constraints** on arguments (e.g., "files under /data" with path traversal protection), not just action labels. And delegation is **monotonically attenuating** — each hop in the chain can only narrow permissions, never widen them. The receiving verifier checks the signed chain and structural constraint containment. These comparisons are explanatory, not equivalent IAM/OAuth policies; those systems can also support fine-grained authorization.

## Flow

### Phase 1: Context Discovery

Scan the codebase for tenuo usage:
1. Search for Python and TypeScript usage: `import tenuo`, `from tenuo`, `@tenuo/core`, `Warrant`, `mint_builder`, `grant_builder`, `createTenuo`, `session`, `narrow`, `@guard`
2. Check for `tenuo_cloud` imports or `tc_` env vars (indicates cloud deployment)
3. Look for actual serialization/deserialization APIs in the installed runtime (Python commonly uses `to_base64()` / `from_base64()`). Do not invent constructor or `serialize()` methods from these search hints.

Determine what the application actually imports: installed version, lockfile,
editable checkout, vendored source or git dependency. Inspect that code and the
matching immutable release before consulting main for differences. Open PRs
are pending context, not installed functionality; they can reveal a known gap
without making a replacement API available. Apply the same resolution to Cloud
and framework SDKs. Source inspection alone does not establish enforcement.

### Phase 2: Scope Check

Infer the requested work from the project and conversation. Do not require a persona interview or route by job title. A developer requesting a review belongs here.

- **Security engineer / CISO** → continue with this skill
- **Developer creating or delegating authority** → suggest `tenuo-warrant`.
- **Developer integrating enforcement into an application or tool boundary** → suggest `tenuo-agent-authorization`.
- **Developer with a denied call to make work** → suggest `tenuo-denial-triage`.
- **Platform engineer** → continue, adjusting framing for infrastructure review

### Phase 3: Source Selection

Use the artifact or review scope already supplied; ask only if it is unclear.

- **a) A warrant string** — they'll paste a base64-encoded warrant for you to decode and explain
- **b) Warrants in the codebase** — find all `mint_builder`, `grant_builder`, `GuardBuilder`, `mint()`, `grant()` calls and analyze them
- **c) A delegation chain** — multiple warrants showing parent → child relationships
- **d) Cloud audit trail ☁️** *(Tenuo Cloud only)* — connect to tenuo cloud API for issuance receipts, approval history, revocation status

### Phase 4: Decode and Analyze

For each warrant found, extract and present:

**Structural properties:**
- Issuer public key (who created it)
- Holder public key (who can use it)
- Current depth and max_depth
- TTL / expiration time
- Parent hash (chain link to parent warrant)

**Authorization surface:**
- List of capabilities (tools/actions granted)
- Constraints on each capability's arguments
- Closed-world status (are unconstrained arguments rejected?)

Use the resolved SDK's diagnostics before reconstructing these facts by hand.
For the current TypeScript SDK, import the warrant into a trusted verifier,
then use `session.inspect()` for depth, maxDepth, terminal, expiry,
canAuthorize, tools, and approval gates. Use `tenuo.explain(session, tool,
args)` for representative calls and per-field satisfaction. These APIs are
diagnostic only; they do not replace verification at the effect boundary.
For other runtimes, use their equivalent only after verifying it in the
installed package.

### Phase 5: Plain-Language Explanation

Present what the warrant authorizes in security review format:

```
🔍 Warrant Analysis

Holder: [key fingerprint or identifier]
Issuer: [key fingerprint or identifier]
Chain depth: 2 of 3 (root is depth 0; at most 1 more hop, subject to terminal policy)

AUTHORIZED ACTIONS:
  ✓ read_file
    └─ path: Subpath("/data/reports") — traversal protected
       Allowed: /data/reports/*, /data/reports/2024/q4.csv
       Blocked: /data/reports/../../etc/passwd, /data/other/*

  ✓ create_issue
    └─ url: UrlSafe + UrlPattern("https://api.github.com/*")
       Allowed: https://api.github.com/repos/org/repo/issues
       Blocked: http://169.254.169.254/metadata (SSRF), http://internal:8080

DENIED (not in capability set):
  ✗ write_file, delete_file, execute_command, send_email, ...
  ✗ Any tool not explicitly listed above

TEMPORAL:
  ⏱ TTL: 1800s (expires 2026-03-13T15:30:00Z)
  🔗 Delegation: depth 2/3 — remaining depth alone does not establish delegation authority

BINDING:
  🔒 Proof-of-possession: Required by the warrant; invocation enforcement must be verified
  📋 Closed-world: Active (unconstrained arguments rejected)
```

### Phase 6: Familiar Framework Mapping

Translate the warrant into equivalent policies the security engineer is used to reviewing:

```
IAM-style conceptual mapping (not a deployable IAM policy):
  Action: read_file
  Resource: path strings under /data/reports
  Action: create_issue
  Destination: https://api.github.com/*
  Expiry: 2026-03-13T15:30:00Z
  UrlSafe constrains destination values, not caller source IP.

RBAC Equivalent:
  Role: report-reader-github-issuer
  Namespace: agent-pool
  Bindings: [read_file, create_issue]
  Session limit: 30 minutes

OAuth Equivalent:
  Scopes: files:read:reports, github:issues:write
  Token binding: Tenuo holder proof (conceptually similar to DPoP; not RFC 9449 wire format)
  Expires: 1800s
  Refresh: New signed warrant; previous grant remains valid until expiry or revocation
```

### Phase 7: Delegation Chain Verification

For delegation chains (multiple warrants showing parent → child):

A decoded chain is untrusted data. Establish an independently configured trusted
root, decode the complete root-to-leaf chain, and use the installed SDK
verifier to validate signatures, links, time bounds and attenuation. Do not
trust each intermediate key or the leaf issuer to repair a missing parent.
Do not claim validity when the root or parent warrants are unavailable.

**Inspect these chain properties, then confirm with the real verifier:**
- **I1**: `child.issuer == parent.holder` (delegation comes from the right entity)
- **I2**: `child.depth == parent.depth + 1` (depth increments correctly)
- **I3**: `child.expires_at <= parent.expires_at` (child can't outlive parent)
- **I4**: `child.capabilities ⊆ parent.capabilities` (capabilities only narrow)
- **I5**: `child.parent_hash == SHA256(parent.payload)` (chain integrity)

**Holder proof is invocation-specific.** A warrant alone does not include the
proof for a future call. Verify a supplied proof against the exact tool and
arguments, using the installed binding; otherwise report it as untested. Inspect
actual enforcement placement, trusted roots, final argument canonicalization,
mode and bypass paths. The five checks above are not a complete verifier: also
check depth ceilings/terminal policy, warrant type, constraint keysets, clearance,
approvals and revocation where supported. Observe-mode DENY may still run the
effect; a decision receipt is not evidence that execution was blocked.

**Visualize attenuation:**
```
Root Warrant (depth 0, max_depth 3)
  ├─ read_file: Subpath("/data")
  ├─ write_file: Subpath("/data")
  ├─ call_api: UrlSafe + UrlPattern("https://*.example.com/*")
  └─ TTL: 3600s

  └─► Orchestrator Warrant (depth 1)    [ATTENUATION: -write_file, narrowed path]
      ├─ read_file: Subpath("/data/reports")
      ├─ call_api: UrlSafe + UrlPattern("https://api.example.com/*")
      └─ TTL: 1800s

      └─► Worker Warrant (depth 2)       [ATTENUATION: -call_api, terminal]
          ├─ read_file: Subpath("/data/reports/2024")
          └─ TTL: 300s (TERMINAL — cannot delegate further)
```

Flag violations clearly:
- "**VIOLATION I3**: Child warrant expires at 16:00 but parent expires at 15:30 — child outlives parent"
- "**VIOLATION I4**: Child has `write_file` capability but parent does not — privilege escalation"

### Phase 8: Risk Assessment

Assess each warrant against this risk framework:

| Finding | Severity | What it means |
|---|---|---|
| `_allow_unknown=True` | **HIGH** | Additional unlisted arguments are admitted; declared constraints still apply. Assess whether those additional fields can affect the operation. The flag travels on the wire; inspect the minting side and actual installed diagnostics rather than assuming a TypeScript view proves its absence. |
| PoP not enforced | **HIGH** | A path accepting only warrant possession lacks holder authentication. Confirm whether another trusted layer enforces proof before describing the path as protected. |
| Public URL fetching without SSRF controls | **HIGH** | Inspect private/metadata destination access, redirects and DNS behavior. Deliberately authorized private endpoints need explicit scope, not a blanket public-only rule. |
| No TTL or TTL > 1 hour | **MEDIUM** | Long-lived credential. Increases the blast radius time window. Like a non-expiring session token. |
| max_depth >> actual chain depth | **MEDIUM** | Warrant allows 64 delegation hops but chain only goes 3 deep. Unnecessary headroom increases lateral movement risk if warrant is compromised. |
| CEL constraint without review | **MEDIUM** | Custom evaluation logic. Could contain subtle bugs or overly permissive expressions. Needs human verification — like a custom OPA policy. |
| Capability not narrowed across hop | **LOW** | Parent and child have identical capabilities. Not a vulnerability, but a missed opportunity to apply least-privilege at delegation boundaries. |
| Regex constraint on delegated warrant | **LOW** | Regex constraints can stay identical or narrow to an admitted Exact value; arbitrary regex containment is unsupported. May limit attenuation flexibility downstream. |

Present findings with severity and remediation:

```
🔒 Security Assessment

HIGH ⚠️  Public URL fetching admits unintended private destinations
         Risk: Agent could reach internal services or cloud metadata endpoints
         Fix: Supported URL constraints plus redirect/resolution checks in the fetcher

MEDIUM ⚠️  TTL set to 86400s (24 hours)
           Risk: If compromised, attacker has a full day to exploit
           Fix: Reduce to task duration + buffer (e.g., 1800s for a 15-min task)

LOW ℹ️  Capability "read_file" not narrowed from parent to child
        Note: Both have Subpath("/data") — child could be narrowed to
              Subpath("/data/reports") for tighter least-privilege
```

### Phase 9: Cloud Audit Trail ☁️ (Tenuo Cloud only)

> This phase only applies if Tenuo Cloud is configured — look for `tenuo_cloud` imports or `tc_` env vars. Skip entirely for open-source deployments.

Use existing authorization for read-only Cloud inspection when available; otherwise ask before accessing that account. Verify the installed Cloud client supports the requested query rather than inventing audit/history methods.

If yes, check:
- **Issuance receipts** — cryptographic proof of when and why the warrant was issued
- **Approval history** — which approval gates were triggered, who approved
- **Revocation status** — is this warrant on the Signed Revocation List (SRL)?
- **Template source** — which policy template was used to generate this warrant

Present: "This warrant was issued via trigger `trg_abc123` at 2026-03-13T14:00:00Z. Approved by admin@example.com. Not revoked. Last SRL sync: 3 seconds ago."

### Output Formats

Offer the appropriate format based on context:

- **Summary** — One paragraph, shareable with stakeholders who don't need technical detail
- **Detailed** — Full constraint-by-constraint analysis with analogies and risk ratings (default)
- **Comparison** — Side-by-side diff of two warrants (useful for before/after attenuation review, or comparing two versions of a policy)

After completing, suggest: "Want to create a tighter replacement warrant? Use `/tenuo-warrant` to build one from scratch with the right constraints."

## Key Tenuo Concepts for Security Review

**Monotonic attenuation**: Every delegation can only narrow permissions. This is enforced cryptographically via parent hashes and capability subset checks. A conforming verifier rejects widened delegation. Missing mediation, an untrusted root configuration, unsafe argument handling or a verifier bug can defeat the intended protection; signed tokens alone do not secure an application.

**Proof-of-Possession (PoP)**: Warrants are bound to a public key. Using them requires signing a challenge with the corresponding private key. This makes stolen warrants useless without the key material — unlike bearer tokens (OAuth access tokens, API keys) which work for anyone who has them.

**Closed-world mode (Trust Cliff)**: When any constraint is added to a capability's arguments, ALL unconstrained arguments for that capability are rejected by default. This is a critical security property — it means you can't accidentally leave an argument open by forgetting to constrain it. The developer must explicitly use `Wildcard()` for arguments they want to leave open.

**MAX_DELEGATION_DEPTH = 64**: Core hard cap on depth, with root depth 0. Inspect the installed builder before recommending a setter: released Python 0.3.2's high-level `MintBuilder` has no `max_depth()` or `terminal()`. A supported grant builder can make the worker child terminal.

**Signed Revocation List (SRL)**: Available locally through the SDK, with CLI
helpers when installed. A verifier must receive and enforce a correctly signed,
current list for early revocation to take effect. Inspect its trusted issuer,
version and update path; do not infer a propagation deadline or rollback
protection across restarts from the existence of an SRL file.

**Open-source vs. Tenuo Cloud — audit implications:**

| | Open-source | Tenuo Cloud ☁️ |
|---|---|---|
| Warrant chain verification | ✅ | ✅ |
| HSM-backed managed KMS | ❌ | ✅ |
| Signed revocation list (SRL) — revoke before TTL | ✅; operator distributes updates | ✅ |
| Signed authorization receipts — per-decision, verifiable, exportable | ✅; inspect the configured sink | ✅ |
| Receipt signature and link verification | ✅; does not prove complete history | ✅; inspect collection guarantees |
| Managed issuance + approval workflow history | Operator-managed local artifacts | ✅ |
| Approval channel integrations — Slack, Telegram, dashboard | ❌ | ✅ |
| Automated warrant generation from observed call patterns | ❌ | ✅ |
| Constraint drift detection + alerts | ❌ | ✅ |
| Authorizer fleet health monitoring | ❌ | ✅ |

For local deployments, assess the actual verifier: capabilities, argument
constraints, expiry, holder proof, approval gates and installed SRL enforcement.
A signed warrant grants authority until expiry or revocation; it is not inherently
one-use. Reissuance creates a new grant and does not invalidate the old one.
Signed decision receipts do not prove a completed effect or a complete history.

Cloud is optional for centralized collection, managed distribution and fleet
operations. Do not recommend it as a prerequisite for local revocation or audit.
