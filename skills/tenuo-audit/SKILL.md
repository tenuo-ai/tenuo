---
name: tenuo-audit
description: Audit, explain, and review tenuo warrants for security engineers and CISOs. Use this skill when someone wants to understand what a warrant authorizes, assess blast radius, review delegation chains, check for security risks, or audit agent permissions. Also trigger when a security engineer asks about agent authorization, access control review, permission auditing, or wants warrants explained in IAM/RBAC/OAuth terms.
---

# Tenuo Warrant Auditor

Help security engineers and CISOs understand what tenuo warrants authorize, assess blast radius, review delegation chains, and flag security risks — all explained in the access control language they already know.

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

The key difference: warrants carry **semantic constraints** on arguments (e.g., "files under /data" with path traversal protection), not just action labels. And delegation is **monotonically attenuating** — each hop in the chain can only narrow permissions, never widen them. This is enforced cryptographically, not by policy.

## Flow

### Phase 1: Context Discovery

Scan the codebase for tenuo usage:
1. Search for `import tenuo`, `from tenuo`, `Warrant`, `mint_builder`, `grant_builder`, `@guard`
2. Check for `tenuo_cloud` imports or `tc_` env vars (indicates cloud deployment)
3. Look for warrant serialization patterns (base64 strings, `warrant.serialize()`, `Warrant(...)` deserialization)

### Phase 2: Persona Check

Ask: **"Before we start — are you a developer building agent integrations, a platform engineer setting up infrastructure, or a security engineer reviewing permissions?"**

- **Security engineer / CISO** → continue with this skill
- **Developer** → suggest `/tenuo-warrant` instead ("That skill helps you create warrants from scratch — it'll walk you through what your agent needs")
- **Platform engineer** → continue, adjusting framing for infrastructure review

### Phase 3: Source Selection

Ask: **"What would you like to audit?"**

- **a) A warrant string** — they'll paste a base64-encoded warrant for you to decode and explain
- **b) Warrants in the codebase** — find all `mint_builder`, `grant_builder`, `GuardBuilder`, `mint()`, `grant()` calls and analyze them
- **c) A delegation chain** — multiple warrants showing parent → child relationships
- **d) Cloud audit trail** — connect to tenuo cloud API for issuance receipts, approval history, revocation status

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

### Phase 5: Plain-Language Explanation

Present what the warrant authorizes in security review format:

```
🔍 Warrant Analysis

Holder: [key fingerprint or identifier]
Issuer: [key fingerprint or identifier]
Chain depth: 2 of 3 (1 delegation hop remaining)

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
  🔗 Delegation: depth 2/3 — can delegate once more, then terminal

BINDING:
  🔒 Proof-of-possession: Required (bearer token risk mitigated)
  📋 Closed-world: Active (unconstrained arguments rejected)
```

### Phase 6: Familiar Framework Mapping

Translate the warrant into equivalent policies the security engineer is used to reviewing:

```
IAM Policy Equivalent:
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "github:CreateIssue"],
  "Resource": ["arn:aws:s3:::data/reports/*", "github:repos/*/issues"],
  "Condition": {
    "IpAddress": {"aws:SourceIp": "not-applicable (UrlSafe handles this)"},
    "DateLessThan": {"aws:CurrentTime": "2026-03-13T15:30:00Z"}
  }
}

RBAC Equivalent:
  Role: report-reader-github-issuer
  Namespace: agent-pool
  Bindings: [read_file, create_issue]
  Session limit: 30 minutes

OAuth Equivalent:
  Scopes: files:read:reports, github:issues:write
  Token type: DPoP-bound (not bearer)
  Expires: 1800s
  Refresh: None (warrant is one-use authority chain)
```

### Phase 7: Delegation Chain Verification

For delegation chains (multiple warrants showing parent → child):

**Verify invariants I1-I5 statically:**
- **I1**: `child.issuer == parent.holder` (delegation comes from the right entity)
- **I2**: `child.depth == parent.depth + 1` (depth increments correctly)
- **I3**: `child.expires_at <= parent.expires_at` (child can't outlive parent)
- **I4**: `child.capabilities ⊆ parent.capabilities` (capabilities only narrow)
- **I5**: `child.parent_hash == SHA256(parent.payload)` (chain integrity)

**I6 (PoP signature) is a runtime property** — it cannot be verified from static warrant inspection. Instead, check whether PoP enforcement is configured in the codebase. If not, flag as HIGH risk.

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
| `_allow_unknown=True` | **HIGH** | Closed-world disabled. Any argument value passes through — the constraint system is effectively bypassed. Like an IAM policy with `"Resource": "*"`. |
| PoP not enforced | **HIGH** | Warrant is a bearer token. If stolen, attacker can use it without the holder's private key. Like an API key vs. mTLS. |
| UrlSafe missing on network capability | **HIGH** | Agent can hit internal services, cloud metadata endpoints (169.254.169.254). SSRF risk. |
| No TTL or TTL > 1 hour | **MEDIUM** | Long-lived credential. Increases the blast radius time window. Like a non-expiring session token. |
| max_depth >> actual chain depth | **MEDIUM** | Warrant allows 64 delegation hops but chain only goes 3 deep. Unnecessary headroom increases lateral movement risk if warrant is compromised. |
| CEL constraint without review | **MEDIUM** | Custom evaluation logic. Could contain subtle bugs or overly permissive expressions. Needs human verification — like a custom OPA policy. |
| Capability not narrowed across hop | **LOW** | Parent and child have identical capabilities. Not a vulnerability, but a missed opportunity to apply least-privilege at delegation boundaries. |
| Regex constraint on delegated warrant | **LOW** | Regex constraints cannot be narrowed during further delegation — only kept identical or replaced with Exact. May limit attenuation flexibility downstream. |

Present findings with severity and remediation:

```
🔒 Security Assessment

HIGH ⚠️  UrlSafe not applied to "call_api" capability
         Risk: Agent could call internal services or cloud metadata endpoints
         Fix: Add UrlSafe() constraint — All([UrlSafe(), UrlPattern("https://...")])

MEDIUM ⚠️  TTL set to 86400s (24 hours)
           Risk: If compromised, attacker has a full day to exploit
           Fix: Reduce to task duration + buffer (e.g., 1800s for a 15-min task)

LOW ℹ️  Capability "read_file" not narrowed from parent to child
        Note: Both have Subpath("/data") — child could be narrowed to
              Subpath("/data/reports") for tighter least-privilege
```

### Phase 9: Cloud Audit Trail

If tenuo cloud is configured (`tenuo_cloud` imports or `tc_` API keys detected):

Ask: "Want me to pull the audit trail from tenuo cloud for this warrant?"

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

**Monotonic attenuation**: Every delegation can only narrow permissions. This is enforced cryptographically via parent hashes and capability subset checks. Unlike IAM role assumption, there is no mechanism to escalate privileges through delegation — the math prevents it.

**Proof-of-Possession (PoP)**: Warrants are bound to a public key. Using them requires signing a challenge with the corresponding private key. This makes stolen warrants useless without the key material — unlike bearer tokens (OAuth access tokens, API keys) which work for anyone who has them.

**Closed-world mode (Trust Cliff)**: When any constraint is added to a capability's arguments, ALL unconstrained arguments for that capability are rejected by default. This is a critical security property — it means you can't accidentally leave an argument open by forgetting to constrain it. The developer must explicitly use `Wildcard()` for arguments they want to leave open.

**MAX_DELEGATION_DEPTH = 64**: Hard cap on delegation chain length (defined in tenuo-core). This prevents unbounded trust propagation. In practice, most chains are 2-4 hops. A `max_depth` of 64 on a warrant with a 3-hop chain is unnecessary headroom.

**Signed Revocation List (SRL)**: Cloud-only feature. Warrants can be explicitly revoked before TTL expiry. SRL propagates to authorizer sidecars within ~10 seconds. For open-source deployments, TTL is the only expiration mechanism.
