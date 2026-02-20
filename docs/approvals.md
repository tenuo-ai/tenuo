# Human Approvals

> **Cryptographically verified human-in-the-loop authorization for AI agent tool calls.**

Warrants define *what* an agent can do. Approval policies define *when* a human must confirm before execution. Every approval is cryptographically signed — there is no unsigned path.

---

## Architecture

```
                   Warrant Authorization           Approval Policy
                   ──────────────────             ────────────────
Tool Call ──► Rust Core verifies warrant ──► Python checks policy rules
              (PoP, expiration, constraints)        |
                                              no rule matches → proceed
                                              rule matches → invoke handler
                                                    |
                                              handler(s) sign → collect approvals
                                                    |
                                              Rust core verifies signatures
                                              + hash binding + expiry + trust
                                                    |
                                              threshold met (m-of-n) → proceed
                                              threshold not met → raise error
```

**Key separation**:

| Concern | Mechanism | Where |
|---------|-----------|-------|
| *What* an agent can do | Warrant (cryptographic) | Rust core |
| *When* a human must confirm | ApprovalPolicy (runtime) | Python |
| *Proof* of confirmation | SignedApproval (Ed25519) | Rust core |
| *Who* can confirm | trusted_approvers (PublicKey list) | Python policy |
| *How many* must confirm | threshold (m-of-n) | Python policy, verified by Rust core |

---

## Cryptographic Model

### Request Hash

Every approval is bound to a specific `(warrant_id, tool, args, holder)` tuple via a SHA-256 request hash computed in the Rust core:

```python
from tenuo import compute_request_hash

hash = compute_request_hash(
    warrant_id="tnu_wrt_...",
    tool="transfer",
    args={"amount": 50000, "to": "alice"},
    holder=agent_key.public_key,  # binds to specific agent
)
# Returns 32-byte SHA-256 hash
```

The hash ensures:
- An approval for `transfer(amount=50000)` cannot be reused for `transfer(amount=999999)`
- An approval for warrant A cannot be replayed against warrant B
- An approval for agent X cannot be stolen by agent Y (holder binding)

### SignedApproval

The `SignedApproval` is the cryptographic proof. It contains:

| Field | Purpose |
|-------|---------|
| `approval_version` | Protocol version (currently 1) |
| `payload` | CBOR-encoded `ApprovalPayload` (signed content) |
| `approver_key` | Ed25519 public key of the approver |
| `signature` | Ed25519 signature over the payload |

The `ApprovalPayload` contains:

| Field | Purpose |
|-------|---------|
| `request_hash` | SHA-256 hash binding to the exact call |
| `nonce` | 16-byte random nonce (replay protection) |
| `external_id` | Identity of the approver (e.g., email) |
| `approved_at` | Unix timestamp when approved |
| `expires_at` | Unix timestamp when the approval expires |

### Verification Pipeline

When `enforce_tool_call()` receives `SignedApproval`(s) from a handler, the Rust core verifies each one:

1. **Signature** — Ed25519 signature check
2. **Hash match** — `payload.request_hash == expected_hash` (prevents reuse across calls)
3. **Expiry** — `payload.expires_at > now` (with 30-second clock tolerance for distributed systems)
4. **Key trust** — `signed.approver_key in policy.trusted_approvers` (prevents rogue approvers)
5. **Deduplication** — one vote per approver key (prevents double-counting)
6. **Threshold** — valid approval count >= `policy.threshold` (m-of-n satisfaction)

For **1-of-1** failures, the Rust core returns the specific rejection reason (e.g., "request hash mismatch", "approval expired"). For **m-of-n** failures, it returns a summary of all rejection reasons (e.g., "required 2, received 1 [rejected: 1 expired, 1 not trusted]").

---

## Quick Start

```python
from tenuo import (
    SigningKey, Warrant, ApprovalPolicy,
    require_approval, auto_approve, sign_approval, cli_prompt,
    guard, warrant_scope, key_scope,
)

# 1. Keys
agent_key = SigningKey.generate()      # the AI agent
approver_key = SigningKey.generate()   # the human approver

# 2. Warrant (what the agent can do)
warrant = (Warrant.mint_builder()
    .capability("transfer")
    .capability("search")
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(agent_key)
)

# 3. Approval policy (when a human must confirm)
policy = ApprovalPolicy(
    require_approval("transfer", when=lambda args: args["amount"] > 10_000),
    trusted_approvers=[approver_key.public_key],
)

# 4. Protect a function with @guard
@guard(
    tool="transfer",
    approval_policy=policy,
    approval_handler=cli_prompt(approver_key=approver_key),
)
def transfer(amount: int, to: str):
    print(f"Transferring {amount} to {to}")

# 5. Call it within a warrant context
with warrant_scope(warrant), key_scope(agent_key):
    transfer(amount=50_000, to="alice")
    # The CLI prompts the human. If they type 'y', a SignedApproval is
    # created, verified, and the call proceeds. If 'n', ApprovalDenied is raised.
```

---

## M-of-N Multi-Sig

Require multiple approvers to sign before a tool call proceeds:

```python
policy = ApprovalPolicy(
    require_approval("deploy_prod"),
    require_approval("transfer_funds", when=lambda a: a["amount"] > 100_000),
    trusted_approvers=[alice.public_key, bob.public_key, carol.public_key],
    threshold=2,  # any 2-of-3 must approve
)
```

The `threshold` parameter (default: 1) specifies the minimum number of valid approvals required. The Rust core verifies each approval independently and checks that the count of valid, unique approvals meets the threshold.

| `threshold` | `trusted_approvers` | Meaning |
|-------------|---------------------|---------|
| 1 | `[alice]` | Single approver (default) |
| 2 | `[alice, bob, carol]` | Any 2 of 3 must approve |
| 3 | `[alice, bob, carol]` | All 3 must approve |

Validation rules:
- `threshold` must be >= 1
- `threshold` must be <= `len(trusted_approvers)` when `trusted_approvers` is set
- Each approver can only contribute one vote (duplicates are rejected)

---

## TTL Hierarchy

Approval TTL (how long a signed approval remains valid) is resolved in priority order:

```
1. Handler-level ttl_seconds argument         (highest priority)
2. Policy-level default_ttl                   (org-wide default)
3. 300 seconds (5 minutes)                    (fallback)
```

Examples:

```python
# Policy sets a 1-hour default for async workflows
policy = ApprovalPolicy(
    require_approval("deploy"),
    trusted_approvers=[ops.public_key],
    default_ttl=3600,
)

# Handler overrides with a shorter window
handler = cli_prompt(approver_key=ops_key, ttl_seconds=60)

# Or let the policy default flow through
handler = cli_prompt(approver_key=ops_key)  # uses policy's 3600s
```

For long-running approval flows (e.g., Slack-based, email-based), set `default_ttl` on the policy:

```python
policy = ApprovalPolicy(
    require_approval("deploy_prod"),
    trusted_approvers=[...],
    threshold=2,
    default_ttl=86400,  # 24 hours for async multi-sig collection
)
```

---

## Framework Integration

Approval policies plug into all framework `GuardBuilder`s via `.approval_policy()` and `.on_approval()`:

### CrewAI

```python
from tenuo.crewai import GuardBuilder
from tenuo import SigningKey, ApprovalPolicy, require_approval, cli_prompt

approver_key = SigningKey.generate()

guard = (GuardBuilder()
    .allow("search", query=Wildcard())
    .allow("transfer_funds", amount=Range(0, 100_000))
    .with_warrant(warrant, agent_key)
    .approval_policy(ApprovalPolicy(
        require_approval("transfer_funds", when=lambda a: a["amount"] > 10_000),
        trusted_approvers=[approver_key.public_key],
    ))
    .on_approval(cli_prompt(approver_key=approver_key))
    .build())

guard.register()
crew.kickoff()
```

### AutoGen

```python
from tenuo.autogen import GuardBuilder

guard = (GuardBuilder()
    .allow("transfer_funds")
    .with_warrant(warrant, agent_key)
    .approval_policy(policy)
    .on_approval(cli_prompt(approver_key=approver_key))
    .build())

protected = guard.guard_tool(transfer_funds)
```

### OpenAI

```python
from tenuo.openai import GuardBuilder

client = (GuardBuilder(openai.OpenAI())
    .allow("transfer_funds")
    .with_warrant(warrant, agent_key)
    .approval_policy(policy)
    .on_approval(cli_prompt(approver_key=approver_key))
    .build())
```

### Google ADK

```python
from tenuo.google_adk import GuardBuilder

guard = (GuardBuilder()
    .with_warrant(warrant, agent_key)
    .approval_policy(policy)
    .on_approval(cli_prompt(approver_key=approver_key))
    .build())

agent = Agent(
    tools=guard.filter_tools(tools),
    before_tool_callback=guard.before_tool,
)
```

### LangGraph

Both `TenuoMiddleware` (recommended) and `TenuoToolNode` accept approval parameters directly:

```python
from tenuo.langgraph import TenuoMiddleware

middleware = TenuoMiddleware(
    approval_policy=policy,
    approval_handler=cli_prompt(approver_key=approver_key),
)

agent = create_agent(
    model="gpt-4.1",
    tools=tools,
    middleware=[middleware],
)
```

### LangChain

Pass approval parameters through `guard()`:

```python
from tenuo.langchain import guard

tools = guard(
    [search, transfer_funds],
    bound_warrant,
    approval_policy=policy,
    approval_handler=cli_prompt(approver_key=approver_key),
)
```

---

## Approval Rules

Rules define which tool calls require approval:

```python
from tenuo import require_approval

# Always requires approval
require_approval("delete_user")

# Conditional — only when amount > 10K
require_approval("transfer", when=lambda args: args["amount"] > 10_000)

# With description (shown to the approver)
require_approval("send_email",
    when=lambda args: not args["to"].endswith("@company.com"),
    description="External emails require approval")
```

If the `when` predicate raises an exception, the rule **triggers** (fail-closed).

---

## Approval Policy

The policy collects rules and configures trust and threshold:

```python
from tenuo import ApprovalPolicy

policy = ApprovalPolicy(
    require_approval("transfer", when=lambda a: a["amount"] > 10_000),
    require_approval("delete_user"),
    require_approval("send_email"),
    trusted_approvers=[admin_key.public_key, ops_key.public_key],
    threshold=1,       # default: single approval required
    default_ttl=3600,  # optional: 1-hour approval window
)
```

| Parameter | Default | Effect |
|-----------|---------|--------|
| `*rules` | (required) | One or more `ApprovalRule` instances |
| `trusted_approvers` | `None` | If set, only these `PublicKey`s are accepted. If `None`, any valid signature passes |
| `threshold` | `1` | Minimum valid approvals required (m-of-n multi-sig) |
| `default_ttl` | `None` | Default TTL in seconds for signed approvals. `None` means handlers use their own default (typically 300s) |

---

## Built-in Handlers

| Handler | Signs? | Use Case |
|---------|--------|----------|
| `cli_prompt(approver_key=key)` | Yes | Local development — prompts in terminal |
| `auto_approve(approver_key=key)` | Yes | Testing — signs everything automatically |
| `auto_deny(reason=...)` | No (raises) | Dry-run / audit mode |
| `tenuo.approval.webhook(url=...)` | Placeholder | Tenuo Cloud integration (not yet in public API) |

All signing handlers require the approver's `SigningKey`. This is the key that produces the `SignedApproval`. It should be held by the human (or approval service), not the agent.

---

## Custom Handlers

Handlers implement a simple protocol: receive an `ApprovalRequest`, return a `SignedApproval` (or raise `ApprovalDenied`).

```python
from tenuo.approval import sign_approval, ApprovalDenied

def slack_approval(request):
    """Post to Slack, wait for reaction."""
    channel_response = post_to_slack(
        channel="#approvals",
        text=f"Approve {request.tool}({request.arguments})?",
    )
    reaction = wait_for_reaction(channel_response, timeout=300)

    if reaction != "thumbsup":
        raise ApprovalDenied(request, reason=f"denied in Slack by {reaction.user}")

    return sign_approval(
        request,
        approver_key,
        external_id=reaction.user,
        ttl_seconds=60,
    )
```

### Async Handlers

Async handlers are supported natively:

```python
async def async_handler(request):
    result = await call_approval_service(request)
    if not result.approved:
        raise ApprovalDenied(request, reason=result.reason)
    return sign_approval(request, approver_key)
```

### The `sign_approval` Helper

The canonical way to produce a `SignedApproval`:

```python
from tenuo import sign_approval

signed = sign_approval(
    request,                           # ApprovalRequest
    approver_key,                      # SigningKey
    external_id="alice@company.com",   # who approved (metadata)
    ttl_seconds=300,                   # approval validity window
)
```

This handles nonce generation, timestamps, and signing. You can also construct the `ApprovalPayload` and `SignedApproval` manually for full control.

---

## Exceptions

All approval exceptions are in `tenuo.approval`:

```python
from tenuo.approval import (
    ApprovalRequired,
    ApprovalDenied,
    ApprovalTimeout,
    ApprovalVerificationError,
)
```

| Exception | When | Contains |
|-----------|------|----------|
| `ApprovalRequired` | Rule triggered but no handler configured | `request` |
| `ApprovalDenied` | Handler explicitly denied | `request`, `reason` |
| `ApprovalTimeout` | Handler timed out (subclass of `ApprovalDenied`) | `request`, `timeout_seconds` |
| `ApprovalVerificationError` | Crypto verification failed | `request`, `reason` |

`ApprovalVerificationError` reasons include:
- `"invalid signature: ..."` — Ed25519 signature check failed
- `"request hash mismatch (approval was signed for a different request)"` — replay attempt
- `"approval expired (beyond clock tolerance)"` — `expires_at` in the past (with 30s tolerance)
- `"approver not in trusted set"` — untrusted key
- `"duplicate approval from same approver"` — same key signed twice

For m-of-n failures, `InsufficientApprovals` is raised with a diagnostic summary:
```
Insufficient approvals: required 2, received 1 [rejected: 1 expired, 1 not trusted]
```

---

## Security Properties

| Property | Mechanism | Test |
|----------|-----------|------|
| **No unsigned approvals** | Handler must return `SignedApproval`; no `approved=True` boolean | `TestAutoApprove`, `TestCliPrompt` |
| **Call binding** | SHA-256 request hash over `(warrant, tool, args, holder)` | `TestRequestHashBinding` |
| **Replay prevention** | Different warrant/tool/args/holder = different hash; random nonce | `test_approval_reuse_across_warrants_fails` |
| **Forgery resistance** | Ed25519 signature verification in Rust core | `test_tampered_bytes_fail_verify` |
| **Key trust** | `trusted_approvers` list on policy | `TestMultiApprover`, `test_untrusted_key_rejected` |
| **Time-bound** | `expires_at` checked with 30s clock tolerance | `test_expired_approval_rejected` |
| **Fail-closed** | Buggy handler = `internal_error` denial | `test_handler_exception_is_fail_closed` |
| **Warrant priority** | Warrant denial short-circuits before approval check | `test_warrant_denial_takes_priority` |
| **Constraint priority** | Constraint violation short-circuits before approval check | `test_constraint_violation_skips_approval` |
| **M-of-N threshold** | Rust core counts valid approvals, rejects duplicates | `TestMofN` (13 Rust + 11 Python tests) |
| **Diagnostic errors** | Specific rejection reasons for 1-of-1; summary for m-of-n | `test_1of1_*`, `test_mofn_diagnostic_*` |

---

## Warrants vs Approvals

| | Warrants | Approvals |
|---|---------|-----------|
| **Question** | "Can this agent do X?" | "Should this specific call proceed?" |
| **Issuer** | Control plane / parent agent | Human approver |
| **Scope** | Capabilities + constraints | Single tool call |
| **Lifetime** | TTL (minutes to hours) | TTL (seconds to minutes) |
| **Enforcement** | Rust core (security boundary) | Python + Rust crypto (defense in depth) |
| **Bypass impact** | Full security breach | Operational control loss (warrant still enforced) |

Warrants are the security boundary. Approvals are defense in depth. Even if the approval layer is bypassed (compromised Python process), the warrant still limits what the agent can do.

---

## See Also

- [Enforcement Models](enforcement.md) — Where approvals fit in the enforcement pipeline
- [AI Agents Security](ai-agents.md) — The 4-layer defense strategy
- [Concepts](concepts.md) — Warrants, PoP, attenuation
