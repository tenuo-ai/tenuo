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
                                              handler signs → verify → proceed
                                              handler denies → raise ApprovalDenied
```

**Key separation**:

| Concern | Mechanism | Where |
|---------|-----------|-------|
| *What* an agent can do | Warrant (cryptographic) | Rust core |
| *When* a human must confirm | ApprovalPolicy (runtime) | Python |
| *Proof* of confirmation | SignedApproval (Ed25519) | Rust core |
| *Who* can confirm | trusted_approvers (PublicKey list) | Python policy |

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

When `enforce_tool_call()` receives a `SignedApproval` from a handler, it verifies:

1. **Signature** — `signed.verify()` checks the Ed25519 signature (Rust core)
2. **Hash match** — `payload.request_hash == expected_hash` (prevents reuse)
3. **Expiry** — `payload.expires_at > now` (prevents stale approvals)
4. **Key trust** — `signed.approver_key in policy.trusted_approvers` (prevents rogue approvers)

If any check fails, `ApprovalVerificationError` is raised. The tool call never executes.

---

## Quick Start

```python
from tenuo import (
    SigningKey, Warrant, ApprovalPolicy,
    require_approval, auto_approve, cli_prompt,
)
from tenuo._enforcement import enforce_tool_call

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
bound = warrant.bind(agent_key)

# 3. Approval policy (when a human must confirm)
policy = ApprovalPolicy(
    require_approval("transfer", when=lambda args: args["amount"] > 10_000),
    trusted_approvers=[approver_key.public_key],
)

# 4. Enforce
result = enforce_tool_call(
    "transfer", {"amount": 50_000}, bound,
    approval_policy=policy,
    approval_handler=cli_prompt(approver_key=approver_key),
)
# The CLI prompts the human. If they type 'y', a SignedApproval is created,
# verified, and the call proceeds. If 'n', ApprovalDenied is raised.
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

The policy collects rules and optionally specifies trusted approver keys:

```python
from tenuo import ApprovalPolicy

policy = ApprovalPolicy(
    require_approval("transfer", when=lambda a: a["amount"] > 10_000),
    require_approval("delete_user"),
    require_approval("send_email"),
    trusted_approvers=[admin_key.public_key, ops_key.public_key],
)
```

| Parameter | Default | Effect |
|-----------|---------|--------|
| `*rules` | (required) | One or more `ApprovalRule` instances |
| `trusted_approvers` | `None` | If set, only these `PublicKey`s are accepted. If `None`, any valid signature passes |

---

## Built-in Handlers

| Handler | Signs? | Use Case |
|---------|--------|----------|
| `cli_prompt(approver_key=key)` | Yes | Local development — prompts in terminal |
| `auto_approve(approver_key=key)` | Yes | Testing — signs everything automatically |
| `auto_deny(reason=...)` | No (raises) | Dry-run / audit mode |
| `webhook(url=...)` | Placeholder | Tenuo Cloud integration |

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
from tenuo.approval import sign_approval

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

| Exception | When | Contains |
|-----------|------|----------|
| `ApprovalRequired` | Rule triggered but no handler configured | `request` |
| `ApprovalDenied` | Handler explicitly denied | `request`, `reason` |
| `ApprovalTimeout` | Handler timed out (subclass of `ApprovalDenied`) | `request`, `timeout_seconds` |
| `ApprovalVerificationError` | Crypto verification failed | `request`, `reason` |

`ApprovalVerificationError` reasons include:
- `"invalid signature: ..."` — Ed25519 signature check failed
- `"request hash mismatch (approval bound to different call)"` — replay attempt
- `"signed approval has expired"` — `expires_at` in the past
- `"approver key not in trusted_approvers"` — untrusted key

---

## Security Properties

| Property | Mechanism | Test |
|----------|-----------|------|
| **No unsigned approvals** | Handler must return `SignedApproval`; no `approved=True` boolean | `TestAutoApprove`, `TestCliPrompt` |
| **Call binding** | SHA-256 request hash over `(warrant, tool, args, holder)` | `TestRequestHashBinding` |
| **Replay prevention** | Different warrant/tool/args/holder = different hash; random nonce | `test_approval_reuse_across_warrants_fails` |
| **Forgery resistance** | Ed25519 signature verification | `test_tampered_bytes_fail_verify` |
| **Key trust** | `trusted_approvers` list on policy | `TestMultiApprover`, `test_untrusted_key_rejected` |
| **Time-bound** | `expires_at` checked against current time | `test_expired_approval_rejected` |
| **Fail-closed** | Buggy handler = `internal_error` denial | `test_handler_exception_is_fail_closed` |
| **Warrant priority** | Warrant denial short-circuits before approval check | `test_warrant_denial_takes_priority` |
| **Constraint priority** | Constraint violation short-circuits before approval check | `test_constraint_violation_skips_approval` |

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
