# Human Approvals

> **Cryptographically verified human-in-the-loop authorization for AI agent tool calls.**

Define **who must approve**, **how many**, and **which calls** in the warrant. Collect `SignedApproval` signatures and retry. There is no unsigned path.

---

## Quick Start

```python
from tenuo import SigningKey, Warrant, BoundWarrant, enforce_tool_call, cli_prompt

control_key = SigningKey.generate()
agent_key = SigningKey.generate()
approver_key = SigningKey.generate()

# 1. Warrant — capabilities, gates, approvers, threshold
warrant = (Warrant.mint_builder()
    .capability("transfer")
    .approval_gates({"transfer": None})       # this tool needs approval
    .required_approvers([approver_key.public_key])
    .approval_threshold(1)
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_key)
)

# 2. Enforce — handler prompts and signs on gate fire
result = enforce_tool_call(
    tool_name="transfer",
    tool_args={"amount": 50_000, "to": "alice"},
    bound_warrant=BoundWarrant(warrant, agent_key),
    trusted_roots=[control_key.public_key],
    approval_handler=cli_prompt(approver_key=approver_key),
)
```

**Three things to configure:**

| On the warrant | Purpose |
|----------------|---------|
| `.approval_gates({...})` | Which tool calls trigger approval |
| `.required_approvers([...])` | Who may sign |
| `.approval_threshold(n)` | How many valid signatures (m-of-n) |

**Two ways to supply approvals at runtime:**

| Mechanism | When |
|-----------|------|
| `approval_handler=...` | Prompt or call your approval UI when a gate fires |
| `approvals=[signed, ...]` | Pre-collected `SignedApproval` objects (retry / out-of-band) |

Gates are evaluated per call. Listing `required_approvers` alone does **not** require approval unless a gate fires for that `(tool, args)`.

---

## Approval Gates

```python
warrant = (Warrant.mint_builder()
    .capability("search")
    .capability("transfer")
    .approval_gates({
        "transfer": None,   # all transfer calls
        # "search" — no gate, proceeds without approval
    })
    .required_approvers([approver_key.public_key])
    .approval_threshold(1)
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_key)
)
```

Per-argument gates are supported — see [MCP approval gates](mcp.md#approval-gates) for constraint-keyed examples.

---

## M-of-N Multi-Sig

```python
warrant = (Warrant.mint_builder()
    .capability("deploy_prod")
    .approval_gates({"deploy_prod": None})
    .required_approvers([alice.public_key, bob.public_key, carol.public_key])
    .approval_threshold(2)   # any 2-of-3
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_key)
)
```

---

## Retry Flow

```
Call without approvals
  → gate fires
  → caller gets approval_required (or insufficient_approvals if partial)
  → collect SignedApproval(s) bound to request_hash
  → retry same call with approvals attached
  → threshold met → proceed
```

Sign approvals with `sign_approval(request, approver_key)` or a built-in handler (`cli_prompt`, custom Slack handler, etc.).

---

## Signals by Integration

Use these to branch client/workflow retry logic. **Do not** parse denial message strings.

| Integration | First call (gate, no approvals) | Partial multi-sig | Retry with |
|-------------|--------------------------------|-------------------|------------|
| **In-process** | `tenuo.approval.ApprovalRequired` | `tenuo.exceptions.InsufficientApprovals` | Same call + `approvals=[...]` or `approval_handler` |
| **MCP** | JSON-RPC `-32002` + `request_hash` | JSON-RPC `-32002` + `got` / `need` | `_meta.tenuo.approvals` |
| **FastAPI** | HTTP **409** `error: "approval_required"` + `request_hash` | HTTP **409** `error: "insufficient_approvals"` + `got` / `need` | `X-Tenuo-Approvals` header |
| **A2A** | JSON-RPC **-32019** + `request_hash` | JSON-RPC **-32020** + `required` / `received` | Approvals in request metadata |
| **Temporal** | `ApplicationError.type == "approval_required"` | `ApplicationError.type == "insufficient_approvals"` | `x-tenuo-approvals` header or `set_activity_approvals()` |

Scope denials (wrong tool, constraint, expired warrant) use different codes — see each integration guide.

**Field names:** Python exceptions use `required` / `received` in `.details`. HTTP and MCP retry payloads use `got` / `need`. A2A uses `required` / `received`.

---

## Framework Integration

Gates and approvers live on the **warrant**. Pass `approval_handler` (or pre-built `approvals`) to the adapter.

### LangChain

```python
from tenuo.langchain import guard
from tenuo.approval import cli_prompt

tools = guard(
    [search, transfer_funds],
    bound_warrant,
    approval_handler=cli_prompt(approver_key=approver_key),
)
```

### LangGraph

```python
from tenuo.langgraph import TenuoMiddleware

middleware = TenuoMiddleware(
    approval_handler=cli_prompt(approver_key=approver_key),
)
```

### CrewAI / AutoGen / OpenAI / Google ADK

```python
guard = (GuardBuilder()
    .allow("transfer_funds", amount=Range(0, 100_000))
    .with_warrant(warrant, agent_key)
    .on_approval(cli_prompt(approver_key=approver_key))
    .build())
```

See [LangChain](langchain.md), [CrewAI](crewai.md), [OpenAI](openai.md), [AutoGen](autogen.md), [Google ADK](google-adk.md), [MCP](mcp.md), [FastAPI](fastapi.md), [Temporal](temporal-reference.md).

### Temporal

```python
plugin = TenuoTemporalPlugin(
    TenuoPluginConfig(
        key_resolver=resolver,
        trusted_roots=[control_key.public_key],
        approval_handler=cli_prompt(approver_key=approver_key),
    )
)
```

---

## Built-in Handlers

| Handler | Use Case |
|---------|----------|
| `cli_prompt(approver_key=key)` | Local dev — terminal prompt |
| `auto_approve(approver_key=key)` | Tests — signs automatically |
| `auto_deny(reason=...)` | Dry-run — always raises |

All signing handlers require the approver's `SigningKey` (held by the human or approval service, not the agent).

---

## Custom Handlers

```python
from tenuo.approval import sign_approval, ApprovalDenied

def slack_approval(request):
    reaction = wait_for_slack_reaction(request, timeout=300)
    if reaction != "thumbsup":
        raise ApprovalDenied(request, reason="denied in Slack")
    return sign_approval(request, approver_key, external_id=reaction.user, ttl_seconds=60)
```

Async handlers are supported. Default approval TTL: handler `ttl_seconds` → **300s** fallback.

---

## Exceptions

| Exception | Module | When |
|-----------|--------|------|
| `ApprovalRequired` | `tenuo.approval` | Gate fired; no `approval_handler` / `approvals` (`enforce_tool_call`) |
| `ApprovalGateTriggered` | `tenuo.exceptions` | Gate fired; direct `Authorizer` / MCP PEP path |
| `InsufficientApprovals` | `tenuo.exceptions` | Approvals supplied but below threshold |
| `ApprovalDenied` / `ApprovalTimeout` | `tenuo.approval` | Handler denied or timed out |
| `ApprovalVerificationError` | `tenuo.approval` | Bad signature, hash mismatch, expired, untrusted key |
| `InvalidApproval` / `ApprovalExpired` | `tenuo.exceptions` | Invalid or expired signed approval on wire paths |

```python
from tenuo.approval import ApprovalRequired, ApprovalDenied, cli_prompt
from tenuo.exceptions import InsufficientApprovals, ApprovalGateTriggered
```

`InsufficientApprovals` message shape: `Insufficient approvals: required 2, received 1 [rejected: ...]`

---

## Cryptographic Model

Every approval binds to `(warrant_id, tool, args, holder)` via SHA-256:

```python
from tenuo import compute_request_hash

hash = compute_request_hash(
    warrant_id=warrant.id,
    tool="transfer",
    args={"amount": 50000, "to": "alice"},
    holder=agent_key.public_key,
)
```

`SignedApproval` = Ed25519 signature over `ApprovalPayload` (`request_hash`, `nonce`, `expires_at`, ...). Rust core verifies signature, hash, expiry (30s clock tolerance), approver trust, deduplication, and threshold.

---

## See Also

- [Enforcement Architecture](enforcement.md#human-approvals) — Where approvals sit in the pipeline
- [MCP Approval Gates](mcp.md#approval-gates) — Remote PEP retry flow
- [FastAPI](fastapi.md#error-handling) — HTTP 409 approval responses
- [Wire format §16](spec/wire-format-v1.md#16-approval-wire-format) — `SignedApproval` bytes
