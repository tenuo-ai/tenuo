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
    .min_approvals(1)
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

**Three things to configure on the warrant:**

| Method | Purpose |
|--------|---------|
| `.approval_gates({...})` | Which tool calls trigger approval |
| `.required_approvers([...])` | Who may sign |
| `.min_approvals(n)` | How many valid signatures (m-of-n) |

> **Naming:** use `.min_approvals()` when **minting**. On issued warrants, read the threshold with `warrant.approval_threshold()`. The wire field is `min_approvals`.

**Two ways to supply approvals at runtime:**

| Mechanism | When |
|-----------|------|
| `approval_handler=...` | Prompt or call your approval UI when a gate fires |
| `approvals=[signed, ...]` | Pre-collected `SignedApproval` objects (retry / out-of-band) |

Gates are evaluated per call. Listing `required_approvers` alone does **not** require approval unless a gate fires for that `(tool, args)`.

---

## Approval Gates

```python
from tenuo_core import Exact

warrant = (Warrant.mint_builder()
    .capability("search")
    .capability("restart_service")
    .approval_gates({
        "restart_service": {"environment": Exact("production")},  # prod only
        # whole-tool gate: "transfer": None
    })
    .required_approvers([approver_key.public_key])
    .min_approvals(1)
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_key)
)
```

---

## M-of-N Multi-Sig

```python
warrant = (Warrant.mint_builder()
    .capability("deploy_prod")
    .approval_gates({"deploy_prod": None})
    .required_approvers([alice.public_key, bob.public_key, carol.public_key])
    .min_approvals(2)   # any 2-of-3
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

Sign with `sign_approval(request, approver_key)` or a built-in handler (`cli_prompt`, etc.). Default approval TTL: handler `ttl_seconds` → **300s**.

**Branch on the signal, not the message:**
- First attempt → look for `request_hash` (or `ApprovalRequired` / `approval_required`)
- Partial multi-sig → look for `got`/`need` or `required`/`received` (or `InsufficientApprovals`)

---

## Wire Format (retry payloads)

Each `SignedApproval` is CBOR bytes. Adapters differ in how they wrap the list:

| Integration | Where | Encoding |
|-------------|-------|----------|
| **MCP** | `params._meta.tenuo.approvals` | JSON array of **base64(CBOR)** strings — no outer wrapper |
| **FastAPI / A2A** | `X-Tenuo-Approvals` header (A2A also accepts `x-tenuo-approvals` param) | **base64(JSON array of base64(CBOR) strings)** |
| **Temporal** | `x-tenuo-approvals` activity header | **JSON array of base64(CBOR) strings** — no outer base64 wrapper |

```python
import base64, json
from tenuo.approval import sign_approval

signed = sign_approval(request, approver_key)

# MCP / Temporal — array of base64 CBOR blobs
approvals_wire = [base64.b64encode(signed.to_bytes()).decode("ascii")]

# FastAPI / A2A — outer base64 JSON wrapper
header_value = base64.b64encode(json.dumps(approvals_wire).encode()).decode()
```

See integration guides: [MCP](mcp.md#approval-gates), [FastAPI](fastapi.md#headers), [A2A](a2a.md#human-approval), [Temporal](temporal-reference.md#set_activity_approvals---pre-supply-multisig-approvals).

---

## Signals by Integration

| Integration | First call (gate, no approvals) | Partial multi-sig | Retry with |
|-------------|--------------------------------|-------------------|------------|
| **In-process** | `tenuo.approval.ApprovalRequired` | `tenuo.exceptions.InsufficientApprovals` | Same call + `approvals=[...]` or `approval_handler` |
| **MCP** | JSON-RPC `-32002` + `request_hash` | JSON-RPC `-32002` + `got` / `need` | `_meta.tenuo.approvals` |
| **FastAPI** | HTTP **409** `error: "approval_required"` + `request_hash` | HTTP **409** `error: "insufficient_approvals"` + `got` / `need` | `X-Tenuo-Approvals` header |
| **A2A** | JSON-RPC **-32019** + `request_hash` | JSON-RPC **-32020** + `required` / `received` | `X-Tenuo-Approvals` header or `x-tenuo-approvals` param |
| **Temporal** | `ApplicationError.type == "approval_required"` | `ApplicationError.type == "insufficient_approvals"` | `x-tenuo-approvals` header or `set_activity_approvals()` |

Scope denials use different codes — see each integration guide.

**Field names:** Python `.details` use `required` / `received`. HTTP and MCP retry payloads use `got` / `need`. A2A error `data` uses `required` / `received`.

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

See [LangChain](langchain.md), [CrewAI](crewai.md), [OpenAI](openai.md), [AutoGen](autogen.md), [Google ADK](google-adk.md), [MCP](mcp.md), [FastAPI](fastapi.md), [A2A](a2a.md#human-approval), [Temporal](temporal-reference.md#human-approval).

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

Async handlers are supported.

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

---

## Cryptographic Model

Every approval binds to `(warrant_id, tool, args, holder)` via SHA-256 (`compute_request_hash`). `SignedApproval` = Ed25519 over `ApprovalPayload`. Rust verifies signature, hash, expiry (30s clock tolerance), approver trust, deduplication, and threshold.

---

## See Also

- [Enforcement Architecture](enforcement.md#human-approvals) — Where approvals sit in the pipeline
- [MCP Approval Gates](mcp.md#approval-gates) — Remote PEP retry flow
- [FastAPI](fastapi.md#error-handling) — HTTP 409 approval responses
- [Wire format §16](spec/wire-format-v1.md#16-approval-wire-format) — `SignedApproval` bytes
