# Human Approvals

> **Cryptographically verified human-in-the-loop authorization for AI agent tool calls.**

Define **who must approve**, **how many**, and **which calls** in the warrant. Collect `SignedApproval` signatures and retry. There is no unsigned path.

Examples on this page use the explicit low-level API (`Warrant.mint_builder()`, `enforce_tool_call`) rather than the `mint_sync`/`guard` helpers from the README quick start. The concepts are the same: gates and approvers are fields on the warrant, and the framework adapters below enforce them identically.

---

## Quick Start

```python
from tenuo import SigningKey, Warrant, BoundWarrant, enforce_tool_call, cli_prompt

control_key = SigningKey.generate()
agent_key = SigningKey.generate()
approver_key = SigningKey.generate()

# 1. Warrant: capabilities, gates, approvers, threshold
warrant = (Warrant.mint_builder()
    .capability("transfer")
    .approval_gates({
        "transfer": {"args": None, "message": "A human must confirm this transfer."},
    })
    .required_approvers([approver_key.public_key])
    .min_approvals(1)
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_key)
)

# 2. Enforce: handler prompts and signs on gate fire
result = enforce_tool_call(
    tool_name="transfer",
    tool_args={"amount": 50_000, "to": "alice"},
    bound_warrant=BoundWarrant(warrant, agent_key),
    trusted_roots=[control_key.public_key],
    approval_handler=cli_prompt(approver_key=approver_key),
)
result.raise_if_denied()  # a denial is returned, not raised; this turns it into an exception
```

`enforce_tool_call` returns an `EnforcementResult`. A gate that fires without an approval raises `ApprovalRequired`, but most other denials (a constraint that is not satisfied, a tool that is not granted, an untrusted root) do **not** raise: they come back as `result.allowed == False`. Call `result.raise_if_denied()` before you run the tool.

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

Do **not** treat every tool listed in `tenuo.approval_gates` as unconditionally gated. A tool can be listed with a per-argument `Exempt` or `Constraint` gate; only some calls require approval. Inspect the signed extension with the typed API below instead of parsing the raw CBOR keys.

---

## Approval Gates

```python
from tenuo_core import Exact

warrant = (Warrant.mint_builder()
    .capability("search")
    .capability("restart_service")
    .approval_gates({
        "restart_service": {"environment": Exact("production")},  # prod only
        # whole-tool + display text:
        # "transfer": {"args": None, "message": "A human must confirm this transfer."}
    })
    .required_approvers([approver_key.public_key])
    .min_approvals(1)
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_key)
)
```

An optional `message` on a gate is display text only. It is resolved once when
the gate fires and copied onto every adapter (`ApprovalRequired`, FastAPI 409
`message`, MCP `denial_reason`, Temporal `ApplicationError`, authorizer JSON,
A2A, control-plane request). It is not part of `request_hash` or receipts.
Empty strings are omitted; values longer than 200 characters are truncated.
There is no argument interpolation.

Because the message is not a security property, approval UIs should treat it as
context, not authority. A delegated child can replace display text, so approvers
and automated workflows should make decisions from the signed request fields
(`tool`, `arguments`, `request_hash`, `warrant_id`, approver threshold) rather
than from the wording alone.

MCP clients still retry by attaching signatures in `_meta.tenuo.approvals`;
that instruction is documented here rather than rewritten into the denial
reason.

### Inspecting gates (typed preflight)

Adapters that need to know whether a **concrete call** requires approval should
use `Warrant.approval_requirement(tool, args)` (or the module-level
`approval_requirement`). It returns a typed result from the same
`Constraint.matches` implementation the authorizer uses:

| Status | Meaning |
|--------|---------|
| `not_gated` | Tool is granted and either absent from the gate map, or a constrained gate does not match these arguments |
| `exempt` | A per-argument `Exempt` gate is present and this call matches the exemption |
| `required` | The gate fires (`kind` is `whole_tool` or `argument`) |
| `denied` | The warrant does not grant this call (missing tool or capability miss). Do not collect approval. |

To inspect the **structure** without arguments, use
`Warrant.inspect_approval_gate(tool)`:

| `kind` | Meaning |
|--------|---------|
| `none` | Tool is not in the gate map |
| `whole_tool` | Every invocation of this tool is gated |
| `conditional` | Per-argument `All` / `Constraint` / `Exempt` gates (`arguments` lists the names) |

```python
from tenuo import Range, Warrant

warrant = (Warrant.mint_builder()
    .capability("write_approval", amount=Range(0, 1000))
    .approval_gates({
        "write_approval": {"amount": {"exempt": Range(0, 500)}},
    })
    .required_approvers([approver_key.public_key])
    .min_approvals(1)
    .holder(agent_key.public_key)
    .ttl(3600)
    .mint(control_key)
)

assert warrant.inspect_approval_gate("write_approval").kind == "conditional"

# 456.50 is inside 0..500 — capability passes, exemption matches, no approval.
req = warrant.approval_requirement("write_approval", {"amount": 456.50})
assert req.status == "exempt"
assert not req.requires_approval()

# 650 is inside 0..1000 but outside the exemption — approval required.
req = warrant.approval_requirement("write_approval", {"amount": 650})
assert req.status == "required"
assert req.kind == "argument"

# 1200 fails the capability Range(0, 1000). Preflight reports `denied`.
req = warrant.approval_requirement("write_approval", {"amount": 1200})
assert req.status == "denied"
assert not req.requires_approval()
```

`evaluate_approval_gates(warrant, tool, args)` is the gate-map-only boolean
(split-view safe: it does not run capability checks). Prefer
`approval_requirement` so an exemption or a deny is not confused with "this
tool is not gated."

**Compatibility**

- The boolean `evaluate_approval_gates` API is unchanged: it evaluates the
  gate map only. Capability failures still return `True` when a gate fires.
  Use `approval_requirement` for `denied`.
- Malformed or unknown gate encodings raise (Python) or return
  `status="required"` with `error` set (WASM, no fabricated `kind`). Treat
  that as fail-closed — never as ungated.
- This preflight does **not** replace the authorizer. PoP, expiry, and
  collected approvals remain authorizer-only. An SDK-side `exempt` /
  `not_gated` result must not allow a call the authorizer would deny.

Rust: `warrant.approval_requirement(tool, args)` and
`warrant.inspect_approval_gate(tool)`. TypeScript / WASM:
`approvalRequirement(warrantB64, tool, args)`,
`inspectApprovalGate(warrantB64, tool)`, and `evaluateApprovalGates`.

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

## Delegation

A delegated (child) warrant can narrow authority but never remove an approval requirement. In Python, a child adds gates with `with_approval_gates(...)` on the builder returned by `warrant.attenuate_builder()`. These are the ways a child's gates combine with its parent's:

| The child | Result |
|-----------|--------|
| Adds a gate for another tool | Allowed. The inherited gates stay. |
| Gates another argument of a tool the parent already gates | Both gates apply. A call needs approval if either one fires. |
| Passes an empty gate map, or tries to drop an inherited gate | The inherited gate stays. |
| Gates a whole tool that the parent gated per argument | Every call to that tool needs approval. |
| Adds an exemption for a tool the parent gates as a whole | Ignored. Every call still needs approval. |
| Gates the same argument as the parent with a different exemption, broader or narrower | The parent's gate wins. A child cannot loosen it, and a narrower exemption is ignored. |
| Replaces the gate's display `message` | Allowed. The message is display text only; see [Approval Gates](#approval-gates). |

For the tools an issuer warrant gates, the execution warrants it issues keep its approval gates, `required_approvers` and `min_approvals`. A tool the issuer does not gate gets none of them.

Issuance can add approvers or raise the threshold. Removing an approver, or lowering `min_approvals`, fails with a `MonotonicityError`.

Each approver you add also raises the minimum threshold. The threshold must be at least the issuer's threshold plus the number of new approvers, where the issuer's threshold is its `min_approvals`, or all of its approvers if it set none. If you leave `min_approvals` unset you get exactly that minimum: a 1-of-1 issuer plus one approver gives 2-of-2, and a 1-of-2 issuer plus one approver gives 2-of-3. Passing a lower value fails with a `MonotonicityError`. `min_approvals` can't exceed the number of distinct approvers (a `ValidationError`), and repeating an existing approver does not count as adding one.

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
| **MCP** | `params._meta.tenuo.approvals` | JSON array of **base64(CBOR)** strings, no outer wrapper |
| **FastAPI / A2A** | `X-Tenuo-Approvals` header (A2A also accepts `x-tenuo-approvals` param) | **base64(JSON array of base64(CBOR) strings)** |
| **Temporal** | `x-tenuo-approvals` activity header | **JSON array of base64(CBOR) strings**, no outer base64 wrapper |

```python
import base64, json
from tenuo.approval import sign_approval

signed = sign_approval(request, approver_key)

# MCP / Temporal: array of base64 CBOR blobs
approvals_wire = [base64.b64encode(signed.to_bytes()).decode("ascii")]

# FastAPI / A2A: outer base64 JSON wrapper
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

Scope denials use different codes; see each integration guide.

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
| `cli_prompt(approver_key=key)` | Local dev - terminal prompt |
| `auto_approve(approver_key=key)` | Tests - signs automatically |
| `auto_deny(reason=...)` | Dry-run - always raises |

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

> **Tenuo Cloud** provides managed approval routing (approvals delivered to Slack and mobile, with SSO-backed approver identity) so you don't have to build and operate custom handlers. Cloud customers: see the [Cloud approvals API reference](https://docs.tenuo.ai/api-reference/approvals) (sign-in required). Not a customer yet? [Request early access](https://tenuo.ai/early-access.html).

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

## Single-Use Approvals

Approval verification keeps no state, so an approval authorizes its request every time it is presented until it expires. That includes the honest holder being rewound: a run resumed from a checkpoint taken before the approved call, a fork of that checkpoint, or a worker retried after a crash. Each re-signs a fresh PoP, so the PoP `NonceStore` does not see a repeat.

Enable the consumption store to allow each approval once:

```python
import tenuo

tenuo.enable_approval_consumption()   # process-wide; every adapter uses it

# or per call
from tenuo import ApprovalConsumptionStore
store = ApprovalConsumptionStore()
result = enforce_tool_call(..., consumption_store=store)
```

A second use is denied with `error_type="approval_consumed"` (receipt decision code `approval-consumed`, `raise_if_denied()` raises `InvalidApproval`). `approval_metadata["state"]` is `"in_flight"` or `"consumed"`. A fresh approval for the same call is allowed.

One valid approval per approver is consumed, including approvers beyond the threshold, so presenting the same approvals in a different order does not authorize the call again. If several valid approvals come from the same approver, the one with the lowest nonce is selected independently of presentation order. Client-side checks that are not the final enforcement point pass `consumption_store=False`, so only the server consumes. `SecureMCPClient` does this only when it sends the warrant (`inject_warrant`); otherwise its own check is the enforcement point and consumes. The guarded OpenAI client verifies a response without running its tools, so it releases the approvals of any call or response it rejects.

**Reserve / commit.** An allowed call reserves its approvals. Call `result.approval_reservation.commit()` once the action has run, or `.release()` only when it certainly did not. A crash in between leaves the reservation in flight, so a retry is refused rather than treated as unused. Entries are kept until the approval expires.

**Idempotency key.** The store stops a second *authorization*; only the downstream system can stop a second *effect*. Every approved call carries `result.idempotency_key`. An `approval_consumed` denial carries the key the first use stored, so a retry can look the action up even when fewer approvals verify the second time. `tenuo.current_idempotency_key()` returns it inside the tool for paths that enforce one call and then run it. With FastAPI, read `ctx.idempotency_key` from the `SecurityContext` instead: the guard runs in a threadpool, so its context does not reach an async endpoint. When several calls are authorized before any runs (an OpenAI response with several tool calls), use the key for each call instead: `verify_tool_call()` returns it, and `tenuo.openai.idempotency_key_for(tool_call)` reads it from a tool call (or streamed delta) a guarded client verified. It is derived in the core from the `request_hash` receipts already carry plus the approvals' nonces, so it is the same on every retry and replica and new for a fresh approval. Pass it to the payment API, queue or database as its idempotency key.

The in-memory backend is per process. With several replicas, implement `ConsumptionBackend` (`reserve` / `commit` / `release`) on a shared store. `reserve` must atomically insert-if-absent (for example Redis `SET NX EX`), storing the supplied `owner_token` alongside the idempotency key and state. `commit` and `release` must atomically compare `owner_token` before changing or deleting an entry; a missing entry or different owner is a no-op. A Redis implementation needs a Lua script or equivalent transaction for that comparison. The store generates a fresh owner token for each acquisition, even when the idempotency key is unchanged. This prevents a retried release after a lost backend reply from deleting another worker's reservation. If `commit()` or `release()` raises, the keys that failed stay pending; call the same method again to finish them. `margin_seconds` must be a non-negative integer so entries cannot expire before their approvals.

---

## Cryptographic Model

Every approval binds to `(warrant_id, tool, args, holder)` via SHA-256 (`compute_request_hash`). `SignedApproval` = Ed25519 over `ApprovalPayload`. Rust verifies signature, hash, strict expiry, future-timestamp clock tolerance, approver trust, deduplication, and threshold.

---

## See Also

- [Enforcement Architecture](enforcement.md#human-approvals) - Where approvals sit in the pipeline
- [MCP Approval Gates](mcp.md#approval-gates) - Remote PEP retry flow
- [FastAPI](fastapi.md#error-handling) - HTTP 409 approval responses
- [Wire format §16](spec/wire-format-v1.md#16-approval-wire-format-multi-sig) - `SignedApproval` bytes
- [Cloud approvals API reference](https://docs.tenuo.ai/api-reference/approvals) - Managed approval routing for Tenuo Cloud customers (sign-in required)

### Strengthening approvals during Python delegation

`grant_builder()` exposes Rust's additive approval operations:

```python
child = (parent.grant_builder()
    .inherit_all()
    .add_approvers([additional_approver.public_key])
    .raise_min_approvals(2)
    .grant(holder_key))
```

`add_approvers()` preserves inherited approvers and deduplicates keys.
`raise_min_approvals()` cannot lower an existing threshold. The core validates
the final threshold at grant time, including the required increase when new
approvers are added; an impossible threshold is rejected. The native
`attenuate_builder()` exposes the same two operations.
