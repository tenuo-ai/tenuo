---
title: Temporal Sandbox Passthrough — Design Note
description: Why tenuo and tenuo_core must be declared as passthrough modules, what security property depends on it, and evaluated paths to removing the requirement
---

# Temporal Sandbox Passthrough — Design Note

> **Status:** Known design debt. The passthrough requirement is intentional and load-bearing for the current PoP security model. This document explains the constraint, its security rationale, and the tradeoffs of alternatives being considered.

---

## The requirement

Users of the Tenuo Temporal integration must configure the Temporal workflow sandbox to treat `tenuo` and `tenuo_core` as passthrough modules:

```python
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

worker = Worker(
    client,
    task_queue="my-queue",
    workflows=[MyWorkflow],
    activities=[my_activity],
    interceptors=[TenuoPlugin(config)],
    workflow_runner=SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "tenuo", "tenuo_core",
        )
    ),
)
```

Without this, workflows fail immediately with:

```
ImportError: PyO3 modules may only be initialized once per interpreter process
```

---

## Why the sandbox exists and what passthrough means

The Temporal Python SDK re-imports all workflow code inside an **isolated sandbox** on every worker task to enforce replay determinism — the same workflow code must produce the same decisions when re-executed against the same history, even in a fresh interpreter context.

Modules declared as **passthrough** are shared between the sandbox and the main process rather than re-imported. They bypass the sandbox's isolation mechanism entirely.

This is a supported, documented pattern used by any library that wraps a native extension (PyO3, ctypes, cffi) or carries global state that cannot survive re-initialization.

---

## Why Tenuo needs it: where `tenuo_core` runs in the sandbox

The reason is a single code path:

```
workflow.execute_activity()
  → _TenuoWorkflowOutboundInterceptor.start_activity()
      → warrant.sign(signer, tool_name, args_dict, timestamp)   ← tenuo_core PyO3 call
          → activity headers injected with PoP
```

`_TenuoWorkflowOutboundInterceptor` runs **inside the workflow sandbox** to intercept every `execute_activity()` call. It needs to call `warrant.sign()` to compute the Proof-of-Possession signature for that dispatch. `warrant` is a `tenuo_core.Warrant` object (PyO3), and `.sign()` invokes Rust code. PyO3 cannot be re-imported per-sandbox, so `tenuo_core` must be a passthrough module.

The outbound interceptor runs in the sandbox for a deliberate reason explained in the next section.

---

## Why PoP must be signed at workflow schedule time

This is the load-bearing security property. The PoP challenge is:

```
CBOR( warrant_id, tool_name, sorted_args_dict, window_ts )
signed with the holder's Ed25519 private key
```

It commits to **the exact tool and arguments that the workflow code decided to dispatch**, at **the moment of dispatch**, using **`workflow.now()`** (deterministic workflow clock) for the timestamp.

### What this protects

**Tamper detection across Temporal's persistence layer.** After `execute_activity()` is called, the activity task travels through Temporal's history and task queue before reaching the worker. If anything modifies the task in transit (compromised Temporal server, rogue namespace admin, storage tampering), the PoP computed at schedule time will not match the tampered arguments — verification on the worker will fail.

**Schedule-time authorization commitment.** The PoP proves: "the workflow code that holds the private key authorized *this specific call with these specific arguments* at *this point in workflow time*." The signing is done by the entity making the authorization decision, not by the executor.

### What this does not protect

- A fully compromised worker process that also has the private key (via `KeyResolver`) can forge any PoP it wants. This is the same threat model as any key-based system.
- A compromised client that mints a forged warrant entirely.

The threat model PoP addresses is specifically **infrastructure-level tampering** (Temporal cluster, transit) and **replay attacks** (dedup cache + time windows), not a fully compromised participant.

---

## Failure mode if passthrough is omitted

Understanding the exact failure sequence matters for troubleshooting. The failure is **not** a startup error.

| Step | What happens |
|------|-------------|
| Worker starts | ✅ Success — `TenuoPlugin.__init__()` runs in the main process where `tenuo_core` is already loaded |
| Worker connects and polls | ✅ Success — the worker appears healthy from the outside |
| First workflow execution requested | ⚠️ Temporal creates a sandbox and re-imports the module graph |
| Sandbox re-imports `tenuo.temporal` | ❌ Tries to initialise `tenuo_core` (PyO3) a second time — raises `ImportError: PyO3 modules may only be initialized once per interpreter process` |
| Workflow task fails | Temporal marks the workflow task as failed and may retry |
| Subsequent workflow tasks | All fail identically |
| Activity tasks | Never scheduled — because workflow tasks fail before `execute_activity()` is reached |

**The diagnostic trap:** the worker stays connected and keeps polling. From metrics and health checks it looks completely normal. The failure only appears as workflow task errors in Temporal Web UI or in workflow execution history. Without Temporal Web, it looks like workflows hang indefinitely.

**What to check:**
1. Open Temporal Web → find the workflow → look at the execution history
2. If you see repeated `WorkflowTaskFailed` events with the PyO3 message, the passthrough is missing
3. Add `SandboxRestrictions.default.with_passthrough_modules("tenuo", "tenuo_core")` to the `SandboxedWorkflowRunner` on the worker

---

## Evaluated alternatives

### Option A: Move PoP signing to the inbound activity interceptor (worker side)

The activity inbound interceptor (`TenuoActivityInboundInterceptor`) already runs on the worker, outside the sandbox, and has access to `KeyResolver`. It could compute the PoP locally from the activity's arriving arguments, then verify it against the same warrant.

**Why this was rejected:**

The worker would both sign and verify. This is cryptographically a no-op: any worker holding the key can produce a valid PoP for any activity it receives, regardless of whether those arguments are what the workflow intended. The schedule-time commitment is lost entirely.

Concretely, a Temporal server that rewrites activity arguments in transit would go undetected: the worker receives tampered args, signs them, verifies the signature, and proceeds. With the current design, the original PoP (committed at schedule time over the original args) would not match, and the activity is denied.

**Verdict:** Eliminates the passthrough requirement but degrades PoP from a tamper-detection mechanism to an authentication mechanism only. Not acceptable for the current security model.

---

### Option B: Pure Python Ed25519 signing in the sandbox

Replace `warrant.sign()` in the outbound interceptor with a pure Python Ed25519 implementation (e.g., `cryptography` library). The sandbox can import pure Python without the PyO3 re-initialization problem.

**Tradeoffs:**

- `cryptography` uses OpenSSL C extensions under the hood — it has the same PyO3-style initialization issue on some platforms, and even where it doesn't, it is not deterministic across Python versions in the way Tenuo's Rust core is.
- The Ed25519 implementation would be separate from `tenuo_core`, creating a split between the signing and the rest of the warrant machinery (constraint evaluation, chain validation, etc.). Bugs in the pure Python path would not be caught by the Rust test suite.
- The PoP challenge format (CBOR serialization of the canonical args dict) is defined and tested in Rust. A pure Python re-implementation would need to exactly match this format, which is fragile to maintain.
- Requires exposing raw key material to the pure Python path.

**Verdict:** Does not cleanly eliminate the problem (OpenSSL extensions), introduces implementation split risk, and cannot be trusted to produce byte-for-byte identical PoP challenges without a separate, maintained pure Python serialization stack.

---

### Option C: `workflow.unsafe.imports_passed_through()` context manager

Temporal's SDK offers a context manager that temporarily disables sandbox restrictions for a specific import within workflow code:

```python
with workflow.unsafe.imports_passed_through():
    import tenuo_core
```

This avoids the global `with_passthrough_modules(...)` declaration on the worker.

**Tradeoffs:**

- Still requires the application developer to add the `unsafe` context to their workflow code — this is more invasive than the current `SandboxedWorkflowRunner` config, not less.
- It is semantically identical to declaring passthrough at the worker level; no security property changes.
- The `unsafe` namespace is more alarming to enterprise security reviewers than `passthrough_modules`.
- It does not help with the partner program concern, since the developer-visible friction is higher, not lower.

**Verdict:** Worse UX than the current approach. Not a viable path.

---

### Option D: Pre-computed session challenge at workflow start

The client, at workflow start time (outside the sandbox), pre-computes a set of PoP challenges covering the warrants it is submitting. A session nonce or Merkle-style commitment is injected into the workflow headers. The outbound interceptor inside the sandbox uses only pure Python header manipulation, embedding the pre-computed commitment rather than calling `warrant.sign()`.

**Tradeoffs:**

- The client cannot predict which activities will be dispatched or with what arguments — workflows are dynamic. This approach would require either (a) a short-lived session token that authorizes any activity dispatch under that warrant without per-call argument binding, or (b) a different challenge format that commits to the warrant but not the per-call args.
- Option (a) weakens PoP from "bound to specific args" to "bound to warrant + time window only" — partial degradation.
- This is a non-trivial protocol change that affects the wire format, the Rust core, and all language bindings.
- The approach would require the client to hold the private key at workflow start time, which may conflict with deployments where the signing key only lives on workers.

**Verdict:** Architecturally viable but represents a significant protocol revision that changes the threat model. Worth designing for a post-1.0 milestone if the partner program requires zero-passthrough. The trade-off (weaker per-call arg binding vs. no passthrough) would need to be an explicit product decision.

---

### Option E: Separate PoP signer service

The outbound workflow interceptor sends a signing request (over an internal channel, e.g., a local Unix socket or in-process queue) to a sidecar process that holds the key and returns the PoP signature. The interceptor itself is pure Python.

**Tradeoffs:**

- Temporal workflows are not permitted to perform I/O inside the sandbox — they must use `workflow.execute_activity()` or `workflow.execute_local_activity()` for any non-deterministic operations. Calling an external service from within `start_activity()` in the outbound interceptor would violate sandbox determinism rules.
- The only option would be a pre-execution setup that pre-loads computed values, but that collapses back to Option D.

**Verdict:** Not possible within Temporal's determinism model.

---

## Summary

| Option | Removes passthrough? | Preserves schedule-time arg binding? | Complexity |
|--------|---------------------|---------------------------------------|------------|
| **Current (A):** Sign in sandbox (today) | No | ✅ Yes | Low |
| **B:** Worker-side signing | ✅ Yes | ❌ No | Low |
| **C:** Pure Python Ed25519 | Partial | ✅ Yes | High (fragile) |
| **D:** Unsafe context manager | No (worse) | ✅ Yes | Low |
| **E:** Session challenge (client-side) | ✅ Yes | Partial | Very high |
| **F:** Sidecar signer | Not feasible | — | — |

---

## Recommendation

Keep the current design for the beta. The passthrough requirement is **one configuration line** in a well-documented location, uses Temporal's own supported API, and preserves the full PoP security model.

Before engaging with Temporal's AI partner program at a certification tier above basic listing, design Option E (session challenge) as a formal protocol revision. That change should be scoped to:

1. A `TenuoWorkflowSession` issued at workflow start by the client (outside the sandbox), committing to the warrant and a session nonce.
2. The outbound interceptor embeds the session nonce in activity headers (pure Python, no `tenuo_core`).
3. The inbound activity interceptor verifies the session signature against the warrant and performs constraint checking as today.
4. The trade-off (activity-level arg binding vs. session-level arg binding) is documented explicitly.

This would produce a partner-program-quality integration with zero sandbox friction and a clearly documented, intentional security model.
