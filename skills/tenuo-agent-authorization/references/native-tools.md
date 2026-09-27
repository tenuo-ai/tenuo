# Native agent tool integration

Use this workflow when an agent invokes framework function tools, local shell or computer tools, handoffs, or application functions without crossing an MCP boundary. Read [Integration trust levels](trust-levels.md) before reporting the result, and read the applicable language reference before selecting Tenuo APIs.

## Required outcome

Leave at least one effectful native tool protected by a complete, tested path:

```text
issuer -> holder-bound warrant -> invocation proof -> verifier -> effect
```

A framework callback can be a useful interception point. It is an independent security boundary only when the untrusted agent cannot bypass, replace, or disable it and cannot reach the underlying effect by another route.

## Inventory the execution path

Run the read-only helper (the path is relative to this skill's directory; it scans Python, TypeScript, JavaScript, and Rust sources):

```bash
python scripts/inspect_native_tools.py --root <project>
```

Confirm every finding in source. Map the actual path rather than relying on framework terminology:

```text
Model decision -> runtime dispatch -> wrapper or hook -> handler -> external effect
```

Locate:

- Function-tool declarations and where they are registered with the agent.
- Built-in shell, computer, browser, code-execution, patch, or hosted tools.
- Handoffs, agents-as-tools, subagents, workers, and queues that change the executing identity.
- Framework callbacks, middleware, wrappers, and direct handler invocation paths.
- The final filesystem, database, cloud, network, messaging, deployment, or other mutation.
- Issuer and holder ownership, warrant transport, verifier, trusted roots, and denial tests.

Record which arguments the model proposes, which arguments the runtime normalizes or injects, and which values the effect ultimately consumes.

## Choose the enforcement point

Prefer, in order:

1. Verification in a downstream service, worker, gateway, or resource adapter that exclusively owns the effect.
2. Verification at the start of a handler whose effect client and credentials are private and unreachable by other agent-controlled code.
3. A framework tool-input hook or wrapper when it covers every route to the handler.
4. An in-process pre-tool callback as a guardrail when stronger isolation is unavailable.

Do not assume that an agent-level input guardrail runs for every tool call. Do not assume that function-tool guardrails cover built-in shell, computer-use, hosted, handoff, or agents-as-tools execution. Inspect the resolved framework version and prove the exact path.

When a built-in tool cannot carry Tenuo proof or cannot be wrapped, restrict or remove it, replace it with a protected function tool, or point it at a downstream service that verifies independently. Reporting the gap is better than describing an unmediated built-in as protected.

## Resolve authority and identity

Identify the principal or task context that decides what the agent may do. Issue a short-lived warrant outside the untrusted model loop and bind it to the holder key used by the executing runtime.

For handoffs or subagents, choose explicitly:

- The same holder continues execution and retains the same bounded authority; or
- The parent delegates a narrower, child-holder-bound warrant to the new worker.

Do not pass a parent-bound warrant to a different holder and treat that as delegation. Do not place issuer signing material, holder private keys, or reusable proof in model-visible tool arguments.

## Bind authorization to the real call

Verify immediately before the effect using the final tool identity and material arguments. Normalize once, verify those normalized values, and execute with the same values. Include runtime-injected tenant, account, repository, environment, destination, or working-directory fields when they influence the effect.

Create fresh proof for each invocation. Parallel calls, retries, approvals, and resumptions must not accidentally reuse proof for different effective arguments. Authorization does not by itself provide idempotency or exactly-once execution.

## Framework-specific checks

- **OpenAI Agents SDK:** distinguish agent input/output guardrails from per-function-tool input guardrails. Check whether local MCP, hosted tools, shell/computer tools, handoffs, and agents-as-tools traverse the selected hook in the resolved version.
- **LangChain and LangGraph:** inspect wrappers, middleware, `ToolNode`, and direct callable access. Protecting graph dispatch does not protect callers that retain the original function or effect client.
- **CrewAI and similar runtimes:** confirm before-tool hooks run for every tool type and execution mode. Treat process-local registration as an in-process guardrail unless the effect is otherwise isolated.
- **Custom loops:** place verification in the dispatcher or handler and make all effecting clients private to that path.

Use installed documentation and source for exact APIs. Framework behavior changes faster than the Tenuo security invariants.

## Prove behavior

Exercise the same dispatcher, hook, and handler used in production. At minimum, prove:

1. A valid, in-scope invocation reaches the effect once.
2. Missing authority is denied before the effect.
3. A wrong tool or out-of-scope material argument is denied before the effect.
4. Direct invocation of the original handler or effect client is inaccessible or independently denied.
5. A built-in, handoff, retry, or alternate execution mode cannot bypass the boundary when that route exists.

Use an invocation counter, mock at the final adapter, transaction sentinel, or temporary resource. A hook returning `deny` or raising an exception is insufficient if another path can already have performed the mutation.

Also test wrong-holder proof, expiry, tampering, untrusted roots, and normalization mismatches when the chosen integration supports them.

## Report the result

Use one label from [Integration trust levels](trust-levels.md) and report process-local guardrails separately:

```text
Authorization result: incomplete integration | observation only | development loop | production boundary
In-process guardrail: yes | no

Issuer owner:
Holder and execution identity:
Dispatcher or hook:
Verifier:
Protected effect:
Covered tool types:

Verified:
- allowed invocation reaches effect
- denied invocation cannot reach effect

Uncovered built-ins, direct routes, or production blockers:
- ...
```

Do not claim the entire agent is authorized because one function-tool path is protected. State the exact tool types and effects covered.
