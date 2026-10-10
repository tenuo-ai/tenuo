# AutoGen (AgentChat)

Tenuo can protect tools used by [AutoGen AgentChat](https://microsoft.github.io/autogen/stable//index.html) so that **every tool call is authorized** by a warrant.

> AutoGen AgentChat requires **Python ≥ 3.10**.

## Installation

```bash
uv pip install "tenuo[autogen]"
```

## Minimal example (guarded tool)

```python
import asyncio

import tenuo
from tenuo import Pattern, SigningKey, Warrant
from tenuo.autogen import guard_tool


def search(query: str) -> str:
    return f"Results for: {query}"


async def main() -> None:
    issuer_key = SigningKey.generate()  # in production: your issuer's key
    agent_key = SigningKey.generate()

    # The verifier trusts only the issuer's public key
    tenuo.configure(trusted_roots=[issuer_key.public_key])

    # Only allow queries that match "safe*"
    warrant = (Warrant.mint_builder()
        .capability("search", query=Pattern("safe*"))
        .holder(agent_key.public_key)
        .ttl(3600)
        .mint(issuer_key))
    bound = warrant.bind(agent_key)

    guarded_search = guard_tool(search, bound, tool_name="search")

    # AutoGen AgentChat
    from autogen_agentchat.agents import AssistantAgent
    from autogen_ext.models.openai import OpenAIChatCompletionClient

    agent = AssistantAgent(
        "assistant",
        OpenAIChatCompletionClient(model="gpt-4o"),
        tools=[guarded_search],
    )

    print(await agent.run(task="Use search with query 'safe weather NYC' and summarize the result."))
    print(await agent.run(task="Use search with query 'stocks AAPL' and summarize the result."))


asyncio.run(main())
```

Warrant checks fail closed without a trust anchor: every guarded call is denied until trusted roots are set. Set them once with `tenuo.configure(trusted_roots=[...])`, or per guard with `guard_tool(..., trusted_roots=[...])` / `guard_tools(..., trusted_roots=[...])`. Trusted roots are the issuer's public keys only; see [Delegation Chains](#delegation-chains) for warrants that a root did not mint.

## Demos

- `tenuo-python/examples/autogen_demo_unprotected.py` - agentic workflow with no protections
- `tenuo-python/examples/autogen_demo_protected_tools.py` - guarded tools (URL allowlist + Subpath)
- `tenuo-python/examples/autogen_demo_protected_attenuation.py` - per-agent attenuation + escalation block
- `tenuo-python/examples/autogen_demo_guardbuilder_tier1.py` - same agent flow using GuardBuilder (constraints-only)
- `tenuo-python/examples/autogen_demo_guardbuilder_tier2.py` - same agent flow using GuardBuilder with warrant + PoP

> Tip: these demos use `python-dotenv` to load `OPENAI_API_KEY` and set `tool_choice="required"` for deterministic tool calls.

## Human Approval

Define gates and approvers on the warrant, then pass `.on_approval()`. See [Human Approvals](approvals.md) for the full guide.

```python
from tenuo import cli_prompt
from tenuo.autogen import GuardBuilder

guard = (GuardBuilder()
    .allow("transfer_funds")
    .with_warrant(warrant, agent_key)
    .on_approval(cli_prompt(approver_key=approver_key))
    .build())
```

## What happens on denial?

All exceptions are importable from `tenuo.exceptions`.

| Cause | `error_type` | Raised |
|-------|--------------|--------|
| Tool not in the warrant (or not `.allow()`ed on a `GuardBuilder`) | `tool_not_allowed` | `ToolNotAuthorized` |
| Argument fails a warrant constraint (e.g. query not matching `Pattern("safe*")`) | `constraint_violation` | `AuthorizationDenied`, with the failing argument in `constraint_results` |
| Argument fails a `GuardBuilder().allow(...)` constraint (no warrant) | `constraint_violation` | `ConstraintViolation` |
| Warrant expired | `expired` | `ExpiredError` |
| Approval gate needs more approvals | `insufficient_approvals` | `InsufficientApprovals` |
| Untrusted issuer, or a delegated warrant presented without its chain | `untrusted_issuer` | `AuthorizationDenied` |
| No trusted roots configured | `tenuo_error` | `AuthorizationDenied`; the reason says to set `trusted_roots` |

With `GuardBuilder().on_denial("log")` or `"skip"`, a denied guarded tool returns `None` instead of raising (`"log"` also logs a warning). In `guard_stream`, denied tool calls are dropped from the stream.

## Observe mode

To see what a warrant would deny without blocking, configure observe mode at startup:

```python
tenuo.configure(trusted_roots=[issuer_key.public_key], mode="observe")
```

The default is `mode="enforce"`. `"audit"` and `"permissive"` are accepted as aliases for `"observe"`. In observe mode a warrant check that would deny lets the tool run, logs `OBSERVE: would deny <tool>: <reason>`, and, when receipt signing is configured, records `enforced=false` on the receipt.

Observe mode covers warrant (Tier 2) checks. Constraint-only guards built with `GuardBuilder().allow(...)` and no warrant still raise `ConstraintViolation` / `ToolNotAuthorized` in observe mode.

## Delegation Chains

For multi-agent delegation with attenuated warrants, see [Monotonic Attenuation](./concepts#monotonic-attenuation).

Use `Warrant.grant_builder()` to create child warrants with narrower scope:

```python
import tenuo
from tenuo import SigningKey, Warrant
from tenuo.autogen import guard_tool

issuer = SigningKey.generate()
agent = SigningKey.generate()
worker = SigningKey.generate()

root = (Warrant.mint_builder()
    .capability("search").capability("code_exec")
    .holder(agent.public_key).ttl(3600).mint(issuer))

# Worker can only search, not execute code
child = (root.grant_builder()
    .capability("search")
    .holder(worker.public_key).ttl(1800).grant(agent))

# The verifier trusts only the root issuer; present the chain back to it
tenuo.configure(trusted_roots=[issuer.public_key])
guarded_search = guard_tool(search, child.bind(worker), tool_name="search", warrant_chain=[root])
```

The child warrant cannot escalate beyond what the parent allows — Rust enforces monotonic attenuation at creation time.

A delegated warrant verifies only when its path back to a trusted root is presented with it. Pass the parent warrants as `warrant_chain` (root-first, excluding the leaf), or pass `bound` as a root-first list ending in the bound leaf: `guard_tool(search, [root, child.bind(worker)])`. `GuardBuilder().with_warrant(child, worker, warrant_chain=[root])` takes the same argument. Without the chain every call is denied, because the child's issuer is not a trusted root. Do not add intermediate keys (here, `agent`) to `trusted_roots` to make it pass; that trusts anything the intermediate signs, beyond the scope the root granted it.

## See also

- [Quickstart](./quickstart)
- [Debugging](./debugging)

