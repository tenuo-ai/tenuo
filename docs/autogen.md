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

from tenuo import Pattern, SigningKey, Warrant
from tenuo.autogen import guard_tool


def search(query: str) -> str:
    return f"Results for: {query}"


async def main() -> None:
    # Only allow queries that match "safe*"
    key = SigningKey.generate()
    warrant = Warrant.mint_builder().tools(["search"]).constraint("query", Pattern("safe*")).ttl(3600).mint(key)
    bound = warrant.bind(key)

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

## Demos

- `tenuo-python/examples/autogen_demo_unprotected.py` - agentic workflow with no protections
- `tenuo-python/examples/autogen_demo_protected_tools.py` - guarded tools (URL allowlist + Subpath)
- `tenuo-python/examples/autogen_demo_protected_attenuation.py` - per-agent attenuation + escalation block
- `tenuo-python/examples/autogen_demo_guardbuilder_tier1.py` - same agent flow using GuardBuilder (constraints-only)
- `tenuo-python/examples/autogen_demo_guardbuilder_tier2.py` - same agent flow using GuardBuilder with warrant + PoP

> Tip: these demos use `python-dotenv` to load `OPENAI_API_KEY` and set `tool_choice="required"` for deterministic tool calls.

## Human Approval

Add human-in-the-loop approval with `.approval_policy()` and `.on_approval()` when using GuardBuilder. See [Human Approvals](approvals.md) for the full guide.

```python
from tenuo import SigningKey, cli_prompt
from tenuo.autogen import GuardBuilder

key = SigningKey.generate()

guard = (GuardBuilder()
    ...
    .approval_policy(policy)
    .on_approval(cli_prompt(approver_key=key))
    .build())
```

## What happens on denial?

- If the tool name is not in `warrant.tools`, Tenuo raises `ToolNotAuthorized`.
- If arguments violate constraints (e.g. query not matching `Pattern("safe*")`), Tenuo raises `AuthorizationDenied` with a diff-style explanation and a debugging suggestion from `why_denied()`.

## Delegation Chains

For multi-agent delegation with attenuated warrants, see [Delegation Chains](./concepts#delegation).

Use `Warrant.grant_builder()` to create child warrants with narrower scope:

```python
from tenuo import SigningKey, Warrant

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
```

The child warrant cannot escalate beyond what the parent allows — Rust enforces monotonic attenuation at creation time.

## See also

- [Quickstart](./quickstart)
- [Debugging](./debugging)

