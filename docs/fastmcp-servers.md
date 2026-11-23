---
title: "Add Tenuo to an Existing FastMCP Server"
description: "Put per-call, per-argument authorization in front of an MCP server you run but didn't write, without forking it."
canonical_url: https://tenuo.ai/fastmcp-servers
---

# Add Tenuo to an Existing FastMCP Server

You run someone else's MCP server: Jira, Gmail, a database. Its own settings
are per server: a project filter, a tool list, a read-only switch. Your agent
gets one task at a time, and an agent that reads a poisoned ticket or email
will use everything those settings allow.

If the server is built on [FastMCP](https://gofastmcp.com), you can give each
call a warrant that says exactly what this task may do, and have the server
refuse anything else before the tool runs. You don't need to fork it or wait
for an upstream change: it's a ten-line launcher.

Here's mcp-atlassian already pinned to one project and three tools, with an
agent asked to close out OPS-12:

```text
JIRA_PROJECTS_FILTER=OPS, ENABLED_TOOLS=jira_get_issue,jira_add_comment,jira_transition_issue:
  read OPS-99 (security incident)  reached Jira
  comment on OPS-40                reached Jira
  move OPS-12 to Won't Do          reached Jira

same + Tenuo (the agent's warrant: read, comment on and close OPS-12):
  read OPS-99 (security incident)  REFUSED  Constraint 'issue_key'
  comment on OPS-40                REFUSED  Constraint 'issue_key'
  move OPS-12 to Won't Do          REFUSED  Constraint 'transition_id'
```

The full runnable version is in
[tenuo-demos/jira-mcp-scoped-triage](https://github.com/tenuo-ai/tenuo-demos/tree/main/jira-mcp-scoped-triage).

## The launcher

```bash
uv pip install "tenuo[fastmcp]" mcp-atlassian
```

```python
# tenuo_atlassian.py: run this instead of the server's own command
import os

from tenuo import Authorizer, PublicKey
from tenuo.mcp import MCPVerifier, TenuoMiddleware

from mcp_atlassian.servers import main_mcp as server  # the server's FastMCP object
from mcp_atlassian import main                        # the server's own entrypoint

root = PublicKey.from_bytes(bytes.fromhex(os.environ["TENUO_TRUSTED_ROOT"]))
verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[root]), require_warrant=True)
server.middleware.insert(0, TenuoMiddleware(verifier))

if __name__ == "__main__":
    main()
```

Everything else stays the same: same environment variables, same CLI flags
(`python tenuo_atlassian.py --transport streamable-http ...`), same tools.

With `TENUO_TRUSTED_ROOT` set to the public key you issue warrants from, every
`tools/call` must carry a warrant chain that leads back to that key, plus a
signature from the key the warrant was issued to. The middleware checks the
tool name and every argument; refused calls return an error result and the
tool function never runs.

Use `insert(0, ...)`, not `add_middleware`, so Tenuo runs first. Some servers
rewrite arguments in their own middleware (Workspace MCP converts camelCase
to snake_case), and the signature covers the arguments exactly as the client
sent them.

## Finding the two imports

You need the FastMCP object the server runs, and the function its console
script calls. Search the package for where the server is started, then read
its entry points:

```bash
PKG=$(python -c "import mcp_atlassian, os; print(os.path.dirname(mcp_atlassian.__file__))")
grep -rnE "[a-z_]+\.run(_async)?\(" "$PKG" | grep -v asyncio.run
# mcp_atlassian/__init__.py:89:    server_task = asyncio.create_task(main_mcp.run_async(**run_kwargs))

python -c "import importlib.metadata as m; print(m.distribution('mcp-atlassian').read_text('entry_points.txt'))"
# mcp-atlassian = mcp_atlassian:main
```

Import any modules that register tools before the entrypoint runs, if the
server registers them lazily. Servers we've run this way:

| Server | FastMCP object | Entrypoint | Example |
|---|---|---|---|
| [mcp-atlassian](https://github.com/sooperset/mcp-atlassian) 0.23 | `mcp_atlassian.servers.main_mcp` | `mcp_atlassian.main` | [jira-mcp-scoped-triage](https://github.com/tenuo-ai/tenuo-demos/tree/main/jira-mcp-scoped-triage) |
| [Workspace MCP](https://github.com/taylorwilsdon/google_workspace_mcp) 2.1 | `core.server.server` | `main.main` | [workspace-mcp-scoped-email](https://github.com/tenuo-ai/tenuo-demos/tree/main/workspace-mcp-scoped-email) |

## Writing the warrant

List the tools and their argument names first:

```python
import asyncio
from fastmcp import Client

async def main():
    async with Client({"mcpServers": {"s": {"command": "mcp-atlassian"}}}) as c:
        for t in await c.list_tools():
            print(t.name, list(t.inputSchema.get("properties", {})))

asyncio.run(main())
```

Then constrain the arguments that decide what the call does, and leave free
text unconstrained:

```python
from tenuo import Exact, Wildcard

capabilities = {
    "jira_get_issue": {"issue_key": Exact("OPS-12")},
    "jira_add_comment": {"issue_key": Exact("OPS-12"), "body": Wildcard()},
    "jira_transition_issue": {"issue_key": Exact("OPS-12"), "transition_id": Exact("31")},
}
```

Two rules catch most surprises:

- **Arguments are closed-world.** An argument the warrant doesn't name is
  refused, so a transition that also tries to set `comment` or `fields` is
  denied. A constrained argument the caller leaves out is denied too, so
  nothing falls back to a server default.
- **Anchor patterns on fields the server parses.** For a recipient, use
  `Regex(r"^[A-Za-z0-9._%+-]+@acme\.com$")`, not `Pattern("*@acme.com")`; the
  glob also matches `eve@evil.com,bob@acme.com`, which a mail tool reads as two
  recipients. See [Constraints](./constraints).

## Calling it

The agent side holds a key and attaches the warrant. With
`SecureMCPClient` that's automatic:

```python
import asyncio
from tenuo import Capability, Exact, SigningKey, Wildcard, configure, mint
from tenuo.mcp import SecureMCPClient

key = SigningKey.generate()
configure(issuer_key=key, trusted_roots=[key.public_key])

async def main():
    async with SecureMCPClient(
        "python", ["tenuo_atlassian.py"],
        inject_warrant=True,
        env={"TENUO_TRUSTED_ROOT": bytes(key.public_key_bytes()).hex(), "JIRA_URL": "...", "JIRA_PERSONAL_TOKEN": "..."},
    ) as client:
        async with mint(Capability("jira_add_comment", issue_key=Exact("OPS-12"), body=Wildcard())):
            await client.tools["jira_add_comment"](issue_key="OPS-12", body="Fixed in 4.2.1")  # runs
            await client.tools["jira_add_comment"](issue_key="OPS-40", body="Closing")         # ConstraintViolation

asyncio.run(main())
```

The OpenAI Agents, LangChain MCP adapter, and Temporal integrations attach
warrants the same way. To hand a sub-agent a narrower slice of your own
warrant, use `grant_builder()`; the server verifies the whole chain and
refuses anything wider than its parent. See
[Warrant Propagation](./mcp#warrant-propagation).

Callers that don't send a warrant are refused while `require_warrant=True`,
so this is for servers that serve agents you run. Desktop MCP hosts don't
attach warrants today.

## Not built on FastMCP?

For any stdio MCP server, the check can sit in a proxy in front of it instead,
with no change to the server:
[tenuo-demos/mcp-proxy-scoped-files](https://github.com/tenuo-ai/tenuo-demos/tree/main/mcp-proxy-scoped-files)
runs the stock `mcp-proxy` with a Tenuo check on every `tools/call`. If you
write your own server on the official MCP SDK, use `TenuoServerMiddleware`
([MCP Integration](./mcp#pattern-2-securemcpclient-recommended-for-clients)).
