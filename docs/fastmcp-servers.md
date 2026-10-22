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
for an upstream change: you put one command in front of the server's own.

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

## Run it

```bash
uv pip install "tenuo[fastmcp]" mcp-atlassian
tenuo-cli init --dev && tenuo-cli mode observe
python -m tenuo.mcp.wrap --home ~/.tenuo mcp-atlassian
```

With `--home`, the wrapper reads trust, revocations and the mode from a
[`tenuo-cli` workspace](local-cli.md) on every call. In observe mode every call
runs, from any MCP client, and is recorded to the workspace's
`observations.jsonl` under the server's name (`--step` to change it). Use the
server for a while, then:

```bash
tenuo-cli calls summary        # tools and arguments it was called with, and the commands to draft a warrant
tenuo-cli mode enforce         # the next call is checked; no restart
```

In enforce mode every call must carry a warrant, so the client has to present
one: `SecureMCPClient.local`, Hermes with hermes-tenuo, or a framework MCP
adapter with Tenuo ([calling it](#calling-it)). Claude Desktop and Cursor don't
send warrants, so with them the server is useful in observe mode only. Pass
`--key NAME` to sign receipts with a server identity from the workspace.

Without a workspace, give the wrapper the issuer's public key instead:

```bash
TENUO_TRUSTED_ROOT=<hex public key> python -m tenuo.mcp.wrap mcp-atlassian
```

`tenuo.mcp.wrap` takes the server's console script (or a `module:function`
entrypoint) and passes everything after it to the server unchanged: same
environment variables, same flags
(`python -m tenuo.mcp.wrap mcp-atlassian --transport streamable-http`), same
tools. Install it in the same environment as the server.

With `TENUO_TRUSTED_ROOT` set to the public key you issue warrants from
(comma-separated, or repeat `--trusted-root`, for more than one), every
`tools/call` must carry a warrant chain that leads back to that key, plus a
signature from the key the warrant was issued to. The check covers the tool
name and every argument; refused calls return an error result and the tool
function never runs.

The wrapper puts `TenuoMiddleware` at the front of the server's FastMCP
middleware when each MCP session starts, over stdio and HTTP alike. Tenuo has
to run first: some servers rewrite arguments in their own middleware
(Workspace MCP converts camelCase to snake_case), and the signature covers the
arguments exactly as the client sent them. If the server turns out not to be
built on FastMCP, the wrapper refuses to start it rather than run it
unchecked.

Servers we've run this way:

| Server | Command | Example |
|---|---|---|
| [mcp-atlassian](https://github.com/sooperset/mcp-atlassian) 0.23 | `python -m tenuo.mcp.wrap mcp-atlassian` | [jira-mcp-scoped-triage](https://github.com/tenuo-ai/tenuo-demos/tree/main/jira-mcp-scoped-triage) |
| [Workspace MCP](https://github.com/taylorwilsdon/google_workspace_mcp) 2.1 | `python -m tenuo.mcp.wrap workspace-mcp --tools gmail` | [workspace-mcp-scoped-email](https://github.com/tenuo-ai/tenuo-demos/tree/main/workspace-mcp-scoped-email) |

Workspace MCP's code lives in top-level modules such as `main`, so run it from
a directory that doesn't have its own `main.py`; `python -m` puts the current
directory first on the import path.

### In your own launcher

If you'd rather not patch at session start, add the middleware to the
server's FastMCP object yourself and call its entrypoint. This needs a
module-level server object; servers that build theirs at startup (in a
`build_server()` factory, say) need the wrapper.

```python
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

Use `insert(0, ...)`, not `add_middleware`, so Tenuo runs first.

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
- **Paths the server joins to its own root need a regex, not a glob.** Many
  servers take a relative path (`team/standup.md`). `Subpath` needs an absolute
  path, and `Pattern("team/*")` compares text, so `team/../hr/salaries.md`
  matches it and the server opens the HR file. Spell out what a path may
  contain instead: `Regex(r"^team/([A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.md$")`
  only lets dots into the extension, so `..` can't appear. In a YAML template,
  `{regex: '^team/([A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.md$'}`. `tenuo-cli warrant
  review` reports a path glob that lets `..` through.

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
        "python", ["-m", "tenuo.mcp.wrap", "mcp-atlassian"],
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
