---
title: MCP recipes
description: Warrants for jobs agents run through MCP servers, deployed with tenuo.mcp.wrap and tenuo-cli
---

# MCP recipes

Each recipe lets an agent do one job through an MCP server on its own, with a
warrant that names the tools and argument values the job needs, for a set time.
Read-only you can already get from OAuth scopes; these start where a scope
can't say "this thread", "this branch" or "for an hour".

## Reply to a thread (Google Workspace MCP)

Most agents stop at drafts. This lets the agent send the reply itself: one
thread, one recipient, within the hour. `gmail.send` would let it write to
anyone about anything until you revoke it.

```yaml
version: 2
name: reply-to-thread
ttl: 1h
vars:
  me: {description: "your Google account email"}
  thread: {description: "the Gmail thread ID"}
  to: {description: "who the reply may go to, lowercase (a list for several)"}
capabilities:
  get_gmail_thread_content:
    user_google_email: ${me}
    thread_id: ${thread}
    body_format: {optional: any}
    include_analysis: {optional: any}
  send_gmail_message:
    user_google_email: ${me}
    thread_id: ${thread}
    to: ${to}
    subject: any
    body: any
    in_reply_to: {optional: any}
    references: {optional: any}
    body_format: {optional: [plain, html]}
```

The recipient is the boundary. Subject and reply headers aren't pinned, so a
reply Gmail doesn't thread still goes only to `to`.

Workspace MCP is built on FastMCP, so the server checks every call itself.
Issue the warrant and turn enforcement on:

```bash
tenuo-cli init --dev
tenuo-cli warrant issue --template reply.yaml --holder agent --out reply.warrant \
  --set me=you@yourco.com --set thread=18f2a9c0d1e2b3a4 --set to=bob@vendor.com
tenuo-cli mode enforce
```

Then have the agent's MCP client launch the server through the wrapper,
`python -m tenuo.mcp.wrap --home ~/.tenuo workspace-mcp --tools gmail`, and
present the warrant with `SecureMCPClient.local(warrant="reply.warrant", ...)`
or a framework MCP adapter with Tenuo ([calling it](fastmcp-servers.md#calling-it)).
To see what the agent sends before you write a warrant, run
`tenuo-cli mode observe` first and check `tenuo-cli calls summary`; the
wrapper picks up mode changes without a restart.

Checked against workspace-mcp's own tools:

| Call | Result |
|------|--------|
| `send_gmail_message` to bob@vendor.com on the thread | allowed |
| … to someone@else.com | refused: Constraint 'to' not satisfied |
| … with `bcc`, `cc`, `forward_message_id` or `attachments` | refused: unknown field not allowed |
| … on another thread | refused: Constraint 'thread_id' not satisfied |
| `search_gmail_messages` | refused: not authorized |

## GitHub: fix an issue, review the PR

The GitHub MCP server is written in Go, so `tenuo.mcp.wrap` can't sit inside
it. Agents running in Hermes get these through hermes-tenuo, which checks the
call before Hermes sends it:
[work on issues](https://github.com/tenuo-ai/hermes-tenuo/tree/main/hermes_tenuo/recipes/work-on-issues)
(one repository: `agent/*` branches, pull requests into `main`, never a merge,
never another repository) and
[review PRs](https://github.com/tenuo-ai/hermes-tenuo/tree/main/hermes_tenuo/recipes/review-prs)
(the PRs you name, comments only, held by a second agent's key). For other
clients, the same YAML without Hermes' `mcp__github__` prefix works wherever a
Tenuo check sits in front of the server.

## Tool names

Recipes use the server's own tool and argument names. Hermes registers MCP tools
as `mcp__<server>__<tool>`, so a Hermes warrant writes `mcp__google_workspace__send_gmail_message`
where a direct client writes `send_gmail_message`. Every argument a warrant
names must be present and match, unless it's wrapped in `{optional: …}`; every
argument it doesn't name is refused; and `{}` after a tool allows any
arguments. In observe mode, `tenuo-cli calls
summary` shows the names and arguments your agent actually sends.
