# MCP example

Quarterly close at a company that already has MCP tools. Tenuo does not replace
the MCP host. It puts a warrant and a proof-of-possession on `_meta.tenuo`, and
the server verifies that envelope in Rust before a handler runs.

```text
workspace.ts   in-memory reports / HR / drafts
server.ts      trusted root + tools/call JSON-RPC (no SDK)
host.ts        official MCP SDK server + in-memory client
client.ts      issuer, per-agent narrow, attach
scenario.ts    orchestrator → researcher → writer → finance email + smoke
```

`@tenuo/core` does not depend on the official MCP SDK. The quarterly-close
files below show the wire. `host.ts` is the **v1 recipe** (not an adapter):
`@modelcontextprotocol/sdk` as a core *devDependency*, plus `verify({ allow })`.
`test/mcp-host.smoke.test.ts` drives that recipe over an in-memory transport.

For the official v2 server (`@modelcontextprotocol/server`), use `@tenuo/mcp`.

Server `handler` / `verify` `allow` is the host ceiling and is AND'd with the
warrant in Rust. Empty `allow: {}` adds no extra ceiling. Zod on the host is
shape only.

## What the scenario does

1. The issuer mints a 15-minute orchestrator session: read/list `/workspace`,
   write `/workspace/drafts`, email `@acme.com`.
2. `send_email` is approval-gated. Read and write are not.
3. The MCP server process loads only the issuer public key.
4. The orchestrator narrows a researcher to `/workspace/reports` and a writer
   to `/workspace/drafts`.
5. The researcher lists and reads Q3 revenue. HR payroll never leaves the client.
6. The writer drafts a summary. Overwriting a report is denied at attach.
7. Email without a signed approval is `-32002` and never becomes a `tools/call`.
8. After one approval, finance@acme.com is sent.
9. Swapping the path on a live envelope fails closed (`TENUO_INVALID_POP`).

## Run

From `tenuo-ts`:

```bash
pnpm example:mcp
```

`pnpm test` imports `runMcpSmoke()` from `scenario.ts` so CI hits the same path.

The official-SDK host smoke (`pnpm example:mcp:host`) covers discover, allow,
deny-at-attach, narrow, `sessionFromWire`, approvals, revocation, forged args,
missing `_meta`, receipts, and the `tenuo.tool()` AND ceiling.

## Wire

```ts
const request = toolsCall(issuer, researcher, "read_file", {
  path: "/workspace/reports/q3-revenue.md",
});
const response = await server.dispatch(request);
```

`toolsCall` is `tenuo.mcp.attach()` plus an MCP `tools/call` JSON-RPC envelope.
`dispatch` is `tenuo.mcp.handler()` plus `tenuo.mcp.jsonRpcError()`.

## v1 recipe

`host.ts` is the supported v1 pattern: call `registerTool` yourself, then
`tenuo.mcp.verify` from `extra._meta`. Do not add a v1 adapter package.

```ts
mcp.registerTool("read_file", { inputSchema: { path: z.string() } }, async (args, extra) => {
  const authorized = await tenuo.mcp.verify("read_file", args, extra._meta, {
    allow: { path: under("/workspace") },
  });
  return { content: [{ type: "text", text: await read(authorized.path) }] };
});
```
