# MCP example

`tenuo.mcp` attaches a warrant and proof-of-possession to `_meta.tenuo`, then
verifies that envelope on the server before the tool handler runs. There is no
official MCP SDK dependency. Pass `_meta` through from whatever server you use.

```text
client.ts   mint + attach
server.ts   trusted root + handler
smoke.ts    allow / deny / forged args in one process
```

## Run the smoke

From `tenuo-ts`:

```bash
pnpm example:mcp
```

`pnpm test` also imports `runMcpSmoke()` so CI hits the same three cases.

## What this is not

This is not FastMCP, not `SecureMCPClient`, and not a stdio transport. Those
live in the Python SDK. The TypeScript surface is the wire envelope:

```ts
const call = tenuo.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
await handler(call.arguments, { _meta: call._meta });
```
