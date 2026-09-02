# `@tenuo/mcp`

Optional adapter for the official MCP TypeScript **v2** server
(`@modelcontextprotocol/server`). `@tenuo/core` stays free of MCP frameworks.
Decisions still run in Rust via `tenuo.mcp.verify()`.

> **Beta.** Install from the npm `beta` tag. The adapter API may still move
> before a stable tag. Requires **Node 20+**.

```bash
npm i @tenuo/mcp@beta @tenuo/core@beta @modelcontextprotocol/server
```

```ts
import { McpServer } from "@modelcontextprotocol/server";
import { createTenuo, under } from "@tenuo/core";
import { guardTools } from "@tenuo/mcp";
import { z } from "zod";

const tenuo = createTenuo({
  trustedRoots: [createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY")],
});

const server = new McpServer({ name: "reports", version: "0.2.4" });
const tools = guardTools(tenuo, server);

tools.register(
  "read_file",
  {
    description: "Read a file",
    inputSchema: z.object({ path: z.string() }),
    allow: { path: under("/data") },
  },
  async ({ path }) => ({
    content: [{ type: "text", text: await readFile(path) }],
  }),
);
```

The client still uses core:

```ts
const call = tenuo.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
await client.callTool({
  name: call.name,
  arguments: call.arguments,
  _meta: call._meta,
});
```

Zod (or any host schema) is **valid**. `allow` is the server ceiling, AND'd with
the warrant in Rust. Every argument must be named in `allow`. `allow` is
stripped before `registerTool` so it is not advertised.

Tenuo denials become `{ isError: true }` with a JSON-RPC body. Handler
exceptions become `{ isError: true, content: [{ type: "text", text: "Tool execution failed" }] }`
so the transport never sees thrown messages. Pass `onHandlerError` to observe
the original exception server-side.

## Details

- **PoP replay.** Pass `nonceStore: memoryNonceStore()` to reject an exact
  replayed PoP (opt-in, in-process). PoP v1 is otherwise replayable in-window,
  including approval-gated calls. A nonce-store failure returns
  `"Replay store unavailable"`; use `onNonceStoreError` for the cause.
- **Schema-less tools.** Tools without `inputSchema` register as `(ctx)` only,
  matching the official server. `guardHandler()` without a schema returns that
  same `(ctx)` callback. `guardTools().register()` is the schema-typed path;
  `guardHandler()` with a typed callback infers args from it.
- **Unknown options.** Unknown keys, including typos like `{ allow, nonceStroe }`,
  throw at register time.

There is no FastMCP adapter and no v1 adapter package. For
`@modelcontextprotocol/sdk` v1, copy
`packages/core/examples/mcp/host.ts`. Full workspace notes:
[tenuo-ts/README.md](../../README.md).
