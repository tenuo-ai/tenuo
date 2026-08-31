# `@tenuo/mcp`

Optional adapter for the official MCP TypeScript **v2** server
(`@modelcontextprotocol/server`). `@tenuo/core` stays free of MCP frameworks.
Decisions still run in Rust via `tenuo.mcp.verify()`.

Requires **Node 20+**. Peers are required at install time:

```bash
npm i @tenuo/mcp @tenuo/core @modelcontextprotocol/server
```

```ts
import { McpServer } from "@modelcontextprotocol/server";
import { createTenuo, under } from "@tenuo/core";
import { guardTools } from "@tenuo/mcp";
import { z } from "zod";

const tenuo = createTenuo({
  trustedRoots: [createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY")],
});

const server = new McpServer({ name: "reports", version: "0.2.3" });
const tools = guardTools(tenuo, server);

tools.register(
  "read_file",
  {
    description: "Read a file",
    inputSchema: z.object({ path: z.string() }),
    allow: { path: under("/data") },
  },
  async ({ path }) => ({ content: [{ type: "text", text: await readFile(path) }] }),
);
```

The client still uses core:

```ts
const call = tenuo.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
await client.callTool({ name: call.name, arguments: call.arguments, _meta: call._meta });
```

Zod (or any host schema) is **valid**. `allow` is **allowed**, AND'd with the
warrant in Rust, and zero-trust: every argument must be named. `allow` is
stripped before `registerTool` so it is not advertised. Pass `nonceStore:
memoryNonceStore()` to reject an exact replayed PoP (opt-in, in-process only).
Tenuo denials become `{ isError: true }` with a JSON-RPC body. Handler
exceptions become `{ isError: true, content: [{ type: "text", text: "Tool execution failed" }] }`
— the official transport must not see thrown messages. Pass `onHandlerError`
to observe the original exception server-side. Tools without `inputSchema`
are registered as `(ctx)` only, matching the official server. A nonce-store
failure returns the constant "Replay store unavailable"; pass
`onNonceStoreError` for the original cause. Unknown option keys, including
mixed typos like `{ allow, nonceStroe }`, throw at register time.

There is no FastMCP adapter and no v1 adapter package. For
`@modelcontextprotocol/sdk` v1, copy the recipe in
`packages/core/examples/mcp/host.ts`.
