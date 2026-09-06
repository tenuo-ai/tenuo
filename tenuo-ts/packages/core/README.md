# `@tenuo/core`

Task-scoped authorization for AI agents. Decisions run in the Rust core
(WASM). TypeScript wraps tools and sessions; it does not decide allow or deny.

> **Beta.** Install from the npm `beta` tag. The API may still move before a
> stable tag. Requires **Node 20+**. Not a browser or Workers runtime.

```bash
npm i @tenuo/core@beta
```

`devRoot()` needs `NODE_ENV=development` (or `test`),
`devRoot({ allowInProduction: true })`, or `TENUO_ALLOW_DEV=1`.

```ts
import { createTenuo, under } from "@tenuo/core";

const tenuo = createTenuo({ root: createTenuo.devRoot() });
const readFile = tenuo.tool(
  { execute: async ({ path }: { path: string }) => `contents of ${path}` },
  { capability: "read_file", allow: { path: under("/data") } },
);
const session = tenuo.session({ tools: [readFile] });

await tenuo.withSession(session, async () => {
  await readFile.execute({ path: "/data/q3.pdf" }); // allowed
  await readFile.execute({ path: "/etc/passwd" }); // denied; execute does not run
});
```

Host schemas (Zod or otherwise) answer **valid**. Tool `allow` is the host
ceiling. The session is what this agent may do. Rust ANDs both. Every call
argument must be named in `allow`. Empty `allow: {}` adds no extra ceiling.

Production loads an issued warrant and a trusted root:

```ts
const tenuo = createTenuo({
  trustedRoots: [createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY")],
});
const session = tenuo.sessionFromWire({
  warrant: process.env.TENUO_WARRANT!,
  holderKey: createTenuo.holderKeyFromEnv("TENUO_HOLDER_SECRET"),
});
```

MCP wire helpers live on `tenuo.mcp` (`attach` / `verify` / `handler`). They do
not depend on an MCP framework. For the official v2 server, use
[`@tenuo/mcp`](https://www.npmjs.com/package/@tenuo/mcp). For
`@modelcontextprotocol/sdk` v1, copy `examples/mcp/host.ts`.

There is no Vercel AI SDK adapter and no Mastra adapter. `tenuo.tool()` wraps
any `{ execute }` object, including a Vercel `tool()`, but that is not a
supported integration.

See the [workspace README](../../README.md) for MCP PoP replay, receipts,
revocation, the refuse list, and how to rebuild WASM from this monorepo.
