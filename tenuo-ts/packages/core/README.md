# `@tenuo/core`

TypeScript SDK for Tenuo. Authorization decisions run in the Rust core (WASM).

Requires **Node 20+**. This package is not a browser or Workers runtime. There is
no Vercel AI SDK adapter and no Mastra adapter. `tenuo.tool()` wraps any
`{ execute }` object, including a Vercel `tool()`, but that is not a supported
integration.

```bash
npm i @tenuo/core
```

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
  await readFile.execute({ path: "/etc/passwd" }); // denied — execute does not run
});
```

Host schemas (Zod or otherwise) answer **valid**. Tool `allow` is the host ceiling.
The session is what this agent may do. Rust AND's both. `allow` is zero-trust:
every call argument must be named in the policy. `allow: {}` adds no extra
ceiling. `devRoot()` requires `NODE_ENV=development` or `test`,
`devRoot({ allowInProduction: true })`, or `TENUO_ALLOW_DEV=1`. Unset
`NODE_ENV` is not treated as development.

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
not depend on an MCP framework. For the official v2 server, use `@tenuo/mcp`.
For `@modelcontextprotocol/sdk` v1, copy the recipe in `examples/mcp/host.ts`.

See the [workspace README](../../README.md) for the full API, refuse list, and
how to rebuild WASM from this monorepo.
