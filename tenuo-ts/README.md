# `@tenuo/core`

TypeScript SDK for Tenuo. Authorization decisions run in the Rust core (WASM).

What ships today:

- `createTenuo`, `tenuo.tool()`, `session` / `sessionFromWire`, `narrow`, `toWire`
- Allow / hard deny / approval-required — the original `execute` never runs unless Rust allowed
- Signed revocation lists (`revocationList` / `tenuo.revoke`)
- Signed receipts (`onReceipt`)
- MCP attach / verify on `_meta.tenuo` (`tenuo.mcp`)

Requires **Node 20+**. This is not a browser or Workers runtime. There is no
Vercel AI SDK adapter and no Mastra adapter (`@tenuo/mastra` is deferred).
`tenuo.tool()` wraps any `{ execute }` object, including a Vercel `tool()`, but
that is not a supported integration.

## Five-minute path

```ts
import { createTenuo, under } from "@tenuo/core";

const tenuo = createTenuo({ root: createTenuo.devRoot() });

const readFile = tenuo.tool(
  {
    execute: async ({ path }: { path: string }) => `contents of ${path}`,
  },
  { capability: "read_file", allow: { path: under("/data") } },
);

const session = tenuo.session({ tools: [readFile] });

await tenuo.withSession(session, async () => {
  await readFile.execute({ path: "/data/q3.pdf" }); // allowed
  await readFile.execute({ path: "/etc/passwd" }); // denied — execute does not run
});
```

Host schemas (Zod or otherwise) answer **valid**. Tool `allow` is the host ceiling. The session is what this agent may do. Rust AND's both; TypeScript does not decide. `session({ tools })` mints from the wrappers so you do not write the same map twice.

`allow` is **zero-trust**: every argument on the call must be named in the policy. `{ path: under("/data") }` rejects `{ path, encoding }` until `encoding` is in `allow` (for example `pattern("*")`). Empty `allow: {}` adds no extra ceiling. MCP `verify` / `handler` can take an optional `nonceStore` (`memoryNonceStore()`) to reject an exact replayed PoP; that is opt-in and in-memory only.

`devRoot()` throws when `NODE_ENV=production` unless `TENUO_ALLOW_DEV=1`.

Production loads an issued warrant and a trusted root:

```ts
const tenuo = createTenuo({
  trustedRoots: [createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY")],
});

const session = tenuo.sessionFromWire({
  warrant: process.env.TENUO_WARRANT!,
  holderKey: createTenuo.holderKeyFromEnv("TENUO_HOLDER_SECRET"),
});

const reports = tenuo.narrow(session, { path: under("/data/reports") });
// send reports.toWire() to the next process; keep the holder secret here
```

## MCP

The client attaches a warrant and a proof-of-possession to MCP `_meta.tenuo`. The server verifies that envelope in Rust before the tool handler runs. This is the same wire shape as the Python SDK (`warrant`, `signature`, optional `approvals`).

```ts
// Client process
const call = tenuo.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
await mcp.callTool({ name: call.name, arguments: call.arguments, _meta: call._meta });

// Server process — trusted root only, no holder secret
const server = createTenuo({
  trustedRoots: [createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY")],
});

const readFile = server.mcp.handler(
  "read_file",
  { allow: { path: under("/data") } },
  async ({ path }) => readFileFromDisk(path),
);

// extra._meta is params._meta from the MCP CallTool request
await readFile(params.arguments, { _meta: params._meta });
```

`attach` authorizes locally first, so a denied call never leaves the client. `verify` / `handler` is the enforcement point on the server. Handler `allow` is the server's immutable ceiling and is AND'd with the warrant in Rust. A JSON-RPC mapping is available as `tenuo.mcp.jsonRpcError(error)` (`-32001` deny, `-32002` approval required, `-32602` canonicalization).

`@tenuo/core` has no MCP framework dependency. For the official v2 server:

```ts
import { guardTools } from "@tenuo/mcp";

const tools = guardTools(serverTenuo, mcpServer);
tools.register("read_file", {
  inputSchema: z.object({ path: z.string() }),
  allow: { path: under("/data") },
}, async ({ path }) => ({ content: [{ type: "text", text: await read(path) }] }));
```

For `@modelcontextprotocol/sdk` v1, copy the recipe in `packages/core/examples/mcp/host.ts`. There is no FastMCP adapter.

A quarterly-close example lives in `packages/core/examples/mcp/`: per-agent warrants, an MCP `tools/call` dispatcher, approval-gated email, and fail-closed tampering. `pnpm example:mcp` runs the wire smoke. `pnpm test` also drives the official MCP TypeScript SDK host (`examples/mcp/host.ts`) so attach / verify / narrow / approvals / revocation go over a real `tools/call`.

## Revocation and receipts

```ts
const tenuo = createTenuo({
  trustedRoots: [createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY")],
  revocationList: process.env.TENUO_SRL,
});

tenuo.revoke(updatedSrl);

await readFile.execute(
  { path: "/data/q3.pdf" },
  { session, onReceipt: (receipt) => persist(receipt) },
);
```

`onReceipt` is evidence of the decision. A receipt that verifies is not an allow.

## Outcomes

| Core outcome | `execute` runs? | Host behavior |
|---|---|---|
| Allow | Yes, with normalized args | Return the tool output |
| Hard deny | No | Throw `AuthorizationDeniedError` |
| Approval required | No | Throw `ApprovalRequiredError` — not a successful tool result |

## Refuse list

These patterns will not ship:

- `dryRun`
- audit-and-run / passthrough
- treating Zod as authority
- process-global `configure()`
- a signing key on request context
- hooks or tool filtering as the security boundary
- a mock authorizer in tests
- a boolean “user clicked Approve” as a Tenuo approval

## Layout

```text
tenuo-ts/
  packages/core/             @tenuo/core
  packages/mcp/              @tenuo/mcp — official v2 server adapter
  packages/core/examples/mcp quarterly-close + v1 host recipe
```

## Develop

```bash
cd tenuo-ts
pnpm install
pnpm build:wasm   # requires wasm-pack + rustc
pnpm typecheck
pnpm test
pnpm example:mcp
pnpm example:mcp:host      # v1 recipe smoke
pnpm example:mcp:adapter   # @tenuo/mcp v2 adapter
```

Requires Node 20+. `pnpm build:wasm` writes the Node WASM glue into `packages/core/src/generated/`, which `@tenuo/core` ships so `npm i` does not need wasm-pack. Rebuild it when you change `tenuo-wasm`. `pnpm --filter @tenuo/core pack:smoke` and `pnpm --filter @tenuo/mcp pack:smoke` install the published tarballs in a clean directory.
