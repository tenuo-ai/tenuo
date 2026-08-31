# `@tenuo/core`

TypeScript SDK for Tenuo. Authorization decisions run in the Rust core (WASM).

What ships today:

- `createTenuo`, `tenuo.tool()`, `session` / `sessionFromWire`, `narrow`, `toWire`
- Allow / hard deny / approval-required — the original `execute` never runs unless Rust allowed
- Signed revocation lists (`revocationList` / `tenuo.revoke`)
- Signed receipts (`onReceipt`)
- MCP attach / verify on `_meta.tenuo` (`tenuo.mcp`)

There is no Vercel AI SDK adapter and no Mastra adapter. `tenuo.tool()` wraps any `{ execute }` object, including a Vercel `tool()`, but that is not a supported integration.

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

const readFile = server.mcp.handler("read_file", async ({ path }) => {
  return readFileFromDisk(path);
});

// extra._meta is params._meta from the MCP CallTool request
await readFile(params.arguments, { _meta: params._meta });
```

`attach` authorizes locally first, so a denied call never leaves the client. `verify` / `handler` is the enforcement point on the server. A JSON-RPC mapping is available as `tenuo.mcp.jsonRpcError(error)` (`-32001` deny, `-32002` approval required, `-32602` canonicalization).

There is no FastMCP / official MCP SDK dependency. Pass `_meta` through from whatever server you use.

A two-file example and an in-process smoke live in `packages/core/examples/mcp/`. From this directory: `pnpm example:mcp`. `pnpm test` runs the same smoke.

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
  packages/core/examples/mcp attach / verify example + smoke
```

## Develop

```bash
cd tenuo-ts
pnpm install
pnpm build:wasm   # requires wasm-pack + rustc
pnpm typecheck
pnpm test
pnpm example:mcp
```

Requires Node 20+. `pnpm build:wasm` writes the Node WASM glue into `packages/core/src/generated/`, which `@tenuo/core` ships so `npm i` does not need wasm-pack. Rebuild it when you change `tenuo-wasm`.
