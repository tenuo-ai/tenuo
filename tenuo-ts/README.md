# Tenuo TypeScript SDK

Task-scoped authorization for AI agents. Decisions run in the Rust core
(WASM). TypeScript wraps tools, sessions, and MCP wire; it does not decide
allow or deny.

| Package | Role |
|---------|------|
| [`@tenuo/core`](packages/core) | Tools, sessions, SRL, receipts, MCP attach/verify |
| [`@tenuo/mcp`](packages/mcp) | Official MCP TypeScript **v2** server adapter |

> **Beta.** Packages ship as `0.2.4-beta.0` on the npm `beta` tag. The API may
> still move before a stable tag. Requires **Node 20+**. Not a browser or
> Workers runtime.

```bash
npm i @tenuo/core@beta
# MCP v2 server adapter (optional)
npm i @tenuo/mcp@beta @modelcontextprotocol/server
```

What ships today:

- `createTenuo`, `tenuo.tool()`, `session` / `sessionFromWire`, `narrow`, `toWire`
- Allow / hard deny / approval-required. The original `execute` never runs unless Rust allowed
- Signed revocation lists (`revocationList` / `tenuo.revoke`)
- Signed receipts (`onReceipt`)
- MCP attach / verify on `_meta.tenuo` (`tenuo.mcp`)

There is no Vercel AI SDK adapter and no Mastra adapter. `tenuo.tool()` wraps
any `{ execute }` object, including a Vercel `tool()`, but that is not a
supported integration.

## Five-minute path

`devRoot()` is for local development. Set `NODE_ENV=development` (or `test`),
pass `devRoot({ allowInProduction: true })`, or set `TENUO_ALLOW_DEV=1`.
Unset `NODE_ENV` is not treated as development.

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
  await readFile.execute({ path: "/etc/passwd" }); // denied; execute does not run
});
```

Host schemas (Zod or otherwise) answer **valid**. Tool `allow` is the host
ceiling. The session is what this agent may do. Rust ANDs both; TypeScript
does not decide. `session({ tools })` mints from the wrappers so you do not
write the same map twice.

Every argument on the call must be named in `allow`. `{ path: under("/data") }`
rejects `{ path, encoding }` until `encoding` is listed (for example
`pattern("*")`). Empty `allow: {}` adds no extra ceiling.

## Production session

Load an issued warrant and a trusted root:

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

The client attaches a warrant and a proof-of-possession to MCP `_meta.tenuo`.
The server verifies that envelope in Rust before the tool handler runs. Same
wire shape as the Python SDK (`warrant`, `signature`, optional `approvals`).

```ts
// Client: session from the five-minute path, or sessionFromWire in production
const call = tenuo.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
await mcp.callTool({
  name: call.name,
  arguments: call.arguments,
  _meta: call._meta,
});

// Server: trusted root only, no holder secret
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

`attach` authorizes locally first, so a denied call never leaves the client.
`verify` / `handler` is the enforcement point on the server. Handler `allow`
is the server's immutable ceiling and is AND'd with the warrant in Rust.
Map denials with `tenuo.mcp.jsonRpcError(error)` (`-32001` deny, `-32002`
approval required, `-32602` canonicalization).

`@tenuo/core` has no MCP framework dependency. For the official v2 server:

```ts
import { guardTools } from "@tenuo/mcp";

const tools = guardTools(serverTenuo, mcpServer);
tools.register(
  "read_file",
  {
    inputSchema: z.object({ path: z.string() }),
    allow: { path: under("/data") },
  },
  async ({ path }) => ({
    content: [{ type: "text", text: await read(path) }],
  }),
);
```

For `@modelcontextprotocol/sdk` v1, copy
`packages/core/examples/mcp/host.ts`. There is no FastMCP adapter.

### PoP replay (opt-in)

PoP v1 is replayable inside its time window, including approval-gated calls.
A captured `_meta.tenuo` with approvals verifies again until the window closes.
Pass `nonceStore` (`memoryNonceStore()`, or an async Redis `checkAndRecord`)
on `verify` / `handler` if a proof or approval must be one-use. `verify()` is
async so a Promise from the store cannot fail open.

### Examples

`packages/core/examples/mcp/` has a quarterly-close walkthrough: per-agent
warrants, an MCP `tools/call` dispatcher, approval-gated email, and
fail-closed tampering.

```bash
pnpm example:mcp           # wire smoke
pnpm example:mcp:host      # v1 recipe over a real tools/call
pnpm example:mcp:adapter   # @tenuo/mcp v2 adapter
```

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

`onReceipt` is evidence of the decision. A receipt that verifies is not an
allow. If the hook throws, authorize and execute still proceed.

## Outcomes

| Core outcome | `execute` runs? | Host behavior |
|---|---|---|
| Allow | Yes, with normalized args | Return the tool output |
| Hard deny | No | Throw `AuthorizationDeniedError` |
| Approval required | No | Throw `ApprovalRequiredError` (not a successful tool result) |

## Refuse list

These patterns will not ship:

- `dryRun`
- audit-and-run / passthrough
- treating Zod as authority
- process-global `configure()`
- a signing key on request context
- hooks or tool filtering as the security boundary
- a mock authorizer in tests
- a boolean "user clicked Approve" as a Tenuo approval

## Layout

```text
tenuo-ts/
  packages/core/              @tenuo/core
  packages/mcp/               @tenuo/mcp (official v2 server adapter)
  packages/core/examples/mcp  quarterly-close + v1 host recipe
```

## Develop

For contributors working in this monorepo:

```bash
cd tenuo-ts
pnpm install
pnpm build:wasm   # requires wasm-pack + rustc
pnpm typecheck
pnpm test
```

`pnpm build:wasm` writes the Node WASM glue into
`packages/core/src/generated/`, which `@tenuo/core` ships so `npm i` does not
need wasm-pack. Rebuild when you change `tenuo-wasm`.

```bash
pnpm --filter @tenuo/core pack:smoke
pnpm --filter @tenuo/mcp pack:smoke
```

Publish from GitHub Actions (`id-token: write`) so npm can attach provenance.
The `publish:npm` scripts use `--tag beta`. Do not move either package to npm
`latest` until the TypeScript surface is declared stable.
