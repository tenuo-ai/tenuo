# `@tenuo/core`

TypeScript SDK for Tenuo. Authorization decisions run in the Rust core (WASM).

> Beta: install this package from the npm `beta` dist-tag. The authorization
> semantics match Tenuo, but the TypeScript API may still change before the
> first stable npm tag.

Requires **Node 20+**. This package is not a browser or Workers runtime. There is
no Vercel AI SDK adapter and no Mastra adapter. `tenuo.tool()` wraps any
`{ execute }` object, including a Vercel `tool()`, but that is not a supported
integration.

```bash
npm i @tenuo/core@beta
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

Production loads an issued warrant and a trusted root. Prefer `Runtime` when
the same holder identity, roots, revocation list, and receipt buffer should
outlive a single call:

```ts
const identity = createTenuo.identity(createTenuo.holderKeyFromEnv("TENUO_HOLDER_SECRET"));
const runtime = createTenuo.runtime({
  identity,
  trustedRoots: [createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY")],
  receipts: "collect",
});
const session = runtime.sessionFromWire(process.env.TENUO_WARRANT!);
await readFile.execute({ path: "/data/q3.pdf" }, { session });
const receipts = session.drainReceipts(); // persist, then upload
```

`createTenuo.parseConnectToken(raw)` decodes a `tenuo_ct_…` token. It does not
read environment variables or invent an origin. Relative `/v1` endpoints need
`token.resolveEndpoint({ localBase })`. Callers append `/v1/…` to the bare
origin.

See [Receipt delivery](../../README.md#receipt-delivery) for peek / drain / ack
guarantees. This package does not perform HTTP, discovery, or upload.

Delegation to another agent rebinds a narrower child to that agent's key. The
current holder signs; core refuses any child that is not within its parent
before a token exists; a copied chain fails `TENUO_INVALID_POP` under any other
key:

```ts
const holderKey = createTenuo.generateHolderKey();          // in the worker, once
const workerPublicKey = createTenuo.publicKeyFromHolderKey(holderKey);

const handed = tenuo.narrow(session, { path: under("/data/reports") }, {
  holder: workerPublicKey,
  ttlSeconds: 300,
  terminal: true, // the worker cannot hand it on
});
// worker: tenuo.sessionFromWire({ warrant: handed.toWire(), holderKey })
```

`session({ holder, maxDepth })` issues straight to an agent's key and caps how
far the chain may go; `issuerPublicKey()` is what agents put in `trustedRoots`;
`session.inspect()` shows depth, ceiling, tools, and holder public key.

The rest of the protocol is here too: a stable issuer key
(`createTenuo({ root: createTenuo.issuerKeyFromEnv("TENUO_ISSUER_SECRET") })`),
issuer sessions and `tenuo.issue()`, clearance / session id / agent id, the
full constraint set (`range`, `regex`, `cidr`, `urlSafe`, `shlex`, `anyOf`,
`cel`, ...), approval gates with `ApprovalRequiredError.request`,
`createTenuo.signApproval()` and the control-plane v1 wire shape, revocation
lists (`tenuo.revocationList()`), public receipt verification, `tenuo.explain()`,
and `tenuo.present()` / `tenuo.verify()` for boundaries that are not MCP.

MCP wire helpers live on `tenuo.mcp` (`attach` / `verify` / `handler`). They do
not depend on an MCP framework. For the official v2 server, use `@tenuo/mcp`.
For `@modelcontextprotocol/sdk` v1, copy the recipe in `examples/mcp/host.ts`.
`verify` / `handler` can take an optional `nonceStore` (`memoryNonceStore()`,
or an async Redis `checkAndRecord`) to reject an exact replayed PoP; that is
opt-in. PoP v1 is otherwise replayable in-window, including approval-gated
calls. Pass `nonceStore` on those tools if an approval must be one-use.
`memoryNonceStore({ ttlSeconds })` defaults to 180 seconds; an explicit TTL must
be positive, finite, and small enough to represent in milliseconds.

See the [workspace README](../../README.md) for the full API, refuse list, and
how to rebuild WASM from this monorepo.
