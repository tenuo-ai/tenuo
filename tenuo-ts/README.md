# `@tenuo/core`

TypeScript SDK for Tenuo. Authorization decisions run in the Rust core (WASM). `createTenuo({ root: createTenuo.devRoot() })` can mint a session. Production loads an issued warrant with `sessionFromWire` and a trusted root.

## Five-minute path (target API)

```ts
import { createTenuo, under } from "@tenuo/core";
import { tool } from "ai";
import { z } from "zod";

const tenuo = createTenuo({ root: createTenuo.devRoot() });

const readFile = tenuo.tool(
  tool({
    description: "Read a file",
    parameters: z.object({ path: z.string() }),
    execute: async ({ path }) => `contents of ${path}`,
  }),
  { allow: { path: under("/data") } },
);

const session = tenuo.session({
  allow: { read_file: { path: under("/data") } },
});

await tenuo.withSession(session, async () => {
  await readFile.execute({ path: "/data/q3.pdf" }); // allowed
  await readFile.execute({ path: "/etc/passwd" }); // denied — execute does not run
});
```

Zod answers **valid**. `allow` answers **allowed**. Only Rust can produce an allow.

Production setup uses a real root, not `devRoot()`:

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

Production can pin a signed revocation list at construct time, or load one later. Rust verifies the issuer against the trusted roots; TypeScript does not decide revocation.

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

`devRoot()` throws when `NODE_ENV=production` unless `TENUO_ALLOW_DEV=1`.

## Outcomes

| Core outcome | `execute` runs? | Default host behavior |
|---|---|---|
| Allow | Yes, with normalized args | Return the tool output |
| Hard deny | No | Tool-error channel (`onDeny: "tool-error"`) or abort the run |
| Approval required | No | Suspend / interrupt — not a successful tool result |

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

Protocol types (`Warrant`, `mint`, `Authorizer`) will exist as aliases, not as the README API.

## Layout

```text
tenuo-ts/
  packages/core/     @tenuo/core
```

## Develop

```bash
cd tenuo-ts
pnpm install
pnpm build:wasm   # requires wasm-pack + rustc
pnpm typecheck
pnpm test
```

Requires Node 20+. `pnpm build:wasm` writes the Node WASM glue into `packages/core/src/generated/`, which `@tenuo/core` ships so `npm i` does not need wasm-pack. Rebuild it when you change `tenuo-wasm`.
