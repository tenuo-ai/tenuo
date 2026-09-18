# TypeScript integration

Use this reference only for projects using the current `@tenuo/core` or `@tenuo/mcp` APIs. Confirm the resolved version and its shipped README before editing code. The TypeScript API may be on a beta release line.

## Choose the boundary

- Use `tenuo.tool(...)` to wrap a local `{ execute }` object when an in-process guardrail matches the threat model.
- Use `tenuo.present()` / `tenuo.verify()` for a custom remote boundary.
- Use `tenuo.mcp.attach()` / `tenuo.mcp.verify()` or the supported `@tenuo/mcp` integration for MCP boundaries.

For production verification, configure a holder identity and explicit trusted roots rather than `createTenuo.devRoot()`. Development roots are for local examples and tests, not production trust bootstrap.

## Current core pattern

```ts
import { createTenuo, oneOf, range } from "@tenuo/core";

const identity = createTenuo.identity(
  createTenuo.holderKeyFromEnv("TENUO_HOLDER_SECRET"),
);
const runtime = createTenuo.runtime({
  identity,
  trustedRoots: [
    createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY"),
  ],
  receipts: "collect",
});

const scaleCluster = runtime.tenuo.tool(
  {
    execute: async (args: { cluster: string; replicas: number }) =>
      platform.scaleCluster(args),
  },
  {
    capability: "scale_cluster",
    allow: {
      cluster: oneOf(["staging-web"]),
      replicas: range({ min: 1, max: 5 }),
    },
  },
);

const session = runtime.sessionFromWire(process.env.TENUO_WARRANT!);
await scaleCluster.execute(
  { cluster: "staging-web", replicas: 3 },
  { session },
);
```

Verify the exact ownership of `tenuo.tool` on the installed version; some examples construct tools from a `createTenuo(...)` instance and use a `Runtime` only for long-lived identity and session state.

`allow` is a host-side ceiling intersected with the session's authority. Name every call argument whose value matters to the effect. On the current core API, `allow: {}` adds no additional host ceiling; do not describe it as deny-all.

## MCP placement

On the server, verify before recording execution or calling the implementation:

```ts
const authorized = await tenuo.mcp.verify(name, args, meta, {
  allow,
  nonceStore,
});
const result = await runEffect(authorized);
```

Use the returned authorized arguments. Do not verify `args` and then execute values reconstructed from untrusted metadata.

`nonceStore` is optional in the current SDK. Without it, PoP v1 can be replayed within its accepted window. For multi-instance enforcement, use a shared atomic store or application idempotency rather than a per-process memory store.

## Test shape

Wrap the effect with a counter and assert it remains zero for denials:

```ts
let effects = 0;
const effect = async (args: Args) => {
  effects += 1;
  return perform(args);
};

await expect(deniedCall()).rejects.toBeDefined();
expect(effects).toBe(0);
```

Also test a valid call, constraint boundaries, wrong roots, wrong holder, expiry, direct-route bypass, and replay behavior if claimed.
