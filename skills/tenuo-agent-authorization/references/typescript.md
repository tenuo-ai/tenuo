# TypeScript integration

Use this reference only for projects using the current `@tenuo/core` or `@tenuo/mcp` APIs. Confirm the resolved version and its shipped README before editing code. The TypeScript API may be on a beta release line.

Do not treat this reference as an API specification. Use the repository's executable examples and the installed package types:

- [Concurrent protected tools and deny-before-effect evidence](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-ts/packages/core/examples/concurrent-sessions.ts), exercised by [its example test](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-ts/packages/core/test/example-sessions.test.ts)
- [Framework-neutral MCP host boundary](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-ts/packages/core/examples/mcp/host.ts), exercised by [the MCP host smoke test](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-ts/packages/core/test/mcp-host.smoke.test.ts)
- [Current package API and production configuration](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-ts/packages/core/README.md)

## Choose the boundary

- Use `tenuo.tool(...)` to wrap a local `{ execute }` object when an in-process guardrail matches the threat model.
- Use `tenuo.present()` / `tenuo.verify()` for a custom remote boundary.
- Use `tenuo.mcp.attach()` / `tenuo.mcp.verify()` or the supported `@tenuo/mcp` integration for MCP boundaries.

For production verification, configure a holder identity and explicit trusted roots rather than `createTenuo.devRoot()`. Development roots are for local examples and tests, not production trust bootstrap.

## Current core pattern

Use the installed package types to verify the exact ownership and signatures of tool protection, runtime, session, presentation, verification, and MCP methods. The canonical examples above are compiled and tested with the workspace SDK; adapt their architecture rather than copying remembered syntax.

`allow` is a host-side ceiling intersected with the session's authority. Name every call argument whose value matters to the effect. On the current core API, `allow: {}` adds no additional host ceiling; do not describe it as deny-all.

## MCP placement

On the server, verify before recording execution or calling the implementation. Use the returned authorized arguments. Do not verify one argument object and then execute values reconstructed from untrusted metadata.

`nonceStore` is optional in the current SDK. Without it, PoP v1 can be replayed within its accepted window. For multi-instance enforcement, use a shared atomic store or application idempotency rather than a per-process memory store.

## Test shape

Wrap the effect with a counter or append-only test record and assert it remains untouched for denials. Also test a valid call, constraint boundaries, wrong roots, wrong holder, expiry, direct-route bypass, and replay behavior if claimed. Follow the evidence pattern in the concurrent-session and MCP-host tests linked above.
