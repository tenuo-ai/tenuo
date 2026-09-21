# TypeScript integration

Use this reference only for projects using the current `@tenuo/core` or `@tenuo/mcp` APIs. Confirm the resolved version and its shipped README before editing code. The TypeScript API may be on a beta release line.

Do not treat this reference as an API specification. Inspect the resolved package's README, `package.json`, exports, and declaration files in `dist` first. The npm package does not ship the repository examples. If installed artifacts are insufficient, compare the resolved package with the TypeScript entry in the [release contract](../release.json). Use these immutable sources only when the versions match:

- [Framework-neutral MCP host boundary](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-ts/packages/core/examples/mcp/host.ts), exercised by [the MCP host smoke test](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-ts/packages/core/test/mcp-host.smoke.test.ts)
- [Package API and production configuration](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-ts/packages/core/README.md)

For another package version, do not assume that its prerelease suffix names a repository tag. Confirm a candidate tag by reading `tenuo-ts/packages/core/package.json` at that tag.

## Choose the boundary

- Use `tenuo.tool(...)` to wrap a local `{ execute }` object when an in-process guardrail matches the threat model.
- Use `tenuo.present()` / `tenuo.verify()` for a custom remote boundary.
- Use `tenuo.mcp.attach()` / `tenuo.mcp.verify()` or the supported `@tenuo/mcp` integration for MCP boundaries.

For production verification, configure a holder identity and explicit trusted roots rather than `createTenuo.devRoot()`. Development roots are for local examples and tests, not production trust bootstrap.

## Current core pattern

Use the installed package types to verify the exact ownership and signatures of tool protection, runtime, session, presentation, verification, and MCP methods. The release-tagged MCP example above is compiled and tested with that SDK; adapt its boundary placement rather than copying remembered syntax. Newer examples on `main` may use unreleased APIs and are not evidence for the installed version.

`allow` is a host-side ceiling intersected with the session's authority. Name every call argument whose value matters to the effect. On the current core API, `allow: {}` adds no additional host ceiling; do not describe it as deny-all.

## MCP placement

On the server, verify before recording execution or calling the implementation. Use the returned authorized arguments. Do not verify one argument object and then execute values reconstructed from untrusted metadata.

`nonceStore` is optional in the current SDK. Without it, PoP v1 can be replayed within its accepted window. For multi-instance enforcement, use a shared atomic store or application idempotency rather than a per-process memory store.

## Test shape

Wrap the effect with a counter or append-only test record and assert it remains untouched for denials. Also test a valid call, constraint boundaries, wrong roots, wrong holder, expiry, direct-route bypass, and replay behavior if claimed. Follow the evidence pattern in the MCP-host test linked above.
