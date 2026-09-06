# Vitest recipe: testing protected tools

Application authors need a clear pattern for asserting authorization boundaries
around protected tools. This recipe shows how to do that with Vitest and only
`@tenuo/core` public APIs — no `src/testkit.ts`, no generated WASM imports, and
no private package paths.

## What it covers

- An allowed invocation calls the inner tool and returns its result
- A denied invocation throws AuthorizationDeniedError
- Denial is asserted through stable fields (code, field), not the full message
- The denied invocation never calls the inner tool (Vitest spy)
- Session scope is established with withSession and cleaned up per test
- createTenuo.devRoot() is used under Vitest normal NODE_ENV=test guard

Authorization still runs in the real WASM-backed SDK. The recipe does not mock
authorization decisions or add testing bypasses.

## Run

From tenuo-ts/:

```bash
pnpm example:vitest-protected-tools
```

The package test suite also picks up this file via Vitest include examples/**/*.test.ts.

## Consumer copy-paste

After installing `@tenuo/core`, change the import in
protected-tools.test.ts from `../../src/index.ts` to `@tenuo/core`. Keep the
rest of the file as-is.

## Related

- Protect your first tool: ../../../README.md#protect-your-first-tool
- Package README: ../../README.md
