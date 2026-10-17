# Express request-scoped authorization example

This example demonstrates how an ordinary Express 5 route can call a Tenuo-protected
operation. The **application** determines the caller's authority at the request
boundary, while Tenuo enforces the operation's path constraint before execution.

Requires Node.js 20.9+; no cloud account, control plane, credentials, or listening
server is needed.

```sh
cd tenuo-ts/examples/express
npm install --no-audit --no-fund
npm run typecheck
npm test
npm run demo
```

Two illustrative routes are available through Supertest:

- `GET /reports/read?path=/workspace/reports/q3.txt` → 200, executes
- `GET /reports/read?path=/workspace/finance/payroll.txt` → 403, does **not** execute
- `GET /finance/read?path=/workspace/finance/payroll.txt` → 200, executes

`app.ts` binds the route to a trusted demo role, creates a short-lived session for
each request, and calls the protected operation inside `tenuo.withSession()`.
The tests also send concurrent allowed and denied requests and verify that only
the two permitted operations run.

**Security boundary:** The two route names stand in for an authenticated
application's trusted role resolution; this sample does not implement identity,
authentication, or a production issuer. Never choose a role based only on a URL,
query string, or client-controlled header in a real application. The demo root
is for local development only. A production service needs authenticated identity,
trusted warrant issuance, and a separate trusted root. This illustrates an
in-process effect boundary, not protection from an application that deliberately
bypasses the wrapped tool.

## Verify against the local packed package

From `tenuo-ts`, build `@tenuo/core`, then run the isolated check:

```sh
pnpm --filter @tenuo/core build
node examples/express/scripts/verify-packed.mjs
```

The check packs the local `@tenuo/core`, installs its tarball into a temporary
copy of this example (never a workspace link), and runs the TypeScript check,
the test suite, and the demo there. Temporary dependencies are removed afterward.
CI runs this script in the TypeScript SDK job after the Vercel AI SDK example.
