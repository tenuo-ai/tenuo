# LangChain.js protected-tool example

A runnable example of a Tenuo-protected tool composed with LangChain.js's
ordinary tool interface — `tool(func, { name, description, schema })` from
`@langchain/core/tools` — via **shallow composition, not an adapter**. No
LangChain-specific API is added to Tenuo packages; everything
LangChain-shaped lives in this directory.

## Run it

Use Node.js 20.9 or newer. No model provider, API key, network access, or
Tenuo service is required — the tool is invoked directly with `.invoke()`,
the call an agent runtime makes after a model emits a tool call.

```sh
cd tenuo-ts/examples/langchain-js
npm install
npm run demo
```

Expected output:

```text
allowed  /data/reports/q3.pdf -> Q3 revenue up 12% quarter over quarter.
denied   /data/finance/ledger.csv -> TENUO_CONSTRAINT_VIOLATION (field path)
tool executed for: ["/data/reports/q3.pdf"]
```

The denied path never reaches the operation: `tool executed for` lists only
the allowed call.

```sh
npm test        # allow/deny tests (vitest)
npm run typecheck
```

## How the pieces fit

`protected-tool.ts` builds the fixture in three steps:

1. **Wrap the operation.** `tenuo.tool({ execute: readFile }, { capability:
   "read_file", allow: { path: under("/data") } })` returns a protected
   `execute`. The tool ceiling (`allow`) is AND'd with the session in Rust.
   Because `tenuo.tool` is generic over the tool shape, `execute` keeps its
   inferred `{ path: string }` input type, and a misspelled policy field is a
   compile-time error (covered in the tests).
2. **Define the tool with LangChain.** `tool((input) => guarded.execute(input),
   { name, description, schema })` is the standard LangChain definition you
   would hand to an agent. Its zod `schema` is LangChain's own; Tenuo never
   treats it as authority.
3. **Mint a session per caller.** `tenuo.session({ allow: { read_file: {
   path: under("/data/reports") } } })` can only narrow the tool ceiling,
   never widen it.

## Order of checks: schema validation, then authorization

A call passes two independent gates, in this order:

1. **LangChain validates the input against the tool's `schema`.** Malformed
   input (for example `path: 42`) is rejected with LangChain's own schema
   error. Tenuo is never consulted and the operation does not run.
2. **Tenuo authorizes the validated arguments** against the session and the
   tool ceiling, before the operation. A violation throws
   `AuthorizationDeniedError` and the operation does not run.

Passing the schema does not imply permission: a well-formed
`{ path: "/data/finance/ledger.csv" }` is valid input and is still denied.
Conversely, Tenuo does not replace input validation — it sees only arguments
LangChain has already accepted.

## Where the Tenuo session is supplied

LangChain builds the call to the tool function itself, so callers can't add
`session` to its arguments. Run the call (or the whole agent) inside
`tenuo.withSession()`:

```ts
const result = await tenuo.withSession(reportsSession, () =>
  protectedReadFile.invoke({ path: "/data/reports/q3.pdf" }),
);
```

Tenuo reads the session from ambient `AsyncLocalStorage` context. Calling the
tool with no session fails and the operation does not run (covered by a test).

## Verify against the local packed package

From `tenuo-ts`, build `@tenuo/core`, then run the isolated production check:

```sh
pnpm --filter @tenuo/core build
node examples/langchain-js/scripts/verify-packed.mjs
```

The check packs the local `@tenuo/core`, installs its tarball into a
temporary copy of this example (never a workspace link), and runs the
TypeScript check, the test suite, and the demo there. CI runs this script on
every change under `tenuo-ts/`.
