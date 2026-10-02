# Vercel AI SDK protected-tool example

A runnable example of a Tenuo-protected tool composed with the Vercel AI
SDK's normal tool definition shape — `tool({ description, inputSchema,
execute })` — via **shallow composition, not an adapter**. No Vercel AI
SDK-specific API is added to Tenuo packages; everything SDK-shaped lives in
this directory.

## Run it

Use Node.js 20.9 or newer. No model provider, API key, network access, or
Tenuo service is required — the tool is executed directly, the way the SDK
would invoke it after a model emits a tool call.

```sh
cd tenuo-ts/examples/vercel-ai-sdk
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

1. **Define the tool with the SDK.** `tool({ description, inputSchema,
   execute })` is exactly what you would hand to `generateText({ tools })`.
   Tenuo never imports the SDK; it only receives this object.
2. **Wrap it.** `tenuo.tool({ description, inputSchema, execute }, {
   capability: "read_file", allow: { path: under("/data") } })` returns a
   `ProtectedTool` built from the SDK tool's own fields. The tool ceiling
   (`allow`) is AND'd with the session in Rust, and because `tenuo.tool` is
   generic over the tool shape, `execute` keeps its inferred
   `{ path: string }` input type — a misspelled argument or policy field is a
   compile-time error. `description` and `inputSchema` pass through untouched,
   so the SDK keeps validating inputs with zod (Tenuo never treats the host
   schema as authority).
3. **Mint a session per caller.** `tenuo.session({ allow: { read_file: {
   path: under("/data/reports") } } })` can only narrow the tool ceiling,
   never widen it.

## Where the Tenuo session is supplied

In a real agent loop, wrap the `generateText`/`streamText` call in
`tenuo.withSession()` — the AI SDK builds the `execute` options object
itself (`toolCallId`, `messages`, `abortSignal`, …), so callers can't add
`session` to it:

```ts
const result = await tenuo.withSession(reportsSession, () =>
  streamText({
    model,
    tools: { readFile: protectedReadFile },
    prompt: "Read /data/reports/q3.pdf",
  }),
);
```

Tenuo reads the session from ambient `AsyncLocalStorage` context, authorizes
each tool call against it, and forwards the SDK's own options to the original
`execute` untouched. This holds even though the tools run while the stream is
being read, after the `withSession` callback has returned — the session
survives stream consumption (covered by the `streamText` agent-loop test).

Calling `execute` with no session at all throws `TenuoConfigurationError`
("No session…") instead of running the operation.

### Direct-call / testing path

When you invoke the tool yourself — in tests, scripts, or the demo — pass
the session explicitly in the options object:

```ts
await protectedReadFile.execute(
  { path: "/data/reports/q3.pdf" },
  { session: reportsSession },
);
```

Tenuo reads `session` from the options (or from `tenuo.withSession()`
ambient context when the options omit it), strips its own keys, and forwards
anything else to the original `execute`.

One typing note: `tenuo.tool` accepts tools whose `execute` takes just
`(args)` — the SDK always invokes `execute(input, options)`, so a
single-argument implementation is safe. If your operation needs the SDK's
options (e.g. `abortSignal`), declare them as an optional second parameter;
Tenuo picks them up and forwards them.

## Verify against the local packed package

From `tenuo-ts`, build `@tenuo/core`, then run the isolated production check:

```sh
pnpm --filter @tenuo/core build
node examples/vercel-ai-sdk/scripts/verify-packed.mjs
```

The check packs the local `@tenuo/core`, installs its tarball into a
temporary copy of this example (never a workspace link), and runs the
TypeScript check, the test suite, and the demo there. Temporary dependencies
are removed afterward. CI runs this script on every change under `tenuo-ts/`.
