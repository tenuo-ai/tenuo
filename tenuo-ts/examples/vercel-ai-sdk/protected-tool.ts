/**
 * Vercel AI SDK + Tenuo — a protected tool via shallow composition.
 *
 * This example wraps one deterministic local tool operation (an in-memory
 * file read) with Tenuo and exercises it the way the Vercel AI SDK would:
 * the tool is defined with the SDK's normal `tool({ description,
 * inputSchema, execute })` shape, and its fields are composed with
 * `tenuo.tool()` — shallow composition, not an adapter.
 *
 * Shallow composition, not an adapter:
 * - `description` and `inputSchema` pass through untouched, so the SDK keeps
 *   validating inputs with zod and the model keeps seeing the same tool.
 *   (Tenuo never treats the host schema as authority.)
 * - `tenuo.tool()` is generic over the tool shape, so `execute` keeps its
 *   inferred `{ path: string }` input type and the policy's `allow` keys are
 *   checked against the tool's real arguments at compile time.
 * - No Vercel AI SDK concept enters `@tenuo/core`; the wrapped tool is still
 *   a valid AI SDK tool you could pass to `generateText({ tools })`.
 *
 * Where the Tenuo session is supplied: in a real agent loop, wrap the
 * `generateText`/`streamText` call in `tenuo.withSession(session, …)` — the
 * SDK builds the `execute` options object itself, so callers can't add
 * `session` to it. Tenuo reads the session from ambient context (or from
 * `{ session }` in the options when you call `execute` directly, e.g. in
 * tests), strips its own keys, and forwards the rest (`toolCallId`,
 * `messages`, `abortSignal`, …) to the original `execute` untouched.
 *
 * No LLM call, API key, or network is involved: the tool is executed
 * directly, the way the SDK would invoke it after a model emits a tool call.
 */
import { tool } from "ai";
import {
  AuthorizationDeniedError,
  createTenuo,
  under,
} from "@tenuo/core";
import { z } from "zod";

/** The deterministic local operation under test. No I/O, no network. */
const FILES: Readonly<Record<string, string>> = {
  "/data/reports/q3.pdf": "Q3 revenue up 12% quarter over quarter.",
  "/data/finance/ledger.csv": "id,amount\n1,42\n2,1337\n",
};

const readFileInput = z.object({
  path: z.string().describe("Absolute path of the file to read."),
});

/**
 * Builds the fixture: one Tenuo client, one protected tool, one session, and
 * the `executed` ledger that proves denied calls never reach the operation.
 */
export function createHarness() {
  const tenuo = createTenuo({ root: createTenuo.devRoot() });
  const executed: string[] = [];

  const readFile = async ({ path }: { path: string }): Promise<string> => {
    executed.push(path);
    const contents = FILES[path];
    if (contents === undefined) throw new Error(`no such file: ${path}`);
    return contents;
  };

  // 1. The AI SDK tool, defined exactly as the SDK documents it: a
  //    description, a zod input schema, and a single-argument execute.
  //    Tenuo never imports the SDK; it only receives plain objects shaped
  //    like this one.
  const aiTool = tool({
    description: "Read a UTF-8 text file and return its contents.",
    inputSchema: readFileInput,
    execute: readFile,
  });

  // 2. The wrap — shallow composition, not an adapter. `tenuo.tool` accepts
  //    tools whose `execute` takes just `(args)`; the SDK always invokes
  //    execute as `execute(input, options)`, so a single-argument
  //    implementation is safe. The wrapped tool keeps the SDK's
  //    `description` and `inputSchema`, so it remains a valid AI SDK tool
  //    you could hand to `generateText({ tools })`.
  //
  //    The tool ceiling (`allow`) is AND'd with the session in Rust. Because
  //    `tenuo.tool` is generic over the tool shape, `execute` keeps its
  //    inferred `{ path: string }` input type and `allow`'s keys are checked
  //    against the tool's real arguments — a misspelled field is a
  //    compile-time error.
  const protectedReadFile = tenuo.tool(
    {
      description: aiTool.description,
      inputSchema: aiTool.inputSchema,
      execute: readFile,
    },
    {
      capability: "read_file",
      allow: { path: under("/data") },
    },
  );

  // 3. A session per caller. Sessions can only narrow the tool ceiling —
  //    this one may read under /data/reports and nothing else.
  const reportsSession = tenuo.session({
    allow: { read_file: { path: under("/data/reports") } },
  });

  return { tenuo, protectedReadFile, reportsSession, executed };
}

/** The fixture `createHarness()` builds. */
export type Harness = ReturnType<typeof createHarness>;

export type DemoLog = (line: string) => void;

/**
 * Runs the allowed and denied scenarios and prints what happened.
 * `npm run demo` executes this; the tests assert the same behavior.
 */
export async function runDemo(log: DemoLog = console.log): Promise<void> {
  const { protectedReadFile, reportsSession, executed } = createHarness();

  // Where the Tenuo session is supplied on the direct-call path: the
  // `execute` options. (In a real agent loop you'd wrap the
  // `generateText`/`streamText` call in `tenuo.withSession()` instead —
  // see the README.)
  const options = { session: reportsSession };

  const allowed = await protectedReadFile.execute({ path: "/data/reports/q3.pdf" }, options);
  log(`allowed  /data/reports/q3.pdf -> ${allowed}`);

  try {
    await protectedReadFile.execute({ path: "/data/finance/ledger.csv" }, options);
    log("ERROR: the denied call unexpectedly succeeded");
  } catch (error) {
    if (error instanceof AuthorizationDeniedError) {
      log(`denied   /data/finance/ledger.csv -> ${error.code} (field ${error.field})`);
    } else {
      throw error;
    }
  }

  log(`tool executed for: ${JSON.stringify(executed)}`);
}
