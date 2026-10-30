/**
 * LangChain.js + Tenuo — a protected tool via shallow composition.
 *
 * This example wraps one deterministic local tool operation (an in-memory
 * file read) with Tenuo and exercises it the way LangChain.js would: the
 * tool is built with LangChain's ordinary `tool(func, { name, description,
 * schema })` helper, and the function handed to it is the one `tenuo.tool()`
 * returns — shallow composition, not an adapter.
 *
 * - LangChain keeps validating inputs with the zod `schema` before it calls
 *   the function, and the model keeps seeing the same tool definition.
 *   Tenuo never treats that schema as authority.
 * - `tenuo.tool()` is generic over the tool shape, so `execute` keeps its
 *   inferred `{ path: string }` input type and the policy's `allow` keys are
 *   checked against the tool's real arguments at compile time.
 * - No LangChain concept enters `@tenuo/core`.
 *
 * Where the Tenuo session is supplied: LangChain builds the call to the tool
 * function itself, so callers cannot add `session` to its arguments. Run the
 * agent or tool call inside `tenuo.withSession(session, …)` and Tenuo reads
 * the session from ambient context.
 *
 * No LLM call, API key, or network is involved: the tool is invoked
 * directly, the way an agent runtime would after a model emits a tool call.
 */
import { tool } from "@langchain/core/tools";
import { AuthorizationDeniedError, createTenuo, under } from "@tenuo/core";
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
 * Builds the fixture: one Tenuo client, one protected LangChain tool, one
 * session, and the `executed` ledger that proves denied calls never reach the
 * operation.
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

  // 1. The Tenuo wrap. The ceiling (`allow`) is AND'd with the session in
  //    Rust. `capability` names the tool in session policies.
  const guarded = tenuo.tool(
    { execute: readFile },
    {
      capability: "read_file",
      allow: { path: under("/data") },
    },
  );

  // 2. The LangChain tool, defined exactly as LangChain documents it. The
  //    guarded function is the tool function; the schema is LangChain's own.
  //    LangChain passes `(input, runManager, config)`; only the validated
  //    input is forwarded, and the session comes from `withSession()`.
  const protectedReadFile = tool(
    (input: z.infer<typeof readFileInput>) => guarded.execute(input),
    {
      name: "read_file",
      description: "Read a UTF-8 text file and return its contents.",
      schema: readFileInput,
    },
  );

  // 3. A session per caller. Sessions can only narrow the tool ceiling —
  //    this one may read under /data/reports and nothing else.
  const reportsSession = tenuo.session({
    allow: { read_file: { path: under("/data/reports") } },
  });

  return { tenuo, guarded, protectedReadFile, reportsSession, executed };
}

/** The fixture `createHarness()` builds. */
export type Harness = ReturnType<typeof createHarness>;

export type DemoLog = (line: string) => void;

/**
 * Runs the allowed and denied scenarios and prints what happened.
 * `npm run demo` executes this; the tests assert the same behavior.
 */
export async function runDemo(log: DemoLog = console.log): Promise<void> {
  const { tenuo, protectedReadFile, reportsSession, executed } = createHarness();

  await tenuo.withSession(reportsSession, async () => {
    const allowed = await protectedReadFile.invoke({ path: "/data/reports/q3.pdf" });
    log(`allowed  /data/reports/q3.pdf -> ${allowed}`);

    try {
      await protectedReadFile.invoke({ path: "/data/finance/ledger.csv" });
      log("ERROR: the denied call unexpectedly succeeded");
    } catch (error) {
      if (error instanceof AuthorizationDeniedError) {
        log(`denied   /data/finance/ledger.csv -> ${error.code} (field ${error.field})`);
      } else {
        throw error;
      }
    }
  });

  log(`tool executed for: ${JSON.stringify(executed)}`);
}
