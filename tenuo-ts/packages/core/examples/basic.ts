/**
 * Quickstart: protect one tool, then watch one call run and one get denied.
 *
 * This is the README's "Protect your first tool" snippet as a runnable file.
 * The authorizer is the real committed WASM core; the dev root needs no keys,
 * credentials, or network.
 *
 * From `tenuo-ts`: `pnpm example:basic`
 *
 * Expected output:
 *
 * ```text
 * allowed  withSession  /data/q3.pdf -> contents of /data/q3.pdf
 * allowed  { session }  /data/q3.pdf -> contents of /data/q3.pdf
 * denied   withSession  /etc/passwd -> TENUO_CONSTRAINT_VIOLATION (field path)
 * execute ran 2 times; the denied call never reached it
 * ```
 */
import { AuthorizationDeniedError, createTenuo, under } from "../src/index.ts";

/**
 * Runs the three calls and returns how many times the tool body ran. `log` is
 * injected so `test/example-basic.test.ts` drives this same code quietly.
 * `createTenuo.devRoot()` refuses to run unless `NODE_ENV` is development or
 * test; vitest sets `test`.
 */
export async function runBasicExample(log: (line: string) => void = console.log): Promise<number> {
  const tenuo = createTenuo({ root: createTenuo.devRoot() });

  let executed = 0;
  const readFile = tenuo.tool(
    {
      execute: async ({ path }: { path: string }) => {
        executed += 1;
        return `contents of ${path}`;
      },
    },
    { capability: "read_file", allow: { path: under("/data") } },
  );

  const session = tenuo.session({ tools: [readFile] });

  // Ambient session: every protected call inside the callback uses it.
  const ambient = await tenuo.withSession(session, () => readFile.execute({ path: "/data/q3.pdf" }));
  log(`allowed  withSession  /data/q3.pdf -> ${ambient}`);

  // Explicit session: for code that runs outside a withSession() scope.
  const explicit = await readFile.execute({ path: "/data/q3.pdf" }, { session });
  log(`allowed  { session }  /data/q3.pdf -> ${explicit}`);

  try {
    await tenuo.withSession(session, () => readFile.execute({ path: "/etc/passwd" }));
  } catch (error) {
    // Show the stable code and field, never the raw error, which may carry details.
    if (!(error instanceof AuthorizationDeniedError)) {
      throw error;
    }
    log(`denied   withSession  /etc/passwd -> ${error.code} (field ${String(error.field)})`);
  }

  log(`execute ran ${executed} times; the denied call never reached it`);
  return executed;
}
