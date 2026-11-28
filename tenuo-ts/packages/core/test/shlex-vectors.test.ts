/**
 * The same Shlex cases the Rust core and the Python SDK run.
 * Evaluation goes through the WASM core, so a stale wasm build fails here.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkShlex, createTenuo, shlex } from "../src/index.ts";

interface ShlexCase {
  name: string;
  allow: string[];
  command: string;
  matches: boolean;
}

const here = dirname(fileURLToPath(import.meta.url));
const suite = JSON.parse(
  readFileSync(resolve(here, "../../../../tests/vectors/shlex.json"), "utf8"),
) as { cases: ShlexCase[] };

describe("shlex shared vectors", () => {
  it("matches tests/vectors/shlex.json", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    for (const case_ of suite.cases) {
      const tool = tenuo.tool(
        { execute: async (args: Record<string, unknown>) => args },
        { capability: "run", allow: {} },
      );
      const session = tenuo.session({ allow: { run: { cmd: shlex(case_.allow) } } });
      const call = tool.execute({ cmd: case_.command }, { session });
      if (case_.matches) {
        await expect(call, case_.name).resolves.toEqual({ cmd: case_.command });
      } else {
        await expect(call, case_.name).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" });
      }
    }
  });

  it("reports the shell decision from the core", () => {
    const hidden = checkShlex(["ls"], "ls foo#; rm -rf /");
    expect(hidden.allowed).toBe(false);
    expect(hidden.reason).toBe("operator ';'");
    expect(hidden.tokens).toEqual(["ls", "foo#", ";", "rm", "-rf", "/"]);

    const comma = checkShlex(["ls"], "./ls,evil -la");
    expect(comma.allowed).toBe(false);
    expect(comma.binary_allowed).toBe(false);
    expect(comma.tokens).toEqual(["./ls,evil", "-la"]);

    const literal = checkShlex(["echo"], 'echo ";"');
    expect(literal.allowed).toBe(true);
    expect(literal.tokens).toEqual(["echo", ";"]);
  });
});
