import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { createTenuo, under } from "../src/index.ts";
import type { Session, Tenuo } from "../src/index.ts";
import { exportSession } from "../src/testkit.ts";

const script = join(dirname(fileURLToPath(import.meta.url)), "interop", "mint_session.py");
const seed = Number.parseInt(process.env.FC_SEED ?? "20260906", 10);
const numRuns = Number.parseInt(process.env.FC_RUNS ?? "40", 10);

type WireSession = {
  warrant: string;
  warrants: string[];
  root_hex: string;
  holder_hex: string;
};

function python(): string | undefined {
  return ["python3", "python"].find(
    (bin) => spawnSync(bin, ["-c", "import tenuo"], { encoding: "utf8" }).status === 0,
  );
}

function runPython<T>(bin: string, command: string, value: unknown): T {
  const result = spawnSync(bin, [script, command], {
    encoding: "utf8",
    input: JSON.stringify(value),
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || `python exited ${result.status}`);
  }
  return JSON.parse(result.stdout) as T;
}

function fromHex(hex: string): Uint8Array {
  return Uint8Array.from({ length: hex.length / 2 }, (_, index) =>
    Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16),
  );
}

async function authorize(
  tenuo: Tenuo,
  session: Session,
  tool: string,
  path: string,
): Promise<boolean> {
  let executed = false;
  const protectedTool = tenuo.tool(
    {
      execute: async () => {
        executed = true;
        return "ok";
      },
    },
    { capability: tool, allow: { path: under("/workspace") } },
  );
  try {
    await tenuo.withSession(session, () => protectedTool.execute({ path } as never));
    expect(executed).toBe(true);
    return true;
  } catch {
    expect(executed).toBe(false);
    return false;
  }
}

function pythonVerdict(bin: string, session: WireSession, tool: string, path: string): boolean {
  return runPython<{ ok: boolean }>(bin, "verify", {
    ...session,
    tool,
    args: { path },
  }).ok;
}

const segment = fc.stringMatching(/^[a-z][a-z0-9]{0,7}$/);
const delegationCase = fc
  .array(segment, { minLength: 0, maxLength: 5 })
  .chain((segments) => {
    const roots = segments.map((_, index) => `/workspace/${segments.slice(0, index + 1).join("/")}`);
    const leaf = roots.at(-1) ?? "/workspace";
    return fc.record({
      roots: fc.constant(roots),
      tool: fc.constantFrom("read_file", "write_file"),
      allowedPath: fc.boolean(),
      suffix: segment,
      leaf: fc.constant(leaf),
    });
  });

const pythonBin = python();

describe.skipIf(pythonBin === undefined)("randomized Rust/Python/TypeScript differential security", () => {
  it("keeps randomized delegated path chains fail-closed across runtimes", async () => {
    await fc.assert(
      fc.asyncProperty(delegationCase, async ({ roots, tool, allowedPath, suffix, leaf }) => {
        const path = allowedPath ? `${leaf}/${suffix}` : `/outside/${suffix}`;
        const spec = {
          allow: { read_file: { path: { kind: "under", root: "/workspace" } } },
          narrows: roots.map((root) => ({ path: { kind: "under", root } })),
        };

        const minted = runPython<WireSession>(pythonBin!, "mint", spec);
        const verifier = createTenuo({
          trustedRoots: [createTenuo.publicKeyFromHex(minted.root_hex)],
        });
        const imported = verifier.sessionFromWire({
          warrant: minted.warrants,
          holderKey: fromHex(minted.holder_hex),
        });
        const expected = tool === "read_file" && allowedPath;
        expect(await authorize(verifier, imported, tool, path)).toBe(expected);
        expect(pythonVerdict(pythonBin!, minted, tool, path)).toBe(expected);

        const issuer = createTenuo({ root: createTenuo.devRoot() });
        let tsSession = issuer.session({
          allow: { read_file: { path: under("/workspace") } },
        });
        for (const root of roots) {
          tsSession = issuer.narrow(tsSession, { path: under(root) });
        }
        const exported = exportSession(tsSession);
        expect(pythonVerdict(pythonBin!, { ...exported, warrant: exported.warrants.at(-1)! }, tool, path)).toBe(
          expected,
        );
      }),
      { seed, numRuns, verbose: true },
    );
  }, 180_000);
});
