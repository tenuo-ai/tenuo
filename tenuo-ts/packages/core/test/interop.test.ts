import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createTenuo, max, oneOf, pattern, under } from "../src/index.ts";
import type { AllowPolicy, Session, Tenuo } from "../src/index.ts";
import { exportSession } from "../src/testkit.ts";

const script = join(dirname(fileURLToPath(import.meta.url)), "interop", "mint_session.py");
const CONTROL_PLANE_PUB = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

type WireSession = {
  warrant: string;
  warrants: string[];
  root_hex: string;
  holder_hex: string;
};

type PythonVerdict = {
  ok: boolean;
  error?: string;
  message?: string;
};

type AllowMap = {
  readonly [capability: string]: AllowPolicy;
};

function python(): string | undefined {
  for (const bin of ["python3", "python"]) {
    const probe = spawnSync(bin, ["-c", "import tenuo"], { encoding: "utf8" });
    if (probe.status === 0) {
      return bin;
    }
  }
  return undefined;
}

function runPython<T>(bin: string, args: string[], stdin?: string): T {
  const result = spawnSync(bin, [script, ...args], {
    encoding: "utf8",
    input: stdin,
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || `python exited ${result.status}`);
  }
  return JSON.parse(result.stdout) as T;
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function mintPython(bin: string, spec?: { allow?: AllowMap; narrow?: AllowPolicy | AllowMap }): WireSession {
  return runPython<WireSession>(bin, ["mint"], spec === undefined ? undefined : JSON.stringify(spec));
}

function verifyPython(
  bin: string,
  session: Pick<WireSession, "warrants" | "holder_hex" | "root_hex">,
  tool: string,
  args: Record<string, unknown>,
): PythonVerdict {
  return runPython<PythonVerdict>(
    bin,
    ["verify"],
    JSON.stringify({
      warrants: session.warrants,
      holder_hex: session.holder_hex,
      root_hex: session.root_hex,
      tool,
      args,
    }),
  );
}

function importPythonSession(tenuo: Tenuo, minted: WireSession): Session {
  return tenuo.sessionFromWire({
    warrant: minted.warrants.length > 1 ? minted.warrants : minted.warrant,
    holderKey: fromHex(minted.holder_hex),
  });
}

async function tsCall(
  tenuo: Tenuo,
  session: Session,
  capability: string,
  allow: AllowPolicy,
  args: Record<string, unknown>,
): Promise<{ ok: true; value: unknown } | { ok: false; code: string }> {
  let executed = false;
  const tool = tenuo.tool(
    {
      execute: async (input: Record<string, unknown>) => {
        executed = true;
        return input;
      },
    },
    { capability, allow },
  );
  try {
    const value = await tenuo.withSession(session, () => tool.execute(args as never));
    expect(executed).toBe(true);
    return { ok: true, value };
  } catch (error) {
    expect(executed).toBe(false);
    return { ok: false, code: (error as { code: string }).code };
  }
}

function expectAgree(
  ts: { ok: boolean; code?: string },
  py: PythonVerdict,
  expected: "allow" | "deny",
  code?: string,
) {
  if (expected === "allow") {
    expect(ts).toMatchObject({ ok: true });
    expect(py).toEqual({ ok: true });
    return;
  }
  expect(ts.ok).toBe(false);
  expect(py.ok).toBe(false);
  if (code !== undefined) {
    expect(ts.code).toBe(code);
  }
}

const pythonBin = python();

describe.skipIf(pythonBin === undefined)("Python ↔ TypeScript compatibility", () => {
  describe("Python mints, TypeScript imports", () => {
    it("agrees on Subpath allow and deny", async () => {
      const minted = mintPython(pythonBin!);
      expect(minted.root_hex).toBe(CONTROL_PLANE_PUB);
      const tenuo = createTenuo({
        trustedRoots: [createTenuo.publicKeyFromHex(minted.root_hex)],
      });
      const session = importPythonSession(tenuo, minted);
      const allow = { path: under("/data") };

      expectAgree(
        await tsCall(tenuo, session, "read_file", allow, { path: "/data/q3.pdf" }),
        verifyPython(pythonBin!, minted, "read_file", { path: "/data/q3.pdf" }),
        "allow",
      );
      expectAgree(
        await tsCall(tenuo, session, "read_file", allow, { path: "/etc/passwd" }),
        verifyPython(pythonBin!, minted, "read_file", { path: "/etc/passwd" }),
        "deny",
        "TENUO_CONSTRAINT_VIOLATION",
      );
    });

    it("agrees on Pattern and Range and rejects the wrong tool", async () => {
      const minted = mintPython(pythonBin!, {
        allow: {
          search: { q: { kind: "pattern", pattern: "report*" } },
          query: { limit: { kind: "max", value: 10 } },
        },
      });
      const tenuo = createTenuo({
        trustedRoots: [createTenuo.publicKeyFromHex(minted.root_hex)],
      });
      const session = importPythonSession(tenuo, minted);

      expectAgree(
        await tsCall(tenuo, session, "search", { q: pattern("report*") }, { q: "report-q3" }),
        verifyPython(pythonBin!, minted, "search", { q: "report-q3" }),
        "allow",
      );
      expectAgree(
        await tsCall(tenuo, session, "search", { q: pattern("report*") }, { q: "secret" }),
        verifyPython(pythonBin!, minted, "search", { q: "secret" }),
        "deny",
        "TENUO_CONSTRAINT_VIOLATION",
      );
      expectAgree(
        await tsCall(tenuo, session, "query", { limit: max(10) }, { limit: 3 }),
        verifyPython(pythonBin!, minted, "query", { limit: 3 }),
        "allow",
      );
      expectAgree(
        await tsCall(tenuo, session, "query", { limit: max(10) }, { limit: 50 }),
        verifyPython(pythonBin!, minted, "query", { limit: 50 }),
        "deny",
        "TENUO_CONSTRAINT_VIOLATION",
      );
      expectAgree(
        await tsCall(tenuo, session, "write_file", { path: under("/data") }, { path: "/data/q3.pdf" }),
        verifyPython(pythonBin!, minted, "write_file", { path: "/data/q3.pdf" }),
        "deny",
        "TENUO_TOOL_NOT_AUTHORIZED",
      );
    });

    it("imports a Python-attenuated chain and both runtimes stay on the leaf", async () => {
      const minted = mintPython(pythonBin!, {
        allow: { read_file: { path: { kind: "under", root: "/data" } } },
        narrow: { path: { kind: "under", root: "/data/reports" } },
      });
      expect(minted.warrants).toHaveLength(2);
      const tenuo = createTenuo({
        trustedRoots: [createTenuo.publicKeyFromHex(minted.root_hex)],
      });
      const session = importPythonSession(tenuo, minted);
      const allow = { path: under("/data") };

      expectAgree(
        await tsCall(tenuo, session, "read_file", allow, { path: "/data/reports/q3.pdf" }),
        verifyPython(pythonBin!, minted, "read_file", { path: "/data/reports/q3.pdf" }),
        "allow",
      );
      expectAgree(
        await tsCall(tenuo, session, "read_file", allow, { path: "/data/other.txt" }),
        verifyPython(pythonBin!, minted, "read_file", { path: "/data/other.txt" }),
        "deny",
        "TENUO_CONSTRAINT_VIOLATION",
      );
    });
  });

  describe("TypeScript mints, Python verifies", () => {
    it("agrees on Subpath allow and deny", async () => {
      const tenuo = createTenuo({ root: createTenuo.devRoot() });
      const allow = { path: under("/data") };
      const session = tenuo.session({ allow: { read_file: allow } });
      const exported = exportSession(session);

      expectAgree(
        await tsCall(tenuo, session, "read_file", allow, { path: "/data/q3.pdf" }),
        verifyPython(pythonBin!, exported, "read_file", { path: "/data/q3.pdf" }),
        "allow",
      );
      expectAgree(
        await tsCall(tenuo, session, "read_file", allow, { path: "/etc/passwd" }),
        verifyPython(pythonBin!, exported, "read_file", { path: "/etc/passwd" }),
        "deny",
        "TENUO_CONSTRAINT_VIOLATION",
      );
    });

    it("agrees on OneOf and a TypeScript-narrowed chain", async () => {
      const tenuo = createTenuo({ root: createTenuo.devRoot() });
      const parent = tenuo.session({
        allow: {
          send_email: { to: oneOf(["ops@acme.com", "sec@acme.com"]) },
          read_file: { path: under("/data") },
        },
      });
      const reports = tenuo.narrow(parent, { read_file: { path: under("/data/reports") } });
      const exportedParent = exportSession(parent);
      const exportedLeaf = exportSession(reports);
      expect(exportedLeaf.warrants).toHaveLength(2);
      expect(exportedLeaf.root_hex).toBe(exportedParent.root_hex);

      expectAgree(
        await tsCall(tenuo, parent, "send_email", { to: oneOf(["ops@acme.com", "sec@acme.com"]) }, {
          to: "ops@acme.com",
        }),
        verifyPython(pythonBin!, exportedParent, "send_email", { to: "ops@acme.com" }),
        "allow",
      );
      expectAgree(
        await tsCall(tenuo, parent, "send_email", { to: oneOf(["ops@acme.com", "sec@acme.com"]) }, {
          to: "attacker@evil.test",
        }),
        verifyPython(pythonBin!, exportedParent, "send_email", { to: "attacker@evil.test" }),
        "deny",
        "TENUO_CONSTRAINT_VIOLATION",
      );
      expectAgree(
        await tsCall(tenuo, reports, "read_file", { path: under("/data") }, { path: "/data/reports/q3.pdf" }),
        verifyPython(pythonBin!, exportedLeaf, "read_file", { path: "/data/reports/q3.pdf" }),
        "allow",
      );
      expectAgree(
        await tsCall(tenuo, reports, "read_file", { path: under("/data") }, { path: "/data/other.txt" }),
        verifyPython(pythonBin!, exportedLeaf, "read_file", { path: "/data/other.txt" }),
        "deny",
        "TENUO_CONSTRAINT_VIOLATION",
      );
    });
  });

  describe("both runtimes write the chain", () => {
    it("Python mints, TypeScript narrows, Python verifies the leaf", async () => {
      const minted = mintPython(pythonBin!, {
        allow: { read_file: { path: { kind: "under", root: "/data" } } },
      });
      const tenuo = createTenuo({
        trustedRoots: [createTenuo.publicKeyFromHex(minted.root_hex)],
      });
      const parent = importPythonSession(tenuo, minted);
      const reports = tenuo.narrow(parent, { path: under("/data/reports") });
      const exported = exportSession(reports);
      expect(exported.warrants).toHaveLength(2);
      expect(exported.root_hex).toBe(minted.root_hex);

      expectAgree(
        await tsCall(tenuo, reports, "read_file", { path: under("/data") }, { path: "/data/reports/q3.pdf" }),
        verifyPython(pythonBin!, exported, "read_file", { path: "/data/reports/q3.pdf" }),
        "allow",
      );
      expectAgree(
        await tsCall(tenuo, reports, "read_file", { path: under("/data") }, { path: "/data/other.txt" }),
        verifyPython(pythonBin!, exported, "read_file", { path: "/data/other.txt" }),
        "deny",
        "TENUO_CONSTRAINT_VIOLATION",
      );
      expectAgree(
        await tsCall(tenuo, parent, "read_file", { path: under("/data") }, { path: "/data/other.txt" }),
        verifyPython(pythonBin!, minted, "read_file", { path: "/data/other.txt" }),
        "allow",
      );
    });
  });
});
