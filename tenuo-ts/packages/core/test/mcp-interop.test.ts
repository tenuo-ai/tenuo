import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createTenuo, TenuoError, under } from "../src/index.ts";
import { exportSession } from "../src/testkit.ts";

const script = join(dirname(fileURLToPath(import.meta.url)), "interop", "mint_session.py");

type WireSession = {
  warrant: string;
  warrants: string[];
  root_hex: string;
  holder_hex: string;
};

type McpCall = {
  name: string;
  arguments: Record<string, unknown>;
  _meta: { tenuo: { warrant: string; signature: string } };
};

type PythonVerify = {
  allowed: boolean;
  reason?: string | null;
  code?: number | null;
};

function python(): string | undefined {
  for (const bin of ["python3", "python"]) {
    const probe = spawnSync(bin, ["-c", "from tenuo.mcp.server import MCPVerifier"], {
      encoding: "utf8",
    });
    if (probe.status === 0) {
      return bin;
    }
  }
  return undefined;
}

function runPython<T>(bin: string, command: string, stdin: unknown): T {
  const result = spawnSync(bin, [script, command], {
    encoding: "utf8",
    input: JSON.stringify(stdin),
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || `python exited ${result.status}`);
  }
  return JSON.parse(result.stdout) as T;
}

const pythonBin = python();

describe.skipIf(pythonBin === undefined)("Python ↔ TypeScript MCP wire", () => {
  it("verifies a Python-attached envelope in TypeScript", async () => {
    const minted = runPython<WireSession>(pythonBin!, "mint", {
      allow: { read_file: { path: { kind: "under", root: "/data" } } },
    });
    const call = runPython<McpCall>(pythonBin!, "mcp_attach", {
      warrants: minted.warrants,
      holder_hex: minted.holder_hex,
      tool: "read_file",
      args: { path: "/data/q3.pdf" },
    });
    const server = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(minted.root_hex)],
    });
    await expect(server.mcp.verify(call.name, call.arguments, call._meta)).resolves.toMatchObject({
      path: "/data/q3.pdf",
    });
    await expect(server.mcp.verify(call.name, { path: "/etc/passwd" }, call._meta)).rejects.toThrow(TenuoError);
  });

  it("verifies a TypeScript-attached envelope in Python", () => {
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const session = issuer.session({
      allow: { read_file: { path: under("/data") } },
    });
    const leaked = exportSession(session);
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    const allowed = runPython<PythonVerify>(pythonBin!, "mcp_verify", {
      root_hex: leaked.root_hex,
      tool: call.name,
      args: call.arguments,
      meta: call._meta,
    });
    expect(allowed).toMatchObject({ allowed: true });

    const denied = runPython<PythonVerify>(pythonBin!, "mcp_verify", {
      root_hex: leaked.root_hex,
      tool: call.name,
      args: { path: "/etc/passwd" },
      meta: call._meta,
    });
    expect(denied.allowed).toBe(false);
  });

  it("round-trips a TypeScript-narrowed chain through Python MCPVerifier", () => {
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const parent = issuer.session({
      allow: { read_file: { path: under("/data") } },
    });
    const reports = issuer.narrow(parent, { path: under("/data/reports") });
    const leaked = exportSession(reports);
    expect(leaked.warrants).toHaveLength(2);
    const call = issuer.mcp.attach(reports, "read_file", { path: "/data/reports/q3.pdf" });
    const allowed = runPython<PythonVerify>(pythonBin!, "mcp_verify", {
      root_hex: leaked.root_hex,
      tool: call.name,
      args: call.arguments,
      meta: call._meta,
    });
    expect(allowed).toMatchObject({ allowed: true });
  });
});
