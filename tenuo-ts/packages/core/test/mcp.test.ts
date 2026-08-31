import { describe, expect, it } from "vitest";
import {
  ApprovalRequiredError,
  AuthorizationDeniedError,
  createTenuo,
  memoryNonceStore,
  TenuoConfigurationError,
  TenuoError,
  under,
} from "../src/index.ts";
import {
  devContext,
  exportSession,
  signApproval,
  signRevocationList,
  verifyReceipt,
  warrantIds,
  wrapSession,
} from "../src/testkit.ts";
import { APPROVER1_PUB, APPROVER1_SECRET, APPROVER2_PUB, APPROVER2_SECRET } from "./vectors/spec.ts";

function issuerAndServer() {
  const issuer = createTenuo({ root: createTenuo.devRoot() });
  const session = issuer.session({
    allow: { read_file: { path: under("/data") } },
  });
  const leaked = exportSession(session);
  const server = createTenuo({
    trustedRoots: [createTenuo.publicKeyFromHex(leaked.root_hex)],
  });
  return { issuer, session, leaked, server };
}

function flipWire(value: string): string {
  const last = value[value.length - 1] === "A" ? "B" : "A";
  return `${value.slice(0, -1)}${last}`;
}

describe("tenuo.mcp", () => {
  it("attaches a warrant and lets a second process verify before execute", async () => {
    const { issuer, session, server } = issuerAndServer();
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    expect(call.name).toBe("read_file");
    expect(call._meta.tenuo.warrant.length).toBeGreaterThan(0);
    expect(call._meta.tenuo.signature.length).toBeGreaterThan(0);

    let executed: string | undefined;
    const readFile = server.mcp.handler("read_file", async ({ path }: { path: string }) => {
      executed = path;
      return `ok:${path}`;
    });
    await expect(readFile(call.arguments as { path: string }, { _meta: call._meta })).resolves.toBe(
      "ok:/data/q3.pdf",
    );
    expect(executed).toBe("/data/q3.pdf");
  });

  it("denies a path outside the warrant and never runs the handler", async () => {
    const { issuer, session, server } = issuerAndServer();
    expect(() => issuer.mcp.attach(session, "read_file", { path: "/etc/passwd" })).toThrow(
      AuthorizationDeniedError,
    );

    const allowed = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    const forged = { ...allowed, arguments: { path: "/etc/passwd" } };
    let executed = false;
    const readFile = server.mcp.handler("read_file", async () => {
      executed = true;
      return "leaked";
    });
    await expect(readFile(forged.arguments, { _meta: forged._meta })).rejects.toMatchObject({
      code: "TENUO_INVALID_POP",
    });
    expect(executed).toBe(false);
  });

  it("rejects a handler policy typo instead of asking for execute", () => {
    const { server } = issuerAndServer();
    expect(() =>
      server.mcp.handler("read_file", { allowed: { path: under("/data") } } as never, async () => ""),
    ).toThrow(/unknown key 'allowed'/);
  });

  it("rejects an exact replayed PoP when a nonceStore is set", async () => {
    const { issuer, session, server } = issuerAndServer();
    const store = memoryNonceStore();
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    await expect(server.mcp.verify(call.name, call.arguments, call._meta, { nonceStore: store })).resolves.toEqual({
      path: "/data/q3.pdf",
    });
    await expect(server.mcp.verify(call.name, call.arguments, call._meta, { nonceStore: store })).rejects.toMatchObject({
      code: "TENUO_INVALID_POP",
      message: expect.stringMatching(/replay/),
    });
    const other = issuer.mcp.attach(session, "read_file", { path: "/data/other.txt" });
    await expect(server.mcp.verify(other.name, other.arguments, other._meta, { nonceStore: store })).resolves.toEqual({
      path: "/data/other.txt",
    });
  });

  it("awaits an async nonceStore and fails closed when it rejects", async () => {
    const { issuer, session, server } = issuerAndServer();
    const seen = new Set<string>();
    const store = {
      async checkAndRecord(popSignature: string) {
        if (seen.has(popSignature)) {
          return false;
        }
        seen.add(popSignature);
        return true;
      },
    };
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    await expect(server.mcp.verify(call.name, call.arguments, call._meta, { nonceStore: store })).resolves.toEqual({
      path: "/data/q3.pdf",
    });
    await expect(server.mcp.verify(call.name, call.arguments, call._meta, { nonceStore: store })).rejects.toMatchObject({
      code: "TENUO_INVALID_POP",
    });
    const seenErrors: unknown[] = [];
    const broken = {
      async checkAndRecord() {
        throw new Error("redis://user:secret@host/0");
      },
    };
    const other = issuer.mcp.attach(session, "read_file", { path: "/data/other.txt" });
    await expect(
      server.mcp.verify(other.name, other.arguments, other._meta, {
        nonceStore: broken,
        onNonceStoreError: (error) => {
          seenErrors.push(error);
        },
      }),
    ).rejects.toMatchObject({
      message: "Replay store unavailable",
      cause: expect.objectContaining({ message: "redis://user:secret@host/0" }),
    });
    expect(seenErrors).toEqual([expect.objectContaining({ message: "redis://user:secret@host/0" })]);
  });

  it("rejects a mixed option typo instead of ignoring it", () => {
    const { server } = issuerAndServer();
    expect(() =>
      server.mcp.handler(
        "read_file",
        { allow: { path: under("/data") }, nonceStroe: memoryNonceStore() } as never,
        async () => "",
      ),
    ).toThrow(/unknown key 'nonceStroe'/);
  });

  it("fails closed without _meta.tenuo", async () => {
    const server = createTenuo({
      trustedRoots: [
        createTenuo.publicKeyFromHex("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"),
      ],
    });
    await expect(server.mcp.verify("read_file", { path: "/data/q3.pdf" }, {})).rejects.toThrow(
      TenuoConfigurationError,
    );
    expect(server.mcp.jsonRpcError(new TenuoConfigurationError("missing"))).toMatchObject({
      code: -32001,
    });
  });

  it("maps denial, approval-required, and canonicalization onto JSON-RPC codes", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    expect(tenuo.mcp.jsonRpcError(new ApprovalRequiredError("transfer", 2, 0))).toMatchObject({
      code: -32002,
      data: { tenuo: { code: "TENUO_APPROVAL_REQUIRED" } },
    });
    expect(
      tenuo.mcp.jsonRpcError(new AuthorizationDeniedError("TENUO_INVALID_POP", "bad pop")),
    ).toMatchObject({
      code: -32001,
      data: { tenuo: { code: "TENUO_INVALID_POP" } },
    });
    expect(
      tenuo.mcp.jsonRpcError(new TenuoError("TENUO_CANONICALIZATION", "not a constraint value")),
    ).toMatchObject({
      code: -32602,
      data: { tenuo: { code: "TENUO_CANONICALIZATION" } },
    });
  });

  it("rejects the wrong tool name on a valid envelope", async () => {
    const { issuer, session, server } = issuerAndServer();
    expect(() => issuer.mcp.attach(session, "write_file", { path: "/data/q3.pdf" })).toThrow(
      AuthorizationDeniedError,
    );
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    await expect(server.mcp.verify("write_file", call.arguments, call._meta)).rejects.toThrow(TenuoError);
  });

  it("rejects a tampered warrant or signature", async () => {
    const { issuer, session, server } = issuerAndServer();
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    await expect(
      server.mcp.verify(call.name, call.arguments, {
        tenuo: { warrant: flipWire(call._meta.tenuo.warrant), signature: call._meta.tenuo.signature },
      }),
    ).rejects.toThrow(TenuoError);
    await expect(
      server.mcp.verify(call.name, call.arguments, {
        tenuo: { warrant: call._meta.tenuo.warrant, signature: flipWire(call._meta.tenuo.signature) },
      }),
    ).rejects.toThrow(TenuoError);
  });

  it("verifies a narrowed chain from another process", async () => {
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const parent = issuer.session({
      allow: { read_file: { path: under("/data") } },
    });
    const reports = issuer.narrow(parent, { path: under("/data/reports") });
    const leaked = exportSession(reports);
    expect(leaked.warrants).toHaveLength(2);
    const server = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(leaked.root_hex)],
    });

    const inside = issuer.mcp.attach(reports, "read_file", { path: "/data/reports/q3.pdf" });
    await expect(server.mcp.verify(inside.name, inside.arguments, inside._meta)).resolves.toMatchObject({
      path: "/data/reports/q3.pdf",
    });
    expect(() => issuer.mcp.attach(reports, "read_file", { path: "/data/other.txt" })).toThrow(
      AuthorizationDeniedError,
    );
    const parentCall = issuer.mcp.attach(parent, "read_file", { path: "/data/other.txt" });
    await expect(server.mcp.verify(parentCall.name, parentCall.arguments, parentCall._meta)).resolves.toMatchObject({
      path: "/data/other.txt",
    });
  });

  it("denies a revoked warrant on verify", async () => {
    const ctx = devContext();
    const session = wrapSession(
      ctx.mint({ read_file: { path: { kind: "under", root: "/data" } } }, 300),
    );
    const leaked = exportSession(session);
    const leafId = warrantIds(session)[0];
    if (leafId === undefined) {
      throw new Error("expected a warrant id");
    }
    const srl = signRevocationList(ctx, [leafId]);
    const client = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(leaked.root_hex)],
    });
    const imported = client.sessionFromWire({
      warrant: leaked.warrants,
      holderKey: createTenuo.holderKeyFromHex(leaked.holder_hex),
    });
    const call = client.mcp.attach(imported, "read_file", { path: "/data/q3.pdf" });
    const server = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(leaked.root_hex)],
      revocationList: srl,
    });
    await expect(server.mcp.verify(call.name, call.arguments, call._meta)).rejects.toMatchObject({
      code: "TENUO_REVOKED",
    });
  });

  it("attaches signed approvals so a gated tool verifies on the server", async () => {
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const session = issuer.session({
      allow: { read_file: { path: under("/data") } },
      requireApproval: {
        approvers: [
          createTenuo.publicKeyFromHex(APPROVER1_PUB),
          createTenuo.publicKeyFromHex(APPROVER2_PUB),
        ],
        min: 2,
      },
    });
    const args = { path: "/data/q3.pdf" };
    expect(() => issuer.mcp.attach(session, "read_file", args)).toThrow(ApprovalRequiredError);

    const one = signApproval(session, "read_file", args, APPROVER1_SECRET);
    expect(() => issuer.mcp.attach(session, "read_file", args, { approvals: [one] })).toThrow(
      AuthorizationDeniedError,
    );

    const two = signApproval(session, "read_file", args, APPROVER2_SECRET);
    const call = issuer.mcp.attach(session, "read_file", args, { approvals: [one, two] });
    expect(call._meta.tenuo.approvals).toHaveLength(2);

    const leaked = exportSession(session);
    const server = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(leaked.root_hex)],
    });
    const readFile = server.mcp.handler("read_file", async ({ path }: { path: string }) => path);
    await expect(readFile(call.arguments as { path: string }, { _meta: call._meta })).resolves.toBe(
      "/data/q3.pdf",
    );
  });

  it("emits receipts on attach and verify without treating them as allow", async () => {
    const { issuer, session, server } = issuerAndServer();
    const attached: string[] = [];
    const verified: string[] = [];
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" }, {
      onReceipt: (receipt) => { attached.push(receipt); },
    });
    await server.mcp.verify(call.name, call.arguments, call._meta, {
      onReceipt: (receipt) => { verified.push(receipt); },
    });
    expect(attached).toHaveLength(1);
    expect(verified).toHaveLength(1);
    expect(verifyReceipt(attached[0]!)).toMatchObject({ authentic: true, outcome: "allow" });
    expect(verifyReceipt(verified[0]!)).toMatchObject({ authentic: true, outcome: "allow" });
  });

  it("forwards handler onReceipt to verify", async () => {
    const { issuer, session, server } = issuerAndServer();
    const receipts: string[] = [];
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    const readFile = server.mcp.handler(
      "read_file",
      { onReceipt: (receipt) => { receipts.push(receipt); } },
      async ({ path }: { path: string }) => path,
    );
    await expect(readFile(call.arguments as { path: string }, { _meta: call._meta })).resolves.toBe(
      "/data/q3.pdf",
    );
    expect(receipts).toHaveLength(1);
    expect(verifyReceipt(receipts[0]!)).toMatchObject({ authentic: true, outcome: "allow" });
  });

  it("reads _meta from extra.meta (MCP 1.x) as well as extra._meta", async () => {
    const { issuer, session, server } = issuerAndServer();
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    const readFile = server.mcp.handler("read_file", async ({ path }: { path: string }) => path);
    await expect(readFile(call.arguments as { path: string }, { meta: call._meta })).resolves.toBe(
      "/data/q3.pdf",
    );
  });

  it("ANDs a handler allow ceiling with a broader presented warrant", async () => {
    const { issuer, session, server } = issuerAndServer();
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/other.txt" });
    let executed = false;
    const readFile = server.mcp.handler(
      "read_file",
      { allow: { path: under("/data/reports") } },
      async ({ path }: { path: string }) => {
        executed = true;
        return path;
      },
    );
    await expect(readFile(call.arguments as { path: string }, { _meta: call._meta })).rejects.toMatchObject({
      code: "TENUO_CONSTRAINT_VIOLATION",
    });
    expect(executed).toBe(false);

    const inside = issuer.mcp.attach(session, "read_file", { path: "/data/reports/q3.pdf" });
    await expect(readFile(inside.arguments as { path: string }, { _meta: inside._meta })).resolves.toBe(
      "/data/reports/q3.pdf",
    );
    expect(executed).toBe(true);
  });

  it("ANDs verify() allow with a broader presented warrant", async () => {
    const { issuer, session, server } = issuerAndServer();
    const outside = issuer.mcp.attach(session, "read_file", { path: "/data/other.txt" });
    await expect(
      server.mcp.verify(outside.name, outside.arguments, outside._meta, {
        allow: { path: under("/data/reports") },
      }),
    ).rejects.toThrow(AuthorizationDeniedError);
    const inside = issuer.mcp.attach(session, "read_file", { path: "/data/reports/q3.pdf" });
    await expect(
      server.mcp.verify(inside.name, inside.arguments, inside._meta, {
        allow: { path: under("/data/reports") },
      }),
    ).resolves.toEqual({ path: "/data/reports/q3.pdf" });
  });

  it("isolates a throwing onReceipt from authorize and execute", async () => {
    const { issuer, session, server } = issuerAndServer();
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/q3.pdf" }, {
      onReceipt: () => {
        throw new Error("receipt hook exploded");
      },
    });
    expect(call.name).toBe("read_file");
    await expect(
      server.mcp.verify(call.name, call.arguments, call._meta, {
        onReceipt: () => {
          throw new Error("verify receipt hook exploded");
        },
      }),
    ).resolves.toEqual({ path: "/data/q3.pdf" });
  });

  it("treats an empty handler allow as no extra ceiling", async () => {
    const { issuer, session, server } = issuerAndServer();
    const call = issuer.mcp.attach(session, "read_file", { path: "/data/other.txt" });
    const readFile = server.mcp.handler("read_file", { allow: {} }, async ({ path }: { path: string }) => path);
    await expect(readFile(call.arguments as { path: string }, { _meta: call._meta })).resolves.toBe(
      "/data/other.txt",
    );
  });

  it("drops optional null args so attach and verify stay aligned", async () => {
    const { issuer, session, server } = issuerAndServer();
    const call = issuer.mcp.attach(session, "read_file", {
      path: "/data/q3.pdf",
      max_size: null,
    });
    expect(call.arguments).toEqual({ path: "/data/q3.pdf" });
    const readFile = server.mcp.handler("read_file", async (args: { path: string }) => args);
    await expect(
      readFile({ path: "/data/q3.pdf", max_size: null } as { path: string }, { _meta: call._meta }),
    ).resolves.toMatchObject({ path: "/data/q3.pdf" });
  });
});
