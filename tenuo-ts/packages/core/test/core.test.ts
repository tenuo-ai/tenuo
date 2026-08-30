import { describe, expect, it } from "vitest";
import {
  ApprovalRequiredError,
  AuthorizationDeniedError,
  createTenuo,
  email,
  max,
  oneOf,
  pattern,
  TenuoConfigurationError,
  TenuoError,
  under,
} from "../src/index.ts";
import type { ToolLike } from "../src/index.ts";
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

describe("createTenuo", () => {
  it("rejects an empty trust set", () => {
    expect(() => createTenuo({})).toThrow(TenuoConfigurationError);
    expect(() => createTenuo({})).toThrow(/trustedRoots/);
  });

  it("ready() succeeds once WASM is built", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    expect(() => tenuo.ready()).not.toThrow();
  });

  it("cannot mint a session without a local issuer", () => {
    const tenuo = createTenuo({
      trustedRoots: [
        createTenuo.publicKeyFromHex(
          "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
        ),
      ],
    });
    expect(() => tenuo.session({ allow: { read_file: { path: under("/data") } } })).toThrow(
      /local issuer/,
    );
  });

  it("fails closed when publicKeyFromEnv is missing", () => {
    const previous = process.env.TENUO_MISSING_ROOT;
    delete process.env.TENUO_MISSING_ROOT;
    expect(() => createTenuo.publicKeyFromEnv("TENUO_MISSING_ROOT")).toThrow(/not set or empty/);
    if (previous !== undefined) {
      process.env.TENUO_MISSING_ROOT = previous;
    }
  });

  it("fails closed when holderKeyFromEnv is missing", () => {
    const previous = process.env.TENUO_MISSING_HOLDER;
    delete process.env.TENUO_MISSING_HOLDER;
    expect(() => createTenuo.holderKeyFromEnv("TENUO_MISSING_HOLDER")).toThrow(/not set or empty/);
    if (previous !== undefined) {
      process.env.TENUO_MISSING_HOLDER = previous;
    }
  });

  it("reads a holder secret from the environment at call time", () => {
    process.env.TENUO_TEST_HOLDER = "02".repeat(32);
    expect(createTenuo.holderKeyFromEnv("TENUO_TEST_HOLDER")).toEqual(
      createTenuo.holderKeyFromHex("02".repeat(32)),
    );
    delete process.env.TENUO_TEST_HOLDER;
  });

  it("refuses a tool with an empty allow policy", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const inner: ToolLike<{ path: string }, string> = {
      execute: async ({ path }) => path,
    };
    expect(() => tenuo.tool(inner, { allow: {} })).toThrow(/non-empty allow policy/);
  });
});

describe("constraints", () => {
  it("builds marker objects for the WASM mapping", () => {
    expect(under("/data")).toEqual({ kind: "under", root: "/data" });
    expect(email({ domain: "acme.com" })).toEqual({ kind: "email", domain: "acme.com" });
    expect(max(500)).toEqual({ kind: "max", value: 500 });
    expect(oneOf(["a", "b"])).toEqual({ kind: "oneOf", values: ["a", "b"] });
    expect(pattern("*@acme.com")).toEqual({ kind: "pattern", pattern: "*@acme.com" });
  });

  it("rejects relative under() roots", () => {
    expect(() => under("data")).toThrow(/absolute path/);
  });
});

describe("errors", () => {
  it("keeps a stable instanceof hierarchy", () => {
    const denied = new AuthorizationDeniedError(
      "TENUO_CONSTRAINT_VIOLATION",
      "blocked",
      "path",
    );
    expect(denied).toBeInstanceOf(TenuoError);
    expect(denied.field).toBe("path");
    expect(denied.code).toBe("TENUO_CONSTRAINT_VIOLATION");

    const approval = new ApprovalRequiredError("send_email", 2, 0);
    expect(approval).toBeInstanceOf(TenuoError);
    expect(approval.code).toBe("TENUO_APPROVAL_REQUIRED");
  });
});

describe("authorize through WASM", () => {
  it("allows a path under the session and denies /etc/passwd without calling execute", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    tenuo.ready();

    let executed: string | undefined;
    const readFile = tenuo.tool(
      {
        execute: async ({ path }: { path: string }) => {
          executed = path;
          return `ok:${path}`;
        },
      },
      { capability: "read_file", allow: { path: under("/data") } },
    );

    const session = tenuo.session({
      allow: { read_file: { path: under("/data") } },
    });

    const allowed = await tenuo.withSession(session, () =>
      readFile.execute({ path: "/data/q3.pdf" }),
    );
    expect(allowed).toBe("ok:/data/q3.pdf");
    expect(executed).toBe("/data/q3.pdf");

    executed = undefined;
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/etc/passwd" })),
    ).rejects.toMatchObject({
      name: "AuthorizationDeniedError",
      code: "TENUO_CONSTRAINT_VIOLATION",
      field: "path",
    });
    expect(executed).toBeUndefined();
  });

  it("blocks a gated tool until signed approvals are attached", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    let executed: string | undefined;
    const readFile = tenuo.tool(
      {
        execute: async ({ path }: { path: string }) => {
          executed = path;
          return `ok:${path}`;
        },
      },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    const session = tenuo.session({
      allow: { read_file: { path: under("/data") } },
      requireApproval: {
        approvers: [
          createTenuo.publicKeyFromHex(APPROVER1_PUB),
          createTenuo.publicKeyFromHex(APPROVER2_PUB),
        ],
        min: 2,
      },
    });

    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/data/q3.pdf" })),
    ).rejects.toMatchObject({
      name: "ApprovalRequiredError",
      code: "TENUO_APPROVAL_REQUIRED",
      tool: "read_file",
      required: 2,
      received: 0,
    });
    expect(executed).toBeUndefined();

    const one = signApproval(session, "read_file", { path: "/data/q3.pdf" }, APPROVER1_SECRET);
    await expect(
      tenuo.withSession(session, () =>
        readFile.execute({ path: "/data/q3.pdf" }, { approvals: [one] }),
      ),
    ).rejects.toMatchObject({ code: "TENUO_INSUFFICIENT_APPROVALS" });
    expect(executed).toBeUndefined();

    const two = signApproval(session, "read_file", { path: "/data/q3.pdf" }, APPROVER2_SECRET);
    await expect(
      tenuo.withSession(session, () =>
        readFile.execute({ path: "/data/q3.pdf" }, { approvals: [one, two] }),
      ),
    ).resolves.toBe("ok:/data/q3.pdf");
    expect(executed).toBe("/data/q3.pdf");
  });

  it("accepts an explicit session on execute", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const search = tenuo.tool(
      { execute: async ({ q }: { q: string }) => q },
      { capability: "search", allow: { q: pattern("report*") } },
    );
    const session = tenuo.session({
      allow: { search: { q: pattern("report*") } },
    });
    await expect(search.execute({ q: "report-q3" }, { session })).resolves.toBe("report-q3");
  });
});

describe("narrow", () => {
  it("tightens a session and leaves the parent unchanged", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const readFile = tenuo.tool(
      { execute: async ({ path }: { path: string }) => `ok:${path}` },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    const session = tenuo.session({
      allow: { read_file: { path: under("/data") } },
    });
    const reports = tenuo.narrow(session, { path: under("/data/reports") });

    await expect(
      tenuo.withSession(reports, () => readFile.execute({ path: "/data/reports/q3.pdf" })),
    ).resolves.toBe("ok:/data/reports/q3.pdf");
    await expect(
      tenuo.withSession(reports, () => readFile.execute({ path: "/data/other.txt" })),
    ).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" });
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/data/other.txt" })),
    ).resolves.toBe("ok:/data/other.txt");
  });

  it("refuses a widening narrow", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({
      allow: { read_file: { path: under("/data/reports") } },
    });
    expect(() => tenuo.narrow(session, { path: under("/data") })).toThrow(/narrow\(\) rejected/);
  });
});

describe("toWire", () => {
  it("exports warrant tokens without the holder and re-imports in a second client", async () => {
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const parent = issuer.session({
      allow: { read_file: { path: under("/data") } },
    });
    const reports = issuer.narrow(parent, { path: under("/data/reports") });
    const tokens = reports.toWire();
    expect(tokens).toHaveLength(2);
    expect(JSON.stringify(reports)).toBe('"[TenuoSession]"');
    const leaked = exportSession(reports);
    expect(tokens.join("")).not.toContain(leaked.holder_hex);

    const worker = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(leaked.root_hex)],
    });
    const imported = worker.sessionFromWire({
      warrant: tokens,
      holderKey: createTenuo.holderKeyFromHex(leaked.holder_hex),
    });
    const readFile = worker.tool(
      { execute: async ({ path }: { path: string }) => `ok:${path}` },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    await expect(
      worker.withSession(imported, () => readFile.execute({ path: "/data/reports/q3.pdf" })),
    ).resolves.toBe("ok:/data/reports/q3.pdf");
    await expect(
      worker.withSession(imported, () => readFile.execute({ path: "/data/other.txt" })),
    ).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" });
  });
});

describe("revocation and receipts", () => {
  it("revokes a live-minted session so execute never runs", async () => {
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
    const tenuo = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(leaked.root_hex)],
      revocationList: srl,
    });
    const imported = tenuo.sessionFromWire({
      warrant: leaked.warrants,
      holderKey: createTenuo.holderKeyFromHex(leaked.holder_hex),
    });
    let executed = false;
    const readFile = tenuo.tool(
      {
        execute: async ({ path }: { path: string }) => {
          executed = true;
          return path;
        },
      },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    await expect(
      tenuo.withSession(imported, () => readFile.execute({ path: "/data/q3.pdf" })),
    ).rejects.toMatchObject({ code: "TENUO_REVOKED" });
    expect(executed).toBe(false);

    const later = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(leaked.root_hex)],
    });
    later.revoke(srl);
    const again = later.sessionFromWire({
      warrant: leaked.warrants,
      holderKey: createTenuo.holderKeyFromHex(leaked.holder_hex),
    });
    const laterTool = later.tool(
      { execute: async ({ path }: { path: string }) => path },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    await expect(
      later.withSession(again, () => laterTool.execute({ path: "/data/q3.pdf" })),
    ).rejects.toMatchObject({ code: "TENUO_REVOKED" });
  });

  it("emits a signed receipt on allow and deny without treating verify as authorize", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({
      allow: { read_file: { path: under("/data") } },
    });
    const receipts: string[] = [];
    const readFile = tenuo.tool(
      { execute: async ({ path }: { path: string }) => `ok:${path}` },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    await expect(
      tenuo.withSession(session, () =>
        readFile.execute({ path: "/data/q3.pdf" }, { onReceipt: (r) => receipts.push(r) }),
      ),
    ).resolves.toBe("ok:/data/q3.pdf");
    await expect(
      tenuo.withSession(session, () =>
        readFile.execute({ path: "/etc/passwd" }, { onReceipt: (r) => receipts.push(r) }),
      ),
    ).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" });
    expect(receipts).toHaveLength(2);
    const allowed = receipts[0];
    const denied = receipts[1];
    if (allowed === undefined || denied === undefined) {
      throw new Error("expected allow and deny receipts");
    }
    expect(verifyReceipt(allowed)).toMatchObject({ authentic: true, outcome: "allow" });
    expect(verifyReceipt(denied)).toMatchObject({
      authentic: true,
      outcome: "deny",
      decision_code: "constraint-violation",
    });
  });
});
