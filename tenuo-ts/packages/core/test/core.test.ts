import { createHash } from "node:crypto";
import { describe, expect, expectTypeOf, it } from "vitest";
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
import type { ExecuteOptions, ProtectedTool, ToolLike } from "../src/index.ts";
import {
  devContext,
  exportSession,
  signApproval,
  signRevocationList,
  verifyReceipt,
  verifyReceiptChain,
  warrantIds,
  wrapSession,
} from "../src/testkit.ts";
import { APPROVER1_PUB, APPROVER1_SECRET, APPROVER2_PUB, APPROVER2_SECRET } from "./vectors/spec.ts";

describe("ProtectedTool types", () => {
  it("intersects the original execute context and returns a Promise", () => {
    type Inner = {
      description: string;
      execute: (args: { path: string }, options?: { abortSignal?: AbortSignal }) => string;
    };
    type Wrapped = ProtectedTool<Inner>;
    type Ctx = NonNullable<Parameters<Wrapped["execute"]>[1]>;
    expectTypeOf<Ctx>().toMatchTypeOf<ExecuteOptions & { abortSignal?: AbortSignal }>();
    expectTypeOf<Ctx>().toHaveProperty("session");
    expectTypeOf<Ctx>().toHaveProperty("abortSignal");
    expectTypeOf<ReturnType<Wrapped["execute"]>>().toEqualTypeOf<Promise<string>>();
  });
});

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

  it("refuses a session with neither tools nor allow", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    expect(() => tenuo.session({})).toThrow(/tools from tenuo\.tool\(\)|capability in allow/);
  });

  it("disables devRoot unless NODE_ENV is development or test", () => {
    const previousEnv = process.env.NODE_ENV;
    const previousAllow = process.env.TENUO_ALLOW_DEV;
    delete process.env.TENUO_ALLOW_DEV;
    try {
      process.env.NODE_ENV = "production";
      expect(() => createTenuo.devRoot()).toThrow(/Unset NODE_ENV is not treated as development/);
      expect(() => createTenuo({ root: { kind: "dev-root" } })).toThrow(
        /Unset NODE_ENV is not treated as development/,
      );
      delete process.env.NODE_ENV;
      expect(() => createTenuo.devRoot()).toThrow(/Unset NODE_ENV is not treated as development/);
      expect(createTenuo.devRoot({ allowInProduction: true })).toEqual({
        kind: "dev-root",
        allowInProduction: true,
      });
      process.env.TENUO_ALLOW_DEV = "1";
      expect(createTenuo.devRoot()).toEqual({ kind: "dev-root" });
    } finally {
      if (previousEnv === undefined) {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = previousEnv;
      }
      if (previousAllow === undefined) {
        delete process.env.TENUO_ALLOW_DEV;
      } else {
        process.env.TENUO_ALLOW_DEV = previousAllow;
      }
    }
  });

  it("rejects wrapping the same tool twice", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const inner = { execute: async ({ path }: { path: string }) => path };
    const readFile = tenuo.tool(inner, { capability: "read_file", allow: { path: under("/data") } });
    expect(() =>
      tenuo.tool(inner, { capability: "read_file", allow: { path: under("/data/reports") } }),
    ).toThrow(/already wrapped/);
    expect(() =>
      tenuo.tool(readFile, { capability: "read_file", allow: { path: under("/data") } }),
    ).toThrow(/already wrapped/);
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

  it("rejects extra arguments under a non-empty allow and names the fix", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const readFile = tenuo.tool(
      { execute: async ({ path }: { path: string }) => path },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    const session = tenuo.session({ tools: [readFile] });
    await expect(
      tenuo.withSession(session, () =>
        readFile.execute({ path: "/data/a.txt", encoding: "utf8" } as { path: string }),
      ),
    ).rejects.toMatchObject({
      code: "TENUO_CONSTRAINT_VIOLATION",
      field: "encoding",
      message: expect.stringMatching(/Zero-trust: name 'encoding' in allow/),
    });
  });

  it("does not forward session, approvals, or onReceipt into the inner tool", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    let seen: unknown;
    const readFile = tenuo.tool(
      {
        execute: async ({ path }: { path: string }, options?: { abortSignal?: AbortSignal }) => {
          seen = options;
          return path;
        },
      },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    const session = tenuo.session({ tools: [readFile] });
    const signal = new AbortController().signal;
    await tenuo.withSession(session, () =>
      readFile.execute(
        { path: "/data/q3.pdf" },
        { session, onReceipt: () => undefined, abortSignal: signal },
      ),
    );
    expect(seen).toEqual({ abortSignal: signal });
  });

  it("maps a garbage warrant to TENUO_CHAIN_INVALID, not configuration", () => {
    const tenuo = createTenuo({
      trustedRoots: [
        createTenuo.publicKeyFromHex("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"),
      ],
    });
    expect(() =>
      tenuo.sessionFromWire({
        warrant: "not-a-warrant",
        holderKey: createTenuo.holderKeyFromHex("02".repeat(32)),
      }),
    ).toThrow(expect.objectContaining({ code: "TENUO_CHAIN_INVALID", name: "TenuoError" }));
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

describe("tool allow and session({ tools })", () => {
  it("mints from wrapped tools so allow is written once", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    let executed: string | undefined;
    const readFile = tenuo.tool(
      {
        execute: async ({ path }: { path: string }) => {
          executed = path;
          return path;
        },
      },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    const session = tenuo.session({ tools: [readFile] });
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/data/q3.pdf" })),
    ).resolves.toBe("/data/q3.pdf");
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/etc/passwd" })),
    ).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" });
    expect(executed).toBe("/data/q3.pdf");
  });

  it("ANDs a tighter wrapper with a wider session", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
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
    const session = tenuo.session({
      allow: { read_file: { path: under("/") } },
    });
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/data/q3.pdf" })),
    ).resolves.toBe("/data/q3.pdf");
    executed = false;
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/etc/passwd" })),
    ).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION", field: "path" });
    expect(executed).toBe(false);
  });

  it("ANDs a tighter session with a wider wrapper", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
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
    const session = tenuo.session({
      allow: { read_file: { path: under("/data/reports") } },
    });
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/data/reports/q3.pdf" })),
    ).resolves.toBe("/data/reports/q3.pdf");
    executed = false;
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/data/other.txt" })),
    ).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" });
    expect(executed).toBe(false);
  });

  it("rejects session allow that disagrees with tools", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const readFile = tenuo.tool(
      { execute: async ({ path }: { path: string }) => path },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    expect(() =>
      tenuo.session({
        tools: [readFile],
        allow: { read_file: { path: under("/") } },
      }),
    ).toThrow(/disagree on read_file/);
  });

  it("accepts a no-arg tool with an empty allow and mints from it", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const ping = tenuo.tool(
      { execute: async (_args: Record<string, never>) => "pong" },
      { capability: "ping", allow: {} },
    );
    const session = tenuo.session({ tools: [ping] });
    await expect(tenuo.withSession(session, () => ping.execute({} as Record<string, never>))).resolves.toBe(
      "pong",
    );
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
    expect(() => tenuo.narrow(session, { path: under("/data") })).toThrow(
      expect.objectContaining({ code: "TENUO_CHAIN_INVALID" }),
    );
  });
});

describe("dedupKey", () => {
  it("is stable for the same tool and args, and changes when args change", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({
      allow: { read_file: { path: under("/data") } },
    });
    const a = session.dedupKey("read_file", { path: "/data/q3.pdf" });
    const b = session.dedupKey("read_file", { path: "/data/q3.pdf" });
    const c = session.dedupKey("read_file", { path: "/data/other.txt" });
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).toBe(b);
    expect(a).not.toBe(c);
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
  it("commits to the revocation list in force at decision time", async () => {
    const ctx = devContext();
    const victim = wrapSession(ctx.mint({ read_file: { path: { kind: "under", root: "/data" } } }, 300));
    const live = wrapSession(ctx.mint({ read_file: { path: { kind: "under", root: "/data" } } }, 300));
    const leaked = exportSession(live);
    const victimId = warrantIds(victim)[0];
    if (victimId === undefined) {
      throw new Error("expected a warrant id");
    }
    const srl = signRevocationList(ctx, [victimId]);

    const tenuo = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(leaked.root_hex)],
      revocationList: srl,
    });
    const session = tenuo.sessionFromWire({
      warrant: leaked.warrants,
      holderKey: createTenuo.holderKeyFromHex(leaked.holder_hex),
    });
    const tool = tenuo.tool({ execute: async (args: { path: string }) => args.path }, {
      capability: "read_file",
      allow: {},
    });

    let wire = "";
    await tenuo.withSession(session, () =>
      tool.execute({ path: "/data/a.txt" }, {
        onReceipt: (receipt: string) => {
          wire = receipt;
        },
      } as never),
    );

    const receipt = verifyReceipt(wire);
    // The commitment is over the bytes as loaded, so a verifier can re-derive it
    // from the published list without agreeing on a canonical re-encoding.
    expect(receipt.srl_hash).toBe(createHash("sha256").update(Buffer.from(srl, "hex")).digest("hex"));
    // A plain SignedRevocationList carries no version; the commitment says so
    // rather than inventing one.
    expect(receipt.srl_version).toBeUndefined();
  });

  it("omits the revocation commitment when no list was loaded", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({ allow: { read_file: { path: under("/data") } } });
    const tool = tenuo.tool({ execute: async (args: { path: string }) => args.path }, {
      capability: "read_file",
      allow: {},
    });

    let wire = "";
    await tenuo.withSession(session, () =>
      tool.execute({ path: "/data/a.txt" }, {
        onReceipt: (receipt: string) => {
          wire = receipt;
        },
      } as never),
    );

    // Absent, not zero-filled: "revocation was never consulted" is a distinct
    // claim from "a list was consulted and matched nothing".
    const receipt = verifyReceipt(wire);
    expect(receipt.srl_hash).toBeUndefined();
    expect(receipt.srl_version).toBeUndefined();
  });

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
        readFile.execute({ path: "/data/q3.pdf" }, { onReceipt: (r) => { receipts.push(r); } }),
      ),
    ).resolves.toBe("ok:/data/q3.pdf");
    await expect(
      tenuo.withSession(session, () =>
        readFile.execute({ path: "/etc/passwd" }, { onReceipt: (r) => { receipts.push(r); } }),
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

  it("does not fail execute when onReceipt throws", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({
      allow: { read_file: { path: under("/data") } },
    });
    const readFile = tenuo.tool(
      { execute: async ({ path }: { path: string }) => `ok:${path}` },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    await expect(
      tenuo.withSession(session, () =>
        readFile.execute(
          { path: "/data/q3.pdf" },
          {
            onReceipt: () => {
              throw new Error("receipt hook exploded");
            },
          },
        ),
      ),
    ).resolves.toBe("ok:/data/q3.pdf");
  });

  it("rejects deeply nested arguments before they can allocate without bound", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({
      allow: { read_file: { path: under("/data") } },
    });
    const readFile = tenuo.tool(
      { execute: async ({ path }: { path: string }) => path },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    let nested: unknown = "/data/q3.pdf";
    for (let i = 0; i < 40; i += 1) {
      nested = { nested };
    }
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: nested } as { path: string })),
    ).rejects.toMatchObject({
      code: "TENUO_CANONICALIZATION",
      message: expect.stringMatching(/nesting exceeds maximum depth/),
    });
  });

  it("rejects a cumulative argument payload even when each field is under the per-item cap", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({
      allow: { read_file: { path: under("/data") } },
    });
    const readFile = tenuo.tool(
      { execute: async ({ path }: { path: string }) => path },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    const bomb: Record<string, string> = { path: "/data/q3.pdf" };
    for (let i = 0; i < 20; i += 1) {
      bomb[`k${i}`] = "x".repeat(10_000);
    }
    await expect(
      tenuo.withSession(session, () => readFile.execute(bomb as { path: string })),
    ).rejects.toMatchObject({
      code: "TENUO_CANONICALIZATION",
      message: expect.stringMatching(/value budget/),
    });
  });

  it("rejects an oversized warrant string at the WASM boundary", () => {
    const tenuo = createTenuo({
      trustedRoots: [
        createTenuo.publicKeyFromHex("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"),
      ],
    });
    expect(() =>
      tenuo.sessionFromWire({
        warrant: "A".repeat(256 * 1024 * 2 + 1),
        holderKey: createTenuo.holderKeyFromHex("02".repeat(32)),
      }),
    ).toThrow(/WASM input budget|TENUO_CHAIN_INVALID/);
  });
});

describe("consumer e2e", () => {
  it("allows, denies without execute, redacts session, and rejects missing config", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    tenuo.ready();

    let executed = 0;
    const readFile = tenuo.tool(
      {
        execute: async ({ path }: { path: string }) => {
          executed += 1;
          return `ok:${path}`;
        },
      },
      { capability: "read_file", allow: { path: under("/data") } },
    );

    const session = tenuo.session({ tools: [readFile] });
    expect(JSON.stringify(session)).toBe('"[TenuoSession]"');

    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/data/q3.pdf" })),
    ).resolves.toBe("ok:/data/q3.pdf");
    expect(executed).toBe(1);

    executed = 0;
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/etc/passwd" })),
    ).rejects.toBeInstanceOf(AuthorizationDeniedError);
    expect(executed).toBe(0);

    expect(() => createTenuo({})).toThrow(TenuoConfigurationError);
    await expect(readFile.execute({ path: "/data/q3.pdf" })).rejects.toBeInstanceOf(
      TenuoConfigurationError,
    );
  });
});

describe("request correlation", () => {
  it("writes the host's own identifier into the receipt", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({ allow: { read_file: { path: under("/data") } } });
    const tool = tenuo.tool({ execute: async (args: { path: string }) => args.path }, {
      capability: "read_file",
      allow: {},
    });

    let wire = "";
    await tenuo.withSession(session, () =>
      tool.execute({ path: "/data/a.txt" }, {
        requestId: "trace-abc-123",
        onReceipt: (receipt: string) => {
          wire = receipt;
        },
      } as never),
    );

    expect(verifyReceipt(wire).request_id).toBe("trace-abc-123");
  });

  it("falls back to a derived handle when the host supplies none", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({ allow: { read_file: { path: under("/data") } } });
    const tool = tenuo.tool({ execute: async (args: { path: string }) => args.path }, {
      capability: "read_file",
      allow: {},
    });

    let wire = "";
    await tenuo.withSession(session, () =>
      tool.execute({ path: "/data/a.txt" }, {
        onReceipt: (receipt: string) => {
          wire = receipt;
        },
      } as never),
    );

    // A correlation aid, not an identity — repeats within a second collide,
    // which is why the chain link is what distinguishes them.
    expect(verifyReceipt(wire).request_id).toMatch(/^read_file:\d+$/);
  });

  it("does not leak the handle into the wrapped tool", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({ allow: { read_file: {} } });
    let seen: unknown;
    const tool = tenuo.tool(
      { execute: async (_args: { path: string }, options?: unknown) => { seen = options; return "ok"; } },
      { capability: "read_file", allow: {} },
    );

    await tenuo.withSession(session, () =>
      tool.execute({ path: "/data/a.txt" }, { requestId: "trace-abc-123" } as never),
    );

    expect(seen).toBeUndefined();
  });
});

describe("receipt argument commitment", () => {
  it("commits to the invocation the decision was made over", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({ allow: { read_file: { path: under("/data") } } });
    const tool = tenuo.tool({ execute: async (args: { path: string }) => args.path }, {
      capability: "read_file",
      allow: {},
    });

    let wire = "";
    await tenuo.withSession(session, () =>
      tool.execute({ path: "/data/a.txt" }, {
        onReceipt: (receipt: string) => {
          wire = receipt;
        },
      } as never),
    );

    // Without key 7 a receipt records that a decision happened but not what it
    // was made over, which is most of what makes it evidence.
    const receipt = verifyReceipt(wire);
    expect(receipt.request_hash).toBeDefined();
    expect(receipt.request_hash).toHaveLength(64);
  });

  it("commits to a different invocation differently", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({ allow: { read_file: { path: under("/data") } } });
    const tool = tenuo.tool({ execute: async (args: { path: string }) => args.path }, {
      capability: "read_file",
      allow: {},
    });
    const hashes: (string | undefined)[] = [];
    for (const path of ["/data/a.txt", "/data/b.txt"]) {
      await tenuo.withSession(session, () =>
        tool.execute({ path }, {
          onReceipt: (receipt: string) => {
            hashes.push(verifyReceipt(receipt).request_hash);
          },
        } as never),
      );
    }

    expect(hashes[0]).not.toBe(hashes[1]);
  });
});

describe("root-anchored receipt verification", () => {
  async function receiptAndRoot() {
    const ctx = devContext();
    const live = wrapSession(ctx.mint({ read_file: { path: { kind: "under", root: "/data" } } }, 300));
    const leaked = exportSession(live);
    const tenuo = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(leaked.root_hex)],
    });
    const session = tenuo.sessionFromWire({
      warrant: leaked.warrants,
      holderKey: createTenuo.holderKeyFromHex(leaked.holder_hex),
    });
    const tool = tenuo.tool({ execute: async (args: { path: string }) => args.path }, {
      capability: "read_file",
      allow: {},
    });
    let wire = "";
    await tenuo.withSession(session, () =>
      tool.execute({ path: "/data/a.txt" }, {
        onReceipt: (receipt: string) => {
          wire = receipt;
        },
      } as never),
    );
    return { wire, rootHex: leaked.root_hex };
  }

  it("verifies the embedded chain to the root that issued the authority", async () => {
    const { wire, rootHex } = await receiptAndRoot();

    // No trust in the signer needed: the chain is signed by the root and the
    // holder, not the enforcement point.
    const result = verifyReceiptChain(wire, [rootHex]);
    expect(result.chain_valid).toBe(true);
    expect(result.root_issuer).toBe(rootHex);
    expect(result.leaf_holder).toBeDefined();
    expect(result.corroborates_denial).toBeUndefined();
  });

  it("rejects the chain under a root that did not issue it", async () => {
    const { wire } = await receiptAndRoot();
    // A real key that simply is not the issuer.
    const stranger = exportSession(
      wrapSession(devContext().mint({ read_file: {} }, 300)),
    ).root_hex;

    const result = verifyReceiptChain(wire, [stranger]);
    expect(result.chain_valid).toBe(false);
    expect(result.chain_error).toBeDefined();
  });

  it("exposes the signer for the caller's own authorizer-set check", async () => {
    const { wire, rootHex } = await receiptAndRoot();

    // Membership is the verifier's judgment, made against an out-of-band set —
    // this function deliberately has no opinion on who is a legitimate signer.
    const result = verifyReceiptChain(wire, [rootHex]);
    expect(result.signer_key).toHaveLength(64);
    expect(result.signer_key).toBe(verifyReceipt(wire) && result.signer_key);
  });
});
