import { describe, expect, it } from "vitest";
import {
  AuthorizationDeniedError,
  createTenuo,
  max,
  memoryNonceStore,
  TenuoConfigurationError,
  under,
} from "../src/index.ts";
import type { NonceStore, Session } from "../src/index.ts";

function dev() {
  return createTenuo({ root: createTenuo.devRoot() });
}

/** A tool whose body records every run, so tests can assert it never ran. */
function recorder<TArgs extends Record<string, unknown>>() {
  const runs: TArgs[] = [];
  return {
    runs,
    inner: {
      execute: async (args: TArgs, options?: unknown) => {
        runs.push(args);
        return { args, options };
      },
    },
  };
}

describe("session({ tools }) with an empty tool policy", () => {
  it("refuses to mint an any-arguments capability from allow: {}", () => {
    const tenuo = dev();
    const { inner } = recorder<{ path: string }>();
    const readFile = tenuo.tool(inner, { capability: "read_file", allow: {} });
    expect(() => tenuo.session({ tools: [readFile] })).toThrow(TenuoConfigurationError);
    expect(() => tenuo.session({ tools: [readFile] })).toThrow(/read_file has allow: \{\}.*allow: \{ read_file: \{\} \}/);
  });

  it("never runs the body with smuggled arguments through a tools-built session", async () => {
    const tenuo = dev();
    const { inner, runs } = recorder<{ path: string }>();
    const readFile = tenuo.tool(inner, { capability: "read_file", allow: {} });
    let session: Session | undefined;
    try {
      session = tenuo.session({ tools: [readFile] });
    } catch {
      session = undefined;
    }
    expect(session).toBeUndefined();
    // Without a session the call has nothing to authorize against.
    await expect(readFile.execute({ path: "/etc/shadow", anything: "goes" } as never)).rejects.toThrow(/No session/);
    expect(runs).toEqual([]);
  });

  it("accepts the explicit opt-in and still applies constrained tools normally", async () => {
    const tenuo = dev();
    const open = recorder<{ path: string }>();
    const closed = recorder<{ path: string }>();
    const readAny = tenuo.tool(open.inner, { capability: "read_any", allow: {} });
    const readData = tenuo.tool(closed.inner, { capability: "read_data", allow: { path: under("/data") } });
    const session = tenuo.session({ tools: [readAny, readData], allow: { read_any: {} } });
    expect(session.inspect().tools).toEqual(["read_any", "read_data"]);
    await readAny.execute({ path: "/anywhere" }, { session });
    await expect(readData.execute({ path: "/etc/passwd" }, { session })).rejects.toBeInstanceOf(AuthorizationDeniedError);
    expect(open.runs).toEqual([{ path: "/anywhere" }]);
    expect(closed.runs).toEqual([]);
  });

  it("does not accept an opt-in for a different capability", () => {
    const tenuo = dev();
    const readFile = tenuo.tool(recorder().inner, { capability: "read_file", allow: {} });
    expect(() => tenuo.session({ tools: [readFile], allow: { other: {} } })).toThrow(/read_file has allow: \{\}/);
  });
});

describe("in-process approvals with a nonce store", () => {
  function gated(store?: NonceStore, onNonceStoreError?: (error: unknown) => void) {
    const tenuo = dev();
    const approver = createTenuo.generateHolderKey();
    const fx = recorder<{ amount: number }>();
    const transfer = tenuo.tool(fx.inner, {
      capability: "transfer",
      allow: { amount: max(100_000) },
      ...(store !== undefined ? { nonceStore: store } : {}),
      ...(onNonceStoreError !== undefined ? { onNonceStoreError } : {}),
    });
    const session = tenuo.session({
      allow: { transfer: { amount: max(100_000) } },
      requireApproval: { approvers: [createTenuo.publicKeyFromHolderKey(approver)], min: 1, tools: ["transfer"] },
    });
    const approve = (amount: number, externalId = "alice") =>
      createTenuo.signApproval(tenuo.approvalRequest(session, "transfer", { amount }), approver, { externalId });
    return { tenuo, transfer, session, approve, runs: fx.runs };
  }

  it("consumes an approval on first use; a replay never runs the body", async () => {
    const { transfer, session, approve, runs } = gated(memoryNonceStore());
    const approval = approve(5000);
    await transfer.execute({ amount: 5000 }, { session, approvals: [approval] });
    for (let i = 0; i < 2; i += 1) {
      await expect(transfer.execute({ amount: 5000 }, { session, approvals: [approval] })).rejects.toMatchObject({
        code: "TENUO_INSUFFICIENT_APPROVALS",
        message: expect.stringMatching(/already used/),
      });
    }
    expect(runs).toEqual([{ amount: 5000 }]);
  });

  it("re-encoding the same approval does not make it fresh", async () => {
    const { transfer, session, approve, runs } = gated(memoryNonceStore());
    const approval = approve(5000);
    await transfer.execute({ amount: 5000 }, { session, approvals: [approval] });
    const hex = Buffer.from(approval, "base64").toString("hex");
    const bytes = new Uint8Array(Buffer.from(approval, "base64"));
    await expect(transfer.execute({ amount: 5000 }, { session, approvals: [hex] })).rejects.toMatchObject({
      code: "TENUO_INSUFFICIENT_APPROVALS",
    });
    await expect(transfer.execute({ amount: 5000 }, { session, approvals: [bytes] })).rejects.toMatchObject({
      code: "TENUO_INSUFFICIENT_APPROVALS",
    });
    expect(runs).toHaveLength(1);
  });

  it("a fresh approval for the same call runs again", async () => {
    const { transfer, session, approve, runs } = gated(memoryNonceStore());
    await transfer.execute({ amount: 5000 }, { session, approvals: [approve(5000, "alice")] });
    await transfer.execute({ amount: 5000 }, { session, approvals: [approve(5000, "alice-again")] });
    expect(runs).toHaveLength(2);
  });

  it("a denied call does not consume the approval", async () => {
    const store = memoryNonceStore();
    const { transfer, session, approve, runs } = gated(store);
    const approval = approve(5000);
    // Approval is for 5000, call is for 6000: core denies, nothing recorded.
    await expect(transfer.execute({ amount: 6000 }, { session, approvals: [approval] })).rejects.toBeDefined();
    await transfer.execute({ amount: 5000 }, { session, approvals: [approval] });
    expect(runs).toEqual([{ amount: 5000 }]);
  });

  it("only consumes approvals that match the call", async () => {
    const { transfer, session, approve, runs } = gated(memoryNonceStore());
    const forThisCall = approve(5000);
    const forAnother = approve(7000);
    await transfer.execute({ amount: 5000 }, { session, approvals: [forAnother, forThisCall] });
    await transfer.execute({ amount: 7000 }, { session, approvals: [forAnother] });
    expect(runs).toEqual([{ amount: 5000 }, { amount: 7000 }]);
  });

  it("without a nonce store an approval stays reusable in-window (documented default)", async () => {
    const { transfer, session, approve, runs } = gated();
    const approval = approve(5000);
    await transfer.execute({ amount: 5000 }, { session, approvals: [approval] });
    await transfer.execute({ amount: 5000 }, { session, approvals: [approval] });
    expect(runs).toHaveLength(2);
  });

  it("fails closed when the store throws, rejects, or returns a non-boolean", async () => {
    const seen: unknown[] = [];
    const stores: NonceStore[] = [
      { checkAndRecord: () => { throw new Error("redis down"); } },
      { checkAndRecord: async () => { throw new Error("redis down"); } },
      { checkAndRecord: () => "yes" as never },
    ];
    for (const store of stores) {
      const { transfer, session, approve, runs } = gated(store, (error) => seen.push(error));
      await expect(
        transfer.execute({ amount: 5000 }, { session, approvals: [approve(5000)] }),
      ).rejects.toThrow("Replay store unavailable");
      expect(runs).toEqual([]);
    }
    expect(seen).toHaveLength(3);
  });

  it("does not touch the store for calls that carry no approvals", async () => {
    const keys: string[] = [];
    const tenuo = dev();
    const fx = recorder<{ amount: number }>();
    const pay = tenuo.tool(fx.inner, {
      capability: "pay",
      allow: { amount: max(10) },
      nonceStore: { checkAndRecord: (key) => { keys.push(key); return true; } },
    });
    const session = tenuo.session({ allow: { pay: { amount: max(10) } } });
    await pay.execute({ amount: 1 }, { session });
    await pay.execute({ amount: 1 }, { session });
    expect(keys).toEqual([]);
    expect(fx.runs).toHaveLength(2);
  });

  it("rejects a malformed nonceStore at wrap time", () => {
    const tenuo = dev();
    expect(() =>
      tenuo.tool(recorder().inner, { capability: "t", allow: {}, nonceStore: {} as never }),
    ).toThrow(/checkAndRecord/);
  });
});

describe("tool policy keys", () => {
  it("rejects a misspelled allow before any call can run", () => {
    const tenuo = dev();
    const { inner, runs } = recorder<{ path: string }>();
    expect(() =>
      tenuo.tool(inner, { capability: "read_file", alow: { path: under("/data") } } as never),
    ).toThrow(/unknown key 'alow'/);
    expect(runs).toEqual([]);
  });

  it("requires allow and rejects non-object allow", () => {
    const tenuo = dev();
    expect(() => tenuo.tool(recorder().inner, { capability: "a" } as never)).toThrow(/requires allow/);
    expect(() => tenuo.tool(recorder().inner, { capability: "b", allow: null } as never)).toThrow(/must be an object/);
    expect(() => tenuo.tool(recorder().inner, { capability: "c", allow: [] } as never)).toThrow(/must be an object/);
    expect(() => tenuo.tool(recorder().inner, undefined as never)).toThrow(/policy object/);
  });

  it("rejects unknown session() and issue() keys", () => {
    const tenuo = dev();
    expect(() => tenuo.session({ allow: { a: { x: max(1) } }, ttlSecond: 60 } as never)).toThrow(/unknown key 'ttlSecond'/);
    const issuer = tenuo.session({ kind: "issuer", issuableTools: ["a"], constraintBounds: { x: max(10) } });
    const holder = createTenuo.publicKeyFromHolderKey(createTenuo.generateHolderKey());
    expect(() => tenuo.issue(issuer, { allow: { a: { x: max(1) } }, holder, requireAproval: {} } as never)).toThrow(
      /unknown key 'requireAproval'/,
    );
  });
});

describe("execute options", () => {
  function setup() {
    const tenuo = dev();
    const fx = recorder<{ path: string }>();
    const readFile = tenuo.tool(fx.inner, { capability: "read_file", allow: { path: under("/") } });
    const broad = tenuo.session({ allow: { read_file: { path: under("/") } } });
    const narrow = tenuo.narrow(broad, { read_file: { path: under("/data") } });
    return { tenuo, readFile, broad, narrow, runs: fx.runs };
  }

  it("a misspelled session option throws instead of falling back to the ambient session", async () => {
    const { tenuo, readFile, broad, narrow, runs } = setup();
    for (const key of ["sesion", "Session", "sessoin", "sessions"]) {
      await expect(
        tenuo.withSession(broad, () => readFile.execute({ path: "/etc/passwd" }, { [key]: narrow } as never)),
      ).rejects.toThrow(new RegExp(`unknown key '${key}'. Did you mean 'session'`));
    }
    expect(runs).toEqual([]);
  });

  it("misspelled approvals, onReceipt, and requestId throw", async () => {
    const { readFile, broad, runs } = setup();
    for (const key of ["approval", "aprovals", "onReciept", "onreceipt", "requestID", "reqestId"]) {
      await expect(
        readFile.execute({ path: "/data/a" }, { session: broad, [key]: "x" } as never),
      ).rejects.toThrow(/Did you mean/);
    }
    expect(runs).toEqual([]);
  });

  it("other keys still pass through to the wrapped tool", async () => {
    const { readFile, broad } = setup();
    const signal = new AbortController().signal;
    const result = (await readFile.execute(
      { path: "/data/a" },
      { session: broad, toolCallId: "c1", sessionId: "s1", messages: [], abortSignal: signal } as never,
    )) as { options: Record<string, unknown> };
    expect(result.options).toEqual({ toolCallId: "c1", sessionId: "s1", messages: [], abortSignal: signal });
  });
});

describe("single-string warrant chains", () => {
  function delegated() {
    const cp = createTenuo({ root: createTenuo.issuerKeyFromBytes(createTenuo.generateIssuerKey()) });
    const orchestratorKey = createTenuo.generateHolderKey();
    const orchestrator = createTenuo({ trustedRoots: [cp.issuerPublicKey()] });
    const root = orchestrator.sessionFromWire({
      warrant: cp
        .session({
          allow: { read_file: { path: under("/data") } },
          holder: createTenuo.publicKeyFromHolderKey(orchestratorKey),
        })
        .toWire(),
      holderKey: orchestratorKey,
    });
    const identity = createTenuo.generateIdentity();
    const handed = orchestrator.narrow(root, { read_file: { path: under("/data/r") } }, { holder: identity.publicKey });
    const fx = recorder<{ path: string }>();
    const readFile = orchestrator.tool(fx.inner, { capability: "read_file", allow: { path: under("/data") } });
    return { cp, orchestrator, handed, identity, readFile, runs: fx.runs };
  }

  it("toWireString() round-trips a delegated chain through sessionFromWire and the runtime", async () => {
    const { cp, orchestrator, handed, identity, readFile, runs } = delegated();
    const wire = handed.toWireString();
    expect(typeof wire).toBe("string");
    expect(wire).not.toMatch(/[\s,]/);
    const runtime = createTenuo.runtime({ identity, trustedRoots: [cp.issuerPublicKey()] });
    const viaRuntime = runtime.sessionFromWire(wire);
    expect(viaRuntime.inspect().warrantIds).toEqual(handed.inspect().warrantIds);
    await readFile.execute({ path: "/data/r/q3.pdf" }, { session: viaRuntime });
    const direct = orchestrator.sessionFromWire({ warrant: wire, holderKey: identity.holderKey });
    await expect(readFile.execute({ path: "/data/other" }, { session: direct })).rejects.toBeInstanceOf(
      AuthorizationDeniedError,
    );
    expect(runs).toEqual([{ path: "/data/r/q3.pdf" }]);
    expect(direct.toWireString()).toBe(wire);
  });

  it("explains a joined array instead of reporting a chain or PoP failure", () => {
    const { cp, handed, identity } = delegated();
    const runtime = createTenuo.runtime({ identity, trustedRoots: [cp.issuerPublicKey()] });
    const tokens = handed.toWire();
    for (const joined of [tokens.join("\n"), tokens.join(" "), tokens.join(","), tokens.join("."), JSON.stringify(tokens)]) {
      expect(() => runtime.sessionFromWire(joined)).toThrow(/joined together.*toWireString\(\)/);
    }
  });
});

describe("narrow() approval threshold and lifetime", () => {
  it("refuses a lower minApprovals and accepts an equal or higher one", () => {
    const tenuo = dev();
    const a = createTenuo.publicKeyFromHolderKey(createTenuo.generateHolderKey());
    const b = createTenuo.publicKeyFromHolderKey(createTenuo.generateHolderKey());
    const parent = tenuo.session({
      allow: { transfer: { amount: max(100) } },
      requireApproval: { approvers: [a, b], min: 2, tools: ["transfer"] },
    });
    expect(() => tenuo.narrow(parent, { transfer: { amount: max(100) } }, { minApprovals: 1 })).toThrow(
      /minApprovals 1 is below the parent's 2/,
    );
    expect(tenuo.narrow(parent, { transfer: { amount: max(100) } }, { minApprovals: 2 }).inspect().minApprovals).toBe(2);
  });

  it("clamps a longer child ttlSeconds to the parent's expiry", () => {
    const tenuo = dev();
    const parent = tenuo.session({ allow: { t: { a: max(10) } }, ttlSeconds: 60 });
    const child = tenuo.narrow(parent, { t: { a: max(5) } }, { ttlSeconds: 3600 });
    expect(child.inspect().expiresAt).toBeLessThanOrEqual(parent.inspect().expiresAt);
  });
});

describe("small validation fixes", () => {
  it("session ttlSeconds: 0 throws instead of minting the default lifetime", () => {
    const tenuo = dev();
    expect(() => tenuo.session({ allow: { t: { a: max(1) } }, ttlSeconds: 0 })).toThrow(/ttlSeconds/);
  });

  it("revoke() errors carry a code", () => {
    const cp = createTenuo({ root: createTenuo.issuerKeyFromBytes(createTenuo.generateIssuerKey()) });
    const stranger = createTenuo({ root: createTenuo.issuerKeyFromBytes(createTenuo.generateIssuerKey()) });
    const agent = createTenuo({ trustedRoots: [cp.issuerPublicKey()] });
    expect(() => agent.revoke(stranger.revocationList({ revoke: ["w"] }))).toThrow(
      expect.objectContaining({ code: "TENUO_UNTRUSTED_ROOT" }),
    );
    expect(() => agent.revoke("deadbeef")).toThrow(expect.objectContaining({ code: "TENUO_CONFIGURATION" }));
    agent.revoke(cp.revocationList({ revoke: ["w"], version: 2 }));
    expect(() => agent.revoke(cp.revocationList({ revoke: ["w"], version: 1 }))).toThrow(
      expect.objectContaining({ code: "TENUO_CONFIGURATION", message: expect.stringMatching(/rollback/) }),
    );
  });
});
