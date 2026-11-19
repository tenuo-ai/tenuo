import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { createTenuo, exact, pattern, range, TenuoConfigurationError } from "../src/index.ts";
import type { PresentedCall, Session } from "../src/index.ts";
import { loadWasm, protocolLimits } from "../src/wasm.ts";

const T = createTenuo;
const REPO = "acme/app";
const args = { repo: REPO, pr: "7", head_sha: "a".repeat(40) };

function setup() {
  const issuerSecret = T.generateIssuerKey();
  const cp = createTenuo({ root: T.issuerKeyFromBytes(issuerSecret) });
  const root = cp.issuerPublicKey();
  const authorKey = T.generateHolderKey();
  const reviewerKey = T.generateHolderKey();
  const outsiderKey = T.generateHolderKey();
  const issued = cp.session({
    allow: { merge_pr: { repo: exact(REPO), pr: pattern("*"), head_sha: pattern("*") } },
    holder: T.publicKeyFromHolderKey(authorKey),
    ttlSeconds: 600,
    requireApproval: { approvers: [T.publicKeyFromHolderKey(reviewerKey)], min: 1, tools: ["merge_pr"] },
  });
  const tokens = issued.toWire();
  const author = createTenuo({ trustedRoots: [root] });
  const authorSession = author.sessionFromWire({ warrant: tokens, holderKey: authorKey });
  const request = author.approvalRequest(authorSession, "merge_pr", args);
  const sign = (key: Uint8Array, who: string, req = request) => T.signApproval(req, key, { externalId: who });
  // The checker trusts the root and holds no secret at all.
  const checker = createTenuo({ trustedRoots: [root] });
  return { cp, root, authorKey, reviewerKey, outsiderKey, issued, tokens, author, authorSession, request, sign, checker };
}

function tamperLastByte(token: string): string {
  const bytes = Buffer.from(token, "base64url");
  bytes.writeUInt8(bytes.readUInt8(bytes.length - 1) ^ 0x01, bytes.length - 1);
  return bytes.toString("base64url");
}

/** Same approver key, signature broken: the envelope still parses. */
function forgeApproval(envelope: string): string {
  const bytes = Buffer.from(envelope, "base64");
  bytes.writeUInt8(bytes.readUInt8(bytes.length - 1) ^ 0x01, bytes.length - 1);
  return bytes.toString("base64");
}

/**
 * A chain whose second link was signed by the parent's holder but is wider
 * than the parent and not derived from it.
 */
function widenedChain() {
  const cp = createTenuo({ root: T.issuerKeyFromBytes(T.generateIssuerKey()) });
  const holder = T.generateHolderKey();
  const parent = cp.session({ allow: { m: { repo: exact("a/b") } }, holder: T.publicKeyFromHolderKey(holder), ttlSeconds: 600 });
  const asIssuer = createTenuo({ root: T.issuerKeyFromBytes(holder) });
  const wide = asIssuer.session({ allow: { m: { repo: pattern("*") } }, holder: T.publicKeyFromHolderKey(T.generateHolderKey()), ttlSeconds: 300 });
  return { root: cp.issuerPublicKey(), chain: [parent.toWire()[0] as string, wide.toWire()[0] as string] };
}

describe("inspectWarrant", () => {
  it("decodes a chain without the holder key", () => {
    const { tokens, issued, authorKey, reviewerKey } = setup();
    for (const input of [tokens, issued.toWireString(), tokens[0] as string]) {
      const [leaf] = T.inspectWarrant(input);
      expect(leaf?.holderPublicKey).toBe(T.publicKeyFromHolderKey(authorKey).hex);
      expect(leaf?.requiredApprovers).toEqual([T.publicKeyFromHolderKey(reviewerKey).hex]);
      expect(leaf?.minApprovals).toBe(1);
      expect(leaf?.tools).toEqual(["merge_pr"]);
      expect(leaf?.depth).toBe(0);
    }
  });

  it("decodes a delegated chain root first", () => {
    const { author, authorSession } = setup();
    const worker = T.generateHolderKey();
    const child = author.narrow(authorSession, { merge_pr: { repo: exact(REPO), pr: exact("7"), head_sha: pattern("*") } }, {
      holder: T.publicKeyFromHolderKey(worker),
    });
    const chain = T.inspectWarrant(child.toWire());
    expect(chain.map((w) => w.depth)).toEqual([0, 1]);
    expect(chain[1]?.holderPublicKey).toBe(T.publicKeyFromHolderKey(worker).hex);
  });

  it("rejects empty input", () => {
    expect(() => T.inspectWarrant([])).toThrow(/requires a warrant/);
    expect(() => T.inspectWarrant("  ")).toThrow(/requires a warrant/);
  });
});

describe("explainWarrant", () => {
  it("reports satisfied approval evidence for an exact call", () => {
    const { checker, tokens, sign, reviewerKey, root } = setup();
    const r = checker.explainWarrant(tokens, "merge_pr", args, { approvals: [sign(reviewerKey, "reviewer")] });
    expect(r).toMatchObject({ constraints: { status: "satisfied" }, chain: { status: "valid" }, possession: { status: "not_checked" }, rootPublicKey: root.hex });
    expect(r.approvals).toMatchObject({ valid: 1, required: 1, rejected: 0 });
  });

  it("accepts the stack string form", () => {
    const { checker, issued, sign, reviewerKey } = setup();
    const r = checker.explainWarrant(issued.toWireString(), "merge_pr", args, { approvals: [sign(reviewerKey, "r")] });
    expect(r.approvals.status).toBe("satisfied");
  });

  it("requires approval when none is given", () => {
    const { checker, tokens } = setup();
    const r = checker.explainWarrant(tokens, "merge_pr", args);
    expect(r).toMatchObject({ approvals: { status: "required" }, chain: { status: "valid" }, code: "TENUO_APPROVAL_REQUIRED" });
  });

  it("does not count the holder's own approval or an unlisted key", () => {
    const { checker, tokens, sign, authorKey, outsiderKey } = setup();
    const r = checker.explainWarrant(tokens, "merge_pr", args, {
      approvals: [sign(authorKey, "author"), sign(outsiderKey, "outsider")],
    });
    expect(r.approvals.status).toBe("required");
    expect(r.approvals).toMatchObject({ valid: 0, required: 1, rejected: 2 });
  });

  it("does not count an approval of different arguments", () => {
    const { checker, tokens, sign, reviewerKey } = setup();
    const r = checker.explainWarrant(tokens, "merge_pr", { ...args, head_sha: "b".repeat(40) }, {
      approvals: [sign(reviewerKey, "reviewer")],
    });
    expect(r.approvals.status).toBe("required");
  });

  it("an invalid envelope from the approver's key does not displace a valid one", () => {
    const { checker, tokens, sign, reviewerKey } = setup();
    const good = sign(reviewerKey, "reviewer");
    const forged = forgeApproval(good);
    const r = checker.explainWarrant(tokens, "merge_pr", args, { approvals: [forged, "not-an-approval", good] });
    expect(r.approvals.status).toBe("satisfied");
    expect(r.approvals).toMatchObject({ valid: 1, required: 1, rejected: 2 });
  });

  it("counts each approver once", () => {
    const { checker, tokens, sign, reviewerKey, cp, authorKey } = setup();
    const second = T.generateHolderKey();
    const twoOfTwo = cp.session({
      allow: { merge_pr: { repo: exact(REPO), pr: pattern("*"), head_sha: pattern("*") } },
      holder: T.publicKeyFromHolderKey(authorKey),
      ttlSeconds: 600,
      requireApproval: {
        approvers: [T.publicKeyFromHolderKey(reviewerKey), T.publicKeyFromHolderKey(second)],
        min: 2,
        tools: ["merge_pr"],
      },
    }).toWire();
    const a = createTenuo({ trustedRoots: [cp.issuerPublicKey()] });
    const req = a.approvalRequest(a.sessionFromWire({ warrant: twoOfTwo, holderKey: authorKey }), "merge_pr", args);
    const once = sign(reviewerKey, "r", req);
    const twice = sign(reviewerKey, "r", req);
    const r = checker.explainWarrant(twoOfTwo, "merge_pr", args, { approvals: [once, twice] });
    expect(r).toMatchObject({ approvals: { status: "required" }, code: "TENUO_INSUFFICIENT_APPROVALS" });
    expect(r.approvals?.valid).toBe(1);
    expect(tokens.length).toBe(1);
  });

  it("reports unsatisfied constraints even with an approval", () => {
    const { checker, tokens, sign, reviewerKey } = setup();
    const r = checker.explainWarrant(tokens, "merge_pr", { ...args, repo: "other/repo" }, {
      approvals: [sign(reviewerKey, "reviewer")],
    });
    expect(r).toMatchObject({ constraints: { status: "unsatisfied" }, chain: { status: "valid" } });
  });

  it("reports an untrusted chain as invalid", () => {
    const { tokens, sign, reviewerKey } = setup();
    const other = createTenuo({ trustedRoots: [createTenuo({ root: T.issuerKeyFromBytes(T.generateIssuerKey()) }).issuerPublicKey()] });
    const r = other.explainWarrant(tokens, "merge_pr", args, { approvals: [sign(reviewerKey, "reviewer")] });
    expect(r).toMatchObject({ chain: { status: "invalid" } });
  });

  it("reports a tampered warrant as invalid", () => {
    const { checker, tokens } = setup();
    const r = checker.explainWarrant([tamperLastByte(tokens[0] as string)], "merge_pr", args);
    expect(r).toMatchObject({ chain: { status: "invalid" } });
  });

  it("applies loaded revocation lists", () => {
    const { cp, root, tokens, sign, reviewerKey } = setup();
    const id = T.inspectWarrant(tokens)[0]?.id as string;
    const revoked = createTenuo({ trustedRoots: [root], revocationList: cp.revocationList({ revoke: [id] }) });
    const r = revoked.explainWarrant(tokens, "merge_pr", args, { approvals: [sign(reviewerKey, "reviewer")] });
    expect(r).toMatchObject({ chain: { status: "invalid" } });
  });

  it("checks a delegated chain to its leaf", () => {
    const { checker, author, authorSession } = setup();
    const worker = T.generateHolderKey();
    const ungated = createTenuo({ root: T.issuerKeyFromBytes(T.generateIssuerKey()) });
    const s = ungated.session({ allow: { read: { path: pattern("/data/*") } }, holder: T.publicKeyFromHolderKey(worker), ttlSeconds: 600 });
    const v = createTenuo({ trustedRoots: [ungated.issuerPublicKey()] });
    expect(v.explainWarrant(s.toWire(), "read", { path: "/data/a" })).toMatchObject({ constraints: { status: "satisfied" } });
    expect(v.explainWarrant(s.toWire(), "read", { path: "/etc/a" })).toMatchObject({ constraints: { status: "unsatisfied" } });
    const child = author.narrow(authorSession, { merge_pr: { repo: exact(REPO), pr: exact("8"), head_sha: pattern("*") } }, {
      holder: T.publicKeyFromHolderKey(worker),
    });
    expect(checker.explainWarrant(child.toWire(), "merge_pr", args)).toMatchObject({ constraints: { status: "unsatisfied" }, chain: { status: "valid" } });
  });

  it("reports a widened chain as invalid", () => {
    const { root, chain } = widenedChain();
    const r = createTenuo({ trustedRoots: [root] }).explainWarrant(chain, "m", { repo: "other/x" });
    expect(r).toMatchObject({ chain: { status: "invalid" } });
  });

  it("never reports a proof-of-possession check", () => {
    const { checker, tokens } = setup();
    const report = checker.explainWarrant(tokens, "merge_pr", args);
    expect(report.possession.status).toBe("not_checked");
    expect(report.kind).toBe("diagnostic");
    expect(report).not.toHaveProperty("outcome");
    expect(report).not.toHaveProperty("authorized");
  });
});

describe("standalone WASM helpers", () => {
  it("the dry-run chain check verifies the chain, not only its links", () => {
    const { tokens, root } = setup();
    const w = loadWasm() as unknown as {
      check_chain_access(t: string[], tool: string, args: unknown, root: string, dry: boolean): { authorized: boolean };
    };
    expect(w.check_chain_access(tokens as string[], "merge_pr", args, root.hex, true).authorized).toBe(true);
    const widened = widenedChain();
    expect(w.check_chain_access(widened.chain, "m", { repo: "other/x" }, widened.root.hex, true).authorized).toBe(false);
  });

  it("the approval-set helper ignores an invalid envelope before a valid one", () => {
    const { tokens, sign, reviewerKey, request } = setup();
    const w = loadWasm() as unknown as {
      verify_approval_set(warrant: string, hash: string, approvals: string[]): { satisfied: boolean; valid_count: number };
    };
    const good = sign(reviewerKey, "reviewer");
    const r = w.verify_approval_set(tokens[0] as string, request.requestHash, [forgeApproval(good), good]);
    expect(r).toMatchObject({ satisfied: true, valid_count: 1 });
  });
});


describe("diagnostic/enforcement boundary", () => {
  it("satisfied diagnostics never substitute for possession", async () => {
    const { checker, tokens, author, authorSession, sign, reviewerKey } = setup();
    const approvals = [sign(reviewerKey, "reviewer")];
    const report = checker.explainWarrant(tokens, "merge_pr", args, { approvals });
    expect(report).toMatchObject({
      kind: "diagnostic", chain: { status: "valid" },
      constraints: { status: "satisfied" }, approvals: { status: "satisfied" },
      possession: { status: "not_checked" },
    });
    expect(report).not.toHaveProperty("outcome");
    const presented = author.present(authorSession, "merge_pr", args, { approvals });
    await expect(checker.verify({ ...presented, signature: "00".repeat(64) }, "merge_pr", args)).rejects.toBeDefined();
    await expect(checker.verify(presented, "merge_pr", args)).resolves.toEqual(args);
  });

  it("uses normalized constraints but hashes the original arguments", async () => {
    const { checker, tokens, author, authorSession, reviewerKey } = setup();
    const wireArgs = { ...args, omitted: null };
    // Null unmentioned fields are removed only from the constraint view.
    const approval = T.signApproval(author.approvalRequest(authorSession, "merge_pr", wireArgs), reviewerKey, { externalId: "r" });
    const report = checker.explainWarrant(tokens, "merge_pr", wireArgs, { approvals: [approval] });
    expect(report.constraints.status).toBe("satisfied");
    expect(report.approvals.status).toBe("satisfied");
    const presented = author.present(authorSession, "merge_pr", wireArgs, { approvals: [approval] });
    await expect(checker.verify(presented, "merge_pr", wireArgs)).resolves.toEqual(wireArgs);
    // Removing null changes the signed request even though constraints still match.
    expect(checker.explainWarrant(tokens, "merge_pr", args, { approvals: [approval] }).approvals.status).toBe("required");
  });

  it("rejects expired approvals even while the warrant remains valid", async () => {
    const { checker, tokens, author, authorSession, request, reviewerKey } = setup();
    const approval = T.signApproval(request, reviewerKey, { externalId: "r", ttlSeconds: 60 });
    const presented = author.present(authorSession, "merge_pr", args, { approvals: [approval] });
    const expires = T.inspectApproval(approval).expiresAt;
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date(expires * 1000));
      const report = checker.explainWarrant(tokens, "merge_pr", args, { approvals: [approval] });
      expect(report.chain.status).toBe("valid");
      expect(report.approvals).toMatchObject({ status: "required", valid: 0, rejected: 1 });
      const wasm = loadWasm() as unknown as {
        verify_approval_set(warrant: string, hash: string, approvals: string[]): { satisfied: boolean; valid_count: number };
      };
      expect(wasm.verify_approval_set(tokens[0]!, request.requestHash, [approval])).toMatchObject({ satisfied: false, valid_count: 0 });
      await expect(checker.verify(presented, "merge_pr", args)).rejects.toBeDefined();
    } finally { vi.useRealTimers(); }
  });

  it("does not report downstream checks as passed for an invalid chain", () => {
    const { checker, tokens } = setup();
    const report = checker.explainWarrant([tamperLastByte(tokens[0]!)], "merge_pr", args);
    expect(report).toMatchObject({
      chain: { status: "invalid" }, constraints: { status: "not_evaluated" },
      approvals: { status: "not_evaluated" }, possession: { status: "not_checked" },
    });
  });

  it("marks ungated calls not_required and expired chains invalid", () => {
    const cp = createTenuo({ root: T.issuerKeyFromBytes(T.generateIssuerKey()) });
    const session = cp.session({ allow: { read: {} }, ttlSeconds: 60 });
    const checker = createTenuo({ trustedRoots: [cp.issuerPublicKey()] });
    expect(checker.explainWarrant(session.toWire(), "read", {}).approvals.status).toBe("not_required");
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date((session.inspect().expiresAt + 120) * 1000));
      expect(checker.explainWarrant(session.toWire(), "read", {})).toMatchObject({
        chain: { status: "invalid" }, constraints: { status: "not_evaluated" },
        approvals: { status: "not_evaluated" },
      });
    } finally { vi.useRealTimers(); }
  });
});


/** These casts intentionally bypass TypeScript: the boundary must hold at runtime. */
describe("diagnostics cannot become execution credentials", () => {
  function boundary() {
    const fx = setup();
    const approvals = [fx.sign(fx.reviewerKey, "reviewer")];
    const presented = fx.author.present(fx.authorSession, "merge_pr", args, { approvals });
    const report = fx.checker.explainWarrant(fx.tokens, "merge_pr", args, { approvals });
    expect(report).toMatchObject({
      chain: { status: "valid" }, constraints: { status: "satisfied" },
      approvals: { status: "satisfied" }, possession: { status: "not_checked" },
    });
    const body = vi.fn(async (input: Readonly<Record<string, unknown>>) => input);
    const handler = fx.checker.mcp.handler("merge_pr", body);
    const tool = fx.checker.tool({ execute: body }, { capability: "merge_pr", allow: {} });
    return { ...fx, approvals, presented, report, body, handler, tool };
  }

  it("rejects a report as a presented call and as MCP metadata before execution", async () => {
    const { checker, report, handler, body, presented } = boundary();
    await expect(checker.verify(report as unknown as PresentedCall, "merge_pr", args))
      .rejects.toBeInstanceOf(TenuoConfigurationError);
    await expect(handler(args, { _meta: { tenuo: report } }))
      .rejects.toBeInstanceOf(TenuoConfigurationError);
    expect(body).not.toHaveBeenCalled();
    // Positive control: the same real boundary invokes the body with valid proof.
    await expect(handler(args, { _meta: { tenuo: presented } })).resolves.toEqual(args);
    expect(body).toHaveBeenCalledExactlyOnceWith(args);
  });

  it("rejects a report as a Session even inside a valid ambient session", async () => {
    const { checker, report, tool, body, authorSession, approvals } = boundary();
    const counterfeit = report as unknown as Session;
    expect(() => checker.present(counterfeit, "merge_pr", args, { approvals }))
      .toThrow(TenuoConfigurationError);
    await expect(checker.withSession(authorSession, () => tool.execute(args, {
      session: counterfeit, approvals,
    }))).rejects.toBeInstanceOf(TenuoConfigurationError);
    expect(body).not.toHaveBeenCalled();
    await expect(tool.execute(args, { session: authorSession, approvals })).resolves.toEqual(args);
    expect(body).toHaveBeenCalledExactlyOnceWith(args, undefined);
  });

  it.each(["missing", "empty", "invalid", "other_holder"] as const)(
    "%s proof cannot execute despite satisfied diagnostics and approvals",
    async (proof) => {
      const { cp, presented, report, handler, body } = boundary();
      const envelope: Record<string, unknown> = { ...report, ...presented, outcome: "allow", authorized: true };
      if (proof === "missing") delete envelope.signature;
      if (proof === "empty") envelope.signature = "";
      if (proof === "invalid") envelope.signature = "00".repeat(64);
      if (proof === "other_holder") {
        // A real signed invocation from another holder cannot be transplanted.
        const otherKey = T.generateHolderKey();
        const otherGrant = cp.session({ allow: { merge_pr: {} }, holder: T.publicKeyFromHolderKey(otherKey) });
        const otherSession = cp.sessionFromWire({ warrant: otherGrant.toWire(), holderKey: otherKey });
        envelope.signature = cp.present(otherSession, "merge_pr", args).signature;
      }
      await expect(handler(args, { _meta: { tenuo: envelope } })).rejects.toMatchObject({
        code: proof === "missing" || proof === "empty" ? "TENUO_CONFIGURATION" : "TENUO_INVALID_POP",
      });
      expect(body).not.toHaveBeenCalled();
    },
  );

  it("does not let a satisfied report authorize changed invocation arguments", async () => {
    const { handler, body, presented, report } = boundary();
    const changed = { ...args, head_sha: "b".repeat(40) };
    await expect(handler(changed, { _meta: { tenuo: { ...report, ...presented } } }))
      .rejects.toMatchObject({ code: "TENUO_INVALID_POP" });
    expect(body).not.toHaveBeenCalled();
  });

  it("a satisfied report cannot replace the invocation's signed approvals", async () => {
    const { handler, body, presented, report } = boundary();
    const { approvals: _approvals, ...withoutApprovals } = presented;
    await expect(handler(args, { _meta: { tenuo: { ...report, ...withoutApprovals, approvals: [] } } }))
      .rejects.toMatchObject({ code: "TENUO_APPROVAL_REQUIRED" });
    expect(body).not.toHaveBeenCalled();
  });

  it("rechecks approval expiry after satisfied diagnostics without executing", async () => {
    const { checker, tokens, author, authorSession, request, reviewerKey, handler, body, tool } = boundary();
    const approval = T.signApproval(request, reviewerKey, { externalId: "r", ttlSeconds: 60 });
    const approvals = [approval];
    const presented = author.present(authorSession, "merge_pr", args, { approvals });
    expect(checker.explainWarrant(tokens, "merge_pr", args, { approvals }).approvals.status).toBe("satisfied");
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date(T.inspectApproval(approval).expiresAt * 1000));
      await expect(handler(args, { _meta: { tenuo: presented } }))
        .rejects.toMatchObject({ code: "TENUO_INSUFFICIENT_APPROVALS" });
      await expect(tool.execute(args, { session: authorSession, approvals }))
        .rejects.toMatchObject({ code: "TENUO_INSUFFICIENT_APPROVALS" });
      expect(body).not.toHaveBeenCalled();
    } finally { vi.useRealTimers(); }
  });

  it("rechecks revocation after a satisfied report, on both execution paths", async () => {
    const { cp, checker, issued, tool, authorSession, approvals, handler, body, presented } = boundary();
    checker.revoke(cp.revocationList({ revoke: issued.inspect().warrantIds }));
    await expect(handler(args, { _meta: { tenuo: presented } }))
      .rejects.toMatchObject({ code: "TENUO_REVOKED" });
    await expect(tool.execute(args, { session: authorSession, approvals }))
      .rejects.toMatchObject({ code: "TENUO_REVOKED" });
    expect(body).not.toHaveBeenCalled();
  });

  it("rechecks warrant expiry after a satisfied report, on both execution paths", async () => {
    const { issued, tool, authorSession, approvals, handler, body, presented } = boundary();
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date((issued.inspect().expiresAt + 120) * 1000));
      await expect(handler(args, { _meta: { tenuo: presented } }))
        .rejects.toMatchObject({ code: "TENUO_WARRANT_EXPIRED" });
      await expect(tool.execute(args, { session: authorSession, approvals }))
        .rejects.toMatchObject({ code: "TENUO_WARRANT_EXPIRED" });
      expect(body).not.toHaveBeenCalled();
    } finally { vi.useRealTimers(); }
  });

  it("diagnostics emit no receipts or execution credentials and never invoke a registered tool", async () => {
    const { root, tokens, approvals, presented } = boundary();
    const runtime = T.runtime({ identity: T.generateIdentity(), trustedRoots: [root], receipts: "collect" });
    const body = vi.fn(async (input: Readonly<Record<string, unknown>>) => input);
    const handler = runtime.tenuo.mcp.handler("merge_pr", body);
    const cases = [
      runtime.tenuo.explainWarrant(tokens, "merge_pr", args, { approvals }),
      runtime.tenuo.explainWarrant(tokens, "merge_pr", args),
      runtime.tenuo.explainWarrant(tokens, "merge_pr", { ...args, repo: "elsewhere/repo" }),
      runtime.tenuo.explainWarrant([tamperLastByte(tokens[0]!)], "merge_pr", args),
      runtime.tenuo.explainWarrant(tokens, "merge_pr", { value: Number.NaN }),
    ];
    for (const report of cases) {
      expect(report.kind).toBe("diagnostic");
      expect(report.possession.status).toBe("not_checked");
      for (const key of ["outcome", "authorized", "allow", "ok", "success", "receipt", "session", "warrant", "signature", "execute"]) {
        expect(report).not.toHaveProperty(key);
      }
    }
    expect(body).not.toHaveBeenCalled();
    expect(runtime.peekReceipts()).toEqual([]);
    // Verify that the observer really collects receipts and the handler runs.
    await handler(args, { _meta: { tenuo: presented } });
    expect(body).toHaveBeenCalledExactlyOnceWith(args);
    expect(runtime.peekReceipts()).toHaveLength(1);
    expect(T.verifyReceipt(runtime.peekReceipts()[0]!)).toMatchObject({ outcome: "allow" });
  });
});


describe("diagnostic approval input budget", () => {
  it.each(["signed", "bytes", "unreadable"] as const)(
    "rejects too many %s envelopes before signature inspection",
    (encoding) => {
      const { checker, tokens, sign, reviewerKey } = setup();
      const good = sign(reviewerKey, "reviewer");
      const envelope = encoding === "signed" ? good
        : encoding === "bytes" ? new Uint8Array(Buffer.from(good, "base64")) : "unreadable";
      const approvals = Array.from({ length: protocolLimits().max_approvals + 1 }, () => envelope);
      const inspect = vi.spyOn(loadWasm(), "sdkInspectApproval");
      try {
        expect(() => checker.explainWarrant(tokens, "merge_pr", args, { approvals }))
          .toThrow(/accepts at most .* approval envelopes/);
        expect(inspect).not.toHaveBeenCalled();
      } finally { inspect.mockRestore(); }
    },
  );

  it("checks length before even reading an oversized array element", () => {
    const { checker, tokens } = setup();
    const approvals = new Array<string>(protocolLimits().max_approvals + 1);
    const read = vi.fn(() => { throw new Error("must not read oversized input"); });
    Object.defineProperty(approvals, 0, { get: read });
    expect(() => checker.explainWarrant(tokens, "merge_pr", args, { approvals }))
      .toThrow(/accepts at most .* approval envelopes/);
    expect(read).not.toHaveBeenCalled();
  });

  it("direct WASM diagnostics reject oversized approvals without copying elements", () => {
    const { root, tokens } = setup();
    const context = loadWasm().SdkContext.fromTrustedRoots([root.hex]);
    const approvals = new Array<string>(protocolLimits().max_approvals + 1);
    const read = vi.fn(() => { throw new Error("must not copy oversized approvals"); });
    Object.defineProperty(approvals, 0, { get: read });
    try {
      expect(context.explainWarrant(tokens, "merge_pr", args, approvals)).toMatchObject({
        kind: "diagnostic", code: "TENUO_CANONICALIZATION",
        approvals: { status: "not_evaluated" }, possession: { status: "not_checked" },
      });
      expect(read).not.toHaveBeenCalled();
    } finally { (context as typeof context & { free(): void }).free(); }
  });

  it("accepts the core limit itself without an off-by-one rejection", () => {
    const { checker, tokens } = setup();
    const maximum = protocolLimits().max_approvals;
    expect(maximum).toBeGreaterThan(0);
    const report = checker.explainWarrant(tokens, "merge_pr", args, {
      approvals: Array.from({ length: maximum }, () => "unreadable"),
    });
    expect(report.approvals).toMatchObject({ status: "required", rejected: maximum });
  });
});


describe("diagnostic chain input budget", () => {
  it.each(["inspect", "explain", "wasm"] as const)(
    "%s rejects oversized token arrays before reading or copying elements",
    (entry) => {
      const { checker } = setup();
      const chain = new Array<string>(protocolLimits().max_delegation_depth + 1);
      const read = vi.fn(() => { throw new Error("must not read oversized chain"); });
      Object.defineProperty(chain, 0, { get: read });
      const invoke = () => entry === "inspect" ? T.inspectWarrant(chain)
        : entry === "explain" ? checker.explainWarrant(chain, "merge_pr", args)
        : loadWasm().sdkDecodeChain(chain);
      expect(invoke).toThrow(/chain exceeds/);
      expect(read).not.toHaveBeenCalled();
    },
  );

  it("accepts the exact token limit for decoding without implying chain validity", () => {
    const { tokens, checker } = setup();
    const maximum = protocolLimits().max_delegation_depth;
    const chain = Array.from({ length: maximum }, () => tokens[0]!);
    expect(T.inspectWarrant(chain)).toHaveLength(maximum);
    expect(checker.explainWarrant(chain, "merge_pr", args)).toMatchObject({
      chain: { status: "invalid" }, possession: { status: "not_checked" },
    });
  });
});


describe("legacy approval helper input budget", () => {
  it("rejects oversized duplicate approvals before reading any envelope", () => {
    const { tokens, request, sign, reviewerKey } = setup();
    const good = sign(reviewerKey, "r");
    const maximum = protocolLimits().max_approvals;
    const wasm = loadWasm() as unknown as {
      verify_approval_set(warrant: string, hash: string, approvals: string[]): { satisfied: boolean; valid_count: number; error?: string };
    };
    const approvals = Array.from({ length: maximum + 1 }, () => good);
    const read = vi.fn(() => { throw new Error("must not read oversized approval set"); });
    Object.defineProperty(approvals, 0, { get: read });
    expect(wasm.verify_approval_set(tokens[0]!, request.requestHash, approvals)).toMatchObject({
      satisfied: false, valid_count: 0, error: "too many approval envelopes",
    });
    expect(read).not.toHaveBeenCalled();
    expect(wasm.verify_approval_set(tokens[0]!, request.requestHash, Array(maximum).fill(good))).toMatchObject({
      satisfied: true, valid_count: 1,
    });
  });
});

describe("lossless warrant inspection", () => {
  it("distinguishes inclusive and exclusive range bounds in the decoded policy", () => {
    const cp = createTenuo({ root: T.issuerKeyFromBytes(T.generateIssuerKey()) });
    const inclusive = cp.session({ allow: { pay: { amount: range({ min: 0 }) } } });
    const exclusive = cp.session({ allow: { pay: { amount: range({ min: 0, minExclusive: true }) } } });
    const inclusivePolicy = T.inspectWarrant(inclusive.toWire())[0]!.capabilities.pay;
    const exclusivePolicy = T.inspectWarrant(exclusive.toWire())[0]!.capabilities.pay;
    expect(inclusivePolicy).not.toEqual(exclusivePolicy);
    expect(inclusivePolicy).toHaveProperty("constraints.amount");
    expect(exclusivePolicy).toHaveProperty("constraints.amount");
    expect(cp.explainWarrant(inclusive.toWire(), "pay", { amount: 0 }).constraints.status).toBe("satisfied");
    expect(cp.explainWarrant(exclusive.toWire(), "pay", { amount: 0 }).constraints.status).toBe("unsatisfied");
  });
});


describe("prototype-safe warrant inspection", () => {
  it("preserves __proto__ as an own signed constraint in enumeration and JSON", () => {
    const cp = createTenuo({ root: T.issuerKeyFromBytes(T.generateIssuerKey()) });
    const fields = JSON.parse('{"__proto__":{"kind":"exact","value":"a"},"constructor":{"kind":"exact","value":"b"}}');
    const issued = cp.session({ allow: { read: fields } });
    const info = T.inspectWarrant(issued.toWire())[0]!;
    const policy = info.capabilities.read as { constraints: Record<string, unknown> };
    expect(Object.getPrototypeOf(policy.constraints)).toBe(Object.prototype);
    expect(Object.hasOwn(policy.constraints, "__proto__")).toBe(true);
    expect(Object.keys(policy.constraints).sort()).toEqual(["__proto__", "constructor"]);
    const roundtrip = JSON.parse(JSON.stringify(info));
    expect(Object.hasOwn(roundtrip.capabilities.read.constraints, "__proto__")).toBe(true);
    expect(roundtrip.capabilities.read.constraints).toEqual(policy.constraints);
    // The decoded entry corresponds to a real constraint, not injected metadata.
    expect(cp.explainWarrant(issued.toWire(), "read", JSON.parse('{"__proto__":"wrong","constructor":"b"}')).constraints.status).toBe("unsatisfied");
  });

  it("preserves __proto__ as an own capability name", () => {
    const cp = createTenuo({ root: T.issuerKeyFromBytes(T.generateIssuerKey()) });
    const allow = JSON.parse('{"__proto__":{"value":{"kind":"exact","value":"a"}}}');
    const info = T.inspectWarrant(cp.session({ allow }).toWire())[0]!;
    expect(Object.getPrototypeOf(info.capabilities)).toBe(Object.prototype);
    expect(Object.keys(info.capabilities)).toEqual(["__proto__"]);
    expect(Object.hasOwn(JSON.parse(JSON.stringify(info)).capabilities, "__proto__")).toBe(true);
  });
});


// Signed by Rust using Exact::new(i64), so the inputs never pass through a
// JavaScript number. These are decode-only fixtures; expiry is intentionally irrelevant.
const importedIntegerWarrants = JSON.parse(readFileSync(
  new URL("./fixtures/inspection-integers.json", import.meta.url), "utf8",
)) as { exactInteger: string; warrant: string }[];

describe("precision-safe imported warrant inspection", () => {
  it.each(importedIntegerWarrants)("rejects imported Exact($exactInteger) rather than rounding it", ({ exactInteger, warrant }) => {
    expect(() => T.inspectWarrant(warrant)).toThrow(`inspection cannot represent integer ${exactInteger} exactly in JavaScript`);
    expect(() => loadWasm().sdkDecodeChain([warrant])).toThrow(/cannot represent integer/);
  });

  it.each([Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER])("preserves the safe-integer boundary %s", (value) => {
    const cp = createTenuo({ root: T.issuerKeyFromBytes(T.generateIssuerKey()) });
    const issued = cp.session({ allow: { pay: { amount: exact(value) } } });
    const info = T.inspectWarrant(issued.toWire())[0]!;
    expect(JSON.stringify(info.capabilities)).toContain(String(value));
    expect(cp.explainWarrant(issued.toWire(), "pay", { amount: value }).constraints.status).toBe("satisfied");
  });
});
