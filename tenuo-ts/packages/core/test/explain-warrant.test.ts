import { describe, expect, it, vi } from "vitest";
import { createTenuo, exact, pattern } from "../src/index.ts";
import { loadWasm } from "../src/wasm.ts";

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
    const approval = T.signApproval(request, reviewerKey, { externalId: "r", ttlSeconds: 1 });
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
