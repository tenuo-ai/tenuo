/**
 * Parity with the Python and Rust SDKs: full constraint set, stable issuer
 * key, issuer-type sessions, metadata, approvals end to end, revocation
 * lists, receipts, explain, and transport-agnostic present/verify.
 */
import { describe, expect, it } from "vitest";
import {
  all,
  anyOf,
  ApprovalRequiredError,
  AuthorizationDeniedError,
  cel,
  cidr,
  contains,
  createTenuo,
  exact,
  max,
  min,
  not,
  notOneOf,
  oneOf,
  pattern,
  range,
  regex,
  shlex,
  subset,
  TenuoConfigurationError,
  under,
  urlPattern,
  urlSafe,
  wildcard,
} from "../src/index.ts";
import type { AllowPolicy, Session, Tenuo } from "../src/index.ts";

const hex64 = /^[0-9a-f]{64}$/;

function dev(): Tenuo {
  return createTenuo({ root: createTenuo.devRoot() });
}

/** A tool whose execute echoes its args, under a session that allows `policy` for it. */
function probe(tenuo: Tenuo, capability: string, policy: AllowPolicy) {
  const tool = tenuo.tool(
    { execute: async (args: Record<string, unknown>) => args },
    { capability, allow: {} },
  );
  const session = tenuo.session({ allow: { [capability]: policy } });
  return {
    session,
    ok: (args: Record<string, unknown>) => tool.execute(args, { session }),
    denied: (args: Record<string, unknown>) =>
      expect(tool.execute(args, { session })).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" }),
  };
}

describe("constraint set", () => {
  it("range, min, and max bound numbers with inclusive and exclusive edges", async () => {
    const tenuo = dev();
    const r = probe(tenuo, "pay", { amount: range({ min: 10, max: 100 }) });
    await expect(r.ok({ amount: 10 })).resolves.toEqual({ amount: 10 });
    await expect(r.ok({ amount: 100 })).resolves.toEqual({ amount: 100 });
    await r.denied({ amount: 9 });
    await r.denied({ amount: 101 });

    const x = probe(tenuo, "pay2", { amount: range({ min: 10, max: 100, minExclusive: true, maxExclusive: true }) });
    await x.denied({ amount: 10 });
    await x.denied({ amount: 100 });
    await expect(x.ok({ amount: 50 })).resolves.toEqual({ amount: 50 });

    const m = probe(tenuo, "pay3", { amount: min(5) });
    await expect(m.ok({ amount: 5 })).resolves.toEqual({ amount: 5 });
    await m.denied({ amount: 4 });
    expect(() => range({})).toThrow();
    expect(() => range({ min: 5, max: 1 })).toThrow();
  });

  it("notOneOf, regex, exact, and wildcard", async () => {
    const tenuo = dev();
    const n = probe(tenuo, "route", { region: notOneOf(["cn", "ru"]) });
    await expect(n.ok({ region: "us" })).resolves.toEqual({ region: "us" });
    await n.denied({ region: "cn" });

    const r = probe(tenuo, "ticket", { id: regex("^INC-[0-9]{4}$") });
    await expect(r.ok({ id: "INC-0042" })).resolves.toEqual({ id: "INC-0042" });
    await r.denied({ id: "INC-42" });

    // wildcard names an argument without constraining it, which is how a
    // zero-trust policy admits a free-form field.
    const w = probe(tenuo, "note", { text: wildcard(), kind: exact("memo") });
    await expect(w.ok({ text: "anything at all", kind: "memo" })).resolves.toMatchObject({ kind: "memo" });
    await w.denied({ text: "x", kind: "letter" });
  });

  it("cidr, urlPattern, and urlSafe evaluate as networks and URLs, not strings", async () => {
    const tenuo = dev();
    const c = probe(tenuo, "connect", { ip: cidr("10.0.0.0/8") });
    await expect(c.ok({ ip: "10.20.30.40" })).resolves.toEqual({ ip: "10.20.30.40" });
    await c.denied({ ip: "192.168.1.1" });
    expect(() => cidr("10.0.0.0")).toThrow();

    const u = probe(tenuo, "fetch", { url: urlPattern("https://*.example.com/api/*") });
    await expect(u.ok({ url: "https://a.example.com/api/v1" })).resolves.toEqual({ url: "https://a.example.com/api/v1" });
    await u.denied({ url: "https://example.com.evil.net/api/v1" });

    const s = probe(tenuo, "fetch2", { url: urlSafe({ allowDomains: ["*.example.com"] }) });
    await expect(s.ok({ url: "https://api.example.com/x" })).resolves.toEqual({ url: "https://api.example.com/x" });
    await s.denied({ url: "http://169.254.169.254/latest/meta-data" });
    await s.denied({ url: "https://evil.net/" });
  });

  it("shlex allows listed commands only, parsed with shell rules", async () => {
    const tenuo = dev();
    const s = probe(tenuo, "run", { cmd: shlex(["ls", "cat"]) });
    await expect(s.ok({ cmd: "ls -la /tmp" })).resolves.toEqual({ cmd: "ls -la /tmp" });
    await s.denied({ cmd: "rm -rf /" });
    await s.denied({ cmd: "ls; rm -rf /" });
  });

  it("contains and subset constrain list arguments", async () => {
    const tenuo = dev();
    const c = probe(tenuo, "grant", { roles: contains(["viewer"]) });
    await expect(c.ok({ roles: ["viewer", "editor"] })).resolves.toEqual({ roles: ["viewer", "editor"] });
    await c.denied({ roles: ["editor"] });

    const s = probe(tenuo, "grant2", { roles: subset(["viewer", "editor"]) });
    await expect(s.ok({ roles: ["viewer"] })).resolves.toEqual({ roles: ["viewer"] });
    await s.denied({ roles: ["viewer", "admin"] });
  });

  it("anyOf, all, and not compose", async () => {
    const tenuo = dev();
    const a = probe(tenuo, "read", { path: anyOf([under("/data"), under("/shared")]) });
    await expect(a.ok({ path: "/shared/x" })).resolves.toEqual({ path: "/shared/x" });
    await a.denied({ path: "/etc/passwd" });

    const b = probe(tenuo, "read2", { path: all([under("/data"), pattern("*.csv")]) });
    await expect(b.ok({ path: "/data/a.csv" })).resolves.toEqual({ path: "/data/a.csv" });
    await b.denied({ path: "/data/a.txt" });

    const n = probe(tenuo, "read3", { path: not(under("/data/secret")) });
    await expect(n.ok({ path: "/data/public/a" })).resolves.toEqual({ path: "/data/public/a" });
    await n.denied({ path: "/data/secret/a" });
  });

  it("cel evaluates a predicate over the value in core", async () => {
    const tenuo = dev();
    const c = probe(tenuo, "transfer", { amount: cel("value < 10000 && value > 0") });
    await expect(c.ok({ amount: 500 })).resolves.toEqual({ amount: 500 });
    await c.denied({ amount: 50000 });
    await c.denied({ amount: -1 });
  });

  it("under() takes case and equality options", async () => {
    const tenuo = dev();
    const strict = probe(tenuo, "read", { path: under("/data", { allowEqual: false }) });
    await expect(strict.ok({ path: "/data/x" })).resolves.toEqual({ path: "/data/x" });
    await strict.denied({ path: "/data" });
    const loose = probe(tenuo, "read2", { path: under("/Data", { caseSensitive: false }) });
    await expect(loose.ok({ path: "/data/x" })).resolves.toEqual({ path: "/data/x" });
  });

  it("every kind narrows monotonically or is refused", () => {
    const tenuo = dev();
    const session = tenuo.session({
      allow: {
        pay: { amount: range({ min: 0, max: 100 }), region: notOneOf(["cn"]) },
      },
    });
    expect(() => tenuo.narrow(session, { pay: { amount: range({ min: 10, max: 50 }), region: notOneOf(["cn", "ru"]) } })).not.toThrow();
    expect(() => tenuo.narrow(session, { pay: { amount: range({ min: 0, max: 200 }), region: notOneOf(["cn"]) } })).toThrow(
      expect.objectContaining({ code: "TENUO_CHAIN_INVALID" }),
    );
    expect(() => tenuo.narrow(session, { pay: { amount: range({ min: 0, max: 100 }), region: notOneOf(["ru"]) } })).toThrow(
      expect.objectContaining({ code: "TENUO_CHAIN_INVALID" }),
    );
  });

  it("rejects an unknown constraint kind at mint time", () => {
    const tenuo = dev();
    expect(() => tenuo.session({ allow: { read: { path: { kind: "glob", pattern: "*" } as never } } })).toThrow(
      /unknown constraint kind/,
    );
  });
});

describe("stable issuer key", () => {
  it("two contexts from the same secret are the same issuer, and agents can trust it", async () => {
    const secret = createTenuo.generateIssuerKey();
    const a = createTenuo({ root: createTenuo.issuerKeyFromBytes(secret) });
    const b = createTenuo({ root: createTenuo.issuerKeyFromHex(Buffer.from(secret).toString("hex")) });
    expect(a.issuerPublicKey().hex).toBe(b.issuerPublicKey().hex);
    expect(a.issuerPublicKey().hex).toBe(createTenuo.publicKeyFromHolderKey(secret).hex);

    const holderKey = createTenuo.generateHolderKey();
    const issued = a.session({
      allow: { read_file: { path: under("/data") } },
      holder: createTenuo.publicKeyFromHolderKey(holderKey),
    });
    const agent = createTenuo({ trustedRoots: [b.issuerPublicKey()] });
    const mine = agent.sessionFromWire({ warrant: issued.toWire(), holderKey });
    const readFile = agent.tool({ execute: async ({ path }: { path: string }) => path }, { capability: "read_file", allow: {} });
    await expect(readFile.execute({ path: "/data/x" }, { session: mine })).resolves.toBe("/data/x");
  });

  it("works outside development and reads from the environment", () => {
    const secret = createTenuo.generateIssuerKey();
    process.env.TENUO_TEST_ISSUER = Buffer.from(secret).toString("hex");
    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const cp = createTenuo({ root: createTenuo.issuerKeyFromEnv("TENUO_TEST_ISSUER") });
      expect(cp.issuerPublicKey().hex).toMatch(hex64);
      expect(() => cp.session({ allow: { read_file: { path: under("/data") } } })).not.toThrow();
    } finally {
      process.env.NODE_ENV = previous;
      delete process.env.TENUO_TEST_ISSUER;
    }
    expect(() => createTenuo.issuerKeyFromBytes(new Uint8Array(31))).toThrow(TenuoConfigurationError);
  });

  it("an issuer context also trusts extra roots", async () => {
    const other = dev();
    const cp = createTenuo({ root: createTenuo.issuerKeyFromBytes(createTenuo.generateIssuerKey()), trustedRoots: [other.issuerPublicKey()] });
    const holderKey = createTenuo.generateHolderKey();
    const fromOther = other.session({ allow: { ping: {} }, holder: createTenuo.publicKeyFromHolderKey(holderKey) });
    const mine = cp.sessionFromWire({ warrant: fromOther.toWire(), holderKey });
    const ping = cp.tool({ execute: async (_args: Record<string, unknown>) => "pong" }, { capability: "ping", allow: {} });
    await expect(ping.execute({}, { session: mine })).resolves.toBe("pong");
  });
});

describe("issuer sessions and issue()", () => {
  function setup() {
    const controlPlane = dev();
    const orchestratorKey = createTenuo.generateHolderKey();
    const workerKey = createTenuo.generateHolderKey();
    const orchestrator = createTenuo({ trustedRoots: [controlPlane.issuerPublicKey()] });
    const worker = createTenuo({ trustedRoots: [controlPlane.issuerPublicKey()] });
    const issuerHanded = controlPlane.session({
      kind: "issuer",
      issuableTools: ["read_file", "search"],
      constraintBounds: { path: under("/data") },
      maxIssueDepth: 2,
      holder: createTenuo.publicKeyFromHolderKey(orchestratorKey),
      ttlSeconds: 600,
    });
    const issuer = orchestrator.sessionFromWire({ warrant: issuerHanded.toWire(), holderKey: orchestratorKey });
    return { controlPlane, orchestrator, worker, issuer, workerKey };
  }

  it("an issuer session cannot call tools but can mint execution sessions within its bounds", async () => {
    const { orchestrator, worker, issuer, workerKey } = setup();
    expect(issuer.inspect()).toMatchObject({ kind: "issuer", issuableTools: ["read_file", "search"], maxIssueDepth: 2 });

    const readOnIssuer = orchestrator.tool(
      { execute: async (_args: Record<string, unknown>) => "x" },
      { capability: "read_file", allow: {} },
    );
    await expect(readOnIssuer.execute({ path: "/data/a" }, { session: issuer })).rejects.toBeInstanceOf(AuthorizationDeniedError);

    const handed = orchestrator.issue(issuer, {
      allow: { read_file: { path: under("/data/reports") } },
      holder: createTenuo.publicKeyFromHolderKey(workerKey),
      ttlSeconds: 60,
    });
    expect(handed.inspect().kind).toBe("execution");
    expect(handed.inspect().canAuthorize).toBe(false);
    const mine = worker.sessionFromWire({ warrant: handed.toWire(), holderKey: workerKey });
    const readFile = worker.tool({ execute: async ({ path }: { path: string }) => path }, { capability: "read_file", allow: {} });
    await expect(readFile.execute({ path: "/data/reports/q3" }, { session: mine })).resolves.toBe("/data/reports/q3");
    await expect(readFile.execute({ path: "/data/other" }, { session: mine })).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" });
  });

  it("refuses tools outside issuableTools and constraints outside the bounds", () => {
    const { orchestrator, issuer, workerKey } = setup();
    const holder = createTenuo.publicKeyFromHolderKey(workerKey);
    expect(() => orchestrator.issue(issuer, { allow: { delete_file: { path: under("/data") } }, holder })).toThrow(
      expect.objectContaining({ code: "TENUO_CHAIN_INVALID" }),
    );
    expect(() => orchestrator.issue(issuer, { allow: { read_file: { path: under("/") } }, holder })).toThrow(
      expect.objectContaining({ code: "TENUO_CHAIN_INVALID" }),
    );
  });

  it("issue() needs the issuer holder key, and an execution session cannot issue", () => {
    const { controlPlane, orchestrator, workerKey } = setup();
    const holder = createTenuo.publicKeyFromHolderKey(workerKey);
    const wireOnly = controlPlane.session({ kind: "issuer", issuableTools: ["read_file"], holder });
    expect(() => controlPlane.issue(wireOnly, { allow: { read_file: {} }, holder })).toThrow(TenuoConfigurationError);
    const execution = orchestrator.sessionFromWire({
      warrant: controlPlane.session({ allow: { read_file: {} }, holder }).toWire(),
      holderKey: workerKey,
    });
    expect(() => orchestrator.issue(execution, { allow: { read_file: {} }, holder })).toThrow(
      expect.objectContaining({ code: "TENUO_CHAIN_INVALID" }),
    );
  });

  it("enforces approval gates added while issuing an execution session", async () => {
    const { orchestrator, worker, issuer, workerKey } = setup();
    const approver = createTenuo.generateHolderKey();
    const handed = orchestrator.issue(issuer, {
      allow: { read_file: { path: under("/data/reports") } },
      holder: createTenuo.publicKeyFromHolderKey(workerKey),
      ttlSeconds: 60,
      requireApproval: {
        approvers: [createTenuo.publicKeyFromHolderKey(approver)],
        min: 1,
      },
    });
    expect(handed.inspect().approvalGatedTools).toEqual(["read_file"]);

    const mine = worker.sessionFromWire({ warrant: handed.toWire(), holderKey: workerKey });
    const readFile = worker.tool(
      { execute: async ({ path }: { path: string }) => path },
      { capability: "read_file", allow: {} },
    );
    await expect(readFile.execute({ path: "/data/reports/q3" }, { session: mine })).rejects.toBeInstanceOf(
      ApprovalRequiredError,
    );

    const request = worker.approvalRequest(mine, "read_file", { path: "/data/reports/q3" });
    const approval = createTenuo.signApproval(request, approver, { externalId: "reviewer" });
    await expect(
      readFile.execute({ path: "/data/reports/q3" }, { session: mine, approvals: [approval] }),
    ).resolves.toBe("/data/reports/q3");
  });

  it("rejects issuer-only fields on an execution session", () => {
    const tenuo = dev();
    expect(() => tenuo.session({ allow: { read_file: {} }, issuableTools: ["read_file"] })).toThrow(/issuer/);
    expect(() => tenuo.session({ kind: "issuer" })).toThrow(/issuableTools/);
  });
});

describe("warrant metadata", () => {
  it("clearance, sessionId, and agentId are minted, inspected, and attenuated correctly", () => {
    const tenuo = dev();
    const session = tenuo.session({
      allow: { read_file: { path: under("/data") } },
      clearance: "internal",
      sessionId: "task-42",
      agentId: "planner",
    });
    expect(session.inspect()).toMatchObject({ clearance: 30, sessionId: "task-42", agentId: "planner" });

    const lower = tenuo.narrow(session, { path: under("/data/x") }, { clearance: "partner", agentId: "worker" });
    expect(lower.inspect()).toMatchObject({ clearance: 20, sessionId: "task-42", agentId: "worker" });

    expect(() => tenuo.narrow(session, { path: under("/data/x") }, { clearance: "system" })).toThrow(
      expect.objectContaining({ code: "TENUO_CHAIN_INVALID" }),
    );
    expect(() => tenuo.session({ allow: { read_file: {} }, clearance: 300 })).toThrow(TenuoConfigurationError);
    expect(() => tenuo.session({ allow: { read_file: {} }, clearance: "ultra" as never })).toThrow(TenuoConfigurationError);
    expect(tenuo.session({ allow: { read_file: {} }, clearance: 7 }).inspect().clearance).toBe(7);
  });
});

describe("approvals end to end", () => {
  function gated() {
    const tenuo = dev();
    const approverA = createTenuo.generateHolderKey();
    const approverB = createTenuo.generateHolderKey();
    const transfer = tenuo.tool(
      { execute: async ({ amount }: { amount: number }) => `sent ${amount}` },
      { capability: "transfer", allow: {} },
    );
    const session = tenuo.session({
      allow: { transfer: { amount: max(100000) } },
      requireApproval: {
        approvers: [createTenuo.publicKeyFromHolderKey(approverA), createTenuo.publicKeyFromHolderKey(approverB)],
        min: 1,
        gates: {
          transfer: {
            message: "Large transfer needs a human",
            args: { amount: { when: min(1000) } },
          },
        },
      },
    });
    return { tenuo, approverA, approverB, transfer, session };
  }

  it("a per-argument gate fires only for triggering values and carries the message", async () => {
    const { transfer, session } = gated();
    expect(session.inspect().approvalGatedTools).toEqual(["transfer"]);
    expect(session.inspect().requiredApprovers).toHaveLength(2);
    expect(session.inspect().minApprovals).toBe(1);
    await expect(transfer.execute({ amount: 50 }, { session })).resolves.toBe("sent 50");

    let caught: unknown;
    try {
      await transfer.execute({ amount: 5000 }, { session });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApprovalRequiredError);
    const error = caught as ApprovalRequiredError;
    expect(error.required).toBe(1);
    expect(error.request).toBeDefined();
    expect(error.request?.tool).toBe("transfer");
    expect(error.request?.requestHash).toMatch(hex64);
    expect(error.request?.message).toContain("Large transfer");
    expect(error.request?.holderPublicKey).toBe(session.inspect().holderPublicKey);
    expect(error.request?.args).toEqual({ amount: 5000 });
  });

  it("an approver signs the request hash and the call goes through, once, for those exact args", async () => {
    const { tenuo, approverA, transfer, session } = gated();
    const request = tenuo.approvalRequest(session, "transfer", { amount: 5000 });
    expect(request.requiredApprovers).toHaveLength(2);
    const envelope = createTenuo.signApproval(request, approverA, { externalId: "alice@example.com" });
    const info = createTenuo.inspectApproval(envelope);
    expect(info).toMatchObject({
      signatureValid: true,
      expired: false,
      externalId: "alice@example.com",
      requestHash: request.requestHash,
      approverPublicKey: createTenuo.publicKeyFromHolderKey(approverA).hex,
    });
    expect(info.expiresAt).toBeLessThanOrEqual(request.warrantExpiresAt);

    await expect(transfer.execute({ amount: 5000 }, { session, approvals: [envelope] })).resolves.toBe("sent 5000");
    // The approval binds the arguments: presenting it for a different call is refused outright.
    await expect(transfer.execute({ amount: 6000 }, { session, approvals: [envelope] })).rejects.toMatchObject({
      code: expect.stringMatching(/APPROVAL/),
    });
    // A stranger's signature does not count.
    const stranger = createTenuo.signApproval(request, createTenuo.generateHolderKey(), { externalId: "nobody" });
    await expect(transfer.execute({ amount: 5000 }, { session, approvals: [stranger] })).rejects.toMatchObject({
      code: expect.stringMatching(/TENUO_(APPROVAL_REQUIRED|INSUFFICIENT_APPROVALS)/),
    });
  });

  it("exempt gates fire for everything outside the exemption, and delegation can only add approvers", async () => {
    const tenuo = dev();
    const approver = createTenuo.generateHolderKey();
    const readFile = tenuo.tool({ execute: async ({ path }: { path: string }) => path }, { capability: "read_file", allow: {} });
    const session = tenuo.session({
      allow: { read_file: { path: under("/data") } },
      requireApproval: {
        approvers: [createTenuo.publicKeyFromHolderKey(approver)],
        min: 1,
        gates: { read_file: { args: { path: { exempt: under("/data/public") } } } },
      },
    });
    await expect(readFile.execute({ path: "/data/public/a" }, { session })).resolves.toBe("/data/public/a");
    await expect(readFile.execute({ path: "/data/private/a" }, { session })).rejects.toBeInstanceOf(ApprovalRequiredError);

    const second = createTenuo.generateHolderKey();
    const stricter = tenuo.narrow(session, { path: under("/data") }, {
      addApprovers: [createTenuo.publicKeyFromHolderKey(second)],
      minApprovals: 2,
    });
    expect(stricter.inspect().requiredApprovers).toHaveLength(2);
    expect(stricter.inspect().minApprovals).toBe(2);
    // The threshold only rises: asking for less leaves it where it was.
    const attempt = tenuo.narrow(stricter, { path: under("/data") }, { minApprovals: 1 });
    expect(attempt.inspect().minApprovals).toBe(2);
  });

  it("produces the control-plane v1 body Python emits, with an attestation the holder signed", () => {
    const { tenuo, session } = gated();
    const request = tenuo.approvalRequest(session, "transfer", { amount: 5000 });
    const attestation = tenuo.attestApprovalRequest(session, "transfer", { amount: 5000 });
    expect(attestation.signerKeyHex).toBe(session.inspect().holderPublicKey);
    expect(attestation.requestHash).toBe(request.requestHash);
    expect(attestation.signatureB64.length).toBeGreaterThan(0);

    const body = createTenuo.controlPlaneApprovalRequestV1(request, { attestation, temporal: { workflow_id: "wf-1" } });
    expect(body).toMatchObject({
      schema_version: 1,
      warrant_id: request.warrantId,
      tool: "transfer",
      arguments: { amount: 5000 },
      request_hash_hex: request.requestHash,
      holder_public_key_hex: request.holderPublicKey,
      min_approvals: 1,
      temporal: { workflow_id: "wf-1" },
      message: request.message,
    });
    expect(body.required_approver_keys_hex).toHaveLength(2);
    expect(body.attestation).toMatchObject({ signer_key: attestation.signerKeyHex, signature: attestation.signatureB64 });
    expect(body.request_id_hex).toMatch(/^[0-9a-f]{32}$/);

    expect(createTenuo.signedApprovalsFromResponseV1({ status: "approved", signed_approvals_b64: ["AAAA"] })).toEqual(["AAAA"]);
    expect(createTenuo.signedApprovalsFromResponseV1({ status: "denied", error: "no" })).toEqual([]);
    expect(createTenuo.signedApprovalsFromResponseV1({ status: "denied", signed_approvals_b64: ["AAAA"] })).toEqual([]);
    expect(() => createTenuo.signedApprovalsFromResponseV1({ status: "approved", signed_approvals_b64: [1] as never })).toThrow(
      TenuoConfigurationError,
    );
  });

  it("a wire-only session cannot attest, and signApproval validates its inputs", () => {
    const tenuo = dev();
    const holder = createTenuo.publicKeyFromHolderKey(createTenuo.generateHolderKey());
    const issued = tenuo.session({ allow: { transfer: {} }, holder });
    expect(() => tenuo.attestApprovalRequest(issued, "transfer", {})).toThrow(TenuoConfigurationError);
    expect(() => createTenuo.signApproval("not-a-hash", createTenuo.generateHolderKey(), { externalId: "x" })).toThrow(
      TenuoConfigurationError,
    );
    expect(() => createTenuo.signApproval("ab".repeat(32), createTenuo.generateHolderKey(), { externalId: " " })).toThrow(
      TenuoConfigurationError,
    );
  });
});

describe("revocation lists", () => {
  it("an issuer signs a list, a verifier loads it, and the revoked session stops working", async () => {
    const controlPlane = dev();
    const holderKey = createTenuo.generateHolderKey();
    const issued = controlPlane.session({ allow: { ping: {} }, holder: createTenuo.publicKeyFromHolderKey(holderKey) });
    const [warrantId] = issued.inspect().warrantIds;
    const list = controlPlane.revocationList({ revoke: [warrantId!], version: 2 });
    const info = createTenuo.inspectRevocationList(list);
    expect(info).toMatchObject({ version: 2, revokedIds: [warrantId], issuerPublicKey: controlPlane.issuerPublicKey().hex, signatureValid: true });

    const agent = createTenuo({ trustedRoots: [controlPlane.issuerPublicKey()] });
    const ping = agent.tool({ execute: async (_args: Record<string, unknown>) => "pong" }, { capability: "ping", allow: {} });
    const mine = agent.sessionFromWire({ warrant: issued.toWire(), holderKey });
    await expect(ping.execute({}, { session: mine })).resolves.toBe("pong");
    agent.revoke(list);
    await expect(ping.execute({}, { session: mine })).rejects.toMatchObject({ code: "TENUO_REVOKED" });
  });

  it("signs with an explicit issuer secret, and verifiers refuse a list from an untrusted issuer", () => {
    const secret = createTenuo.generateIssuerKey();
    const list = createTenuo.signRevocationList({ revoke: ["tnu_wrt_0123456789abcdef"] }, secret);
    expect(createTenuo.inspectRevocationList(list).issuerPublicKey).toBe(createTenuo.publicKeyFromHolderKey(secret).hex);
    const verifier = dev();
    expect(() => verifier.revoke(list)).toThrow(/trusted root/);
    expect(() => verifier.revocationList({ revoke: [] })).toThrow(TenuoConfigurationError);
    expect(() => createTenuo({ trustedRoots: [verifier.issuerPublicKey()] }).revocationList({ revoke: ["x"] })).toThrow(
      /issuer key/,
    );
  });
});

describe("receipts", () => {
  it("verifyReceipt and verifyReceiptChain are public and camelCase", async () => {
    const tenuo = dev();
    const readFile = tenuo.tool({ execute: async ({ path }: { path: string }) => path }, { capability: "read_file", allow: {} });
    const session = tenuo.session({ allow: { read_file: { path: under("/data") } } });
    const receipts: string[] = [];
    const keep = (r: string): void => {
      receipts.push(r);
    };
    await readFile.execute({ path: "/data/a" }, { session, requestId: "req-1", onReceipt: keep });
    await expect(
      readFile.execute({ path: "/etc/passwd" }, { session, onReceipt: keep }),
    ).rejects.toBeInstanceOf(AuthorizationDeniedError);
    expect(receipts).toHaveLength(2);

    const allow = createTenuo.verifyReceipt(receipts[0]!);
    expect(allow).toMatchObject({ authentic: true, outcome: "allow", action: "read_file", requestId: "req-1" });
    expect(allow.signerKey).toMatch(hex64);
    expect(allow.trustedRootsHash).toMatch(hex64);
    const deny = createTenuo.verifyReceipt(receipts[1]!);
    expect(deny).toMatchObject({ outcome: "deny", decisionCode: expect.any(String) });

    const chain = createTenuo.verifyReceiptChain(receipts[0]!, [tenuo.issuerPublicKey()]);
    expect(chain).toMatchObject({ chainValid: true, outcome: "allow", rootIssuer: tenuo.issuerPublicKey().hex });
    const wrong = createTenuo.verifyReceiptChain(receipts[0]!, [dev().issuerPublicKey()]);
    expect(wrong.chainValid).toBe(false);
    expect(() => createTenuo.verifyReceipt("not a receipt")).toThrow(TenuoConfigurationError);
  });
});

describe("explain()", () => {
  it("reports each constrained field, unknown and missing fields, and the decision", () => {
    const tenuo = dev();
    const session = tenuo.session({
      allow: { read_file: { path: under("/data"), mode: oneOf(["r", "rw"]) } },
    });
    const ok = tenuo.explain(session, "read_file", { path: "/data/a", mode: "r" });
    expect(ok).toMatchObject({ outcome: "allow", toolGranted: true, chainValid: true, expired: false, kind: "execution" });
    expect(ok.fields.map((f) => [f.field, f.kind, f.satisfied])).toEqual([
      ["mode", "OneOf", true],
      ["path", "Subpath", true],
    ]);

    const bad = tenuo.explain(session, "read_file", { path: "/etc/passwd", mode: "r" });
    expect(bad).toMatchObject({ outcome: "deny", code: "TENUO_CONSTRAINT_VIOLATION", field: "path" });
    const pathField = bad.fields.find((f) => f.field === "path");
    expect(pathField?.satisfied).toBe(false);
    expect(pathField?.reason).toBeDefined();
    expect(pathField?.value).toBe("/etc/passwd");

    const partial = tenuo.explain(session, "read_file", { path: "/data/a", extra: 1 });
    expect(partial.unknownFields).toEqual(["extra"]);
    expect(partial.missingFields).toEqual(["mode"]);

    const wrongTool = tenuo.explain(session, "delete_file", { path: "/data/a" });
    expect(wrongTool).toMatchObject({ outcome: "deny", toolGranted: false, code: "TENUO_TOOL_NOT_AUTHORIZED" });
  });

  it("works on a session issued to another holder, since no proof-of-possession is needed", () => {
    const tenuo = dev();
    const issued = tenuo.session({
      allow: { read_file: { path: under("/data") } },
      holder: createTenuo.publicKeyFromHolderKey(createTenuo.generateHolderKey()),
    });
    expect(issued.inspect().canAuthorize).toBe(false);
    expect(tenuo.explain(issued, "read_file", { path: "/data/a" }).outcome).toBe("allow");
    expect(tenuo.explain(issued, "read_file", { path: "/x" }).outcome).toBe("deny");
  });

  it("flags a chain the verifier does not trust", () => {
    const tenuo = dev();
    const holderKey = createTenuo.generateHolderKey();
    const foreign = dev().session({ allow: { ping: {} }, holder: createTenuo.publicKeyFromHolderKey(holderKey) });
    const imported = tenuo.sessionFromWire({ warrant: foreign.toWire(), holderKey });
    const result = tenuo.explain(imported, "ping", {});
    expect(result).toMatchObject({ outcome: "deny", chainValid: false, chainError: "TENUO_UNTRUSTED_ROOT" });
  });
});

describe("present() and verify() across any boundary", () => {
  it("a presented call verifies at a service that trusts only the root, and tampering fails", async () => {
    const controlPlane = dev();
    const holderKey = createTenuo.generateHolderKey();
    const issued = controlPlane.session({
      allow: { read_file: { path: under("/data") } },
      holder: createTenuo.publicKeyFromHolderKey(holderKey),
    });
    const agent = createTenuo({ trustedRoots: [controlPlane.issuerPublicKey()] });
    const mine = agent.sessionFromWire({ warrant: issued.toWire(), holderKey });
    const service = createTenuo({ trustedRoots: [controlPlane.issuerPublicKey()] });

    const presented = agent.present(mine, "read_file", { path: "/data/q3.pdf" });
    expect(presented.warrant.length).toBeGreaterThan(0);
    expect(presented.signature.length).toBeGreaterThan(0);
    await expect(service.verify(presented, "read_file", { path: "/data/q3.pdf" })).resolves.toEqual({ path: "/data/q3.pdf" });

    await expect(service.verify(presented, "read_file", { path: "/etc/passwd" })).rejects.toMatchObject({ code: "TENUO_INVALID_POP" });
    await expect(
      service.verify(presented, "read_file", { path: "/data/q3.pdf" }, { allow: { path: under("/data/reports") } }),
    ).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" });
    expect(() => agent.present(mine, "read_file", { path: "/etc/passwd" })).toThrow(AuthorizationDeniedError);
    await expect(service.verify({ warrant: "", signature: "" }, "read_file", {})).rejects.toBeInstanceOf(TenuoConfigurationError);

    // The same envelope is what MCP carries in _meta.tenuo.
    const viaMcp = agent.mcp.attach(mine, "read_file", { path: "/data/q3.pdf" });
    await expect(service.verify(viaMcp._meta.tenuo, "read_file", viaMcp.arguments)).resolves.toEqual({ path: "/data/q3.pdf" });
  });
});
