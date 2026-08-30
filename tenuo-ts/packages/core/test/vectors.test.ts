import { describe, expect, it } from "vitest";
import { createTenuo, TenuoConfigurationError, under } from "../src/index.ts";
import {
  authorizeAsOf,
  inspectParts,
  inspectWarrant,
  signApproval,
  signRevocationList,
  sessionFromChain,
  sessionFromParts,
  sessionFromWire,
  verifierContext,
  verifyReceipt,
} from "../src/testkit.ts";
import {
  A1_BASE64,
  A1_ENVELOPE_HEX,
  A1_PAYLOAD_HEX,
  A1_SIGNATURE_HEX,
  A10_CHILD_PAYLOAD_HEX,
  A10_CHILD_SIG_HEX,
  A10_PARENT_PAYLOAD_HEX,
  A10_PARENT_SIG_HEX,
  A11_CHILD_PAYLOAD_HEX,
  A11_CHILD_SIG_HEX,
  A11_PARENT_PAYLOAD_HEX,
  A11_PARENT_SIG_HEX,
  A12_CHILD_PAYLOAD_HEX,
  A12_CHILD_SIG_HEX,
  A12_PARENT_PAYLOAD_HEX,
  A12_PARENT_SIG_HEX,
  A13_CHILD_PAYLOAD_HEX,
  A13_CHILD_SIG_HEX,
  A13_PARENT_PAYLOAD_HEX,
  A13_PARENT_SIG_HEX,
  A14_FORGED_SIG_HEX,
  A14_PAYLOAD_HEX,
  A14_VALID_SIG_HEX,
  A3_CHAIN,
  A3_L0_PAYLOAD_HEX,
  A3_L0_SIG_HEX,
  A4_CHILD_PAYLOAD_HEX,
  A4_CHILD_SIG_HEX,
  A21_1_PAYLOAD_HEX,
  A21_1_SIG_HEX,
  A21_2_PAYLOAD_HEX,
  A21_2_SIG_HEX,
  A22_CHAIN,
  A22_CHILD_ID,
  A22_CHILD_PAYLOAD_HEX,
  A22_CHILD_SIG_HEX,
  A22_ROOT_ID,
  A22_ROOT_PAYLOAD_HEX,
  A22_ROOT_SIG_HEX,
  A22B_SRL_HEX,
  A5_PAYLOAD_HEX,
  A5_SIG_HEX,
  APPROVER1_PUB,
  APPROVER1_SECRET,
  APPROVER2_PUB,
  APPROVER2_SECRET,
  APPROVER3_PUB,
  AS_OF,
  ISSUED_AT,
  ATTACKER_PUB,
  ATTACKER_SECRET,
  CONTROL_PLANE_PUB,
  CONTROL_PLANE_SECRET,
  EXPIRES_AT,
  ORCHESTRATOR_SECRET,
  WORKER2_SECRET,
  WORKER_SECRET,
} from "./vectors/spec.ts";

describe("A.1 published envelope", () => {
  it("decodes to the spec payload and signature hex", () => {
    const fromB64 = inspectWarrant(A1_BASE64);
    const fromHex = inspectWarrant(A1_ENVELOPE_HEX);
    expect(fromB64.payload_hex).toBe(A1_PAYLOAD_HEX);
    expect(fromB64.signature_hex).toBe(A1_SIGNATURE_HEX);
    expect(fromHex).toEqual(fromB64);
  });

  it("allows read_file at the published instant", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromWire(A1_BASE64, ORCHESTRATOR_SECRET);
    const decision = authorizeAsOf(ctx, session, "read_file", { path: "/data/q3.pdf" }, AS_OF);
    expect(decision).toMatchObject({ outcome: "allow", args: { path: "/data/q3.pdf" } });
  });

  it("denies an unauthorized tool at the published instant", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromWire(A1_BASE64, ORCHESTRATOR_SECRET);
    const decision = authorizeAsOf(ctx, session, "write_file", { path: "/data/q3.pdf" }, AS_OF);
    expect(decision.outcome).toBe("deny");
    expect(decision.code).toBe("TENUO_TOOL_NOT_AUTHORIZED");
  });

  it("expires against the wall clock through the public API", async () => {
    const tenuo = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(CONTROL_PLANE_PUB)],
    });
    const session = tenuo.sessionFromWire({
      warrant: A1_BASE64,
      holderKey: ORCHESTRATOR_SECRET,
    });
    let executed = false;
    const readFile = tenuo.tool(
      {
        execute: async (_args: { path: string }) => {
          executed = true;
          return "leaked";
        },
      },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/data/q3.pdf" })),
    ).rejects.toMatchObject({
      name: "AuthorizationDeniedError",
      code: "TENUO_WARRANT_EXPIRED",
    });
    expect(executed).toBe(false);
  });

  it("expires when as_of is after expires_at", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromWire(A1_ENVELOPE_HEX, ORCHESTRATOR_SECRET);
    const decision = authorizeAsOf(ctx, session, "read_file", { path: "/data/q3.pdf" }, EXPIRES_AT);
    expect(decision).toMatchObject({ outcome: "deny", code: "TENUO_WARRANT_EXPIRED" });
  });

  it("rejects a root that did not issue the warrant", () => {
    const ctx = verifierContext([ATTACKER_PUB]);
    const session = sessionFromWire(A1_BASE64, ORCHESTRATOR_SECRET);
    const decision = authorizeAsOf(ctx, session, "read_file", { path: "/data/q3.pdf" }, AS_OF);
    expect(decision).toMatchObject({ outcome: "deny", code: "TENUO_UNTRUSTED_ROOT" });
  });

  it("refuses a holder key that is not the authorized holder", () => {
    expect(() => sessionFromWire(A1_BASE64, ATTACKER_SECRET)).toThrow(/authorized holder/);
  });
});

describe("A.14 signature verification", () => {
  it("keeps payload bytes identical and only the signature different", () => {
    const forged = inspectParts(A14_PAYLOAD_HEX, A14_FORGED_SIG_HEX);
    const valid = inspectParts(A14_PAYLOAD_HEX, A14_VALID_SIG_HEX);
    expect(forged.payload_hex).toBe(A14_PAYLOAD_HEX);
    expect(valid.payload_hex).toBe(A14_PAYLOAD_HEX);
    expect(forged.signature_hex).toBe(A14_FORGED_SIG_HEX);
    expect(valid.signature_hex).toBe(A14_VALID_SIG_HEX);
    expect(forged.signature_hex).not.toBe(valid.signature_hex);
  });

  it("rejects the attacker-signed envelope", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromParts(A14_PAYLOAD_HEX, A14_FORGED_SIG_HEX, ORCHESTRATOR_SECRET);
    const decision = authorizeAsOf(ctx, session, "read_file", { path: "/data/q3.pdf" }, AS_OF);
    expect(decision).toMatchObject({ outcome: "deny", code: "TENUO_SIGNATURE_INVALID" });
  });

  it("accepts the control-plane signature under /data and denies /etc/passwd", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromParts(A14_PAYLOAD_HEX, A14_VALID_SIG_HEX, ORCHESTRATOR_SECRET);
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/data/q3.pdf" }, AS_OF),
    ).toMatchObject({ outcome: "allow" });
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/etc/passwd" }, AS_OF),
    ).toMatchObject({ outcome: "deny", code: "TENUO_CONSTRAINT_VIOLATION" });
  });
});

describe("publicKeyFromEnv", () => {
  it("fails closed when the variable is missing", () => {
    const previous = process.env.TENUO_ROOT_PUBLIC_KEY;
    delete process.env.TENUO_ROOT_PUBLIC_KEY;
    expect(() => createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY")).toThrow(
      TenuoConfigurationError,
    );
    if (previous !== undefined) {
      process.env.TENUO_ROOT_PUBLIC_KEY = previous;
    }
  });

  it("reads a hex root from the environment", () => {
    process.env.TENUO_ROOT_PUBLIC_KEY = CONTROL_PLANE_PUB;
    expect(createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY")).toEqual({
      kind: "public-key",
      source: "env",
      hex: CONTROL_PLANE_PUB,
    });
  });
});

describe("sessionFromWire through createTenuo", () => {
  it("imports A.1 and still cannot mint", () => {
    const tenuo = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(CONTROL_PLANE_PUB)],
    });
    const session = tenuo.sessionFromWire({
      warrant: A1_BASE64,
      holderKey: ORCHESTRATOR_SECRET,
    });
    expect(JSON.stringify(session)).toBe('"[TenuoSession]"');
    expect(() => tenuo.session({ allow: { read_file: { path: under("/data") } } })).toThrow(
      /local issuer/,
    );
  });
});

describe("A.3 three-level chain", () => {
  it("matches published payload and signature bytes", () => {
    const l0 = inspectParts(A3_L0_PAYLOAD_HEX, A3_L0_SIG_HEX);
    expect(l0.payload_hex).toBe(A3_L0_PAYLOAD_HEX);
    expect(l0.signature_hex).toBe(A3_L0_SIG_HEX);
  });

  it("allows only the exact leaf path at the published instant", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromChain(A3_CHAIN, WORKER2_SECRET);
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/data/reports/q3.pdf" }, AS_OF),
    ).toMatchObject({ outcome: "allow" });
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/data/reports/other.pdf" }, AS_OF),
    ).toMatchObject({ outcome: "deny", code: "TENUO_CONSTRAINT_VIOLATION" });
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/etc/passwd" }, AS_OF),
    ).toMatchObject({ outcome: "deny", code: "TENUO_CONSTRAINT_VIOLATION" });
  });

  it("expires the chain against the wall clock", async () => {
    const tenuo = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(CONTROL_PLANE_PUB)],
    });
    const session = tenuo.sessionFromWire({
      warrant: A3_CHAIN,
      holderKey: WORKER2_SECRET,
    });
    let executed = false;
    const readFile = tenuo.tool(
      {
        execute: async (_args: { path: string }) => {
          executed = true;
          return "leaked";
        },
      },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/data/reports/q3.pdf" })),
    ).rejects.toMatchObject({ code: "TENUO_WARRANT_EXPIRED" });
    expect(executed).toBe(false);
  });
});

describe("A.4 I1 issuer is not the parent holder", () => {
  it("rejects the chain", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromChain(
      [
        { payload_hex: A3_L0_PAYLOAD_HEX, signature_hex: A3_L0_SIG_HEX },
        { payload_hex: A4_CHILD_PAYLOAD_HEX, signature_hex: A4_CHILD_SIG_HEX },
      ],
      WORKER2_SECRET,
    );
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/data/q3.pdf" }, AS_OF),
    ).toMatchObject({ outcome: "deny", code: "TENUO_CHAIN_INVALID" });
  });
});

describe("A.11 I4 capability widening", () => {
  it("rejects a child that expands /data/reports/* to /data/*", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromChain(
      [
        { payload_hex: A11_PARENT_PAYLOAD_HEX, signature_hex: A11_PARENT_SIG_HEX },
        { payload_hex: A11_CHILD_PAYLOAD_HEX, signature_hex: A11_CHILD_SIG_HEX },
      ],
      WORKER_SECRET,
    );
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/data/secret" }, AS_OF),
    ).toMatchObject({ outcome: "deny", code: "TENUO_CHAIN_INVALID" });
  });
});

describe("A.5 expired warrant", () => {
  it("allows at issued_at and expires one second later", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromParts(A5_PAYLOAD_HEX, A5_SIG_HEX, ORCHESTRATOR_SECRET);
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/data/q3.pdf" }, ISSUED_AT),
    ).toMatchObject({ outcome: "allow" });
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/data/q3.pdf" }, ISSUED_AT + 1),
    ).toMatchObject({ outcome: "deny", code: "TENUO_WARRANT_EXPIRED" });
  });
});

describe("A.10 I2 depth skip", () => {
  it("rejects a child whose depth is not parent.depth + 1", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromChain(
      [
        { payload_hex: A10_PARENT_PAYLOAD_HEX, signature_hex: A10_PARENT_SIG_HEX },
        { payload_hex: A10_CHILD_PAYLOAD_HEX, signature_hex: A10_CHILD_SIG_HEX },
      ],
      WORKER_SECRET,
    );
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/data/reports/q3.pdf" }, AS_OF),
    ).toMatchObject({ outcome: "deny", code: "TENUO_CHAIN_INVALID" });
  });
});

describe("A.12 I5 parent_hash mismatch", () => {
  it("rejects a child whose parent_hash is all zeros", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromChain(
      [
        { payload_hex: A12_PARENT_PAYLOAD_HEX, signature_hex: A12_PARENT_SIG_HEX },
        { payload_hex: A12_CHILD_PAYLOAD_HEX, signature_hex: A12_CHILD_SIG_HEX },
      ],
      WORKER_SECRET,
    );
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/data/reports/q3.pdf" }, AS_OF),
    ).toMatchObject({ outcome: "deny", code: "TENUO_CHAIN_INVALID" });
  });
});

describe("A.13 I3 TTL extension", () => {
  it("rejects a child that expires after its parent", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromChain(
      [
        { payload_hex: A13_PARENT_PAYLOAD_HEX, signature_hex: A13_PARENT_SIG_HEX },
        { payload_hex: A13_CHILD_PAYLOAD_HEX, signature_hex: A13_CHILD_SIG_HEX },
      ],
      WORKER_SECRET,
    );
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/data/reports/q3.pdf" }, AS_OF),
    ).toMatchObject({ outcome: "deny", code: "TENUO_CHAIN_INVALID" });
  });
});

describe("A.21 signed approval", () => {
  it("decodes the published 2-of-3 and 2-of-2 envelopes", () => {
    expect(inspectParts(A21_1_PAYLOAD_HEX, A21_1_SIG_HEX).payload_hex).toBe(A21_1_PAYLOAD_HEX);
    expect(inspectParts(A21_1_PAYLOAD_HEX, A21_1_SIG_HEX).signature_hex).toBe(A21_1_SIG_HEX);
    expect(inspectParts(A21_2_PAYLOAD_HEX, A21_2_SIG_HEX).payload_hex).toBe(A21_2_PAYLOAD_HEX);
  });

  it("allows with two of the three published approver keys", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const args = { path: "/data/q3.pdf" };
    const session = tenuo.session({
      allow: { read_file: { path: under("/data") } },
      requireApproval: {
        approvers: [
          createTenuo.publicKeyFromHex(APPROVER1_PUB),
          createTenuo.publicKeyFromHex(APPROVER2_PUB),
          createTenuo.publicKeyFromHex(APPROVER3_PUB),
        ],
        min: 2,
      },
    });
    const a1 = signApproval(session, "read_file", args, APPROVER1_SECRET);
    const a2 = signApproval(session, "read_file", args, APPROVER2_SECRET);
    const readFile = tenuo.tool(
      { execute: async ({ path }: { path: string }) => path },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    await expect(readFile.execute(args, { session, approvals: [a1, a2] })).resolves.toBe(
      "/data/q3.pdf",
    );
  });

  it("rejects a single approval when two are required", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const args = { path: "/data/q3.pdf" };
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
    const a1 = signApproval(session, "read_file", args, APPROVER1_SECRET);
    const attacker = signApproval(session, "read_file", args, ATTACKER_SECRET);
    const readFile = tenuo.tool(
      { execute: async ({ path }: { path: string }) => path },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    await expect(readFile.execute(args, { session, approvals: [a1] })).rejects.toMatchObject({
      code: "TENUO_INSUFFICIENT_APPROVALS",
    });
    await expect(
      readFile.execute(args, { session, approvals: [a1, attacker] }),
    ).rejects.toMatchObject({ code: "TENUO_INSUFFICIENT_APPROVALS" });
  });
});

describe("A.22 cascading revocation", () => {
  it("matches published root, child, and A.22.b bytes", () => {
    const root = inspectParts(A22_ROOT_PAYLOAD_HEX, A22_ROOT_SIG_HEX);
    const child = inspectParts(A22_CHILD_PAYLOAD_HEX, A22_CHILD_SIG_HEX);
    expect(root.payload_hex).toBe(A22_ROOT_PAYLOAD_HEX);
    expect(root.signature_hex).toBe(A22_ROOT_SIG_HEX);
    expect(root.id).toBe(A22_ROOT_ID);
    expect(child.id).toBe(A22_CHILD_ID);
    expect(A22B_SRL_HEX).toHaveLength(466);
  });

  it("allows the child chain when no SRL is loaded", () => {
    const ctx = verifierContext([CONTROL_PLANE_PUB]);
    const session = sessionFromChain(A22_CHAIN, WORKER_SECRET);
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/data/q3.pdf" }, AS_OF),
    ).toMatchObject({ outcome: "allow" });
  });

  it("denies the revoked child and never runs the tool", async () => {
    const tenuo = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromHex(CONTROL_PLANE_PUB)],
      revocationList: A22B_SRL_HEX,
    });
    const session = tenuo.sessionFromWire({
      warrant: A22_CHAIN,
      holderKey: WORKER_SECRET,
    });
    let executed = false;
    const readFile = tenuo.tool(
      {
        execute: async (_args: { path: string }) => {
          executed = true;
          return "leaked";
        },
      },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    const decision = authorizeAsOf(
      verifierContext([CONTROL_PLANE_PUB], { revocationList: A22B_SRL_HEX }),
      session,
      "read_file",
      { path: "/data/q3.pdf" },
      AS_OF,
    );
    expect(decision).toMatchObject({ outcome: "deny", code: "TENUO_REVOKED" });
    expect(decision.receipt).toEqual(expect.any(String));
    const receipt = verifyReceipt(decision.receipt!);
    expect(receipt).toMatchObject({
      authentic: true,
      outcome: "deny",
      decision_code: "warrant-revoked",
    });

    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/data/q3.pdf" })),
    ).rejects.toMatchObject({
      name: "AuthorizationDeniedError",
      code: "TENUO_REVOKED",
    });
    expect(executed).toBe(false);
  });

  it("cascades when the parent is revoked", () => {
    const srl = signRevocationList(CONTROL_PLANE_SECRET, [A22_ROOT_ID]);
    const ctx = verifierContext([CONTROL_PLANE_PUB], { revocationList: srl });
    const session = sessionFromChain(A22_CHAIN, WORKER_SECRET);
    expect(
      authorizeAsOf(ctx, session, "read_file", { path: "/data/q3.pdf" }, AS_OF),
    ).toMatchObject({ outcome: "deny", code: "TENUO_REVOKED" });
  });

  it("rejects an SRL that is not signed by a trusted root", () => {
    const forged = signRevocationList(ATTACKER_SECRET, [A22_CHILD_ID]);
    expect(() => verifierContext([CONTROL_PLANE_PUB], { revocationList: forged })).toThrow(
      /trusted root/,
    );
  });
});
