/**
 * Delegation across agents with separate holder keys.
 *
 * The scenario is a control plane that issues to an orchestrator, which hands
 * narrower authority down a chain of workers. Every hop is a different key.
 * Nothing here needs the Python SDK or a network.
 */
import { describe, expect, it } from "vitest";
import {
  AuthorizationDeniedError,
  createTenuo,
  max,
  oneOf,
  pattern,
  TenuoConfigurationError,
  under,
} from "../src/index.ts";
import type { Session, Tenuo } from "../src/index.ts";

const hex64 = /^[0-9a-f]{64}$/;

/** A control plane plus N agents that trust only its key. */
function fleet(agentNames: readonly string[]) {
  const controlPlane = createTenuo({ root: createTenuo.devRoot() });
  const root = controlPlane.issuerPublicKey();
  const agents = new Map<
    string,
    { tenuo: Tenuo; holderKey: Uint8Array; publicKey: ReturnType<typeof createTenuo.publicKeyFromHolderKey> }
  >();
  for (const name of agentNames) {
    const holderKey = createTenuo.generateHolderKey();
    agents.set(name, {
      tenuo: createTenuo({ trustedRoots: [root] }),
      holderKey,
      publicKey: createTenuo.publicKeyFromHolderKey(holderKey),
    });
  }
  const agent = (name: string) => {
    const found = agents.get(name);
    if (found === undefined) {
      throw new Error(`no agent ${name}`);
    }
    return found;
  };
  /** What an agent does on receipt: import the handed-over chain with its own key. */
  const receive = (name: string, handed: Session): Session =>
    agent(name).tenuo.sessionFromWire({ warrant: handed.toWire(), holderKey: agent(name).holderKey });
  return { controlPlane, root, agent, receive };
}

describe("holder keys", () => {
  it("generates distinct 32-byte secrets and derives their public keys deterministically", () => {
    const a = createTenuo.generateHolderKey();
    const b = createTenuo.generateHolderKey();
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a).toHaveLength(32);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);

    const pubA = createTenuo.publicKeyFromHolderKey(a);
    expect(pubA.kind).toBe("public-key");
    expect(pubA.hex).toMatch(hex64);
    expect(createTenuo.publicKeyFromHolderKey(a).hex).toBe(pubA.hex);
    expect(createTenuo.publicKeyFromHolderKey(b).hex).not.toBe(pubA.hex);
    // The secret never appears in the public half.
    expect(pubA.hex).not.toBe(Buffer.from(a).toString("hex"));
  });

  it("rejects a holder key that is not 32 bytes", () => {
    expect(() => createTenuo.publicKeyFromHolderKey(new Uint8Array(31))).toThrow(TenuoConfigurationError);
  });
});

describe("issuerPublicKey", () => {
  it("is the root other processes must trust, and a verifier context has none", () => {
    const controlPlane = createTenuo({ root: createTenuo.devRoot() });
    const root = controlPlane.issuerPublicKey();
    expect(root.kind).toBe("public-key");
    expect(root.hex).toMatch(hex64);
    expect(controlPlane.issuerPublicKey().hex).toBe(root.hex);

    const verifier = createTenuo({ trustedRoots: [root] });
    expect(() => verifier.issuerPublicKey()).toThrow(TenuoConfigurationError);
  });

  it("a warrant from a different issuer is untrusted even with the right holder key", async () => {
    const { controlPlane, agent, receive } = fleet(["worker"]);
    const worker = agent("worker");
    const readFile = worker.tenuo.tool(
      { execute: async ({ path }: { path: string }) => `ok:${path}` },
      { capability: "read_file", allow: {} },
    );

    const good = controlPlane.session({
      allow: { read_file: { path: under("/data") } },
      holder: worker.publicKey,
    });
    await expect(
      worker.tenuo.withSession(receive("worker", good), () => readFile.execute({ path: "/data/a" })),
    ).resolves.toBe("ok:/data/a");

    // A rogue process mints its own root for the same worker key.
    const rogue = createTenuo({ root: createTenuo.devRoot() });
    const forged = rogue.session({
      allow: { read_file: { path: under("/") } },
      holder: worker.publicKey,
    });
    await expect(
      worker.tenuo.withSession(receive("worker", forged), () => readFile.execute({ path: "/etc/passwd" })),
    ).rejects.toMatchObject({ code: "TENUO_UNTRUSTED_ROOT" });
  });
});

describe("session({ holder })", () => {
  it("issues to another agent's key: wire-only here, usable there", async () => {
    const { controlPlane, agent, receive } = fleet(["worker"]);
    const worker = agent("worker");

    const issued = controlPlane.session({
      allow: { read_file: { path: under("/data") } },
      holder: worker.publicKey,
      ttlSeconds: 60,
    });
    const info = issued.inspect();
    expect(info.canAuthorize).toBe(false);
    expect(info.holderPublicKey).toBe(worker.publicKey.hex);
    expect(info.rootPublicKey).toBe(controlPlane.issuerPublicKey().hex);
    expect(info.depth).toBe(0);
    expect(info.tools).toEqual(["read_file"]);
    expect(issued.toWire()).toHaveLength(1);

    // The issuer holds no secret for it and cannot act as the worker.
    const cpTool = controlPlane.tool(
      { execute: async ({ path }: { path: string }) => `leak:${path}` },
      { capability: "read_file", allow: {} },
    );
    await expect(
      controlPlane.withSession(issued, () => cpTool.execute({ path: "/data/a" })),
    ).rejects.toMatchObject({ code: "TENUO_CONFIGURATION", message: expect.stringMatching(/another holder/) });
    expect(() => controlPlane.narrow(issued, { path: under("/data/x") })).toThrow(
      expect.objectContaining({ name: "TenuoConfigurationError", message: expect.stringMatching(/holder key/) }),
    );

    // The worker imports it with its own key and it works, within scope.
    const mine = receive("worker", issued);
    expect(mine.inspect().canAuthorize).toBe(true);
    const readFile = worker.tenuo.tool(
      { execute: async ({ path }: { path: string }) => `ok:${path}` },
      { capability: "read_file", allow: {} },
    );
    await expect(
      worker.tenuo.withSession(mine, () => readFile.execute({ path: "/data/q3.pdf" })),
    ).resolves.toBe("ok:/data/q3.pdf");
    await expect(
      worker.tenuo.withSession(mine, () => readFile.execute({ path: "/etc/passwd" })),
    ).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" });
  });

  it("rejects a holder that is not a public key handle", () => {
    const controlPlane = createTenuo({ root: createTenuo.devRoot() });
    expect(() =>
      controlPlane.session({
        allow: { read_file: { path: under("/data") } },
        holder: { hex: "ab".repeat(32) } as never,
      }),
    ).toThrow(TenuoConfigurationError);
  });
});

describe("a copied warrant is not authority", () => {
  it("cannot be imported with a different holder key", () => {
    const { controlPlane, agent } = fleet(["boarding", "activity"]);
    const boarding = agent("boarding");
    const activity = agent("activity");
    const issued = controlPlane.session({
      allow: { issue_boarding_pass: { reservation: oneOf(["UA214"]) } },
      holder: boarding.publicKey,
    });
    const tokens = issued.toWire();

    // The rightful holder is fine.
    expect(() =>
      boarding.tenuo.sessionFromWire({ warrant: tokens, holderKey: boarding.holderKey }),
    ).not.toThrow();

    // Same bytes, valid, unexpired, correctly scoped — and useless to anyone else.
    expect(() =>
      activity.tenuo.sessionFromWire({ warrant: tokens, holderKey: activity.holderKey }),
    ).toThrow(
      expect.objectContaining({
        name: "AuthorizationDeniedError",
        code: "TENUO_INVALID_POP",
        message: expect.stringMatching(/not authority/),
      }),
    );
  });
});

describe("narrow({ holder }): delegation down a chain of agents", () => {
  const AGENTS = ["travel", "flight", "checkin", "boarding"] as const;

  function bookingChain() {
    const f = fleet(AGENTS);
    const { controlPlane, agent, receive } = f;

    // Root carries everything anyone below will need. A child can never hold
    // what its parent lacks, so the closure lives at the top.
    const trip = controlPlane.session({
      allow: {
        book_flight: { destination: oneOf(["CUN"]), price: max(300) },
        get_reservation: { reservation: oneOf(["UA214", "AC712"]) },
        check_in: { reservation: oneOf(["UA214", "AC712"]) },
        issue_boarding_pass: { reservation: oneOf(["UA214", "AC712"]) },
        "wallet.charge": { amount: max(1200) },
      },
      holder: agent("travel").publicKey,
      ttlSeconds: 30 * 60,
      maxDepth: 4,
    });

    const travel = receive("travel", trip);
    const flightHanded = agent("travel").tenuo.narrow(
      travel,
      {
        book_flight: { destination: oneOf(["CUN"]), price: max(300) },
        get_reservation: { reservation: oneOf(["UA214", "AC712"]) },
        check_in: { reservation: oneOf(["UA214", "AC712"]) },
        issue_boarding_pass: { reservation: oneOf(["UA214", "AC712"]) },
        "wallet.charge": { amount: max(300) },
      },
      { holder: agent("flight").publicKey, ttlSeconds: 10 * 60 },
    );

    // Flight Agent books UA214 and is the one that knows which reservation.
    const flight = receive("flight", flightHanded);
    const checkinHanded = agent("flight").tenuo.narrow(
      flight,
      {
        get_reservation: { reservation: oneOf(["UA214"]) },
        check_in: { reservation: oneOf(["UA214"]) },
        issue_boarding_pass: { reservation: oneOf(["UA214"]) },
      },
      { holder: agent("checkin").publicKey, ttlSeconds: 5 * 60 },
    );

    const checkin = receive("checkin", checkinHanded);
    const boardingHanded = agent("checkin").tenuo.narrow(
      checkin,
      { issue_boarding_pass: { reservation: oneOf(["UA214"]) } },
      { holder: agent("boarding").publicKey, ttlSeconds: 2 * 60 },
    );
    const boarding = receive("boarding", boardingHanded);

    return { ...f, trip, travel, flight, checkin, boarding, checkinHanded, boardingHanded };
  }

  it("each hop is a different key and each leaf holds only its slice", async () => {
    const { agent, travel, flight, checkin, boarding } = bookingChain();

    expect(travel.inspect()).toMatchObject({ depth: 0, holderPublicKey: agent("travel").publicKey.hex });
    expect(flight.inspect()).toMatchObject({ depth: 1, holderPublicKey: agent("flight").publicKey.hex });
    expect(checkin.inspect()).toMatchObject({ depth: 2, holderPublicKey: agent("checkin").publicKey.hex });
    expect(boarding.inspect()).toMatchObject({
      depth: 3,
      holderPublicKey: agent("boarding").publicKey.hex,
      tools: ["issue_boarding_pass"],
      canAuthorize: true,
    });
    expect(boarding.inspect().warrantIds).toHaveLength(4);
    expect(boarding.toWire()).toHaveLength(4);

    const issuePass = agent("boarding").tenuo.tool(
      { execute: async ({ reservation }: { reservation: string }) => `pass:${reservation}` },
      { capability: "issue_boarding_pass", allow: {} },
    );
    await expect(
      agent("boarding").tenuo.withSession(boarding, () => issuePass.execute({ reservation: "UA214" })),
    ).resolves.toBe("pass:UA214");
    await expect(
      agent("boarding").tenuo.withSession(boarding, () => issuePass.execute({ reservation: "AA882" })),
    ).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" });

    // Boarding Agent did not inherit check-in authority from the handoff.
    const checkIn = agent("boarding").tenuo.tool(
      { execute: async (_args: { reservation: string }) => "checked in" },
      { capability: "check_in", allow: {} },
    );
    await expect(
      agent("boarding").tenuo.withSession(boarding, () => checkIn.execute({ reservation: "UA214" })),
    ).rejects.toMatchObject({ code: "TENUO_TOOL_NOT_AUTHORIZED" });
  });

  it("the delegator cannot act as the delegate after handing off", async () => {
    const { agent, checkin, boardingHanded } = bookingChain();
    expect(boardingHanded.inspect().canAuthorize).toBe(false);
    const issuePass = agent("checkin").tenuo.tool(
      { execute: async (_args: { reservation: string }) => "pass" },
      { capability: "issue_boarding_pass", allow: {} },
    );
    await expect(
      agent("checkin").tenuo.withSession(boardingHanded, () => issuePass.execute({ reservation: "UA214" })),
    ).rejects.toMatchObject({ code: "TENUO_CONFIGURATION" });
    // Its own session still works for its own job.
    const checkIn = agent("checkin").tenuo.tool(
      { execute: async ({ reservation }: { reservation: string }) => `in:${reservation}` },
      { capability: "check_in", allow: {} },
    );
    await expect(
      agent("checkin").tenuo.withSession(checkin, () => checkIn.execute({ reservation: "UA214" })),
    ).resolves.toBe("in:UA214");
  });

  it("refuses to delegate more than the delegator holds, before any token exists", () => {
    const { agent, checkin } = bookingChain();
    const escalate = () =>
      agent("checkin").tenuo.narrow(
        checkin,
        {
          get_reservation: { reservation: pattern("*") },
          check_in: { reservation: pattern("*") },
          cancel_reservation: {},
        },
        { holder: agent("boarding").publicKey },
      );
    expect(escalate).toThrow(AuthorizationDeniedError);
    expect(escalate).toThrow(expect.objectContaining({ code: "TENUO_CHAIN_INVALID" }));

    // Widening a single constraint is enough to be refused.
    expect(() =>
      agent("checkin").tenuo.narrow(
        checkin,
        { check_in: { reservation: oneOf(["UA214", "DL331"]) } },
        { holder: agent("boarding").publicKey },
      ),
    ).toThrow(expect.objectContaining({ code: "TENUO_CHAIN_INVALID" }));

    // Adding a tool the parent never had is refused the same way.
    expect(() =>
      agent("checkin").tenuo.narrow(
        checkin,
        { check_in: { reservation: oneOf(["UA214"]) }, cancel_reservation: {} },
        { holder: agent("boarding").publicKey },
      ),
    ).toThrow(expect.objectContaining({ code: "TENUO_CHAIN_INVALID" }));

    // The parent is untouched.
    expect(checkin.inspect().depth).toBe(2);
  });

  it("a child lifetime never outlives the parent", () => {
    const { agent, checkin, boardingHanded } = bookingChain();
    expect(boardingHanded.inspect().expiresAt).toBeLessThanOrEqual(checkin.inspect().expiresAt);
    const longer = agent("checkin").tenuo.narrow(
      checkin,
      { issue_boarding_pass: { reservation: oneOf(["UA214"]) } },
      { holder: agent("boarding").publicKey, ttlSeconds: 24 * 3600 },
    );
    expect(longer.inspect().expiresAt).toBeLessThanOrEqual(checkin.inspect().expiresAt);
  });

  it("the same identity can hold two different task chains at once", async () => {
    const { controlPlane, agent, receive } = fleet(["checkin"]);
    const checkin = agent("checkin");
    const forTask = (reservation: string) =>
      receive(
        "checkin",
        controlPlane.session({
          allow: { check_in: { reservation: oneOf([reservation]) } },
          holder: checkin.publicKey,
        }),
      );
    const alice = forTask("UA214");
    const bob = forTask("DL331");
    const checkIn = checkin.tenuo.tool(
      { execute: async ({ reservation }: { reservation: string }) => `in:${reservation}` },
      { capability: "check_in", allow: {} },
    );
    await expect(checkIn.execute({ reservation: "UA214" }, { session: alice })).resolves.toBe("in:UA214");
    await expect(checkIn.execute({ reservation: "DL331" }, { session: bob })).resolves.toBe("in:DL331");
    await expect(checkIn.execute({ reservation: "DL331" }, { session: alice })).rejects.toMatchObject({
      code: "TENUO_CONSTRAINT_VIOLATION",
    });
    await expect(checkIn.execute({ reservation: "UA214" }, { session: bob })).rejects.toMatchObject({
      code: "TENUO_CONSTRAINT_VIOLATION",
    });
  });

  it("narrow without a holder keeps the current holder, as before", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({ allow: { read_file: { path: under("/data") } } });
    const reports = tenuo.narrow(session, { path: under("/data/reports") });
    expect(reports.inspect().canAuthorize).toBe(true);
    expect(reports.inspect().holderPublicKey).toBe(session.inspect().holderPublicKey);
    expect(reports.inspect().depth).toBe(1);
  });

  it("narrowing to the holder you already are keeps the secret", () => {
    const { controlPlane, agent, receive } = fleet(["worker"]);
    const worker = agent("worker");
    const mine = receive(
      "worker",
      controlPlane.session({ allow: { read_file: { path: under("/data") } }, holder: worker.publicKey }),
    );
    const again = worker.tenuo.narrow(mine, { path: under("/data/x") }, { holder: worker.publicKey });
    expect(again.inspect().canAuthorize).toBe(true);
  });

  it("rejects unknown narrow options instead of silently keeping the holder", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({ allow: { read_file: { path: under("/data") } } });
    expect(() =>
      tenuo.narrow(session, { path: under("/data/x") }, { holderKey: "ab".repeat(32) } as never),
    ).toThrow(expect.objectContaining({ name: "TenuoConfigurationError", message: expect.stringMatching(/holderKey/) }));
    expect(() => tenuo.narrow(session, { path: under("/data/x") }, { ttlSeconds: 0 })).toThrow(
      TenuoConfigurationError,
    );
    expect(() => tenuo.narrow(session, { path: under("/data/x") }, { terminal: true, maxDepth: 1 })).toThrow(
      TenuoConfigurationError,
    );
  });
});

describe("terminal and maxDepth", () => {
  it("a terminal child cannot delegate, and the restriction was decided one hop up", () => {
    const { controlPlane, agent, receive } = fleet(["flight", "checkin", "boarding"]);
    const flight = receive(
      "flight",
      controlPlane.session({
        allow: { check_in: { reservation: oneOf(["UA214"]) } },
        holder: agent("flight").publicKey,
      }),
    );
    const handed = agent("flight").tenuo.narrow(
      flight,
      { check_in: { reservation: oneOf(["UA214"]) } },
      { holder: agent("checkin").publicKey, terminal: true },
    );
    expect(handed.inspect().terminal).toBe(true);
    expect(handed.inspect().maxDepth).toBe(1);

    const checkin = receive("checkin", handed);
    expect(checkin.inspect().terminal).toBe(true);
    const onward = () =>
      agent("checkin").tenuo.narrow(
        checkin,
        { check_in: { reservation: oneOf(["UA214"]) } },
        { holder: agent("boarding").publicKey },
      );
    expect(onward).toThrow(AuthorizationDeniedError);
    expect(onward).toThrow(expect.objectContaining({ code: "TENUO_DEPTH_EXCEEDED" }));

    // Relaxing it at the hop above restores the handoff.
    const relaxed = receive(
      "checkin",
      agent("flight").tenuo.narrow(
        flight,
        { check_in: { reservation: oneOf(["UA214"]) } },
        { holder: agent("checkin").publicKey },
      ),
    );
    expect(relaxed.inspect().terminal).toBe(false);
    expect(() =>
      agent("checkin").tenuo.narrow(
        relaxed,
        { check_in: { reservation: oneOf(["UA214"]) } },
        { holder: agent("boarding").publicKey },
      ),
    ).not.toThrow();
  });

  it("the root's maxDepth caps how far authority travels, and can only shrink", () => {
    const { controlPlane, agent, receive } = fleet(["a", "b", "c"]);
    const root = controlPlane.session({
      allow: { read_file: { path: under("/data") } },
      holder: agent("a").publicKey,
      maxDepth: 1,
    });
    expect(root.inspect()).toMatchObject({ depth: 0, maxDepth: 1, terminal: false });

    const a = receive("a", root);
    const toB = agent("a").tenuo.narrow(a, { path: under("/data/b") }, { holder: agent("b").publicKey });
    expect(toB.inspect()).toMatchObject({ depth: 1, maxDepth: 1, terminal: true });

    const b = receive("b", toB);
    expect(() =>
      agent("b").tenuo.narrow(b, { path: under("/data/b/c") }, { holder: agent("c").publicKey }),
    ).toThrow(expect.objectContaining({ code: "TENUO_DEPTH_EXCEEDED" }));

    // An intermediate cannot raise the ceiling it inherited.
    expect(() =>
      agent("a").tenuo.narrow(a, { path: under("/data/b") }, { holder: agent("b").publicKey, maxDepth: 3 }),
    ).toThrow(expect.objectContaining({ code: "TENUO_CHAIN_INVALID" }));
    // It can lower it.
    expect(
      agent("a").tenuo.narrow(a, { path: under("/data/b") }, { holder: agent("b").publicKey, maxDepth: 1 })
        .inspect().maxDepth,
    ).toBe(1);
  });

  it("maxDepth 0 is a terminal root", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const session = tenuo.session({ allow: { read_file: { path: under("/data") } }, maxDepth: 0 });
    expect(session.inspect().terminal).toBe(true);
    expect(() => tenuo.narrow(session, { path: under("/data/x") })).toThrow(
      expect.objectContaining({ code: "TENUO_DEPTH_EXCEEDED" }),
    );
    expect(() => tenuo.session({ allow: { read_file: { path: under("/data") } }, maxDepth: -1 })).toThrow(
      TenuoConfigurationError,
    );
    expect(() => tenuo.session({ allow: { read_file: { path: under("/data") } }, maxDepth: 1000 })).toThrow(
      TenuoConfigurationError,
    );
  });
});

describe("numeric security boundaries", () => {
  const invalidDepths = [
    -1,
    1.5,
    65,
    2 ** 32,
    2 ** 32 + 64,
    Number.MAX_SAFE_INTEGER,
    Number.NaN,
    Number.POSITIVE_INFINITY,
  ];

  it.each(invalidDepths)("rejects session maxDepth=%s before WASM can coerce it", (maxDepth) => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    expect(() =>
      tenuo.session({ allow: { read_file: { path: under("/data") } }, maxDepth }),
    ).toThrow(TenuoConfigurationError);
  });

  it.each(invalidDepths)("rejects narrow maxDepth=%s without changing the parent", (maxDepth) => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const parent = tenuo.session({ allow: { read_file: { path: under("/data") } } });
    const before = parent.toWire();

    expect(() =>
      tenuo.narrow(parent, { path: under("/data/reports") }, { maxDepth }),
    ).toThrow(TenuoConfigurationError);
    expect(parent.toWire()).toEqual(before);
    expect(parent.inspect()).toMatchObject({ depth: 0, maxDepth: 64, terminal: false });
  });

  it.each([
    -1,
    1.5,
    90 * 24 * 60 * 60 + 1,
    2 ** 32,
    Number.MAX_SAFE_INTEGER,
    Number.NaN,
    Number.POSITIVE_INFINITY,
  ])(
    "rejects session ttlSeconds=%s before WASM can coerce it",
    (ttlSeconds) => {
      const tenuo = createTenuo({ root: createTenuo.devRoot() });
      expect(() =>
        tenuo.session({ allow: { read_file: { path: under("/data") } }, ttlSeconds }),
      ).toThrow(TenuoConfigurationError);
    },
  );

  it.each([
    0,
    -1,
    1.5,
    90 * 24 * 60 * 60 + 1,
    2 ** 32,
    Number.MAX_SAFE_INTEGER,
    Number.NaN,
    Number.POSITIVE_INFINITY,
  ])(
    "rejects narrow ttlSeconds=%s without changing the parent",
    (ttlSeconds) => {
      const tenuo = createTenuo({ root: createTenuo.devRoot() });
      const parent = tenuo.session({ allow: { read_file: { path: under("/data") } } });
      const before = parent.toWire();

      expect(() =>
        tenuo.narrow(parent, { path: under("/data/reports") }, { ttlSeconds }),
      ).toThrow(TenuoConfigurationError);
      expect(parent.toWire()).toEqual(before);
      expect(parent.inspect().depth).toBe(0);
    },
  );

  it("accepts the exact protocol and WASM boundaries", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const root = tenuo.session({
      allow: { read_file: { path: under("/data") } },
      ttlSeconds: 90 * 24 * 60 * 60,
      maxDepth: 64,
    });
    expect(root.inspect()).toMatchObject({ depth: 0, maxDepth: 64, terminal: false });

    const child = tenuo.narrow(
      root,
      { path: under("/data/reports") },
      { ttlSeconds: 90 * 24 * 60 * 60 },
    );
    expect(child.inspect().expiresAt).toBeLessThanOrEqual(root.inspect().expiresAt);
  });
});

describe("inspect()", () => {
  it("reports the leaf without the secret", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const before = Math.floor(Date.now() / 1000);
    const session = tenuo.session({
      allow: { read_file: { path: under("/data") }, send_email: { to: pattern("*@example.com") } },
      ttlSeconds: 120,
    });
    const info = session.inspect();
    expect(info.holderPublicKey).toMatch(hex64);
    expect(info.rootPublicKey).toBe(tenuo.issuerPublicKey().hex);
    expect(info.depth).toBe(0);
    expect(info.terminal).toBe(false);
    expect(info.tools).toEqual(["read_file", "send_email"]);
    expect(info.warrantIds).toHaveLength(1);
    expect(info.canAuthorize).toBe(true);
    expect(info.expiresAt).toBeGreaterThanOrEqual(before + 119);
    expect(info.expiresAt).toBeLessThanOrEqual(before + 122);
    expect(JSON.stringify(info)).not.toContain("secret");
  });
});

describe("delegated sessions over the MCP wire", () => {
  it("a rebound holder's proof-of-possession verifies at a server that trusts only the root", async () => {
    const { controlPlane, root, agent, receive } = fleet(["orchestrator", "worker"]);
    const orchestrator = receive(
      "orchestrator",
      controlPlane.session({
        allow: { read_file: { path: under("/data") } },
        holder: agent("orchestrator").publicKey,
      }),
    );
    const worker = receive(
      "worker",
      agent("orchestrator").tenuo.narrow(
        orchestrator,
        { path: under("/data/reports") },
        { holder: agent("worker").publicKey },
      ),
    );
    const server = createTenuo({ trustedRoots: [root] });
    const call = agent("worker").tenuo.mcp.attach(worker, "read_file", { path: "/data/reports/q3.pdf" });
    await expect(server.mcp.verify(call.name, call.arguments, call._meta)).resolves.toEqual({
      path: "/data/reports/q3.pdf",
    });
    expect(() =>
      agent("worker").tenuo.mcp.attach(worker, "read_file", { path: "/data/other.txt" }),
    ).toThrow(expect.objectContaining({ code: "TENUO_CONSTRAINT_VIOLATION" }));
  });
});
