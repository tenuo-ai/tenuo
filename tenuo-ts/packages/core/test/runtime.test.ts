import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import {
  createTenuo,
  TenuoConfigurationError,
  under,
} from "../src/index.ts";
import { verifyReceipt } from "../src/testkit.ts";

function encodeToken(payload: Record<string, unknown>, padded = false): string {
  const json = JSON.stringify(payload);
  const encoded = Buffer.from(json).toString("base64url");
  const body = padded ? encoded + "=".repeat((4 - (encoded.length % 4)) % 4) : encoded;
  return `tenuo_ct_${body}`;
}

describe("parseConnectToken", () => {
  it("parses a hosted absolute token and strips /v1", () => {
    const token = createTenuo.parseConnectToken(
      encodeToken({
        v: 1,
        e: "https://control.example.com/v1/",
        k: "tc_secret",
        a: "agt_1",
        t: "tok_1",
      }),
    );
    expect(token.version).toBe(1);
    expect(token.endpoint).toBe("https://control.example.com");
    expect(token.apiKey).toBe("tc_secret");
    expect(token.agentId).toBe("agt_1");
    expect(token.registrationToken).toBe("tok_1");
    expect(token.needsEndpointBase).toBe(false);
    expect(JSON.stringify(token)).not.toContain("tc_secret");
    expect(JSON.stringify(token)).not.toContain("tok_1");
    expect(inspect(token)).not.toContain("tc_secret");
    expect(inspect(token)).not.toContain("tok_1");
    expect(JSON.stringify({ ...token })).not.toContain("tc_secret");
    expect(Object.entries(token).flat().join()).not.toContain("tc_secret");
    expect(JSON.stringify(structuredClone(token))).not.toContain("tc_secret");
  });

  it("joins a remaining relative path onto localBase", () => {
    const token = createTenuo.parseConnectToken(
      encodeToken({ v: 1, e: "/api/v1", k: "tc_secret" }),
    );
    expect(token.endpoint).toBe("/api");
    token.resolveEndpoint({ localBase: "https://control.example.com" });
    expect(token.endpoint).toBe("https://control.example.com/api");
  });

  it("accepts padded Base64URL and the registration-token aliases", () => {
    const raw = encodeToken(
      { v: 1, e: "https://control.example.com/v1", k: "tc_secret", r: "alias-token" },
      true,
    );
    expect(createTenuo.parseConnectToken(raw).registrationToken).toBe("alias-token");
    const named = encodeToken({
      v: 1,
      e: "https://control.example.com/v1",
      k: "tc_secret",
      registration_token: "named-token",
    });
    expect(createTenuo.parseConnectToken(named).registrationToken).toBe("named-token");
  });

  it("rejects a missing version and any version other than 1", () => {
    expect(() =>
      createTenuo.parseConnectToken(
        encodeToken({ e: "https://control.example.com/v1", k: "tc_secret" }),
      ),
    ).toThrow(/version/i);
    expect(() =>
      createTenuo.parseConnectToken(
        encodeToken({ v: 2, e: "https://control.example.com", k: "tc_secret" }),
      ),
    ).toThrow(/version 2 is not supported/);
    expect(() =>
      createTenuo.parseConnectToken(
        encodeToken({ v: 0, e: "https://control.example.com", k: "tc_secret" }),
      ),
    ).toThrow(/version 0 is not supported/);
  });

  it("rejects a missing prefix, bad payload, and empty required fields", () => {
    expect(() => createTenuo.parseConnectToken("not-a-token")).toThrow(/tenuo_ct_/);
    expect(() => createTenuo.parseConnectToken("tenuo_ct_????")).toThrow(/Base64URL/);
    expect(() =>
      createTenuo.parseConnectToken(encodeToken({ v: 1, e: "", k: "tc_secret" })),
    ).toThrow(/endpoint/);
    expect(() =>
      createTenuo.parseConnectToken(encodeToken({ v: 1, e: "https://control.example.com", k: "" })),
    ).toThrow(/api_key/);
  });

  it("leaves loopback and scheme-less hosted endpoints unchanged", () => {
    expect(
      createTenuo.parseConnectToken(encodeToken({ v: 1, e: "http://127.0.0.1:8080/v1", k: "k" }))
        .endpoint,
    ).toBe("http://127.0.0.1:8080");
    expect(
      createTenuo.parseConnectToken(encodeToken({ v: 1, e: "localhost:8080/v1", k: "k" })).endpoint,
    ).toBe("localhost:8080");
    expect(
      createTenuo.parseConnectToken(encodeToken({ v: 1, e: "control.example.com/v1", k: "k" }))
        .endpoint,
    ).toBe("control.example.com");
  });

  it("resolves a relative /v1 token only when the caller supplies a base", () => {
    const token = createTenuo.parseConnectToken(encodeToken({ v: 1, e: "/v1", k: "k" }));
    expect(token.needsEndpointBase).toBe(true);
    expect(token.endpoint).toBe("");
    expect(() => token.resolveEndpoint()).toThrow(/localBase/);
    expect(() => token.resolveEndpoint({ localBase: "/v1" })).toThrow(/localBase/);
    token.resolveEndpoint({ localBase: "https://control.example.com/v1" });
    expect(token.endpoint).toBe("https://control.example.com");
    expect(token.needsEndpointBase).toBe(false);
    token.resolveEndpoint({ localBase: "https://other.example" });
    expect(token.endpoint).toBe("https://control.example.com");
  });

  it("does not read environment variables while parsing", () => {
    const previous = process.env.TENUO_API_URL;
    process.env.TENUO_API_URL = "https://should-not-be-used.example";
    try {
      const token = createTenuo.parseConnectToken(encodeToken({ v: 1, e: "/v1", k: "k" }));
      expect(token.endpoint).toBe("");
    } finally {
      if (previous === undefined) {
        delete process.env.TENUO_API_URL;
      } else {
        process.env.TENUO_API_URL = previous;
      }
    }
  });
});

describe("HolderIdentity", () => {
  it("generates and imports a key without leaking the secret", () => {
    const identity = createTenuo.generateIdentity();
    expect(identity.holderKey).toHaveLength(32);
    expect(identity.publicKey.hex).toMatch(/^[0-9a-f]{64}$/);
    const imported = createTenuo.identity(identity.holderKey);
    expect(imported.publicKey.hex).toBe(identity.publicKey.hex);
    expect(JSON.stringify(identity)).not.toContain(Buffer.from(identity.holderKey).toString("hex"));
    expect(String(identity)).toMatch(/^TenuoIdentity\([0-9a-f]{8}…\)$/);
    expect(inspect(identity)).not.toContain(Buffer.from(identity.holderKey).toString("hex"));
    expect(() => createTenuo.identity(new Uint8Array(16))).toThrow(/32-byte/);
  });
});

describe("Runtime", () => {
  function issuedRuntime() {
    const identity = createTenuo.generateIdentity();
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const minted = issuer.session({
      allow: { read_file: { path: under("/data") } },
      holder: identity.publicKey,
    });
    const runtime = createTenuo.runtime({
      identity,
      trustedRoots: [issuer.issuerPublicKey()],
      receipts: "collect",
    });
    const session = runtime.sessionFromWire(minted.toWire());
    const readFile = runtime.tenuo.tool(
      { execute: async ({ path }: { path: string }) => `ok:${path}` },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    return { identity, issuer, runtime, session, readFile };
  }

  it("creates a session from a wire warrant and applies a revocation list", async () => {
    const { issuer, runtime, session, readFile } = issuedRuntime();
    await expect(readFile.execute({ path: "/data/q3.pdf" }, { session })).resolves.toBe(
      "ok:/data/q3.pdf",
    );
    const srl = issuer.revocationList({ revoke: session.inspect().warrantIds, version: 3 });
    runtime.applyRevocationList(srl);
    await expect(readFile.execute({ path: "/data/q3.pdf" }, { session })).rejects.toMatchObject({
      code: "TENUO_REVOKED",
    });
  });

  it("collects allow and deny receipts in order, isolated per session, without repeats", async () => {
    const { runtime, session, readFile, issuer, identity } = issuedRuntime();
    const other = issuer.session({
      allow: { read_file: { path: under("/data") } },
      holder: identity.publicKey,
    });
    const otherSession = runtime.sessionFromWire(other.toWire());

    await readFile.execute({ path: "/data/a.pdf" }, { session });
    await expect(readFile.execute({ path: "/etc/passwd" }, { session })).rejects.toMatchObject({
      code: "TENUO_CONSTRAINT_VIOLATION",
    });
    await readFile.execute({ path: "/data/b.pdf" }, { session: otherSession });

    const first = session.drainReceipts();
    expect(first).toHaveLength(2);
    expect(verifyReceipt(first[0]!)).toMatchObject({ outcome: "allow" });
    expect(verifyReceipt(first[1]!)).toMatchObject({ outcome: "deny" });
    expect(session.drainReceipts()).toEqual(first);
    expect(session.acknowledgeReceipts(2)).toBe(2);
    expect(session.drainReceipts()).toEqual([]);
    expect(otherSession.drainReceipts()).toHaveLength(1);
    expect(otherSession.peekReceipts()).toHaveLength(1);
    expect(otherSession.acknowledgeReceipts(1)).toBe(1);
    expect(otherSession.peekReceipts()).toEqual([]);
  });

  it("acknowledges only successfully persisted receipts", async () => {
    const { runtime, session, readFile } = issuedRuntime();
    await readFile.execute({ path: "/data/a.pdf" }, { session });
    await readFile.execute({ path: "/data/b.pdf" }, { session });
    await readFile.execute({ path: "/data/c.pdf" }, { session });

    expect(session.peekReceipts()).toHaveLength(3);
    expect(runtime.peekReceipts()).toHaveLength(3);
    expect(session.acknowledgeReceipts(1)).toBe(1);
    expect(session.peekReceipts()).toHaveLength(2);
    expect(session.drainReceipts()).toHaveLength(2);
    expect(runtime.peekReceipts()).toHaveLength(2);
    expect(session.acknowledgeReceipts(2)).toBe(2);
    expect(session.peekReceipts()).toEqual([]);
    expect(runtime.peekReceipts()).toEqual([]);
  });

  it("collects present and MCP receipts without a per-call onReceipt", async () => {
    const { runtime, session, issuer } = issuedRuntime();
    const presented = runtime.tenuo.present(session, "read_file", { path: "/data/q3.pdf" });
    const attached = runtime.tenuo.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
    expect(session.drainReceipts()).toHaveLength(2);
    expect(session.acknowledgeReceipts(2)).toBe(2);
    expect(session.drainReceipts()).toEqual([]);

    const server = createTenuo.runtime({
      identity: createTenuo.generateIdentity(),
      trustedRoots: [issuer.issuerPublicKey()],
      receipts: "collect",
    });
    await server.tenuo.verify(presented, "read_file", { path: "/data/q3.pdf" });
    await server.tenuo.mcp.verify(attached.name, attached.arguments, attached._meta);
    const verified = server.drainReceipts();
    expect(verified).toHaveLength(2);
    expect(verifyReceipt(verified[0]!)).toMatchObject({ outcome: "allow" });
    expect(server.drainReceipts()).toEqual(verified);
    expect(server.acknowledgeReceipts(2)).toBe(2);
    expect(server.drainReceipts()).toEqual([]);
  });

  it("keeps receipt collection on narrowed runtime sessions", async () => {
    const { runtime, session, readFile } = issuedRuntime();
    const child = runtime.tenuo.narrow(session, { read_file: { path: under("/data/reports") } });

    await readFile.execute({ path: "/data/reports/q3.pdf" }, { session: child });
    expect(child.drainReceipts()).toHaveLength(1);
    expect(session.drainReceipts()).toHaveLength(1);
    expect(runtime.drainReceipts()).toHaveLength(1);
  });

  it("keeps explicit onReceipt compatible and still collects", async () => {
    const { session, readFile } = issuedRuntime();
    const hooked: string[] = [];
    await readFile.execute(
      { path: "/data/q3.pdf" },
      {
        session,
        onReceipt: (receipt) => {
          hooked.push(receipt);
        },
      },
    );
    expect(hooked).toHaveLength(1);
    expect(session.drainReceipts()).toEqual(hooked);
  });

  it("does not deny an authorized call when the receipt outbox is full", async () => {
    const identity = createTenuo.generateIdentity();
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const minted = issuer.session({
      allow: { read_file: { path: under("/data") } },
      holder: identity.publicKey,
    });
    const runtime = createTenuo.runtime({
      identity,
      trustedRoots: [issuer.issuerPublicKey()],
      receipts: "collect",
      receiptMax: 1,
    });
    const session = runtime.sessionFromWire(minted.toWire());
    const readFile = runtime.tenuo.tool(
      { execute: async ({ path }: { path: string }) => `ok:${path}` },
      { capability: "read_file", allow: { path: under("/data") } },
    );
    await expect(readFile.execute({ path: "/data/a.pdf" }, { session })).resolves.toBe(
      "ok:/data/a.pdf",
    );
    await expect(readFile.execute({ path: "/data/b.pdf" }, { session })).resolves.toBe(
      "ok:/data/b.pdf",
    );
    expect(session.drainReceipts()).toHaveLength(1);
    expect(runtime.receiptOverflows()).toBe(1);
  });

  it("requires trusted roots and does not invent hosted defaults", () => {
    expect(() =>
      createTenuo.runtime({
        identity: createTenuo.generateIdentity(),
        trustedRoots: [],
      }),
    ).toThrow(TenuoConfigurationError);
  });
});

describe("browser-compatible modules", () => {
  it("keeps connect, identity, receipts, and runtime free of Node imports", () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
    for (const name of ["connect.ts", "identity.ts", "receipts.ts", "runtime.ts"]) {
      const source = readFileSync(join(root, name), "utf8");
      expect(source, name).not.toMatch(/from ["']node:/);
      expect(source, name).not.toMatch(/require\(["']node:/);
    }
  });
});
