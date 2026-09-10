import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createTenuo } from "../src/index.ts";
import { parseConnectToken } from "../src/connect.ts";

type TokenCase = {
  name: string;
  raw: string;
  expect: "ok" | "error";
  error_contains?: string;
  version?: number;
  endpoint?: string;
  api_key?: string;
  agent_id?: string | null;
  registration_token?: string | null;
  needs_endpoint_base?: boolean;
  resolve_base?: string;
  resolved_endpoint?: string;
};

type Vectors = {
  connect_tokens: TokenCase[];
  identity: {
    secret_hex: string;
    public_key_hex: string;
  };
  receipts: {
    drain_is_snapshot: boolean;
    remove_only_on_acknowledge: boolean;
    overflow_does_not_deny_authorized_call: boolean;
    overflow_is_observable: boolean;
  };
};

const vectors = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "../../../../tests/vectors/holder-lifecycle.json",
    ),
    "utf8",
  ),
) as Vectors;

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

describe("holder-lifecycle vectors", () => {
  it("parses connect tokens", () => {
    for (const testCase of vectors.connect_tokens) {
      if (testCase.expect === "error") {
        expect(() => parseConnectToken(testCase.raw), testCase.name).toThrow(
          testCase.error_contains,
        );
        continue;
      }
      const token = parseConnectToken(testCase.raw);
      expect(token.version, testCase.name).toBe(testCase.version);
      expect(token.endpoint, testCase.name).toBe(testCase.endpoint);
      expect(token.apiKey, testCase.name).toBe(testCase.api_key);
      expect(token.agentId ?? null, testCase.name).toBe(testCase.agent_id ?? null);
      expect(token.registrationToken ?? null, testCase.name).toBe(
        testCase.registration_token ?? null,
      );
      expect(token.needsEndpointBase, testCase.name).toBe(testCase.needs_endpoint_base);
      if (testCase.resolve_base) {
        token.resolveEndpoint({ localBase: testCase.resolve_base });
        expect(token.endpoint, testCase.name).toBe(testCase.resolved_endpoint);
        expect(token.needsEndpointBase, testCase.name).toBe(false);
      }
    }
  });

  it("derives the identity public key and redacts the secret", () => {
    const secret = hexToBytes(vectors.identity.secret_hex);
    const pub = createTenuo.publicKeyFromHolderKey(secret);
    expect(pub.hex).toBe(vectors.identity.public_key_hex);
    expect(JSON.stringify(pub)).not.toContain(vectors.identity.secret_hex);
  });

  it("enforces the receipt contract on a live runtime", async () => {
    expect(vectors.receipts.drain_is_snapshot).toBe(true);
    expect(vectors.receipts.remove_only_on_acknowledge).toBe(true);
    expect(vectors.receipts.overflow_does_not_deny_authorized_call).toBe(true);
    expect(vectors.receipts.overflow_is_observable).toBe(true);

    const identity = createTenuo.generateIdentity();
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const minted = issuer.session({
      allow: { read_file: {} },
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
      { execute: async () => "ok" },
      { capability: "read_file" },
    );
    await readFile.execute({}, { session });
    await readFile.execute({}, { session });
    const first = session.drainReceipts();
    expect(first).toHaveLength(1);
    expect(session.drainReceipts()).toEqual(first);
    expect(runtime.receiptOverflows()).toBe(1);
    expect(session.acknowledgeReceipts(1)).toBe(1);
    expect(session.drainReceipts()).toEqual([]);
  });
});
