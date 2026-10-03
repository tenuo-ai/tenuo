import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { loadWasm } from "../src/wasm.ts";
import { createTenuo } from "../src/index.ts";
import { exportSession } from "../src/testkit.ts";

const suite = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../../../../tests/vectors/tenuo-meta-conformance.json"), "utf8")) as {
  valid: { args: string; equivalent: string; tampered: string }[];
  invalid_arguments: string[];
  invalid_envelopes: Record<string, unknown>[];
  delegated: { holder_seed_hex: string; tool: string; args_json: string; timestamp: number; warrant: string; signature: string; approvals: string[] };
};

const vector = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "../../../../tests/vectors/tenuo-meta.json"),
    "utf8",
  ),
) as {
  holder_seed_hex: string;
  tool: string;
  args_json: string;
  rejected_args_json: string;
  timestamp: number;
  warrant: string;
  signature: string;
  float_args_json: string;
  float_signature: string;
};

describe("meta envelope vector", () => {
  it("round-trips the delegated chain and approval token from Python", () => {
    const fixture = suite.delegated;
    const wasm = loadWasm();
    const ctx = new wasm.SdkContext();
    const session = wasm.SdkSession.fromWire(fixture.warrant, Uint8Array.from(Buffer.from(fixture.holder_seed_hex, "hex")));
    const signed = ctx.signMeta(session, fixture.tool, fixture.args_json, fixture.timestamp, fixture.approvals);
    expect(signed).toEqual({ warrant: fixture.warrant, signature: fixture.signature, approvals: fixture.approvals });
    expect(ctx.verifyMetaPop(fixture.warrant, fixture.signature, fixture.tool, fixture.args_json, fixture.timestamp)).toBe(true);
  });

  it.each(suite.valid)("preserves the shared proof equivalence: $args", (test) => {
    const wasm = loadWasm();
    const ctx = new wasm.SdkContext();
    const session = wasm.SdkSession.fromWire(vector.warrant, Uint8Array.from(Buffer.from(vector.holder_seed_hex, "hex")));
    const signed = ctx.signMeta(session, vector.tool, test.args, vector.timestamp, null);
    expect(ctx.verifyMetaPop(signed.warrant, signed.signature, vector.tool, test.equivalent, vector.timestamp)).toBe(true);
    expect(ctx.verifyMetaPop(signed.warrant, signed.signature, vector.tool, test.tampered, vector.timestamp)).toBe(false);
  });

  it.each(suite.invalid_arguments)("rejects shared malformed argument text %s", (text) => {
    const wasm = loadWasm();
    const ctx = new wasm.SdkContext();
    const session = wasm.SdkSession.fromWire(vector.warrant, Uint8Array.from(Buffer.from(vector.holder_seed_hex, "hex")));
    expect(() => ctx.signMeta(session, vector.tool, text, vector.timestamp, null)).toThrow();
  });

  it("bounds bytes, aggregate nodes, strings and approvals", () => {
    const wasm = loadWasm();
    const ctx = new wasm.SdkContext();
    const session = wasm.SdkSession.fromWire(vector.warrant, Uint8Array.from(Buffer.from(vector.holder_seed_hex, "hex")));
    for (const text of ["!".repeat(262145), JSON.stringify({ rows: Array(17).fill(Array(256).fill(0)) }), JSON.stringify({ rows: Array(9).fill("x".repeat(8192)) })]) {
      expect(() => ctx.signMeta(session, vector.tool, text, vector.timestamp, null)).toThrow(/size limit/);
    }
    expect(() => ctx.signMeta(session, vector.tool, JSON.stringify({ content: "x".repeat(64 * 1024 + 1) }), vector.timestamp, null)).toThrow(/size limit/);
    expect(() => ctx.signMeta(session, vector.tool, "{}", vector.timestamp, Array(65).fill("!"))).toThrow(/too many approvals/);
  });

  it("accepts one string up to the 64 KiB string budget", () => {
    const wasm = loadWasm();
    const ctx = new wasm.SdkContext();
    const session = wasm.SdkSession.fromWire(vector.warrant, Uint8Array.from(Buffer.from(vector.holder_seed_hex, "hex")));
    expect(() => ctx.signMeta(session, vector.tool, JSON.stringify({ content: "x".repeat(48 * 1024) }), vector.timestamp, null)).not.toThrow();
  });

  it.each(suite.invalid_envelopes)("rejects malformed envelopes without executing: %j", async (fields) => {
    const issuer = createTenuo({ root: createTenuo.devRoot() });
    const session = issuer.session({ allow: { test: {} } });
    const wire = exportSession(session);
    const server = createTenuo({ trustedRoots: [createTenuo.publicKeyFromHex(wire.root_hex)] });
    const call = issuer.mcp.attach(session, "test", {});
    let executed = false;
    const handler = server.mcp.handler("test", async () => { executed = true; });
    await expect(handler({}, { _meta: { tenuo: { ...call._meta.tenuo, ...fields } } })).rejects.toThrow();
    expect(executed).toBe(false);
  });
  it("matches the core warrant and signature strings", () => {
    const wasm = loadWasm();
    const seed = Uint8Array.from(Buffer.from(vector.holder_seed_hex, "hex"));
    const session = wasm.SdkSession.fromWire(vector.warrant, seed);
    const ctx = new wasm.SdkContext();
    const signed = ctx.signMeta(session, vector.tool, vector.args_json, vector.timestamp, null);
    const floatSigned = ctx.signMeta(
      session,
      vector.tool,
      vector.float_args_json,
      vector.timestamp,
      null,
    );

    expect(signed.warrant).toBe(vector.warrant);
    expect(signed.signature).toBe(vector.signature);
    expect(floatSigned.signature).toBe(vector.float_signature);
    expect(JSON.stringify({ limit: 1.0, note: null, path: "/data/ok" })).toBe(
      '{"limit":1,"note":null,"path":"/data/ok"}',
    );
    expect(
      ctx.verifyMeta(vector.warrant, vector.signature, vector.tool, vector.args_json, vector.timestamp),
    ).toBe(true);
    expect(
      ctx.verifyMeta(
        vector.warrant,
        vector.signature,
        vector.tool,
        vector.rejected_args_json,
        vector.timestamp,
      ),
    ).toBe(false);
  });
});
