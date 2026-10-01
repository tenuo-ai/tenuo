import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { loadWasm } from "../src/wasm.ts";

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
};

describe("meta envelope vector", () => {
  it("matches the core warrant and signature strings", () => {
    const wasm = loadWasm();
    const seed = Uint8Array.from(Buffer.from(vector.holder_seed_hex, "hex"));
    const session = wasm.SdkSession.fromWire(vector.warrant, seed);
    const ctx = new wasm.SdkContext();
    const signed = ctx.signMeta(session, vector.tool, vector.args_json, vector.timestamp);

    expect(signed.warrant).toBe(vector.warrant);
    expect(signed.signature).toBe(vector.signature);
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
