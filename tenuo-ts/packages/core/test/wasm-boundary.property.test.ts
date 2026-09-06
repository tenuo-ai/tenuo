import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { createTenuo, under } from "../src/index.ts";

const seed = Number.parseInt(process.env.FC_SEED ?? "20260906", 10);
const numRuns = Number.parseInt(process.env.FC_BOUNDARY_RUNS ?? "500", 10);

describe("randomized untrusted TypeScript/WASM boundaries", () => {
  it("rejects malformed warrant and PoP envelopes without executing the handler", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    await fc.assert(
      fc.asyncProperty(
        fc.string({ maxLength: 2_048 }).filter((value) => value.length > 0),
        fc.string({ maxLength: 512 }).filter((value) => value.length > 0),
        fc.dictionary(fc.string({ maxLength: 32 }), fc.jsonValue(), { maxKeys: 16 }),
        async (warrant, signature, args) => {
          let executed = false;
          const guarded = tenuo.mcp.handler(
            "read_file",
            { allow: { path: under("/workspace") } },
            async () => {
              executed = true;
              return "should-not-run";
            },
          );

          await expect(
            guarded(args, { _meta: { tenuo: { warrant, signature } } }),
          ).rejects.toBeDefined();
          expect(executed).toBe(false);
        },
      ),
      { seed, numRuns, verbose: true },
    );
  });

  it("never imports arbitrary wire data as an authorized session", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    fc.assert(
      fc.property(
        fc.array(fc.string({ maxLength: 1_024 }), { minLength: 1, maxLength: 8 }),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        (warrants, holderKey) => {
          expect(() => tenuo.sessionFromWire({ warrant: warrants, holderKey })).toThrow();
        },
      ),
      { seed: seed + 1, numRuns, verbose: true },
    );
  });
});
