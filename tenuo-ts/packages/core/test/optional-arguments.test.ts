/** Signed Rust-issued policies retain presence rules at the WASM receiver. */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { SdkContext, SdkSession } from "../src/generated/tenuo_wasm.js";

const fixtures: Record<string, string> = JSON.parse(readFileSync(
  new URL("../../../../tenuo-core/tests/fixtures/optional_arguments.json", import.meta.url), "utf8",
));
// Public synthetic fixture key, never a deployed trust root.
const key = new Uint8Array(32).fill(7);
const issuer = SdkContext.fromIssuerSecret(key, []);
const verifier = SdkContext.fromTrustedRoots([issuer.issuerPublicKey()]);

describe("optional arguments from signed Rust warrants", () => {
  it("a required leaf cannot revive its unsupported optional parent", () => {
    const wire = fixtures.unknown_required_child!;
    const session = SdkSession.fromWire(wire, key);
    const args = { head: 1 };
    const pop = issuer.signPop(session, "read", args);
    const decision = verifier.authorizePresented([fixtures.unknown!, wire], "read", args, pop, [], null);
    expect(decision.outcome).toBe("deny");
    expect(decision.message).toContain("unknown constraint type ID 99");
    session.free();
  });

  it.each(["issuer_bounds", "issuer_wildcard_bounds"])(
    "%s preserves optional bounds through a required execution child", (name) => {
      const root = SdkContext.fromIssuerSecret(new Uint8Array(32).fill(8), []);
      const receiver = SdkContext.fromTrustedRoots([root.issuerPublicKey()]);
      const wire = fixtures[`${name}_child`]!;
      const session = SdkSession.fromWire(wire, key);
      for (const [args, allowed] of [
        [{ head: [1] }, true],
        [{ head: [1, null] }, false],
        [{ head: null }, false],
      ] as const) {
        const pop = issuer.signPop(session, "read", args);
        const decision = receiver.authorizePresented([fixtures[name]!, wire], "read", args, pop, [], null);
        expect(decision.outcome).toBe(allowed ? "allow" : "deny");
      }
      session.free();
      receiver.free();
      root.free();
    },
  );

  it.each([
    ["range", {}, true],
    ["range", { head: null }, false],
    ["range", { head: 200 }, true],
    ["range", { head: 201 }, false],
    ["list", {}, true],
    ["list", { head: [1] }, true],
    ["list", { head: [1, null] }, false],
    ["null", {}, true],
    ["null", { head: null }, true],
    ["wildcard", {}, true],
    ["wildcard", { head: null }, false],
    ["exact_precedence", {}, false],
    ["exact_precedence", { head: 100 }, true],
    ["exact_precedence", { head: 101 }, false],
    ["unknown", {}, false],
    ["unknown", { head: 1 }, false],
  ] as const)("%s with %j allows=%s", (name, args, allowed) => {
    const wire = fixtures[name]!;
    const session = SdkSession.fromWire(wire, key);
    // signPop only proves possession, so denied calls also reach the receiver
    // with a valid signature instead of failing at a local policy preflight.
    const pop = issuer.signPop(session, "read", args);
    const decision = verifier.authorizePresented([wire], "read", args, pop, [], null);
    expect(decision.outcome).toBe(allowed ? "allow" : "deny");
    const explanation = verifier.explain(session, "read", args);
    expect(explanation.outcome).toBe(allowed ? "allow" : "deny");
    if (!("head" in args)) {
      const required = name === "exact_precedence";
      expect(explanation.missing_fields).toEqual(required ? ["head"] : []);
    }
    expect(explanation.fields[0].satisfied).toBe(allowed);
    session.free();
  });
});
