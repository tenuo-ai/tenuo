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
  ] as const)("%s with %j allows=%s", (name, args, allowed) => {
    const wire = fixtures[name]!;
    const session = SdkSession.fromWire(wire, key);
    // signPop only proves possession, so denied calls also reach the receiver
    // with a valid signature instead of failing at a local policy preflight.
    const pop = issuer.signPop(session, "read", args);
    const decision = verifier.authorizePresented([wire], "read", args, pop, [], null);
    expect(decision.outcome).toBe(allowed ? "allow" : "deny");
    session.free();
  });
});
