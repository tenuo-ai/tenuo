import { createRequire } from "node:module";
import { afterEach, describe, expect, it, vi } from "vitest";

const require = createRequire(import.meta.url);
const wasm = require("../src/generated/tenuo_wasm.js") as {
  create_warrant_from_config: (config: unknown) => {
    warrant_b64: string; error?: string; issuer_public_key_hex: string; holder_private_key_hex: string;
  };
  decode_warrant: (b64: string) => { capabilities: Record<string, Record<string, unknown>> } | string;
  check_access: (w: string, tool: string, args: unknown, root: string, dryRun: boolean) => {
    authorized: boolean; deny_code?: string; reason?: string;
  };
  check_chain_access: (ws: string[], tool: string, args: unknown, root: string, dryRun: boolean) => {
    authorized: boolean; deny_code?: string;
  };
};

const mint = (constraint: unknown, ttl = 60) =>
  wasm.create_warrant_from_config({ tools: { transfer: { amount: constraint } }, ttl });

const constraintsOf = (b64: string) => {
  const decoded = wasm.decode_warrant(b64);
  if (typeof decoded === "string") throw new Error(decoded);
  return decoded.capabilities.transfer ?? {};
};

describe("legacy WASM builder fails closed", () => {
  it.each([
    ["min above max", { range: "1000-0" }],
    ["non-numeric range", { range: "lots" }],
    ["typed range with a string bound", { type: "Range", max: "100" }],
    ["typed range with no bounds", { type: "Range" }],
    ["unparseable cidr", { cidr: "10.0.0.0/99" }],
    ["unparseable regex", { regex: "(" }],
    ["unparseable url pattern", { urlpattern: "not a url" }],
    ["empty one-of", { oneof: " , " }],
    ["not-one-of with a non-string entry", { type: "NotOneOf", values: ["a", 5] }],
    ["empty typed one-of", { type: "OneOf", values: [] }],
    ["deny list with a non-string entry", { url_safe: { deny_domains: ["evil.com", 1] } }],
    ["allow list with no valid entries", { url_safe: { allow_domains: [42] } }],
    ["out-of-range port", { url_safe: { allow_ports: [70000] } }],
    ["two kinds at once", { pattern: "docs/*", exact: "x" }],
    ["a bare string", "0-1000"],
    ["typed kind with a shorthand sibling", { type: "Range", max: 10, pattern: "*" }],
    ["unknown typed option", { type: "Range", max: 10, minExclusive: true }],
    ["non-string type", { type: 3, pattern: "*" }],
    ["invalid URL-safe object", { url_safe: false }],
    ["ignored URL-safe option", { url_safe: { allowDomains: ["safe.test"] } }],
    ["wrong boolean", { url_safe: { block_private: "false" } }],
    ["conflicting aliases", { type: "UrlSafe", allowedHosts: ["a.test"], allow_domains: ["b.test"] }],
    ["blank deny-list member", { type: "NotOneOf", values: ["a", ""] }],
    ["blank CSV deny-list member", { notoneof: "a,,b" }],
    ["unknown Subpath option", { subpath: { root: "/data", depth: 1 } }],
    ["conflicting roots", { type: "Subpath", base: "/data", root: "/other" }],
  ])("rejects %s instead of minting a broader warrant", (_label, constraint) => {
    const result = mint(constraint);
    expect(result.error).toBeTruthy();
    expect(result.warrant_b64).toBe("");
  });

  it("honors typed Regex and URL patterns instead of treating them as globs", () => {
    for (const [constraint, allowed, denied] of [
      [{ type: "Regex", pattern: "^abc$" }, "abc", "^abc$"],
      [{ type: "UrlPattern", pattern: "https://api.example.com/*" }, "https://api.example.com/a", "http://api.example.com/a"],
    ] as const) {
      const result = mint(constraint);
      expect(result.error).toBeFalsy();
      expect(wasm.check_access(result.warrant_b64, "transfer", { amount: allowed }, result.issuer_public_key_hex, true).authorized).toBe(true);
      expect(wasm.check_access(result.warrant_b64, "transfer", { amount: denied }, result.issuer_public_key_hex, true).authorized).toBe(false);
    }
  });

  it("honors maximum depth and refuses unknown config fields", () => {
    const config = { tools: { transfer: {} }, ttl: 60, max_depth: 0 };
    const result = wasm.create_warrant_from_config(config);
    expect(result.error).toBeFalsy();
    expect(wasm.decode_warrant(result.warrant_b64)).toMatchObject({ is_terminal: true });
    expect(wasm.create_warrant_from_config({ ...config, maxDepth: 2 }).error).toMatch(/unknown field/);
    expect(wasm.create_warrant_from_config({ ...config, max_depth: 65 }).error).toBeTruthy();
  });

  it("applies a child depth ceiling and rejects widening the parent ceiling", () => {
    const parent = wasm.create_warrant_from_config({ tools: { transfer: {} }, ttl: 600, max_depth: 3 });
    const config = { tools: { transfer: {} }, ttl: 60, max_depth: 1,
      parent_warrant_b64: parent.warrant_b64, signing_key_hex: parent.holder_private_key_hex };
    const child = wasm.create_warrant_from_config(config);
    expect(child.error).toBeFalsy();
    expect(wasm.decode_warrant(child.warrant_b64)).toMatchObject({ depth: 1, is_terminal: true });
    expect(wasm.check_chain_access([parent.warrant_b64, child.warrant_b64], "transfer", {}, parent.issuer_public_key_hex, true).authorized).toBe(true);
    expect(wasm.create_warrant_from_config({ ...config, max_depth: 4 }).error).toBeTruthy();
  });

  it("names the field and the reason for an inverted range", () => {
    expect(mint({ range: "1000-0" }).error).toMatch(/amount.*min 1000 is greater than max 0/);
  });

  it("rejects malformed supplied keys instead of generating fresh ones", () => {
    for (const key of [{ signing_key_hex: "zz" }, { holder_key_hex: "abcd" }]) {
      const result = wasm.create_warrant_from_config({ tools: { transfer: {} }, ttl: 60, ...key });
      expect(result.error).toMatch(/32 bytes of hex/);
    }
  });

  it.each([
    [{ range: "0-1000" }],
    [{ type: "Range", min: 0, max: 1000 }],
    [{ oneof: "USD,EUR" }],
    [{ type: "NotOneOf", values: ["XXX"] }],
    [{ cidr: "10.0.0.0/8" }],
    [{ url_safe: { allow_domains: ["api.example.com"], allow_ports: [443] } }],
    [{ url_safe: {} }],
  ])("mints valid %j and keeps it in the warrant", (constraint) => {
    const result = mint(constraint);
    expect(result.error).toBeFalsy();
    expect(Object.keys(constraintsOf(result.warrant_b64))).toEqual(["amount"]);
  });
});

describe("dry-run access checks still enforce warrant validity", () => {
  afterEach(() => vi.useRealTimers());
  const args = { amount: 10 };

  it("denies an expired single warrant even though PoP is skipped", () => {
    const { warrant_b64, issuer_public_key_hex } = mint({ range: "0-1000" }, 10);
    expect(wasm.check_access(warrant_b64, "transfer", args, issuer_public_key_hex, true).authorized).toBe(true);
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 13_000);
    const result = wasm.check_access(warrant_b64, "transfer", args, issuer_public_key_hex, true);
    expect(result).toMatchObject({ authorized: false, deny_code: "CHAIN_INVALID" });
  });

  it("denies an expired chain", () => {
    const { warrant_b64, issuer_public_key_hex } = mint({ range: "0-1000" }, 10);
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 13_000);
    expect(wasm.check_chain_access([warrant_b64], "transfer", args, issuer_public_key_hex, true).authorized).toBe(false);
  });

  it("denies a single warrant under the wrong root", () => {
    const { warrant_b64 } = mint({ range: "0-1000" });
    const other = mint({ range: "0-1000" }).issuer_public_key_hex;
    expect(wasm.check_access(warrant_b64, "transfer", args, other, true).authorized).toBe(false);
  });
});
