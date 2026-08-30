import { describe, expect, it } from "vitest";
import {
  ApprovalRequiredError,
  AuthorizationDeniedError,
  createTenuo,
  email,
  max,
  oneOf,
  pattern,
  TenuoConfigurationError,
  TenuoError,
  under,
} from "../src/index.ts";
import type { ToolLike } from "../src/index.ts";

describe("createTenuo", () => {
  it("rejects an empty trust set", () => {
    expect(() => createTenuo({})).toThrow(TenuoConfigurationError);
    expect(() => createTenuo({})).toThrow(/trustedRoots/);
  });

  it("accepts devRoot outside production", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    expect(() => tenuo.ready()).toThrow(/WASM core is not wired yet/);
    expect(() => tenuo.ready()).toThrow(TenuoConfigurationError);
  });

  it("accepts an env public-key handle as a trust anchor", () => {
    const tenuo = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY")],
    });
    expect(() => tenuo.session({ allow: { read_file: { path: under("/data") } } })).toThrow(
      /WASM core is not wired yet/,
    );
  });

  it("refuses a tool with an empty allow policy", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const inner: ToolLike<{ path: string }, string> = {
      execute: async ({ path }) => path,
    };
    expect(() => tenuo.tool(inner, { allow: {} })).toThrow(/non-empty allow policy/);
  });
});

describe("constraints", () => {
  it("builds marker objects for the later WASM mapping", () => {
    expect(under("/data")).toEqual({ kind: "under", root: "/data" });
    expect(email({ domain: "acme.com" })).toEqual({ kind: "email", domain: "acme.com" });
    expect(max(500)).toEqual({ kind: "max", value: 500 });
    expect(oneOf(["a", "b"])).toEqual({ kind: "oneOf", values: ["a", "b"] });
    expect(pattern("*@acme.com")).toEqual({ kind: "pattern", pattern: "*@acme.com" });
  });

  it("rejects relative under() roots", () => {
    expect(() => under("data")).toThrow(/absolute path/);
  });
});

describe("errors", () => {
  it("keeps a stable instanceof hierarchy", () => {
    const denied = new AuthorizationDeniedError(
      "TENUO_CONSTRAINT_VIOLATION",
      "blocked",
      "path",
    );
    expect(denied).toBeInstanceOf(TenuoError);
    expect(denied.field).toBe("path");
    expect(denied.code).toBe("TENUO_CONSTRAINT_VIOLATION");

    const approval = new ApprovalRequiredError("send_email", 2, 0);
    expect(approval).toBeInstanceOf(TenuoError);
    expect(approval.code).toBe("TENUO_APPROVAL_REQUIRED");
  });
});
