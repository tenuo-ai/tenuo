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

  it("ready() succeeds once WASM is built", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    expect(() => tenuo.ready()).not.toThrow();
  });

  it("cannot mint a session without a local issuer", () => {
    const tenuo = createTenuo({
      trustedRoots: [createTenuo.publicKeyFromEnv("TENUO_ROOT_PUBLIC_KEY")],
    });
    expect(() => tenuo.session({ allow: { read_file: { path: under("/data") } } })).toThrow(
      /local issuer/,
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
  it("builds marker objects for the WASM mapping", () => {
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

describe("authorize through WASM", () => {
  it("allows a path under the session and denies /etc/passwd without calling execute", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    tenuo.ready();

    let executed: string | undefined;
    const readFile = tenuo.tool(
      {
        execute: async ({ path }: { path: string }) => {
          executed = path;
          return `ok:${path}`;
        },
      },
      { capability: "read_file", allow: { path: under("/data") } },
    );

    const session = tenuo.session({
      allow: { read_file: { path: under("/data") } },
    });

    const allowed = await tenuo.withSession(session, () =>
      readFile.execute({ path: "/data/q3.pdf" }),
    );
    expect(allowed).toBe("ok:/data/q3.pdf");
    expect(executed).toBe("/data/q3.pdf");

    executed = undefined;
    await expect(
      tenuo.withSession(session, () => readFile.execute({ path: "/etc/passwd" })),
    ).rejects.toMatchObject({
      name: "AuthorizationDeniedError",
      code: "TENUO_CONSTRAINT_VIOLATION",
      field: "path",
    });
    expect(executed).toBeUndefined();
  });

  it("accepts an explicit session on execute", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const search = tenuo.tool(
      { execute: async ({ q }: { q: string }) => q },
      { capability: "search", allow: { q: pattern("report*") } },
    );
    const session = tenuo.session({
      allow: { search: { q: pattern("report*") } },
    });
    await expect(search.execute({ q: "report-q3" }, { session })).resolves.toBe("report-q3");
  });
});
