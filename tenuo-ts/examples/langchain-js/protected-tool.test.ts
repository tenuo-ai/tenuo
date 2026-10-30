/**
 * Allow/deny coverage for the LangChain.js protected-tool example.
 *
 * No model provider, credentials, or network: tools are invoked directly with
 * `.invoke()`, the call an agent runtime makes after a model emits a tool
 * call. `executed` is the evidence — a denied call must never appear in it,
 * proving the underlying operation did not run after denial.
 */

// createHarness() mints a dev root, which refuses NODE_ENV=production
// unless opted in. demo.ts sets this before runDemo(); the suite needs it
// too, because verify-packed.mjs passes the full environment to npm test.
process.env.TENUO_ALLOW_DEV ??= "1";

import { describe, expect, expectTypeOf, it } from "vitest";
import {
  AuthorizationDeniedError,
  createTenuo,
  TenuoConfigurationError,
  under,
} from "@tenuo/core";
import { createHarness, runDemo } from "./protected-tool.ts";

describe("langchain-js protected tool", () => {
  it("keeps the LangChain tool shape: name, description and schema pass through", () => {
    const { protectedReadFile } = createHarness();
    expect(protectedReadFile.name).toBe("read_file");
    expect(protectedReadFile.description).toBe(
      "Read a UTF-8 text file and return its contents.",
    );
    // LangChain still validates inputs against this schema; Tenuo never
    // treats the host schema as authority.
    expect(protectedReadFile.schema).toBeDefined();
  });

  it("preserves useful TypeScript input inference", () => {
    const { guarded } = createHarness();
    expectTypeOf(guarded.execute).parameter(0).toEqualTypeOf<{ path: string }>();
    expectTypeOf(guarded.execute).returns.resolves.toEqualTypeOf<string>();
  });

  it("checks policy keys against the tool's real arguments at compile time", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    tenuo.tool(
      { execute: async (_: { path: string }) => "" },
      // @ts-expect-error `paht` is not an argument of the tool.
      { capability: "read_file", allow: { paht: under("/data") } },
    );
  });

  it("allows a path under the session root and runs the operation", async () => {
    const { tenuo, protectedReadFile, reportsSession, executed } = createHarness();
    const result = await tenuo.withSession(reportsSession, () =>
      protectedReadFile.invoke({ path: "/data/reports/q3.pdf" }),
    );
    expect(result).toBe("Q3 revenue up 12% quarter over quarter.");
    expect(executed).toEqual(["/data/reports/q3.pdf"]);
  });

  it("denies a path outside the session root and never runs the operation", async () => {
    const { tenuo, protectedReadFile, reportsSession, executed } = createHarness();
    const error = await tenuo
      .withSession(reportsSession, () =>
        protectedReadFile.invoke({ path: "/data/finance/ledger.csv" }),
      )
      .then(
        () => "no-error",
        (cause: unknown) => cause,
      );
    expect(error).toBeInstanceOf(AuthorizationDeniedError);
    expect((error as AuthorizationDeniedError).code).toBe("TENUO_CONSTRAINT_VIOLATION");
    expect((error as AuthorizationDeniedError).field).toBe("path");
    // The denial happened before the operation: nothing executed.
    expect(executed).toEqual([]);
  });

  it("denies a path outside the tool ceiling even for a broader session", async () => {
    const { tenuo, protectedReadFile, executed } = createHarness();
    const broadSession = tenuo.session({
      allow: { read_file: { path: under("/etc") } },
    });
    const error = await tenuo
      .withSession(broadSession, () => protectedReadFile.invoke({ path: "/etc/passwd" }))
      .then(
        () => "no-error",
        (cause: unknown) => cause,
      );
    expect(error).toBeInstanceOf(AuthorizationDeniedError);
    expect(executed).toEqual([]);
  });

  it("denies a call made with no session and never runs the operation", async () => {
    const { protectedReadFile, executed } = createHarness();
    await expect(
      protectedReadFile.invoke({ path: "/data/reports/q3.pdf" }),
    ).rejects.toThrow(TenuoConfigurationError);
    expect(executed).toEqual([]);
  });

  it("validates the schema before authorization: malformed input never reaches Tenuo or the operation", async () => {
    const { tenuo, protectedReadFile, reportsSession, executed } = createHarness();
    // `path` must be a string. LangChain rejects this with its own schema
    // error, not a Tenuo denial, and nothing executes.
    const error = await tenuo
      .withSession(reportsSession, () =>
        protectedReadFile.invoke({ path: 42 } as unknown as { path: string }),
      )
      .then(
        () => "no-error",
        (cause: unknown) => cause,
      );
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(AuthorizationDeniedError);
    expect(executed).toEqual([]);
  });

  it("reports the allow/deny transcript via runDemo", async () => {
    const lines: string[] = [];
    await runDemo((line) => lines.push(line));
    expect(lines).toEqual([
      "allowed  /data/reports/q3.pdf -> Q3 revenue up 12% quarter over quarter.",
      "denied   /data/finance/ledger.csv -> TENUO_CONSTRAINT_VIOLATION (field path)",
      'tool executed for: ["/data/reports/q3.pdf"]',
    ]);
  });
});
