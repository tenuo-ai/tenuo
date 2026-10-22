/**
 * optional(inner): an argument the call may omit (or send as null) but that
 * must satisfy `inner` when present. Every decision here runs through the
 * Rust core via a real protected tool.
 */
import { describe, expect, it } from "vitest";
import {
  all,
  anyOf,
  createTenuo,
  exact,
  not,
  optional,
  pattern,
  range,
  TenuoConfigurationError,
  wildcard,
} from "../src/index.ts";
import type { AllowPolicy, ConstraintExpr, Tenuo } from "../src/index.ts";

function dev(): Tenuo {
  return createTenuo({ root: createTenuo.devRoot() });
}

function searchTool(tenuo: Tenuo, policy: AllowPolicy) {
  const ran: Record<string, unknown>[] = [];
  const tool = tenuo.tool(
    {
      execute: async (args: Record<string, unknown>) => {
        ran.push(args);
        return "ok";
      },
    },
    { capability: "search", allow: {} },
  );
  const session = tenuo.session({ allow: { search: policy } });
  return {
    ran,
    session,
    run: (args: Record<string, unknown>) => tool.execute(args, { session }),
  };
}

const denied = { code: "TENUO_CONSTRAINT_VIOLATION" };

describe("optional()", () => {
  it("allows the argument to be absent, null, or valid, and denies an invalid value", async () => {
    const t = searchTool(dev(), { query: wildcard(), limit: optional(range({ min: 1, max: 50 })) });

    await expect(t.run({ query: "q" })).resolves.toBe("ok");
    await expect(t.run({ query: "q", limit: null })).resolves.toBe("ok");
    await expect(t.run({ query: "q", limit: 10 })).resolves.toBe("ok");
    await expect(t.run({ query: "q", limit: 500 })).rejects.toMatchObject(denied);
    expect(t.ran).toHaveLength(3);
  });

  it("keeps the policy closed: the optional key counts as listed, others are still denied", async () => {
    const t = searchTool(dev(), { query: wildcard(), limit: optional(range({ max: 50 })) });
    await expect(t.run({ query: "q", page: 2 })).rejects.toMatchObject(denied);
    // a null unlisted argument is absent, not unknown
    await expect(t.run({ query: "q", page: null })).resolves.toBe("ok");
  });

  it("treats a required argument sent as null as missing", async () => {
    const t = searchTool(dev(), { operation: wildcard(), parameters: wildcard() });
    await expect(t.run({ operation: "x", parameters: null })).rejects.toMatchObject(denied);
    await expect(t.run({ operation: "x", parameters: {} })).resolves.toBe("ok");
  });

  it("is rejected when nested, at the builder or when the policy compiles", () => {
    expect(() => optional(optional(wildcard()) as unknown as Exclude<ConstraintExpr, { kind: "optional" }>)).toThrow(
      TenuoConfigurationError,
    );
    const tenuo = dev();
    for (const nested of [
      all([optional(wildcard())]),
      anyOf([exact("a"), optional(wildcard())]),
      not(optional(wildcard())),
    ]) {
      expect(() => tenuo.session({ allow: { search: { query: nested } } })).toThrow(/top-level/);
    }
  });

  it("explain() reports an absent optional argument as satisfied, not missing", () => {
    const tenuo = dev();
    const session = tenuo.session({
      allow: { search: { query: wildcard(), limit: optional(range({ min: 1, max: 50 })) } },
    });
    const absent = tenuo.explain(session, "search", { query: "q" });
    expect(absent.outcome).toBe("allow");
    expect(absent.missingFields).toEqual([]);
    const limit = absent.fields.find((f) => f.field === "limit");
    expect(limit).toMatchObject({ kind: "Optional", satisfied: true, reasonCode: "argument_absent" });

    const bad = tenuo.explain(session, "search", { query: "q", limit: 99 });
    expect(bad).toMatchObject({ outcome: "deny", field: "limit" });
    expect(bad.fields.find((f) => f.field === "limit")?.satisfied).toBe(false);

    const nullRequired = tenuo.explain(session, "search", { query: null, extra: null });
    expect(nullRequired.missingFields).toEqual(["query"]);
    expect(nullRequired.unknownFields).toEqual([]);
  });

  it("narrow() may tighten or require an optional argument, but never make a required one optional", async () => {
    const tenuo = dev();
    const session = tenuo.session({
      allow: { search: { query: pattern("customers:*"), limit: optional(range({ min: 1, max: 50 })) } },
    });
    const tighter = tenuo.narrow(session, { query: pattern("customers:*"), limit: optional(range({ min: 1, max: 10 })) });
    const required = tenuo.narrow(session, { query: pattern("customers:*"), limit: range({ min: 1, max: 10 }) });
    expect(() =>
      tenuo.narrow(session, { query: pattern("customers:*"), limit: optional(range({ min: 1, max: 100 })) }),
    ).toThrow();
    expect(() => tenuo.narrow(required, { query: pattern("customers:*"), limit: optional(range({ min: 1, max: 10 })) })).toThrow();
    expect(() => tenuo.narrow(session, { query: optional(pattern("customers:*")), limit: optional(range({ max: 10 })) })).toThrow();
    // wildcard() admits any value but not absence, so it cannot become optional either
    const anyQuery = tenuo.session({ allow: { search: { query: wildcard() } } });
    expect(() => tenuo.narrow(anyQuery, { query: optional(wildcard()) })).toThrow();
    expect(() => tenuo.narrow(anyQuery, { query: pattern("customers:*") })).not.toThrow();

    const tool = tenuo.tool(
      { execute: async (_args: Record<string, unknown>) => "ok" },
      { capability: "search", allow: {} },
    );
    await expect(tool.execute({ query: "customers:a" }, { session: tighter })).resolves.toBe("ok");
    await expect(tool.execute({ query: "customers:a", limit: 20 }, { session: tighter })).rejects.toMatchObject(denied);
    await expect(tool.execute({ query: "customers:a" }, { session: required })).rejects.toMatchObject(denied);
    await expect(tool.execute({ query: "customers:a", limit: 5 }, { session: required })).resolves.toBe("ok");
  });
});
