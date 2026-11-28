import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createTenuo, under, type ConstraintExpr } from "../src/index.ts";

const suite = JSON.parse(readFileSync(new URL("../../../../tests/vectors/subpath-lists.json", import.meta.url), "utf8"));

describe("Subpath list shared vectors", () => {
  it("matches the same values as Rust and Python", async () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    const tool = tenuo.tool({ execute: async (args: Record<string, unknown>) => args }, { capability: "read", allow: {} });
    for (const c of suite.matching) {
      const session = tenuo.session({ allow: { read: { paths: under(c.root) } } });
      const call = tool.execute({ paths: c.value }, { session });
      if (c.allowed) await expect(call, c.name).resolves.toEqual({ paths: c.value });
      else await expect(call, c.name).rejects.toMatchObject({ code: "TENUO_CONSTRAINT_VIOLATION" });
    }
  });

  it("permits only the shared attenuation cases", () => {
    const tenuo = createTenuo({ root: createTenuo.devRoot() });
    for (const c of suite.attenuation) {
      const session = tenuo.session({ allow: { read: { paths: under(c.root) } } });
      // Exercise core semantics, including empty lists that the
      // convenience helpers deliberately don't expose.
      const child = (c.kind === "subset"
        ? { kind: "subset", values: c.value }
        : { kind: "exact", value: c.value }) as ConstraintExpr;
      const narrow = () => tenuo.narrow(session, { paths: child });
      if (c.allowed) expect(narrow, c.name).not.toThrow();
      else expect(narrow, c.name).toThrow();
    }
  });
});
