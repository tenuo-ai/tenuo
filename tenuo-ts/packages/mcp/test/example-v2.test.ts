import { describe, expect, it } from "vitest";
import { runMinimalExample } from "../examples/v2/main.ts";

describe("examples/v2", () => {
  it("allows the attached call and denies the swapped one without running the handler", async () => {
    const outcome = await runMinimalExample();
    expect(outcome.allowed).toEqual({ isError: false, text: "contents of /data/reports/q3.pdf" });
    expect(outcome.denied.isError).toBe(true);
    expect(outcome.denied.rpc).toMatchObject({
      code: -32001,
      data: { tenuo: { code: "TENUO_INVALID_POP" } },
    });
    expect(outcome.executed).toEqual(["/data/reports/q3.pdf"]);
  });
});
