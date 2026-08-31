import { describe, expect, it } from "vitest";
import { runMcpSmoke } from "../examples/mcp/smoke.ts";

describe("mcp smoke", () => {
  it("runs the quarterly-close scenario: narrow, deny, approval, and forged args", async () => {
    const result = await runMcpSmoke();
    expect(result.listed).toEqual(["q3-customers.md", "q3-revenue.md"]);
    expect(result.emailed).toMatchObject({ to: "finance@acme.com" });
    expect(result.denials.map((denial) => denial.code)).toEqual([
      "TENUO_CONSTRAINT_VIOLATION",
      "TENUO_CONSTRAINT_VIOLATION",
      "TENUO_APPROVAL_REQUIRED",
      "TENUO_INVALID_POP",
    ]);
  });
});
