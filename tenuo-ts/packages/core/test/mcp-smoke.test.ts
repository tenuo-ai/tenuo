import { describe, expect, it } from "vitest";
import { runMcpSmoke } from "../examples/mcp/smoke.ts";

describe("mcp smoke", () => {
  it("allows an in-scope read, denies at attach, and fails closed on forged args", async () => {
    await expect(runMcpSmoke()).resolves.toBeUndefined();
  });
});
