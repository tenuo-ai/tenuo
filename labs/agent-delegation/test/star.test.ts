import { describe, expect, it, vi } from "vitest";
import { starRepository, type StarRunner } from "../src/star.ts";

describe("terminal star command", () => {
  it("reports success without retrying when the current GitHub login works", () => {
    const runner = vi.fn<StarRunner>().mockReturnValue({ status: 0 });
    expect(starRepository(runner, false)).toEqual({
      ok: true,
      message: "Starred github.com/tenuo-ai/tenuo. Thank you.",
    });
    expect(runner).toHaveBeenCalledOnce();
    expect(runner).toHaveBeenCalledWith(false);
  });

  it("falls back from the Codespaces repository token to a personal gh login", () => {
    const runner = vi.fn<StarRunner>()
      .mockReturnValueOnce({ status: 1 })
      .mockReturnValueOnce({ status: 0 });
    expect(starRepository(runner, true).ok).toBe(true);
    expect(runner.mock.calls).toEqual([[false], [true]]);
  });

  it("gives terminal-only recovery instructions for Codespaces", () => {
    const runner = vi.fn<StarRunner>().mockReturnValue({ status: 1 });
    const result = starRepository(runner, true);
    expect(result.ok).toBe(false);
    expect(result.message).toContain("env -u GH_TOKEN -u GITHUB_TOKEN gh auth login");
    expect(result.message).toContain("npm run star again");
  });

  it("explains how to install a missing GitHub CLI", () => {
    const missing = Object.assign(new Error("not found"), { code: "ENOENT" });
    const runner = vi.fn<StarRunner>().mockReturnValue({ status: null, error: missing });
    const result = starRepository(runner, false);
    expect(result.ok).toBe(false);
    expect(result.message).toContain("cli.github.com");
  });
});
