/**
 * Drives the runnable concurrent-sessions example.
 *
 * `pnpm example:sessions` runs this file to show the example's output. Under
 * `pnpm test` it stays quiet. The isolation criteria themselves live in
 * `session-isolation.test.ts`, which drives the same helpers; this file only
 * checks that the entry point reports both scenarios.
 */
import { describe, expect, it } from "vitest";
import { PATHS, runConcurrentSessionsExample } from "../examples/concurrent-sessions.ts";

const log = process.env.npm_lifecycle_event === "example:sessions" ? console.log : () => undefined;

describe("examples/concurrent-sessions", () => {
  it("reports the allowed and denied outcome of each scenario", async () => {
    const { concurrent, queued } = await runConcurrentSessionsExample(log);
    expect(concurrent.results.map((result) => result.crossed)).toEqual([
      { code: "TENUO_CONSTRAINT_VIOLATION", field: "path" },
      { code: "TENUO_CONSTRAINT_VIOLATION", field: "path" },
    ]);
    expect(concurrent.executed).toEqual([PATHS.reports, PATHS.finance, PATHS.reports, PATHS.finance]);
    expect(queued.ambient).toMatchObject({ ok: false, code: "TENUO_CONFIGURATION" });
    expect(queued.explicit).toEqual({ ok: true, value: `contents:${PATHS.reports}` });
  });
});
