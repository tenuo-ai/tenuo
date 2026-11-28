/**
 * Drives the runnable quickstart. `pnpm example:basic` runs this file to show
 * the example's output; under `pnpm test` it stays quiet.
 */
import { describe, expect, it } from "vitest";
import { runBasicExample } from "../examples/basic.ts";

const log = process.env.npm_lifecycle_event === "example:basic" ? console.log : () => undefined;

describe("examples/basic", () => {
  it("runs the two allowed calls and never runs the denied one", async () => {
    expect(await runBasicExample(log)).toBe(2);
  });
});
