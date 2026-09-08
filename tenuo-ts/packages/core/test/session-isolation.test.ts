import { describe, expect, it } from "vitest";
import { AuthorizationDeniedError, TenuoConfigurationError } from "../src/index.ts";
import {
  createHarness,
  PATHS,
  runConcurrentFlows,
  runQueuedJobs,
  type FlowName,
  type FlowResult,
} from "../examples/concurrent-sessions.ts";

const EXPECTED_LOG = [
  "reports: read own",
  "finance: read own",
  "reports: try other",
  "finance: try other",
  "reports: read own again",
  "finance: read own again",
];

function byName(results: readonly FlowResult[], name: FlowName): FlowResult {
  const found = results.find((result) => result.name === name);
  if (found === undefined) {
    throw new Error(`no result for ${name}`);
  }
  return found;
}

describe("concurrent session isolation", () => {
  it("each flow reads only its own path while interleaved with the other", async () => {
    const run = await runConcurrentFlows(createHarness());
    const reports = byName(run.results, "reports");
    const finance = byName(run.results, "finance");
    expect(reports.own).toBe(`contents:${PATHS.reports}`);
    expect(reports.ownAgain).toBe(`contents:${PATHS.reports}`);
    expect(finance.own).toBe(`contents:${PATHS.finance}`);
    expect(finance.ownAgain).toBe(`contents:${PATHS.finance}`);
  });

  it("a flow cannot use the other flow's session", async () => {
    const run = await runConcurrentFlows(createHarness());
    for (const result of run.results) {
      expect(result.crossed).toEqual({ code: "TENUO_CONSTRAINT_VIOLATION", field: "path" });
    }
  });

  it("denied calls never reach the tool implementation", async () => {
    const run = await runConcurrentFlows(createHarness());
    expect(run.executed).toEqual([PATHS.reports, PATHS.finance, PATHS.reports, PATHS.finance]);
  });

  it("interleaves the flows in a fixed order every run", async () => {
    const first = await runConcurrentFlows(createHarness());
    const second = await runConcurrentFlows(createHarness());
    expect(first.log).toEqual(EXPECTED_LOG);
    expect(second.log).toEqual(EXPECTED_LOG);
  });

  it("does not leave either session in the caller after concurrent work", async () => {
    const harness = createHarness();
    await runConcurrentFlows(harness);
    const executed = [...harness.executed];
    for (const path of [PATHS.reports, PATHS.finance]) {
      await expect(harness.readFile.execute({ path })).rejects.toThrow(TenuoConfigurationError);
      await expect(harness.readFile.execute({ path })).rejects.toMatchObject({
        code: "TENUO_CONFIGURATION",
      });
    }
    expect(harness.executed).toEqual(executed);
  });

  it("an explicit session overrides ambient authority for only that call", async () => {
    const { tenuo, readFile, sessions, executed } = createHarness();
    await tenuo.withSession(sessions.finance, async () => {
      await expect(readFile.execute({ path: PATHS.reports })).rejects.toThrow(AuthorizationDeniedError);
      await expect(readFile.execute({ path: PATHS.reports }, { session: sessions.reports }))
        .resolves.toBe(`contents:${PATHS.reports}`);
      await expect(readFile.execute({ path: PATHS.reports })).rejects.toMatchObject({
        code: "TENUO_CONSTRAINT_VIOLATION", field: "path",
      });
      await expect(readFile.execute({ path: PATHS.finance })).resolves.toBe(`contents:${PATHS.finance}`);
    });
    expect(executed).toEqual([PATHS.reports, PATHS.finance]);
  });

  it("ambient context does not follow a job into a worker started outside withSession()", async () => {
    const harness = createHarness();
    const run = await runQueuedJobs(harness);
    expect(run.ambient).toBe("TenuoConfigurationError:TENUO_CONFIGURATION");
    expect(run.explicit).toBe(`ok:contents:${PATHS.reports}`);
    expect(harness.executed).toEqual([PATHS.reports]);
  });
});
