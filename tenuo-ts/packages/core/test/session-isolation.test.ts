/**
 * Regression test for concurrent session isolation.
 *
 * Drives `examples/concurrent-sessions.ts`. Each test is one acceptance
 * criterion: two simultaneous requests never borrow each other's authority,
 * a denied call never runs the tool, and the interleaving is fixed rather
 * than timing-dependent. The first three tests share one execution on
 * purpose, so they are facts about the same run rather than about three
 * independent ones.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { AuthorizationDeniedError, TenuoConfigurationError } from "../src/index.ts";
import {
  createHarness,
  PATHS,
  runConcurrentFlows,
  runQueuedJobs,
  type ConcurrentRun,
  type FlowName,
  type FlowResult,
} from "../examples/concurrent-sessions.ts";

// Each flow's step lands between the other flow's steps, so this exact order
// can only appear if the two flows really alternated.
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
  // One execution shared by the criteria below, so own-path access, the
  // cross-path denial, and the executed paths all describe the same run.
  let run: ConcurrentRun;
  beforeAll(async () => {
    run = await runConcurrentFlows(createHarness());
  });

  it("each flow reads only its own path while interleaved with the other", () => {
    const reports = byName(run.results, "reports");
    const finance = byName(run.results, "finance");
    expect(reports.own).toBe(`contents:${PATHS.reports}`);
    expect(reports.ownAgain).toBe(`contents:${PATHS.reports}`);
    expect(finance.own).toBe(`contents:${PATHS.finance}`);
    expect(finance.ownAgain).toBe(`contents:${PATHS.finance}`);
  });

  it("a flow cannot use the other flow's session", () => {
    for (const result of run.results) {
      expect(result.crossed).toEqual({ code: "TENUO_CONSTRAINT_VIOLATION", field: "path" });
    }
  });

  it("denied calls never reach the tool implementation", () => {
    expect(run.executed).toEqual([PATHS.reports, PATHS.finance, PATHS.reports, PATHS.finance]);
  });

  it("interleaves the flows in a fixed order every run", async () => {
    const again = await runConcurrentFlows(createHarness());
    expect(run.log).toEqual(EXPECTED_LOG);
    expect(again.log).toEqual(EXPECTED_LOG);
  });

  it("does not leave either session in the caller after concurrent work", async () => {
    // withSession() ends with its callback, so nothing is ambient afterwards.
    const harness = createHarness();
    await runConcurrentFlows(harness);
    const executed = [...harness.executed];
    for (const path of [PATHS.reports, PATHS.finance]) {
      await expect(harness.readFile.execute({ path })).rejects.toThrow(TenuoConfigurationError);
      await expect(harness.readFile.execute({ path })).rejects.toMatchObject({
        code: "TENUO_CONFIGURATION",
        message: expect.stringContaining("No session"),
      });
    }
    expect(harness.executed).toEqual(executed);
  });

  it("an explicit session overrides ambient authority for only that call", async () => {
    // options.session wins over the ambient store for that one call and leaves
    // the ambient session in place for the next.
    const { tenuo, readFile, sessions, executed } = createHarness();
    await tenuo.withSession(sessions.finance, async () => {
      await expect(readFile.execute({ path: PATHS.reports })).rejects.toThrow(AuthorizationDeniedError);
      await expect(
        readFile.execute({ path: PATHS.reports }, { session: sessions.reports }),
      ).resolves.toBe(`contents:${PATHS.reports}`);
      await expect(readFile.execute({ path: PATHS.reports })).rejects.toMatchObject({
        code: "TENUO_CONSTRAINT_VIOLATION",
        field: "path",
      });
      await expect(readFile.execute({ path: PATHS.finance })).resolves.toBe(`contents:${PATHS.finance}`);
    });
    expect(executed).toEqual([PATHS.reports, PATHS.finance]);
  });

  it("ambient context does not follow a job into a worker started outside withSession()", async () => {
    const harness = createHarness();
    const queued = await runQueuedJobs(harness);
    expect(queued.ambient).toMatchObject({
      ok: false,
      name: "TenuoConfigurationError",
      code: "TENUO_CONFIGURATION",
      message: expect.stringContaining("No session"),
    });
    expect(queued.explicit).toEqual({ ok: true, value: `contents:${PATHS.reports}` });
    expect(harness.executed).toEqual([PATHS.reports]);
  });
});
