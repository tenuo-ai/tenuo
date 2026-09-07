import { describe, expect, it } from "vitest";
import { handle, MemoryStore, RejectedEvent, summarize, validate, type Summary } from "../collector/src/collector.ts";

const session = "3f2b4c1e-8d9a-4b7c-9e6f-1a2b3c4d5e6f";
const other = "9f2b4c1e-8d9a-4b7c-9e6f-1a2b3c4d5e6f";
const base = { v: 1, session, sentAt: "2026-09-06T20:00:00.000Z", event: "run", stage: 6, labVersion: "0.1.0+abc1234", env: "local", platform: "darwin", node: 20 };
const at = (minutes: number) => new Date(Date.UTC(2026, 8, 6, 20, minutes)).toISOString();

async function post(store: MemoryStore, events: unknown) {
  return handle("POST", "/v1/events", JSON.stringify(events), new URLSearchParams(), store);
}

describe("collector", () => {
  it("accepts a well-formed run event and stores only known fields", async () => {
    const store = new MemoryStore();
    const r = await post(store, { ...base, command: "score", scenario: "spring-break", functionalityOk: true, score: 100, failedChecks: [], centralCalls: 0, elapsedMs: 4200, fix: "per-task", marginPoints: 20, marginAgents: [], secret: "should not be stored" });
    expect(r).toEqual({ status: 202, body: { accepted: 1, rejected: 0 } });
    expect(store.events[0]).toMatchObject({ session, event: "run", stage: 6, score: 100, functionalityOk: true, labVersion: "0.1.0+abc1234", env: "local", fix: "per-task", marginPoints: 20 });
    expect(JSON.stringify(store.events[0])).not.toContain("secret");
  });

  it("accepts the guide's page events, including stage 0 for the index", async () => {
    const store = new MemoryStore();
    const r = await post(store, [
      { ...base, event: "page_view", stage: 0, env: "web", platform: "web", node: 0 },
      { ...base, event: "hint_open", stage: 5, env: "web", platform: "web", node: 0 },
      { ...base, event: "mark_done", stage: 8, env: "web", platform: "web", node: 0 },
    ]);
    expect(r.body).toEqual({ accepted: 3, rejected: 0 });
  });

  it("rejects off-shape events without failing the batch", async () => {
    const store = new MemoryStore();
    const r = await post(store, [
      base,
      { ...base, session: "not-a-uuid" },
      { ...base, event: "keylog" },
      { ...base, stage: 11 },
      { ...base, failedChecks: ["x".repeat(500)] },
      { ...base, cohort: "bad cohort!" },
      { ...base, env: "office" },
      { ...base, fix: "magic" },
      { ...base, marginPoints: 21 },
    ]);
    expect(r.body).toEqual({ accepted: 1, rejected: 8 });
  });

  it("refuses oversized and malformed bodies", async () => {
    const store = new MemoryStore();
    expect((await handle("POST", "/v1/events", "{", new URLSearchParams(), store)).status).toBe(400);
    expect((await handle("POST", "/v1/events", "x".repeat(20_000), new URLSearchParams(), store)).status).toBe(413);
    expect((await handle("POST", "/v1/events", null, new URLSearchParams(), store)).status).toBe(400);
    expect((await handle("GET", "/nope", null, new URLSearchParams(), store)).status).toBe(404);
  });

  it("summarizes attempts, time, scores, failed checks, and guide use per stage", async () => {
    const store = new MemoryStore();
    await post(store, [
      { ...base, event: "opt_in", stage: 1, sentAt: at(0) },
      // Session A: three tries in stage 4, working on the third, then moves to stage 5 after 30 minutes.
      { ...base, event: "stage_enter", stage: 4, sentAt: at(1) },
      { ...base, event: "page_view", stage: 4, env: "web", sentAt: at(2) },
      { ...base, command: "attack", stage: 4, functionalityOk: false, failedChecks: ["Task A agent: check_in(DL331)", "check_in(UA214)   inherited?"], sentAt: at(5) },
      { ...base, event: "hint_open", stage: 4, env: "web", sentAt: at(6) },
      { ...base, command: "attack", stage: 4, functionalityOk: false, failedChecks: ["Task A agent: check_in(DL331)"], sentAt: at(15) },
      { ...base, command: "score", stage: 4, functionalityOk: true, score: 82, fix: "per-task", sentAt: at(25) },
      { ...base, command: "trace", stage: 4, sentAt: at(28) },
      { ...base, event: "stage_enter", stage: 5, sentAt: at(31) },
      // Session B: one try, working, in Codespaces, 10 minutes, then stage 5.
      { ...base, session: other, env: "codespaces", command: "score", stage: 4, functionalityOk: true, score: 90, fix: "policy-service", failedChecks: ["Task A agent: check_in(DL331)"], sentAt: at(40) },
      { ...base, session: other, env: "codespaces", event: "stage_enter", stage: 5, sentAt: at(50) },
    ]);
    const r = await handle("GET", "/v1/summary", null, new URLSearchParams(), store);
    const s = r.body as Summary;
    expect(s.sessions).toBe(2);
    expect(s.optIns).toBe(1);
    expect(s.envs).toEqual({ local: 1, codespaces: 1 });
    expect(s.versions).toEqual({ "0.1.0+abc1234": 2 });
    expect(s.fixes).toEqual({ "per-task": 1, "policy-service": 1 });
    const stage4 = s.stages[3]!;
    expect(stage4).toMatchObject({ stage: 4, sessionsEntered: 2, sessionsWithWorkingTrip: 2, runs: 5, medianAttemptsToWorkingTrip: 2, medianMinutes: 20, medianScore: 86, pageViews: 1, hintOpens: 1, answerOpens: 0, markedDone: 0 });
    expect(stage4.topFailedChecks).toEqual([
      { label: "Task A agent: check_in(DL331)", sessions: 2 },
      { label: "check_in(UA214)   inherited?", sessions: 1 },
    ]);
    const cohort = await handle("GET", "/v1/summary", null, new URLSearchParams("cohort=room-a"), store);
    expect((cohort.body as Summary).sessions).toBe(0);
  });

  it("validate() normalizes and bounds", () => {
    const e = validate({ ...base, session: session.toUpperCase(), score: 99.6 }, new Date("2026-09-06T20:00:01Z"));
    expect(e.session).toBe(session);
    expect(e.score).toBe(100);
    expect(() => validate({ ...base, v: 2 }, new Date())).toThrow(RejectedEvent);
    expect(summarize([]).stages).toHaveLength(8);
  });
});
