import { describe, expect, it } from "vitest";
import { handle, MemoryStore, validate, RejectedEvent } from "../collector/src/collector.ts";

const session = "3f2b4c1e-8d9a-4b7c-9e6f-1a2b3c4d5e6f";
const base = { v: 1, session, sentAt: "2026-09-06T20:00:00.000Z", event: "run", stage: 6, platform: "darwin", node: 20 };

describe("collector", () => {
  it("accepts a well-formed run event and stores only known fields", async () => {
    const store = new MemoryStore();
    const body = JSON.stringify({ ...base, command: "score", scenario: "spring-break", functionalityOk: true, score: 100, failedChecks: [], centralCalls: 0, elapsedMs: 4200, secret: "should not be stored" });
    const r = await handle("POST", "/v1/events", body, new URLSearchParams(), store);
    expect(r).toEqual({ status: 202, body: { accepted: 1, rejected: 0 } });
    expect(store.events[0]).toMatchObject({ session, event: "run", stage: 6, score: 100, functionalityOk: true });
    expect(JSON.stringify(store.events[0])).not.toContain("secret");
  });

  it("rejects off-shape events without failing the batch", async () => {
    const store = new MemoryStore();
    const body = JSON.stringify([
      base,
      { ...base, session: "not-a-uuid" },
      { ...base, event: "keylog" },
      { ...base, stage: 11 },
      { ...base, failedChecks: ["x".repeat(500)] },
      { ...base, cohort: "bad cohort!" },
    ]);
    const r = await handle("POST", "/v1/events", body, new URLSearchParams(), store);
    expect(r.body).toEqual({ accepted: 1, rejected: 5 });
  });

  it("refuses oversized and malformed bodies", async () => {
    const store = new MemoryStore();
    expect((await handle("POST", "/v1/events", "{", new URLSearchParams(), store)).status).toBe(400);
    expect((await handle("POST", "/v1/events", "x".repeat(20_000), new URLSearchParams(), store)).status).toBe(413);
    expect((await handle("POST", "/v1/events", null, new URLSearchParams(), store)).status).toBe(400);
    expect((await handle("GET", "/nope", null, new URLSearchParams(), store)).status).toBe(404);
  });

  it("summarizes per stage and per cohort", async () => {
    const store = new MemoryStore();
    const other = "9f2b4c1e-8d9a-4b7c-9e6f-1a2b3c4d5e6f";
    const events = [
      { ...base, event: "stage_enter", stage: 4, cohort: "room-a" },
      { ...base, event: "run", stage: 4, cohort: "room-a", functionalityOk: false },
      { ...base, event: "run", stage: 4, cohort: "room-a", functionalityOk: true },
      { ...base, session: other, event: "run", stage: 4, cohort: "room-b", functionalityOk: false },
    ];
    await handle("POST", "/v1/events", JSON.stringify(events), new URLSearchParams(), store);
    const all = await handle("GET", "/v1/summary", null, new URLSearchParams(), store);
    const stage4 = (all.body as { stages: Array<{ stage: number; sessionsEntered: number; sessionsWithWorkingTrip: number; runs: number }> }).stages[3];
    expect(stage4).toEqual({ stage: 4, sessionsEntered: 2, sessionsWithWorkingTrip: 1, runs: 3 });
    const roomA = await handle("GET", "/v1/summary", null, new URLSearchParams("cohort=room-a"), store);
    expect((roomA.body as { stages: Array<{ sessionsEntered: number }> }).stages[3]?.sessionsEntered).toBe(1);
  });

  it("validate() normalizes and bounds", () => {
    const e = validate({ ...base, session: session.toUpperCase(), score: 99.6 }, new Date("2026-09-06T20:00:01Z"));
    expect(e.session).toBe(session);
    expect(e.score).toBe(100);
    expect(() => validate({ ...base, v: 2 }, new Date())).toThrow(RejectedEvent);
  });
});
