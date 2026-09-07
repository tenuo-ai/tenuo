/**
 * Every stage, run with the reference solution, lands every check the guide
 * promises. If an SDK change breaks a chain, this is where it shows up.
 */
process.env.NODE_ENV = "development";

import { describe, expect, it } from "vitest";
import { runBattery } from "../src/harness/attacks.ts";
import { checkFunctionality } from "../src/harness/functionality.ts";
import { measureMargin } from "../src/harness/margin.ts";
import { runScenario } from "../src/harness/run.ts";
import { score } from "../src/harness/score.ts";
import { stage } from "../src/stages.ts";

async function evaluate(n: number, answer?: string, scenario = stage(n).scenario) {
  const def = stage(n);
  const built = await runScenario(def, scenario, answer);
  expect(built.exercise?.error).toBeUndefined();
  const functionality = checkFunctionality(built.plan, built.runtime.audit.records, built.runtime.world);
  const probes = await runBattery(built.runtime, built.plan);
  const margin = await measureMargin(built.runtime);
  return { built, functionality, probes, margin, score: score(functionality, probes, margin) };
}

describe("stage 1: one key for everyone", () => {
  it("books the trip and lets the injected content through", async () => {
    const r = await evaluate(1);
    expect(r.functionality.ok).toBe(true);
    expect(r.functionality.damage.length).toBeGreaterThan(0);
    expect(r.probes.filter((p) => p.category === "blocked").every((p) => !p.ok)).toBe(true);
    expect(r.built.runtime.world.balance("trip-alice-cun")).toBeLessThan(1200 - 286 - 420 - 35);
    expect(r.score.margin.points).toBe(0);
  });
});

describe("stage 2: per-agent identities", () => {
  it("stops cross-role damage and keeps same-role damage", async () => {
    const r = await evaluate(2);
    expect(r.functionality.ok).toBe(true);
    const by = Object.fromEntries(r.probes.map((p) => [p.label, p]));
    expect(by["wallet.charge(412)"]?.actual).toBe("DENIED");
    expect(by["cancel_reservation(UA214)"]?.actual).toBe("DENIED");
    expect(by["get_reservation(AA882)"]?.actual).toBe("ALLOWED");
    expect(by["check_in(AA882)"]?.actual).toBe("ALLOWED");
  });
});

describe("stage 3: scoped rules", () => {
  it("the starter lets AA882 through; the answer blocks everything and books the trip", async () => {
    const starter = await evaluate(3);
    expect(starter.functionality.ok).toBe(true);
    expect(starter.probes.find((p) => p.label === "check_in(AA882)")?.actual).toBe("ALLOWED");

    const r = await evaluate(3, "answers/03-scoped/policy.ts");
    expect(r.functionality.ok).toBe(true);
    expect(r.probes.filter((p) => p.category !== "sanity").every((p) => p.ok)).toBe(true);
    expect(r.score.total).toBeGreaterThanOrEqual(95);
  });
});

describe("stage 4: two travelers", () => {
  it("the stage 3 policy breaks Bob's trip", async () => {
    const r = await evaluate(4);
    expect(r.functionality.ok).toBe(false);
    expect(r.functionality.steps.some((s) => s.trip === "trip-bob-sea" && !s.ok)).toBe(true);
  });
  it("per-task identities pass the cross-task probe, with registration and registry checks counted", async () => {
    const r = await evaluate(4, "answers/04-two-travelers/per-task.ts");
    expect(r.functionality.ok).toBe(true);
    expect(r.probes.filter((p) => p.category === "cross-task").every((p) => p.ok)).toBe(true);
    // Registration at task start plus one registry check per call: not zero.
    expect(r.built.runtime.audit.centralCalls()).toBeGreaterThan(0);
  });
  it("a policy service passes the cross-task probe at one central call per check", async () => {
    const r = await evaluate(4, "answers/04-two-travelers/policy-service.ts");
    expect(r.functionality.ok).toBe(true);
    expect(r.probes.filter((p) => p.category === "cross-task").every((p) => p.ok)).toBe(true);
    expect(r.built.runtime.audit.centralCalls()).toBeGreaterThan(0);
  });
});

describe("stage 5: the handoff", () => {
  it("boarding-agent inherits check-in authority, and the policy service accepts the escalation", async () => {
    const r = await evaluate(5, "answers/04-two-travelers/per-task.ts");
    expect(r.functionality.ok).toBe(true);
    const by = Object.fromEntries(r.probes.map((p) => [p.label, p]));
    expect(by["check_in(UA214)   inherited?"]?.actual).toBe("ALLOWED");
    expect(by["get_reservation(UA214)   inherited?"]?.actual).toBe("ALLOWED");
    expect(by["requested: every reservation; read, check in, cancel"]?.actual).toBe("ALLOWED");
  });
});

describe("stage 6: tenuo", () => {
  it("does not expose root signing material or holder private keys to agent code", async () => {
    const r = await evaluate(6, "answers/06-tenuo/chain.ts");
    const tenuo = r.built.runtime.tenuo!;
    expect("controlPlane" in tenuo).toBe(false);
    expect("holderKeys" in tenuo).toBe(false);
    for (const context of Object.values(tenuo.fleet)) {
      expect("holderKey" in context).toBe(false);
      expect(Object.keys(context).sort()).toEqual(["publicKey", "tenuo"]);
    }
  });

  it("the starter fails at the first link the participant must write", async () => {
    const r = await evaluate(6);
    expect(r.functionality.ok).toBe(false);
    const handoff = r.built.runtime.audit.records.find((x) => x.source === "handoff" && x.decision === "DENIED");
    expect(handoff?.reason).toMatch(/TODO: write the Flight → Check-in link/);
  });
  it("the completed chain books the trip, blocks everything, refuses the escalation locally, with zero central calls", async () => {
    const r = await evaluate(6, "answers/06-tenuo/chain.ts");
    expect(r.functionality.ok).toBe(true);
    expect(r.functionality.damage).toEqual([]);
    expect(r.probes.filter((p) => p.category !== "sanity").every((p) => p.ok)).toBe(true);
    const escalation = r.probes.find((p) => p.section.startsWith("ESCALATION"));
    expect(escalation?.code).toBe("TENUO_CHAIN_INVALID");
    expect(r.built.runtime.audit.centralCalls()).toBe(0);
    expect(r.score.total).toBeGreaterThanOrEqual(95);
  });
  it("the two-traveler run passes cross-task with no policy file", async () => {
    const r = await evaluate(6, "answers/06-tenuo/chain.ts", "two-travelers");
    expect(r.functionality.ok).toBe(true);
    expect(r.probes.filter((p) => p.category === "cross-task").every((p) => p.ok)).toBe(true);
  });
});

describe("stage 7: stolen warrant", () => {
  it("a copied warrant cannot be imported by another agent", async () => {
    const r = await evaluate(7, "answers/06-tenuo/chain.ts");
    const stolen = r.probes.find((p) => p.section.startsWith("STOLEN"));
    expect(stolen?.ok).toBe(true);
    expect(stolen?.code).toBe("TENUO_INVALID_POP");
  });
});

describe("stage 8: terminal", () => {
  it("the terminal link stops the handoff with TENUO_DEPTH_EXCEEDED and the trip breaks there", async () => {
    const r = await evaluate(8, "answers/08-terminal/chain.ts");
    expect(r.functionality.ok).toBe(false);
    const terminal = r.probes.find((p) => p.section === "TERMINAL");
    expect(terminal?.ok).toBe(true);
    expect(terminal?.code).toBe("TENUO_DEPTH_EXCEEDED");
    expect(r.functionality.steps.find((s) => s.step.startsWith("check-in"))?.ok).toBe(true);
    expect(r.functionality.steps.find((s) => s.step.startsWith("boarding"))?.ok).toBe(false);
  });
});

describe("stage 9: the incident", () => {
  it("the starter fails items 4, 5, and 7", async () => {
    const r = await evaluate(9);
    const by = Object.fromEntries(r.probes.map((p) => [p.label.slice(0, 2), p]));
    expect(by["1."]?.ok).toBe(true);
    expect(by["2."]?.ok).toBe(true);
    expect(by["3."]?.ok).toBe(true);
    expect(by["4."]?.ok).toBe(false);
    expect(by["5."]?.ok).toBe(false);
    expect(by["6."]?.ok).toBe(true);
    expect(by["7."]?.ok).toBe(false);
    expect(by["8."]?.ok).toBe(true);
  });
  it("the answer lands all eight and books the trip", async () => {
    const r = await evaluate(9, "answers/09-incident/chain.ts");
    expect(r.functionality.ok).toBe(true);
    expect(r.probes.every((p) => p.ok)).toBe(true);
    expect(r.probes.find((p) => p.label.startsWith("7."))?.code).toBe("TENUO_DEPTH_EXCEEDED");
    expect(r.probes.find((p) => p.label.startsWith("8."))?.code).toBe("TENUO_INVALID_POP");
    expect(r.score.total).toBeGreaterThanOrEqual(95);
  });
});
