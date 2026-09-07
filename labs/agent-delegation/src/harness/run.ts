/**
 * Build a runtime for a stage and run its scenario. Everything the CLI and
 * the tests do starts here.
 */
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { runTravelAgent } from "../agents/travel-agent.ts";
import type { ChainModule, Runtime } from "../agents/runtime.ts";
import { AuditLog } from "../audit.ts";
import { ClassicMode } from "../auth/classic.ts";
import { PolicyService } from "../auth/policy-service.ts";
import type { PolicyConfig } from "../auth/policy.ts";
import { TenuoMode } from "../auth/tenuo-mode.ts";
import type { AuthMode } from "../auth/types.ts";
import { createControlPlane } from "../control-plane.ts";
import { generateFleet } from "../keys.ts";
import { plan, wallets, type ScenarioPlan } from "../scenarios.ts";
import { World } from "../services/index.ts";
import { ROOT } from "../state.ts";
import type { Scenario, StageDef } from "../stages.ts";

export interface LoadedExercise {
  readonly path: string;
  readonly config?: PolicyConfig;
  readonly chain?: ChainModule;
  readonly error?: string;
}

/** Import the participant's file. A file that does not load is a real outcome, reported, never hidden. */
export async function loadExercise(stage: StageDef, override?: string): Promise<LoadedExercise | undefined> {
  const rel = override ?? stage.exercise;
  if (rel === undefined) {
    return undefined;
  }
  const path = join(ROOT, rel);
  try {
    const mod = (await import(`${pathToFileURL(path).href}?t=${Date.now()}`)) as Record<string, unknown>;
    if (stage.mode === "scoped") {
      const config = mod["config"] as PolicyConfig | undefined;
      if (config === undefined || typeof config !== "object" || typeof config.policy !== "object") {
        return { path, error: `${rel} must export \`config: PolicyConfig\`` };
      }
      return { path, config };
    }
    const chain = mod as unknown as ChainModule;
    for (const fn of ["issueTrip", "travelToFlight", "travelToHotel", "travelToActivity", "flightToCheckin", "checkinToBoarding"]) {
      if (typeof (chain as unknown as Record<string, unknown>)[fn] !== "function") {
        return { path, error: `${rel} must export function ${fn}` };
      }
    }
    return { path, chain };
  } catch (error) {
    return { path, error: error instanceof Error ? error.message : String(error) };
  }
}

export interface Built {
  readonly runtime: Runtime;
  readonly plan: ScenarioPlan;
  readonly exercise?: LoadedExercise;
}

export async function buildRuntime(stage: StageDef, scenario: Scenario, exerciseOverride?: string): Promise<Built> {
  const p = plan(scenario);
  const world = new World(wallets(p));
  const audit = new AuditLog();
  const exercise = await loadExercise(stage, exerciseOverride);
  const policyService = new PolicyService();
  for (const trip of p.trips) {
    policyService.registerTask(trip);
  }

  let mode: AuthMode;
  let tenuo: TenuoMode | undefined;
  if (stage.mode === "tenuo") {
    const controlPlane = createControlPlane();
    const generated = generateFleet(controlPlane.issuerPublicKey());
    tenuo = new TenuoMode(generated.fleet, generated.holderKeys);
    if (exercise?.chain !== undefined) {
      for (const trip of p.trips) {
        try {
          const issued = exercise.chain.issueTrip(controlPlane, generated.fleet, trip);
          tenuo.importFor("travel-agent", trip.taskId, issued);
        } catch (error) {
          tenuo.recordIssuanceError(trip.taskId, error);
        }
      }
    }
    mode = tenuo;
  } else if (stage.mode === "scoped") {
    mode = new ClassicMode("scoped", exercise?.config, policyService);
    // Fix A: the orchestrator registers every per-task identity at task start.
    // Each registration is a central call, and it shows in the trace.
    for (const identity of Object.keys(exercise?.config?.policy ?? {}).filter((k) => k.includes(":"))) {
      const taskId = identity.split(":")[1] ?? "";
      if (!p.trips.some((t) => t.taskId === taskId)) {
        continue;
      }
      await policyService.registerIdentity(identity);
      audit.record({
        agent: "travel-agent",
        task: taskId,
        action: "register identity",
        resource: identity,
        mode: "scoped",
        decision: "ALLOWED",
        reason: "orchestrator registered a per-task identity with the registry before the task's first call",
        centralCalls: 1,
        source: "handoff",
      });
    }
  } else {
    mode = new ClassicMode(stage.mode);
  }

  const runtime: Runtime = {
    stage,
    mode,
    world,
    audit,
    policyService,
    ...(exercise?.config !== undefined ? { config: exercise.config } : {}),
    ...(tenuo !== undefined ? { tenuo } : {}),
    ...(exercise?.chain !== undefined ? { chain: exercise.chain } : {}),
    ...(p.compromised !== undefined ? { compromised: p.compromised } : {}),
  };
  return { runtime, plan: p, ...(exercise !== undefined ? { exercise } : {}) };
}

/** Run every trip in the plan. Returns the built runtime with a populated audit log and world. */
export async function runScenario(stage: StageDef, scenario: Scenario, exerciseOverride?: string): Promise<Built> {
  const built = await buildRuntime(stage, scenario, exerciseOverride);
  if (built.exercise?.error !== undefined) {
    return built;
  }
  for (const trip of built.plan.trips) {
    await runTravelAgent(built.runtime, trip, { branches: built.plan.branches });
  }
  return built;
}
