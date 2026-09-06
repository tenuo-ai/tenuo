import { ALICE, BOB, type AgentId, type Trip } from "./mission.ts";
import type { Scenario } from "./stages.ts";

export interface ScenarioPlan {
  readonly name: Scenario;
  readonly trips: readonly Trip[];
  readonly branches: readonly ("flight" | "hotel" | "activity")[];
  readonly compromised?: AgentId;
}

export function plan(name: Scenario): ScenarioPlan {
  switch (name) {
    case "spring-break":
      return { name, trips: [ALICE], branches: ["flight", "hotel", "activity"] };
    case "two-travelers":
      return { name, trips: [ALICE, BOB], branches: ["flight"] };
    case "incident":
      return { name, trips: [ALICE], branches: ["flight", "hotel", "activity"], compromised: "hotel-agent" };
  }
}

export function wallets(p: ScenarioPlan): Record<string, number> {
  return Object.fromEntries(p.trips.map((t) => [t.taskId, t.budget]));
}
