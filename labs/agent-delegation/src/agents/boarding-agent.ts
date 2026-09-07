import type { Credential } from "../auth/types.ts";
import { TOOLS, type Trip } from "../mission.ts";
import { Agent, type Runtime } from "./runtime.ts";

/** Boarding Agent: one reservation, one boarding pass. */
export async function runBoardingAgent(
  rt: Runtime,
  trip: Trip,
  reservation: string,
  credential?: Credential,
): Promise<void> {
  const me = new Agent(rt, "boarding-agent", trip, credential);
  await me.call(TOOLS.issue_boarding_pass, { reservation });
}
