/**
 * Travel Agent. The user talks to this one. It records the trip on the
 * calendar and hands the three branches to specialists. In mode 4 it is the
 * first holder of the trip's authority, received from the control plane.
 */
import { TOOLS, type Trip } from "../mission.ts";
import { Agent, type Runtime } from "./runtime.ts";
import { runActivityAgent } from "./activity-agent.ts";
import { runFlightAgent } from "./flight-agent.ts";
import { runHotelAgent } from "./hotel-agent.ts";

export interface TripOptions {
  /** Which branches to run. Stage 4's two-traveler probe only needs the flight side. */
  readonly branches?: readonly ("flight" | "hotel" | "activity")[];
}

export async function runTravelAgent(rt: Runtime, trip: Trip, options: TripOptions = {}): Promise<void> {
  const branches = options.branches ?? ["flight", "hotel", "activity"];
  const me = new Agent(rt, "travel-agent", trip);

  // Mode 4: the control plane signs the trip's authority for Travel Agent's key.
  const tenuo = rt.tenuo;
  const chain = rt.chain;
  if (tenuo !== undefined && chain !== undefined) {
    const record = (decision: "ALLOWED" | "DENIED", reason: string, code?: string) =>
      rt.audit.record({
        agent: "travel-agent",
        task: trip.taskId,
        action: "receive trip authority",
        resource: "control plane",
        mode: "tenuo",
        decision,
        reason,
        ...(code !== undefined ? { code } : {}),
        centralCalls: 0,
        source: "handoff",
      });
    try {
      const issued = chain.issueTrip(tenuo.controlPlane, tenuo.fleet, trip);
      const mine = tenuo.fleet["travel-agent"].tenuo.sessionFromWire({
        warrant: issued.toWire(),
        holderKey: tenuo.fleet["travel-agent"].holderKey,
      });
      tenuo.setSession("travel-agent", trip.taskId, mine);
      const info = mine.inspect();
      record("ALLOWED", `travel-agent holds {${info.tools.join(", ")}}, maxDepth ${info.maxDepth}`);
    } catch (error) {
      const err = error as { code?: string; message?: string };
      record("DENIED", err.message ?? String(error), err.code);
      return;
    }
  }

  await me.call(TOOLS.traveler_read, { traveler: trip.traveler, field: "name" });
  await me.call(TOOLS.calendar_create, { taskId: trip.taskId, title: `${trip.traveler}: ${trip.city}`, when: "Fri" });

  if (branches.includes("flight")) {
    const ok = me.handoff("flight-agent", (c, mine) => c.travelToFlight(mine, tenuo!.fleet, trip), trip.destination);
    if (ok) {
      await runFlightAgent(rt, trip);
    }
  }
  if (branches.includes("hotel")) {
    const ok = me.handoff("hotel-agent", (c, mine) => c.travelToHotel(mine, tenuo!.fleet, trip), trip.city);
    if (ok) {
      await runHotelAgent(rt, trip);
    }
  }
  if (branches.includes("activity")) {
    const ok = me.handoff("activity-agent", (c, mine) => c.travelToActivity(mine, tenuo!.fleet, trip), trip.city);
    if (ok) {
      await runActivityAgent(rt, trip);
    }
  }
}
