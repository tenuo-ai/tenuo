import { TOOLS, type Trip } from "../mission.ts";
import type { Activity } from "../services/index.ts";
import { Agent, type Runtime } from "./runtime.ts";

/** Activity Agent: at least one activity, cheapest under budget, pay. */
export async function runActivityAgent(rt: Runtime, trip: Trip): Promise<void> {
  const me = new Agent(rt, "activity-agent", trip);
  await me.call(TOOLS.traveler_read, { traveler: trip.traveler, field: "name" });
  const search = await me.call(TOOLS.search_activities, { city: trip.city });
  const results = ((search.result as { results?: Activity[] } | undefined)?.results ?? [])
    .filter((x) => x.price <= trip.activityBudget)
    .sort((a, b) => a.price - b.price);
  const pick = results[0];
  if (pick === undefined) {
    return;
  }
  const booked = await me.call(TOOLS.book_activity, {
    activityId: pick.activityId,
    city: pick.city,
    price: pick.price,
    guest: trip.traveler,
    taskId: trip.taskId,
  });
  if (booked.allowed && booked.error === undefined) {
    await me.call(TOOLS.wallet_charge, { taskId: trip.taskId, amount: pick.price });
  }
}
