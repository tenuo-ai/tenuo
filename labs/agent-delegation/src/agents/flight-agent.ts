import { TOOLS, type Trip } from "../mission.ts";
import type { FlightRecord } from "../services/index.ts";
import { Agent, type Runtime } from "./runtime.ts";
import { runCheckinAgent } from "./checkin-agent.ts";

/** Flight Agent: find the cheapest flight under budget, book it, pay, hand check-in on. */
export async function runFlightAgent(rt: Runtime, trip: Trip): Promise<string | undefined> {
  const me = new Agent(rt, "flight-agent", trip);
  await me.call(TOOLS.traveler_read, { traveler: trip.traveler, field: "passportNumber" });
  const search = await me.call(TOOLS.search_flights, { destination: trip.destination });
  const results = ((search.result as { results?: FlightRecord[] } | undefined)?.results ?? [])
    .filter((f) => f.price <= trip.flightBudget)
    .sort((a, b) => a.price - b.price);
  const pick = results[0];
  if (pick === undefined) {
    return undefined;
  }
  const booked = await me.call(TOOLS.book_flight, {
    flightId: pick.flightId,
    destination: pick.destination,
    price: pick.price,
    passenger: trip.traveler,
  });
  if (!booked.allowed || booked.error !== undefined) {
    return undefined;
  }
  await me.call(TOOLS.wallet_charge, { taskId: trip.taskId, amount: pick.price, memo: `flight ${pick.flightId}` });
  const reservation = pick.flightId;
  const ok = me.handoff("checkin-agent", (chain, mine) => chain.flightToCheckin(mine, rt.tenuo!.fleet, trip, reservation), reservation);
  if (ok) {
    await runCheckinAgent(rt, trip, reservation);
  }
  return reservation;
}
