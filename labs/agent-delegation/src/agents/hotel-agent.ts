import { TOOLS, type Trip } from "../mission.ts";
import { APPROVED_HOTEL, type Hotel } from "../services/index.ts";
import { Agent, type Runtime } from "./runtime.ts";

/** Hotel Agent: book the approved hotel (or the cheapest under the nightly budget), pay. */
export async function runHotelAgent(rt: Runtime, trip: Trip): Promise<void> {
  const me = new Agent(rt, "hotel-agent", trip);
  await me.call(TOOLS.traveler_read, { traveler: trip.traveler, field: "name" });
  const search = await me.call(TOOLS.search_hotels, { city: trip.city });
  const results = ((search.result as { results?: Hotel[] } | undefined)?.results ?? []).filter(
    (h) => h.nightlyRate <= trip.hotelRateBudget,
  );
  const pick = results.find((h) => h.hotelId === APPROVED_HOTEL) ?? results.sort((a, b) => a.nightlyRate - b.nightlyRate)[0];
  if (pick === undefined) {
    return;
  }
  const booked = await me.call(TOOLS.book_hotel, {
    hotelId: pick.hotelId,
    city: pick.city,
    nightlyRate: pick.nightlyRate,
    nights: trip.nights,
    guest: trip.traveler,
    taskId: trip.taskId,
  });
  if (booked.allowed && booked.error === undefined) {
    await me.call(TOOLS.wallet_charge, { taskId: trip.taskId, amount: pick.nightlyRate * trip.nights });
  }

  if (rt.compromised === "hotel-agent") {
    await runCompromisedHotelAgent(me, trip, pick);
  }
}

/**
 * Stage 9. The compromised Hotel Agent tries seven more things. Item 3 books
 * the approved hotel at $320 a night: inside what the catalog offers, outside
 * what the mission allows, which is why a ceiling copied from the catalog
 * lets it through. Each goes
 * through the same chokepoint as everything else; the participant's chain
 * decides what happens.
 */
async function runCompromisedHotelAgent(me: Agent, trip: Trip, approved: Hotel): Promise<void> {
  const rt = me.rt;
  await me.call(TOOLS.book_hotel, { hotelId: "HTL-TUL-1", city: "Tulum", nightlyRate: 220, nights: trip.nights, guest: trip.traveler, taskId: trip.taskId }, "injected");
  await me.call(TOOLS.book_hotel, { hotelId: approved.hotelId, city: approved.city, nightlyRate: 320, nights: trip.nights, guest: trip.traveler, taskId: trip.taskId }, "injected");
  await me.call(TOOLS.traveler_read, { traveler: trip.traveler, field: "passportNumber" }, "injected");
  await me.call(TOOLS.book_flight, { flightId: "UA214", destination: "CUN", price: 286, passenger: trip.traveler }, "injected");
  await me.call(TOOLS.calendar_delete, { taskId: trip.taskId, eventId: "*" }, "injected");

  // 7. Hand wallet access to Activity Agent.
  const tenuo = rt.tenuo;
  if (tenuo !== undefined) {
    const mine = me.session();
    const record = (decision: "ALLOWED" | "DENIED", reason: string, code?: string) =>
      rt.audit.record({
        agent: "hotel-agent",
        task: trip.taskId,
        action: "narrow → activity-agent",
        resource: "wallet.charge",
        mode: "tenuo",
        decision,
        reason,
        ...(code !== undefined ? { code } : {}),
        centralCalls: 0,
        source: "injected",
      });
    if (mine === undefined) {
      record("DENIED", "hotel-agent holds no session to narrow", "NO_SESSION");
    } else {
      try {
        const { exact, max } = await import("@tenuo/core");
        const handed = tenuo.fleet["hotel-agent"].tenuo.narrow(
          mine,
          { "wallet.charge": { taskId: exact(trip.taskId), amount: max(200) } },
          { holder: tenuo.fleet["activity-agent"].publicKey },
        );
        tenuo.importFor("activity-agent", `${trip.taskId}:stolen-wallet`, handed);
        record("ALLOWED", "hotel-agent delegated wallet.charge to activity-agent");
      } catch (error) {
        const err = error as { code?: string; message?: string };
        record("DENIED", err.message ?? String(error), err.code);
      }
    }

    // 8. Use a permission copied from Flight Agent.
    const flight = tenuo.session("flight-agent", trip.taskId);
    const record8 = (decision: "ALLOWED" | "DENIED", reason: string, code?: string) =>
      rt.audit.record({
        agent: "hotel-agent",
        task: trip.taskId,
        action: "import flight-agent's warrant",
        resource: "copied warrant",
        mode: "tenuo",
        decision,
        reason,
        ...(code !== undefined ? { code } : {}),
        centralCalls: 0,
        source: "injected",
      });
    if (flight === undefined) {
      record8("DENIED", "flight-agent holds no session to copy", "NO_SESSION");
    } else {
      try {
        tenuo.importWireFor("hotel-agent", `${trip.taskId}:copied-flight`, flight.toWire());
        record8("ALLOWED", "hotel-agent imported flight-agent's warrant with its own key");
      } catch (error) {
        const err = error as { code?: string; message?: string };
        record8("DENIED", err.message ?? String(error), err.code);
      }
    }
  }
}
