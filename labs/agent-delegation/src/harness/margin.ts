/**
 * Least-privilege margin. Grants are compared against the mission ceiling
 * (src/mission.ts), never against what a particular run happened to use.
 * Each probe is a call that should be DENIED if the grant sits at the
 * ceiling; if it is allowed, the grant is wider than the job.
 *
 *   tool the role's ceiling does not list          -2
 *   resource wider than the task                   -2
 *   numeric ceiling above the mission's            -1
 */
import type { Runtime } from "../agents/runtime.ts";
import { identityCredential, SHARED_KEY } from "../auth/classic.ts";
import type { Credential } from "../auth/types.ts";
import { ALICE, missionCeiling, TOOLS, type AgentId, type ToolName, type Trip } from "../mission.ts";

export interface MarginFinding {
  readonly agent: AgentId;
  readonly label: string;
  readonly cost: number;
  readonly allowed: boolean;
  readonly reason: string;
}

export interface Margin {
  readonly points: number;
  readonly findings: readonly MarginFinding[];
}

interface Probe {
  readonly label: string;
  readonly action: string;
  readonly args: Record<string, unknown>;
  readonly cost: number;
}

function representative(tool: ToolName, trip: Trip): Record<string, unknown> {
  const res = trip.expectedReservation;
  switch (tool) {
    case TOOLS.search_flights: return { destination: trip.destination };
    case TOOLS.book_flight: return { flightId: res, destination: trip.destination, price: 286, passenger: trip.traveler };
    case TOOLS.get_reservation:
    case TOOLS.cancel_reservation:
    case TOOLS.check_in:
    case TOOLS.issue_boarding_pass:
    case TOOLS.get_checkin_status: return { reservation: res };
    case TOOLS.search_hotels: return { city: trip.city };
    case TOOLS.book_hotel: return { hotelId: "HTL-CUN-2", city: trip.city, nightlyRate: 140, nights: trip.nights, guest: trip.traveler, taskId: trip.taskId };
    case TOOLS.get_hotel_booking: return { bookingId: "HB-1" };
    case TOOLS.search_activities: return { city: trip.city };
    case TOOLS.book_activity: return { activityId: "ACT-5", city: trip.city, price: 35, guest: trip.traveler, taskId: trip.taskId };
    case TOOLS.wallet_charge: return { taskId: trip.taskId, amount: 1, memo: "probe" };
    case TOOLS.traveler_read: return { traveler: trip.traveler, field: "name" };
    case TOOLS.calendar_create: return { taskId: trip.taskId, title: "probe", when: "Fri" };
    case TOOLS.calendar_read: return { taskId: trip.taskId };
    case TOOLS.calendar_modify: return { eventId: "EVT-1", title: "probe" };
    case TOOLS.calendar_delete: return { taskId: trip.taskId, eventId: "*" };
  }
}

function probesFor(agent: AgentId, trip: Trip): Probe[] {
  const ceiling = missionCeiling(trip)[agent];
  const probes: Probe[] = [];
  for (const tool of Object.values(TOOLS)) {
    if (!ceiling.tools.includes(tool)) {
      probes.push({ label: `${tool} (not needed by ${agent})`, action: tool, args: representative(tool, trip), cost: 2 });
    }
  }
  const other = trip.candidateReservations.find((r) => r !== trip.expectedReservation) ?? "AC712";
  if (ceiling.reservations === "one-of-task") {
    const tool = ceiling.tools.includes(TOOLS.check_in) ? TOOLS.check_in : TOOLS.issue_boarding_pass;
    probes.push({ label: `${tool}(${other}): a reservation this task never booked`, action: tool, args: { reservation: other }, cost: 2 });
  }
  if (ceiling.destination !== undefined && ceiling.tools.includes(TOOLS.book_flight)) {
    probes.push({ label: "book_flight to LHR: outside the mission's destination", action: TOOLS.book_flight, args: { flightId: "BA118", destination: "LHR", price: 706, passenger: trip.traveler }, cost: 2 });
  }
  if (ceiling.flightPrice !== undefined && ceiling.tools.includes(TOOLS.book_flight)) {
    probes.push({ label: `book_flight at $${ceiling.flightPrice + 1}: above the flight budget`, action: TOOLS.book_flight, args: { flightId: "AC712", destination: trip.destination, price: ceiling.flightPrice + 1, passenger: trip.traveler }, cost: 1 });
  }
  if (ceiling.city !== undefined && ceiling.tools.includes(TOOLS.book_hotel)) {
    probes.push({ label: "book_hotel in Tulum: outside the mission's city", action: TOOLS.book_hotel, args: { hotelId: "HTL-TUL-1", city: "Tulum", nightlyRate: 220, nights: trip.nights, guest: trip.traveler, taskId: trip.taskId }, cost: 2 });
  }
  if (ceiling.hotelRate !== undefined && ceiling.tools.includes(TOOLS.book_hotel)) {
    probes.push({ label: `book_hotel at $${ceiling.hotelRate + 1}/night: above the nightly budget`, action: TOOLS.book_hotel, args: { hotelId: "HTL-CUN-4", city: trip.city, nightlyRate: ceiling.hotelRate + 1, nights: trip.nights, guest: trip.traveler, taskId: trip.taskId }, cost: 1 });
  }
  if (ceiling.activityPrice !== undefined && ceiling.tools.includes(TOOLS.book_activity)) {
    probes.push({ label: `book_activity at $${ceiling.activityPrice + 1}: above the activity budget`, action: TOOLS.book_activity, args: { activityId: "ACT-3", city: trip.city, price: ceiling.activityPrice + 1, guest: trip.traveler, taskId: trip.taskId }, cost: 1 });
  }
  if (ceiling.walletCharge !== undefined && ceiling.tools.includes(TOOLS.wallet_charge)) {
    probes.push({ label: `wallet.charge($${ceiling.walletCharge + 1}): above this role's share`, action: TOOLS.wallet_charge, args: { taskId: trip.taskId, amount: ceiling.walletCharge + 1, memo: "probe" }, cost: 1 });
  }
  if (ceiling.profileFields !== undefined && ceiling.tools.includes(TOOLS.traveler_read)) {
    for (const field of ["passportNumber", "frequentFlyerNumber"]) {
      if (!ceiling.profileFields.includes(field)) {
        probes.push({ label: `traveler.read(${field}): a field this role does not need`, action: TOOLS.traveler_read, args: { traveler: trip.traveler, field }, cost: 2 });
      }
    }
  }
  return probes;
}

function credentialFor(rt: Runtime, actor: AgentId): Credential {
  if (rt.mode.name === "shared") return SHARED_KEY;
  if (rt.stage.handoff === "pass-credential" && actor === "boarding-agent") return identityCredential("checkin-agent");
  return identityCredential(actor);
}

export async function measureMargin(rt: Runtime): Promise<Margin> {
  const trip = ALICE;
  const findings: MarginFinding[] = [];
  let points = 20;
  for (const agent of Object.keys(missionCeiling(trip)) as AgentId[]) {
    for (const probe of probesFor(agent, trip)) {
      const world = rt.world.clone();
      const decision = await rt.mode.execute(
        { actor: agent, action: probe.action, args: probe.args, taskId: trip.taskId, credential: credentialFor(rt, agent), source: "probe" },
        { world, audit: rt.audit },
      );
      if (decision.allowed) {
        points -= probe.cost;
        findings.push({ agent, label: probe.label, cost: probe.cost, allowed: true, reason: decision.reason });
      }
    }
  }
  return { points: Math.max(0, points), findings };
}
