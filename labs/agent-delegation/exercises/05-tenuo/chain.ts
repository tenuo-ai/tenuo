/**
 * Stage 5: access that travels with the work.
 *
 * Each function returns a session bound to the *next* agent's key. The
 * caller cannot use what it hands over (it holds no secret for it); the
 * receiver imports it with its own holder key. Core refuses any link that
 * is not within its parent before a token exists.
 *
 * The first four links are written for you. Read them first:
 *   - the root lists everything anyone further down will ever need, because
 *     a child can never hold what its parent does not;
 *   - `reservation` at the root means "any Cancún flight this trip might
 *     book". Notice which link narrows that to the one that was booked.
 *
 * Flight → Check-in is the tutorial. Read it, run it, then copy its shape for
 * the one level you complete: Check-in → Boarding.
 *
 * Policies are zero-trust: every argument a tool is called with must be
 * named. `any()` names a free-form string argument without constraining it.
 */
import { exact, max, oneOf, pattern, type Session, type Tenuo } from "@tenuo/core";
import type { Fleet } from "../../src/keys.ts";
import type { Trip } from "../../src/mission.ts";

const any = () => pattern("*");

/** Root: minted by the control plane, held by Travel Agent. Written for you. */
export function issueTrip(controlPlane: Tenuo, fleet: Fleet, trip: Trip): Session {
  const reservation = oneOf([...trip.candidateReservations]);
  const destination = oneOf([trip.destination]);
  return controlPlane.session({
    allow: {
      "traveler.read": { traveler: exact(trip.traveler), field: oneOf(["name", "passportNumber"]) },
      "calendar.create": { taskId: exact(trip.taskId), title: any(), when: any() },
      search_flights: { destination },
      book_flight: { flightId: reservation, destination, price: max(trip.flightBudget), passenger: exact(trip.traveler) },
      get_reservation: { reservation },
      check_in: { reservation },
      issue_boarding_pass: { reservation },
      search_hotels: { city: exact(trip.city) },
      book_hotel: {
        hotelId: any(),
        city: exact(trip.city),
        nightlyRate: max(trip.hotelRateBudget),
        nights: max(trip.nights),
        guest: exact(trip.traveler),
        taskId: exact(trip.taskId),
      },
      search_activities: { city: exact(trip.city) },
      book_activity: {
        activityId: any(),
        city: exact(trip.city),
        price: max(trip.activityBudget),
        guest: exact(trip.traveler),
        taskId: exact(trip.taskId),
      },
      "wallet.charge": { taskId: exact(trip.taskId), amount: max(trip.budget) },
    },
    holder: fleet["travel-agent"].publicKey,
    ttlSeconds: 30 * 60,
    maxDepth: 4,
  });
}

/** Travel → Flight. Written for you. */
export function travelToFlight(travel: Session, fleet: Fleet, trip: Trip): Session {
  const reservation = oneOf([...trip.candidateReservations]);
  const destination = oneOf([trip.destination]);
  return fleet["travel-agent"].tenuo.narrow(
    travel,
    {
      "traveler.read": { traveler: exact(trip.traveler), field: oneOf(["passportNumber"]) },
      search_flights: { destination },
      book_flight: { flightId: reservation, destination, price: max(trip.flightBudget), passenger: exact(trip.traveler) },
      get_reservation: { reservation },
      check_in: { reservation },
      issue_boarding_pass: { reservation },
      "wallet.charge": { taskId: exact(trip.taskId), amount: max(trip.flightBudget) },
    },
    { holder: fleet["flight-agent"].publicKey, ttlSeconds: 10 * 60 },
  );
}

/** Travel → Hotel. Written for you. */
export function travelToHotel(travel: Session, fleet: Fleet, trip: Trip): Session {
  return fleet["travel-agent"].tenuo.narrow(
    travel,
    {
      "traveler.read": { traveler: exact(trip.traveler), field: oneOf(["name"]) },
      search_hotels: { city: exact(trip.city) },
      book_hotel: {
        hotelId: any(),
        city: exact(trip.city),
        nightlyRate: max(trip.hotelRateBudget),
        nights: max(trip.nights),
        guest: exact(trip.traveler),
        taskId: exact(trip.taskId),
      },
      "wallet.charge": { taskId: exact(trip.taskId), amount: max(trip.hotelRateBudget * trip.nights) },
    },
    { holder: fleet["hotel-agent"].publicKey, ttlSeconds: 10 * 60 },
  );
}

/** Travel → Activity. Written for you. */
export function travelToActivity(travel: Session, fleet: Fleet, trip: Trip): Session {
  return fleet["travel-agent"].tenuo.narrow(
    travel,
    {
      "traveler.read": { traveler: exact(trip.traveler), field: oneOf(["name"]) },
      search_activities: { city: exact(trip.city) },
      book_activity: {
        activityId: any(),
        city: exact(trip.city),
        price: max(trip.activityBudget),
        guest: exact(trip.traveler),
        taskId: exact(trip.taskId),
      },
      "wallet.charge": { taskId: exact(trip.taskId), amount: max(trip.activityBudget) },
    },
    { holder: fleet["activity-agent"].publicKey, ttlSeconds: 10 * 60 },
  );
}

/**
 * Flight → Check-in. TUTORIAL — complete and annotated.
 *
 * Flight Agent has just booked `reservation`. Check-in Agent needs to read
 * that reservation and check it in, and it needs to be able to hand the
 * boarding pass on. Nothing else. Bind the result to Check-in Agent's key
 * (`fleet["checkin-agent"].publicKey`) with a short lifetime.
 */
export function flightToCheckin(flight: Session, fleet: Fleet, trip: Trip, reservation: string): Session {
  // The agent has learned which reservation was booked, so this hop can turn
  // the parent's list of candidates into one exact value.
  const only = oneOf([reservation]);
  return fleet["flight-agent"].tenuo.narrow(
    flight,
    {
      get_reservation: { reservation: only },
      check_in: { reservation: only },
      // Keep this so Check-in Agent can narrow it once more for Boarding.
      issue_boarding_pass: { reservation: only },
    },
    {
      // Delegation must bind the result to the receiving agent's public key.
      holder: fleet["checkin-agent"].publicKey,
      ttlSeconds: 5 * 60,
    },
  );
}

/**
 * Check-in → Boarding. YOUR LEVEL — copy the narrow() shape above.
 *
 * Boarding Agent needs to issue the boarding pass for `reservation`, and
 * nothing else at all.
 */
export function checkinToBoarding(checkin: Session, fleet: Fleet, trip: Trip, reservation: string): Session {
  throw new Error(`TODO: write the Check-in → Boarding link for ${reservation} (exercises/05-tenuo/chain.ts)`);
}
