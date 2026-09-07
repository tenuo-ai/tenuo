/**
 * Stage 9: the incident.
 *
 *   Hotel Agent has been compromised. The travel system has to stay
 *   online. Legitimate bookings have to keep working.
 *
 * The compromised Hotel Agent will try eight things. One must work and seven
 * must fail. Configure this chain so that all eight land correctly, and
 * keep an eye on your least-privilege score while you do it. Number 3
 * catches more people than any other: blocking it is different from
 * blocking number 2.
 */
import { exact, max, oneOf, pattern, type Session, type Tenuo } from "@tenuo/core";
import type { Fleet } from "../../src/keys.ts";
import type { Trip } from "../../src/mission.ts";

/** A free-form string argument. Named because policies are zero-trust: every argument must be listed. */
const any = () => pattern("*");

/**
 * Root. Minted by the control plane, bound to Travel Agent's key. It must
 * carry everything any agent further down will ever need, because a child
 * can never hold what its parent does not. `reservation` says "any Cancún
 * flight this trip might book"; Flight Agent narrows it to the one it booked.
 */
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

/** Travel → Flight: the flight branch, with the flight's share of the wallet. */
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

/**
 * Travel → Hotel. This link is where the incident lives. Right now it hands
 * Hotel Agent far more than a hotel booking needs. Fix it: only hotel tools,
 * only Cancún, only the approved nightly rate, only the traveler's name,
 * only the hotel's share of the wallet, and no ability to hand anything on.
 */
export function travelToHotel(travel: Session, fleet: Fleet, trip: Trip): Session {
  const reservation = oneOf([...trip.candidateReservations]);
  const destination = oneOf([trip.destination]);
  return fleet["travel-agent"].tenuo.narrow(
    travel,
    {
      "traveler.read": { traveler: exact(trip.traveler), field: oneOf(["name", "passportNumber"]) },
      search_flights: { destination },
      book_flight: { flightId: reservation, destination, price: max(trip.flightBudget), passenger: exact(trip.traveler) },
      search_hotels: { city: exact(trip.city) },
      book_hotel: {
        hotelId: any(),
        city: exact(trip.city),
        nightlyRate: max(trip.hotelRateBudget),
        nights: max(trip.nights),
        guest: exact(trip.traveler),
        taskId: exact(trip.taskId),
      },
      "wallet.charge": { taskId: exact(trip.taskId), amount: max(trip.budget) },
    },
    { holder: fleet["hotel-agent"].publicKey, ttlSeconds: 10 * 60 },
  );
}

/** Travel → Activity. */
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
 * Flight → Check-in. Flight Agent has booked and knows the reservation, so
 * this is the link that narrows "any Cancún flight" to "this one."
 */
export function flightToCheckin(flight: Session, fleet: Fleet, trip: Trip, reservation: string): Session {
  const only = oneOf([reservation]);
  return fleet["flight-agent"].tenuo.narrow(
    flight,
    {
      get_reservation: { reservation: only },
      check_in: { reservation: only },
      issue_boarding_pass: { reservation: only },
    },
    { holder: fleet["checkin-agent"].publicKey, ttlSeconds: 5 * 60 },
  );
}

/** Check-in → Boarding: one reservation, the boarding pass, nothing else. */
export function checkinToBoarding(checkin: Session, fleet: Fleet, trip: Trip, reservation: string): Session {
  const only = oneOf([reservation]);
  return fleet["checkin-agent"].tenuo.narrow(
    checkin,
    { issue_boarding_pass: { reservation: only } },
    { holder: fleet["boarding-agent"].publicKey, ttlSeconds: 2 * 60 },
  );
}
