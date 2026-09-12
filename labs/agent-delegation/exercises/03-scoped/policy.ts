/**
 * Stage 3: rules that fit the job.
 *
 * Right now these rules say what each agent's *role* may do. That is stage 2
 * again. Narrow them until `npm run attack` is clean and the trip still
 * books. Every field you can use is listed in the comment; leave a field out
 * to mean "any".
 *
 * Then run `npm run score` and see what the least-privilege score thinks of
 * grants nobody used.
 */
import type { PolicyConfig } from "../../src/auth/policy.ts";

export const config: PolicyConfig = {
  policy: {
    // Fields per identity:
    //   actions:        tool names this identity may call
    //   reservations:   ["UA214"]   for get_reservation, check_in, cancel_reservation, issue_boarding_pass
    //   destination:    "CUN"       for search_flights, book_flight
    //   maxPrice:       300         for book_flight price and book_activity price
    //   city:           "Cancún"    for hotel and activity tools
    //   maxNightlyRate: 200         for book_hotel
    //   maxCharge:      600         for wallet.charge
    //   profileFields:  ["name"]    for traveler.read

    "travel-agent": {
      actions: ["traveler.read", "calendar.create", "calendar.delete", "wallet.charge"],
    },
    "flight-agent": {
      actions: ["traveler.read", "search_flights", "book_flight", "get_reservation", "wallet.charge"],
    },
    "hotel-agent": {
      actions: ["traveler.read", "search_hotels", "book_hotel", "wallet.charge"],
    },
    "activity-agent": {
      actions: ["traveler.read", "search_activities", "book_activity", "wallet.charge"],
    },
    "checkin-agent": {
      actions: ["get_reservation", "check_in"],
    },
    "boarding-agent": {
      actions: ["issue_boarding_pass"],
    },
  },
};
