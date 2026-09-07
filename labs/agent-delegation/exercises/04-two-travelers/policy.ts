/**
 * Stage 4: a second traveler shows up.
 *
 * This is the stage 3 solution, unchanged. Bob's trip runs through the same
 * agents at the same time. Something will break. Fix it the way that seems
 * obvious, then read all of `npm run attack`, including CROSS-TASK.
 *
 * You can fix this. README.md next to this file shows both ways people find.
 * Stage 5 keeps whichever you choose.
 */
import type { PolicyConfig } from "../../src/auth/policy.ts";

export const config: PolicyConfig = {
  // Fix B flips this to true. See README.md.
  policyService: false,

  policy: {
    "travel-agent": {
      actions: ["traveler.read", "calendar.create"],
      profileFields: ["name"],
    },
    "flight-agent": {
      actions: ["traveler.read", "search_flights", "book_flight", "wallet.charge"],
      destination: "CUN",
      maxPrice: 300,
      maxCharge: 300,
      profileFields: ["passportNumber"],
    },
    "hotel-agent": {
      actions: ["traveler.read", "search_hotels", "book_hotel", "wallet.charge"],
      city: "Cancún",
      maxNightlyRate: 200,
      maxCharge: 600,
      profileFields: ["name"],
    },
    "activity-agent": {
      actions: ["traveler.read", "search_activities", "book_activity", "wallet.charge"],
      city: "Cancún",
      maxPrice: 200,
      maxCharge: 200,
      profileFields: ["name"],
    },
    "checkin-agent": {
      actions: ["get_reservation", "check_in", "issue_boarding_pass"],
      reservations: ["UA214"],
    },
    "boarding-agent": {
      actions: ["issue_boarding_pass"],
      reservations: ["UA214"],
    },
  },
};
