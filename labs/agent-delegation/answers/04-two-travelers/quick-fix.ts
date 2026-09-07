/**
 * Stage 4's deliberately broad quick fix.
 *
 * One shared identity per role now has enough authority for both trips. The
 * trips complete, but the CROSS-TASK probes demonstrate why this is not the
 * final answer.
 */
import type { PolicyConfig } from "../../src/auth/policy.ts";

export const config: PolicyConfig = {
  policyService: false,
  policy: {
    "travel-agent": {
      actions: ["traveler.read", "calendar.create"],
      profileFields: ["name"],
    },
    "flight-agent": {
      actions: ["traveler.read", "search_flights", "book_flight", "wallet.charge"],
      maxPrice: 450,
      maxCharge: 450,
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
      reservations: ["UA214", "DL331"],
    },
    "boarding-agent": {
      actions: ["issue_boarding_pass"],
      reservations: ["UA214", "DL331"],
    },
  },
};
