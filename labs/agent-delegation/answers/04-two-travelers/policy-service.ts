/** Reference solution for stage 4, fix B: a policy service consulted per call. */
import type { PolicyConfig } from "../../src/auth/policy.ts";

export const config: PolicyConfig = {
  policyService: true,
  policy: {
    "travel-agent": {
      actions: ["traveler.read", "calendar.create"],
      profileFields: ["name"],
    },
    // Destination, flight budget, and reservation come from the service, per task.
    "flight-agent": {
      actions: ["traveler.read", "search_flights", "book_flight", "wallet.charge"],
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
    },
    "boarding-agent": {
      actions: ["get_checkin_status", "issue_boarding_pass"],
    },
  },
};
