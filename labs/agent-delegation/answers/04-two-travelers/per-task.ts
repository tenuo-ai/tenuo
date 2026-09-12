/** Reference solution for stage 4, fix A: one identity per task. */
import type { PolicyConfig } from "../../src/auth/policy.ts";

export const config: PolicyConfig = {
  policyService: false,
  policy: {
    "travel-agent": {
      actions: ["traveler.read", "calendar.create"],
      profileFields: ["name"],
    },
    "flight-agent:trip-alice-cun": {
      actions: ["traveler.read", "search_flights", "book_flight", "wallet.charge"],
      destination: "CUN",
      maxPrice: 300,
      maxCharge: 300,
      profileFields: ["passportNumber"],
    },
    "flight-agent:trip-bob-sea": {
      actions: ["traveler.read", "search_flights", "book_flight", "wallet.charge"],
      destination: "SEA",
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
    "checkin-agent:trip-alice-cun": {
      actions: ["get_reservation", "check_in", "issue_boarding_pass"],
      reservations: ["UA214"],
    },
    "checkin-agent:trip-bob-sea": {
      actions: ["get_reservation", "check_in", "issue_boarding_pass"],
      reservations: ["DL331"],
    },
    "boarding-agent:trip-alice-cun": {
      actions: ["issue_boarding_pass"],
      reservations: ["UA214"],
    },
    "boarding-agent:trip-bob-sea": {
      actions: ["issue_boarding_pass"],
      reservations: ["DL331"],
    },
  },
};
