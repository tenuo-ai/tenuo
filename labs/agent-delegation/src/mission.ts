/**
 * The mission and the cast. Everything in the lab is derived from here, and
 * the least-privilege score is computed against `missionCeiling`, not against
 * what any particular run happened to use.
 */

export type AgentId =
  | "travel-agent"
  | "flight-agent"
  | "hotel-agent"
  | "activity-agent"
  | "checkin-agent"
  | "boarding-agent";

export const AGENTS: readonly AgentId[] = [
  "travel-agent",
  "flight-agent",
  "hotel-agent",
  "activity-agent",
  "checkin-agent",
  "boarding-agent",
];

export interface Trip {
  readonly taskId: string;
  readonly traveler: string;
  readonly origin: string;
  readonly destination: string;
  readonly city: string;
  readonly nights: number;
  readonly budget: number;
  readonly flightBudget: number;
  /** Per night. */
  readonly hotelRateBudget: number;
  readonly activityBudget: number;
  /** Any reservation on a flight to `destination` this trip might book. */
  readonly candidateReservations: readonly string[];
  /** The one the recorded run books. */
  readonly expectedReservation: string;
}

export const ALICE: Trip = {
  taskId: "trip-alice-cun",
  traveler: "Alice Chen",
  origin: "YYZ",
  destination: "CUN",
  city: "Cancún",
  nights: 3,
  budget: 1200,
  flightBudget: 300,
  hotelRateBudget: 200,
  activityBudget: 200,
  candidateReservations: ["UA214", "AC712"],
  expectedReservation: "UA214",
};

export const BOB: Trip = {
  taskId: "trip-bob-sea",
  traveler: "Bob Reyes",
  origin: "YYZ",
  destination: "SEA",
  city: "Seattle",
  nights: 2,
  budget: 1500,
  flightBudget: 450,
  hotelRateBudget: 250,
  activityBudget: 150,
  candidateReservations: ["DL331"],
  expectedReservation: "DL331",
};

/** Tool names, exactly as agents call them and as warrants name them. */
export const TOOLS = {
  search_flights: "search_flights",
  book_flight: "book_flight",
  get_reservation: "get_reservation",
  cancel_reservation: "cancel_reservation",
  check_in: "check_in",
  issue_boarding_pass: "issue_boarding_pass",
  search_hotels: "search_hotels",
  book_hotel: "book_hotel",
  search_activities: "search_activities",
  book_activity: "book_activity",
  wallet_charge: "wallet.charge",
  traveler_read: "traveler.read",
  calendar_create: "calendar.create",
  calendar_delete: "calendar.delete",
} as const;

export type ToolName = (typeof TOOLS)[keyof typeof TOOLS];

/**
 * What each role legitimately needs for the mission. This is the ceiling the
 * least-privilege score compares grants against. "one reservation of this
 * task" is scored per task: a grant that lists more reservations than the
 * task can touch is wider than the ceiling.
 */
export interface RoleCeiling {
  readonly tools: readonly ToolName[];
  readonly reservations?: "candidates-of-task" | "one-of-task";
  readonly destination?: readonly string[];
  readonly city?: readonly string[];
  readonly flightPrice?: number;
  readonly hotelRate?: number;
  readonly activityPrice?: number;
  readonly walletCharge?: number;
  readonly profileFields?: readonly string[];
}

export function missionCeiling(trip: Trip): Record<AgentId, RoleCeiling> {
  return {
    "travel-agent": {
      tools: [
        TOOLS.search_flights,
        TOOLS.book_flight,
        TOOLS.get_reservation,
        TOOLS.check_in,
        TOOLS.issue_boarding_pass,
        TOOLS.search_hotels,
        TOOLS.book_hotel,
        TOOLS.search_activities,
        TOOLS.book_activity,
        TOOLS.wallet_charge,
        TOOLS.traveler_read,
        TOOLS.calendar_create,
      ],
      reservations: "candidates-of-task",
      destination: [trip.destination],
      city: [trip.city],
      flightPrice: trip.flightBudget,
      hotelRate: trip.hotelRateBudget,
      activityPrice: trip.activityBudget,
      walletCharge: trip.budget,
      profileFields: ["name", "email", "passportNumber", "dateOfBirth"],
    },
    "flight-agent": {
      tools: [
        TOOLS.search_flights,
        TOOLS.book_flight,
        TOOLS.get_reservation,
        TOOLS.check_in,
        TOOLS.issue_boarding_pass,
        TOOLS.wallet_charge,
        TOOLS.traveler_read,
      ],
      reservations: "candidates-of-task",
      destination: [trip.destination],
      flightPrice: trip.flightBudget,
      walletCharge: trip.flightBudget,
      profileFields: ["name", "passportNumber", "dateOfBirth"],
    },
    "hotel-agent": {
      tools: [TOOLS.search_hotels, TOOLS.book_hotel, TOOLS.wallet_charge, TOOLS.traveler_read],
      city: [trip.city],
      hotelRate: trip.hotelRateBudget,
      walletCharge: trip.hotelRateBudget * trip.nights,
      profileFields: ["name"],
    },
    "activity-agent": {
      tools: [TOOLS.search_activities, TOOLS.book_activity, TOOLS.wallet_charge, TOOLS.traveler_read],
      city: [trip.city],
      activityPrice: trip.activityBudget,
      walletCharge: trip.activityBudget,
      profileFields: ["name"],
    },
    "checkin-agent": {
      tools: [TOOLS.get_reservation, TOOLS.check_in, TOOLS.issue_boarding_pass],
      reservations: "one-of-task",
    },
    "boarding-agent": {
      tools: [TOOLS.issue_boarding_pass],
      reservations: "one-of-task",
    },
  };
}
