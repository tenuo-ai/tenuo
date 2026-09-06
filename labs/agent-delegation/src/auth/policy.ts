/**
 * The policy language for stages 3 to 5. Deliberately small: a rule is
 * about an identity, and says which actions that identity may take and on
 * which resources. Notice what it cannot say: which job a call belongs to.
 */
import { TOOLS, type ToolName } from "../mission.ts";

export interface RolePolicy {
  /** Tool names this identity may call. */
  readonly actions: readonly ToolName[];
  /** Reservation ids for get_reservation / check_in / cancel_reservation / issue_boarding_pass / get_checkin_status. Absent means any. */
  readonly reservations?: readonly string[];
  /** For search_flights / book_flight. Absent means any. */
  readonly destination?: string;
  /** Ceiling for book_flight price and book_activity price. */
  readonly maxPrice?: number;
  /** For search_hotels / book_hotel / search_activities / book_activity. */
  readonly city?: string;
  /** Ceiling for book_hotel nightlyRate. */
  readonly maxNightlyRate?: number;
  /** Ceiling for wallet.charge amount. */
  readonly maxCharge?: number;
  /** For traveler.read. Absent means any field. */
  readonly profileFields?: readonly string[];
}

/**
 * Keyed by identity. A key like `"checkin-agent:trip-alice-cun"` is a
 * per-task identity: when present, the chokepoint uses it for that agent on
 * that task instead of the plain `"checkin-agent"` entry.
 */
export type Policy = Readonly<Record<string, RolePolicy>>;

export interface PolicyConfig {
  readonly policy: Policy;
  /**
   * Stage 4's second fix. When true, reservation checks ask the policy
   * service which reservations belong to the calling task, one round trip
   * per call, instead of reading `reservations` from the file.
   */
  readonly policyService?: boolean;
}

export const RESERVATION_ACTIONS: readonly ToolName[] = [
  TOOLS.get_reservation,
  TOOLS.check_in,
  TOOLS.cancel_reservation,
  TOOLS.issue_boarding_pass,
  TOOLS.get_checkin_status,
];

/** Which identity entry applies to this actor on this task. */
export function identityFor(policy: Policy, actor: string, taskId: string): string {
  const perTask = `${actor}:${taskId}`;
  return perTask in policy ? perTask : actor;
}

export interface PolicyVerdict {
  readonly allowed: boolean;
  readonly reason: string;
}

/** Evaluate one call against one identity's rule. Pure; no round trips. */
export function evaluateRule(
  identity: string,
  rule: RolePolicy | undefined,
  action: string,
  args: Record<string, unknown>,
  reservationsForTask?: readonly string[],
): PolicyVerdict {
  if (rule === undefined) {
    return { allowed: false, reason: `no policy entry for ${identity}` };
  }
  if (!(rule.actions as readonly string[]).includes(action)) {
    return { allowed: false, reason: `${identity} may not ${action} (actions: ${rule.actions.join(", ")})` };
  }
  const reservations = reservationsForTask ?? rule.reservations;
  if ((RESERVATION_ACTIONS as readonly string[]).includes(action) && reservations !== undefined) {
    const target = String(args["reservation"] ?? "");
    if (!reservations.includes(target)) {
      return { allowed: false, reason: `reservation ${target} outside granted scope {${reservations.join(", ")}}` };
    }
  }
  if ((action === TOOLS.book_flight || action === TOOLS.search_flights) && rule.destination !== undefined) {
    if (args["destination"] !== rule.destination) {
      return { allowed: false, reason: `destination ${String(args["destination"])} is not ${rule.destination}` };
    }
  }
  if ((action === TOOLS.book_flight || action === TOOLS.book_activity) && rule.maxPrice !== undefined) {
    const price = Number(args["price"]);
    if (price > rule.maxPrice) {
      return { allowed: false, reason: `price ${price} exceeds maxPrice ${rule.maxPrice}` };
    }
  }
  if (
    (action === TOOLS.search_hotels ||
      action === TOOLS.book_hotel ||
      action === TOOLS.search_activities ||
      action === TOOLS.book_activity) &&
    rule.city !== undefined
  ) {
    if (args["city"] !== rule.city) {
      return { allowed: false, reason: `city ${String(args["city"])} is not ${rule.city}` };
    }
  }
  if (action === TOOLS.book_hotel && rule.maxNightlyRate !== undefined) {
    const rate = Number(args["nightlyRate"]);
    if (rate > rule.maxNightlyRate) {
      return { allowed: false, reason: `nightlyRate ${rate} exceeds maxNightlyRate ${rule.maxNightlyRate}` };
    }
  }
  if (action === TOOLS.wallet_charge && rule.maxCharge !== undefined) {
    const amount = Number(args["amount"]);
    if (amount > rule.maxCharge) {
      return { allowed: false, reason: `amount ${amount} exceeds maxCharge ${rule.maxCharge}` };
    }
  }
  if (action === TOOLS.traveler_read && rule.profileFields !== undefined) {
    const field = String(args["field"]);
    if (!rule.profileFields.includes(field)) {
      return { allowed: false, reason: `profile field ${field} outside {${rule.profileFields.join(", ")}}` };
    }
  }
  return { allowed: true, reason: `${identity} rule permits ${action}` };
}

/** Role-shaped grants for stage 2: what each agent's job title implies, nothing narrower. */
export const ROLE_POLICY: Policy = {
  "travel-agent": {
    actions: [TOOLS.search_flights, TOOLS.search_hotels, TOOLS.search_activities, TOOLS.traveler_read, TOOLS.calendar_create, TOOLS.calendar_read, TOOLS.calendar_modify, TOOLS.calendar_delete, TOOLS.wallet_charge],
  },
  "flight-agent": {
    actions: [TOOLS.search_flights, TOOLS.book_flight, TOOLS.get_reservation, TOOLS.wallet_charge, TOOLS.traveler_read],
  },
  "hotel-agent": {
    actions: [TOOLS.search_hotels, TOOLS.book_hotel, TOOLS.get_hotel_booking, TOOLS.wallet_charge, TOOLS.traveler_read],
  },
  "activity-agent": {
    actions: [TOOLS.search_activities, TOOLS.book_activity, TOOLS.wallet_charge, TOOLS.traveler_read],
  },
  "checkin-agent": {
    actions: [TOOLS.get_reservation, TOOLS.check_in],
  },
  "boarding-agent": {
    actions: [TOOLS.get_checkin_status, TOOLS.issue_boarding_pass],
  },
};
