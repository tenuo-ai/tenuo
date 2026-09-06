/**
 * One record per decision. The `reason` field is the pedagogical payload:
 * it always names the rule that fired, never a generic "unauthorized".
 * `roundTrips` counts calls to a central service before the decision, which
 * is the number stage 4 makes visible and stage 6 makes zero.
 */
import type { AgentId } from "./mission.ts";

export interface AuditRecord {
  readonly seq: number;
  readonly agent: AgentId;
  readonly task: string;
  readonly action: string;
  readonly resource: string;
  readonly mode: string;
  readonly decision: "ALLOWED" | "DENIED";
  readonly reason: string;
  readonly code?: string;
  readonly roundTrips: number;
  /** "trip" for the scripted workflow, "injected" for calls the payload provoked, "probe" for the harness. */
  readonly source: "trip" | "injected" | "probe" | "handoff";
}

export class AuditLog {
  readonly records: AuditRecord[] = [];
  private seq = 0;

  record(entry: Omit<AuditRecord, "seq">): AuditRecord {
    this.seq += 1;
    const record: AuditRecord = { seq: this.seq, ...entry };
    this.records.push(record);
    return record;
  }

  roundTrips(): number {
    return this.records.reduce((n, r) => n + r.roundTrips, 0);
  }
}

/** Human-readable resource for a call, for the trace. */
export function resourceOf(action: string, args: Record<string, unknown>): string {
  for (const key of ["reservation", "flightId", "hotelId", "activityId", "eventId", "field", "amount"]) {
    const v = args[key];
    if (v !== undefined) {
      return key === "amount" ? `$${String(v)}` : String(v);
    }
  }
  if (typeof args["destination"] === "string") return args["destination"];
  if (typeof args["city"] === "string") return args["city"];
  return action.includes("calendar") ? "*" : "-";
}
