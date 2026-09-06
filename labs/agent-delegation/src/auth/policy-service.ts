/**
 * Stage 4's second fix, made concrete. A central service that knows which
 * task is which: its reservations, its destination, its flight budget. The
 * chokepoint consults it on every flight and reservation check, one round
 * trip per call (simulated at 2 ms), and tells it when a flight is booked
 * so the task's reservation narrows from "any candidate" to "this one".
 *
 * It holds state for every open task. It also accepts policy writes from
 * anyone who asks, which is the property stage 5 probes.
 */
import type { Trip } from "../mission.ts";
import type { RolePolicy } from "./policy.ts";

export interface TaskFacts {
  readonly reservations: readonly string[];
  readonly destination: string;
  readonly flightBudget: number;
}

export interface PolicyWriteRequest {
  readonly requestedBy: string;
  readonly target: string;
  readonly rule: RolePolicy;
}

export class PolicyService {
  private readonly tasks = new Map<string, TaskFacts>();
  private readonly writes: PolicyWriteRequest[] = [];
  roundTrips = 0;

  registerTask(trip: Trip): void {
    this.tasks.set(trip.taskId, {
      reservations: trip.candidateReservations,
      destination: trip.destination,
      flightBudget: trip.flightBudget,
    });
  }

  /** One round trip. What this task may touch right now. */
  async factsFor(taskId: string): Promise<TaskFacts | undefined> {
    this.roundTrips += 1;
    await new Promise((resolve) => setTimeout(resolve, 2));
    return this.tasks.get(taskId);
  }

  /** One round trip. The task has booked; from now on it may touch only that reservation. */
  async recordBooking(taskId: string, reservation: string): Promise<void> {
    this.roundTrips += 1;
    await new Promise((resolve) => setTimeout(resolve, 2));
    const facts = this.tasks.get(taskId);
    if (facts !== undefined) {
      this.tasks.set(taskId, { ...facts, reservations: [reservation] });
    }
  }

  /**
   * Stage 5 probe. The service has no record of what `requestedBy` itself
   * holds, so it has nothing to compare the request against. It accepts.
   */
  async writeRule(request: PolicyWriteRequest): Promise<{ accepted: boolean; reason: string }> {
    this.roundTrips += 1;
    this.writes.push(request);
    return {
      accepted: true,
      reason: `policy service accepted a rule for ${request.target} from ${request.requestedBy}: it does not know what ${request.requestedBy} was granted, so it cannot tell that this is broader`,
    };
  }

  pendingWrites(): readonly PolicyWriteRequest[] {
    return this.writes;
  }
}
