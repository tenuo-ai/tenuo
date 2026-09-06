/**
 * The component stage 4 puts in the path of every call. Both fixes build
 * one, wearing different clothes:
 *
 *   - Fix A, per-task identities: an identity registry. The orchestrator
 *     registers `checkin-agent:trip-alice-cun` when the task starts, and the
 *     chokepoint asks the registry whether an identity exists before it
 *     trusts a rule written for it.
 *   - Fix B, per-task policy checks: a policy service that knows which task
 *     is which (its reservations, destination, flight budget) and is asked on
 *     every flight and reservation check.
 *
 * Every call here is a central call (simulated at 2 ms) and is counted in
 * the trace. The component holds state for every open task. It also accepts
 * grants from anyone who asks, because it has no record of what the asker
 * itself was granted, which is the property stage 5 probes.
 */
import type { Trip } from "../mission.ts";
import type { RolePolicy } from "./policy.ts";

export interface TaskFacts {
  readonly reservations: readonly string[];
  readonly destination: string;
  readonly flightBudget: number;
}

export interface GrantRequest {
  readonly requestedBy: string;
  readonly target: string;
  readonly rule: RolePolicy;
}

export type Component = "identity registry" | "policy service";

export class PolicyService {
  private readonly tasks = new Map<string, TaskFacts>();
  private readonly identities = new Set<string>();
  private readonly grants: GrantRequest[] = [];
  centralCalls = 0;

  private async hop(): Promise<void> {
    this.centralCalls += 1;
    await new Promise((resolve) => setTimeout(resolve, 2));
  }

  // ---- Fix B: policy service ---------------------------------------------

  registerTask(trip: Trip): void {
    this.tasks.set(trip.taskId, {
      reservations: trip.candidateReservations,
      destination: trip.destination,
      flightBudget: trip.flightBudget,
    });
  }

  /** One central call. What this task may touch right now. */
  async factsFor(taskId: string): Promise<TaskFacts | undefined> {
    await this.hop();
    return this.tasks.get(taskId);
  }

  /** One central call. The task has booked; from now on it may touch only that reservation. */
  async recordBooking(taskId: string, reservation: string): Promise<void> {
    await this.hop();
    const facts = this.tasks.get(taskId);
    if (facts !== undefined) {
      this.tasks.set(taskId, { ...facts, reservations: [reservation] });
    }
  }

  // ---- Fix A: identity registry ------------------------------------------

  /** One central call. The orchestrator registers a per-task identity at task start. */
  async registerIdentity(identity: string): Promise<void> {
    await this.hop();
    this.identities.add(identity);
  }

  /** One central call. The chokepoint asks before trusting a rule written for a per-task identity. */
  async isRegistered(identity: string): Promise<boolean> {
    await this.hop();
    return this.identities.has(identity);
  }

  // ---- Stage 5 probe -----------------------------------------------------

  /**
   * Someone asks the component to grant `target` a rule. It knows which task
   * an identity belongs to, or which reservations a task owns. It has no
   * record of what `requestedBy` itself holds, so it has nothing to compare
   * the request against. It accepts.
   */
  async grant(request: GrantRequest, component: Component): Promise<{ accepted: boolean; reason: string }> {
    await this.hop();
    this.grants.push(request);
    const knows =
      component === "identity registry"
        ? "which identity belongs to which task"
        : "which reservations belong to which task";
    return {
      accepted: true,
      reason: `the ${component} accepted a rule for ${request.target} from ${request.requestedBy}: it knows ${knows}, not what ${request.requestedBy} was granted, so it cannot tell that this is broader`,
    };
  }

  pendingGrants(): readonly GrantRequest[] {
    return this.grants;
  }
}
