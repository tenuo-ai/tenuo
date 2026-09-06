/**
 * What an agent has at hand while it works: a way to call tools as itself,
 * on its task, and a way to hand work on. Everything an agent does goes
 * through `call`, which goes through the stage's chokepoint.
 *
 * Handoffs in modes 1 to 3 pass a credential (or not). Handoffs in mode 4
 * call the participant's chain code, which returns a session bound to the
 * next agent's key; the next agent imports it with its own holder key.
 */
import type { Session, Tenuo } from "@tenuo/core";
import type { AuditLog } from "../audit.ts";
import type { PolicyService } from "../auth/policy-service.ts";
import type { PolicyConfig } from "../auth/policy.ts";
import { identityCredential, SHARED_KEY } from "../auth/classic.ts";
import type { TenuoMode } from "../auth/tenuo-mode.ts";
import type { AuthMode, Call, Credential, Decision } from "../auth/types.ts";
import type { Fleet } from "../keys.ts";
import type { AgentId, Trip } from "../mission.ts";
import type { World } from "../services/index.ts";
import type { StageDef } from "../stages.ts";

/** The participant's stage 6, 8, or 9 code. Every function returns a session bound to the next agent's key. */
export interface ChainModule {
  issueTrip(controlPlane: Tenuo, fleet: Fleet, trip: Trip): Session;
  travelToFlight(travel: Session, fleet: Fleet, trip: Trip): Session;
  travelToHotel(travel: Session, fleet: Fleet, trip: Trip): Session;
  travelToActivity(travel: Session, fleet: Fleet, trip: Trip): Session;
  flightToCheckin(flight: Session, fleet: Fleet, trip: Trip, reservation: string): Session;
  checkinToBoarding(checkin: Session, fleet: Fleet, trip: Trip, reservation: string): Session;
}

export interface Runtime {
  readonly stage: StageDef;
  readonly mode: AuthMode;
  readonly world: World;
  readonly audit: AuditLog;
  readonly policyService?: PolicyService;
  /** The participant's scoped configuration, when the stage has one. */
  readonly config?: PolicyConfig;
  readonly tenuo?: TenuoMode;
  readonly chain?: ChainModule;
  /** Set by the incident scenario. */
  readonly compromised?: AgentId;
}

export class Agent {
  readonly credential: Credential;

  constructor(
    readonly rt: Runtime,
    readonly id: AgentId,
    readonly trip: Trip,
    credential?: Credential,
  ) {
    this.credential = credential ?? defaultCredential(rt, id);
  }

  /** Call a tool as this agent, on this task. */
  call(action: string, args: Record<string, unknown>, source: Call["source"] = "trip"): Promise<Decision> {
    return this.rt.mode.execute(
      { actor: this.id, action, args, taskId: this.trip.taskId, credential: this.credential, source },
      { world: this.rt.world, audit: this.rt.audit },
    );
  }

  /** Mode 4: this agent's session for this task. */
  session(): Session | undefined {
    return this.rt.tenuo?.session(this.id, this.trip.taskId);
  }

  /**
   * Mode 4 handoff: run the participant's chain function, then import the
   * result in the receiving agent's process with that agent's own key.
   * A failure here is recorded as a denied handoff, which is a real outcome:
   * the receiving agent simply has nothing to work with.
   */
  handoff(to: AgentId, link: (chain: ChainModule, mine: Session) => Session, label: string): boolean {
    const tenuo = this.rt.tenuo;
    const chain = this.rt.chain;
    if (tenuo === undefined || chain === undefined) {
      return true;
    }
    const mine = this.session();
    const record = (decision: "ALLOWED" | "DENIED", reason: string, code?: string) =>
      this.rt.audit.record({
        agent: this.id,
        task: this.trip.taskId,
        action: `handoff → ${to}`,
        resource: label,
        mode: "tenuo",
        decision,
        reason,
        ...(code !== undefined ? { code } : {}),
        centralCalls: 0,
        source: "handoff",
      });
    if (mine === undefined) {
      record("DENIED", `${this.id} has no session to narrow`, "NO_SESSION");
      return false;
    }
    try {
      const handed = link(chain, mine);
      const receiver = tenuo.fleet[to];
      const theirs = receiver.tenuo.sessionFromWire({ warrant: handed.toWire(), holderKey: receiver.holderKey });
      tenuo.setSession(to, this.trip.taskId, theirs);
      const info = theirs.inspect();
      record("ALLOWED", `${to} now holds {${info.tools.join(", ")}} at depth ${info.depth}${info.terminal ? ", terminal" : ""}`);
      return true;
    } catch (error) {
      const err = error as { code?: string; message?: string };
      record("DENIED", err.message ?? String(error), err.code);
      return false;
    }
  }
}

function defaultCredential(rt: Runtime, id: AgentId): Credential {
  if (rt.mode.name === "shared") {
    return SHARED_KEY;
  }
  return identityCredential(id);
}
