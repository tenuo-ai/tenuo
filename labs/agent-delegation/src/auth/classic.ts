/**
 * Modes 1 to 3: shared key, per-agent identities, scoped rules. One class,
 * because they differ only in how much a rule can say.
 */
import { resourceOf } from "../audit.ts";
import { AGENTS, TOOLS } from "../mission.ts";
import { ServiceError, services } from "../services/index.ts";
import type { PolicyService } from "./policy-service.ts";
import { evaluateRule, identityFor, RESERVATION_ACTIONS, ROLE_POLICY, type Policy, type PolicyConfig, type PolicyVerdict } from "./policy.ts";
import type { AuthMode, Call, Credential, Ctx, Decision } from "./types.ts";

export const SHARED_KEY: Credential = { identity: "TRAVEL_SERVICE_KEY", label: "TRAVEL_SERVICE_KEY (shared)" };

export function identityCredential(agent: string, taskId?: string): Credential {
  const identity = taskId === undefined ? agent : `${agent}:${taskId}`;
  return { identity, label: identity };
}

/** Which stage 4 fix a scoped configuration represents. */
export function fixOf(config: PolicyConfig | undefined): "policy-service" | "identities" | "none" {
  if (config?.policyService === true) return "policy-service";
  if (config !== undefined && Object.keys(config.policy).some((k) => k.includes(":"))) return "identities";
  return "none";
}

export class ClassicMode implements AuthMode {
  readonly name: "shared" | "identity" | "scoped";
  readonly config: PolicyConfig;
  private readonly policyService: PolicyService | undefined;

  constructor(name: "shared" | "identity" | "scoped", config?: PolicyConfig, policyService?: PolicyService) {
    this.name = name;
    this.config = config ?? { policy: ROLE_POLICY };
    this.policyService = policyService;
  }

  private async verdict(call: Call): Promise<{ verdict: PolicyVerdict; centralCalls: number }> {
    if (this.name === "shared") {
      return { verdict: { allowed: true, reason: "TRAVEL_SERVICE_KEY opens everything" }, centralCalls: 0 };
    }
    const credential = call.credential ?? identityCredential(call.actor);
    if (this.name === "identity") {
      const base = credential.identity.split(":")[0] ?? credential.identity;
      const rule = ROLE_POLICY[base];
      const allowed = rule !== undefined && (rule.actions as readonly string[]).includes(call.action);
      return {
        verdict: {
          allowed,
          reason: allowed
            ? `role ${base} includes ${call.action}`
            : rule === undefined
              ? `no role for ${base}`
              : `role ${base} does not include ${call.action}`,
        },
        centralCalls: 0,
      };
    }
    // scoped
    const policy: Policy = this.config.policy;
    const identity = credential.identity.includes(":") ? credential.identity : identityFor(policy, credential.identity, call.taskId);
    let centralCalls = 0;
    let rule = policy[identity];

    // Fix A: a per-task identity is only trusted once the registry confirms it exists.
    if (identity.includes(":") && this.policyService !== undefined) {
      const known = await this.policyService.isRegistered(identity);
      centralCalls += 1;
      if (!known) {
        return { verdict: { allowed: false, reason: `identity ${identity} is not registered` }, centralCalls };
      }
    }

    // Fix B: the policy service says which task is calling.
    let reservationsForTask: readonly string[] | undefined;
    const consultsService =
      this.config.policyService === true &&
      this.policyService !== undefined &&
      rule !== undefined &&
      ((RESERVATION_ACTIONS as readonly string[]).includes(call.action) ||
        call.action === TOOLS.search_flights ||
        call.action === TOOLS.book_flight);
    if (consultsService && this.policyService !== undefined && rule !== undefined) {
      const facts = await this.policyService.factsFor(call.taskId);
      centralCalls += 1;
      if (facts === undefined) {
        return { verdict: { allowed: false, reason: `policy service has no record of task ${call.taskId}` }, centralCalls };
      }
      reservationsForTask = facts.reservations;
      if (call.action === TOOLS.search_flights || call.action === TOOLS.book_flight) {
        rule = { ...rule, destination: facts.destination, maxPrice: facts.flightBudget };
      }
    }
    const verdict = evaluateRule(identity, rule, call.action, call.args, reservationsForTask);
    return { verdict, centralCalls };
  }

  async execute(call: Call, ctx: Ctx): Promise<Decision> {
    const { verdict, centralCalls } = await this.verdict(call);
    let calls = centralCalls;
    const record = (decision: "ALLOWED" | "DENIED", reason: string, code?: string) =>
      ctx.audit.record({
        agent: call.actor,
        task: call.taskId,
        action: call.action,
        resource: resourceOf(call.action, call.args),
        mode: this.name,
        decision,
        reason,
        ...(code !== undefined ? { code } : {}),
        centralCalls: calls,
        source: call.source,
      });
    if (!verdict.allowed) {
      record("DENIED", verdict.reason, "POLICY");
      return { allowed: false, reason: verdict.reason, code: "POLICY", centralCalls: calls };
    }
    try {
      const result = services(ctx.world)[call.action]?.(call.args);
      if (
        call.action === TOOLS.book_flight &&
        call.source === "trip" &&
        this.config.policyService === true &&
        this.policyService !== undefined
      ) {
        // The service learns which reservation this task now owns.
        await this.policyService.recordBooking(call.taskId, String(call.args["flightId"]));
        calls += 1;
      }
      record("ALLOWED", verdict.reason);
      return { allowed: true, reason: verdict.reason, centralCalls: calls, result };
    } catch (error) {
      const message = error instanceof ServiceError ? error.message : String(error);
      record("ALLOWED", `${verdict.reason}; service error: ${message}`);
      return { allowed: true, reason: verdict.reason, centralCalls: calls, error: message };
    }
  }

  async describe(): Promise<Record<string, unknown>> {
    if (this.name === "shared") {
      return Object.fromEntries(AGENTS.map((a) => [a, { credential: SHARED_KEY.label, can: Object.values(TOOLS) }]));
    }
    const policy = this.name === "identity" ? ROLE_POLICY : this.config.policy;
    return Object.fromEntries(
      Object.entries(policy).map(([identity, rule]) => [identity, { ...rule }]),
    );
  }
}
