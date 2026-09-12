/**
 * Mode 4. Every tool call runs as `agent.tenuo.withSession(session, () =>
 * tool.execute(args))`, and nothing else decides. The session is whatever
 * this agent imported with its own holder key; the chain must lead back to
 * the control plane's key or it is refused before any constraint is read.
 */
import { ApprovalRequiredError, AuthorizationDeniedError, TenuoError, type ProtectedTool, type Session } from "@tenuo/core";
import { resourceOf } from "../audit.ts";
import { AGENTS, TOOLS, type AgentId } from "../mission.ts";
import { ServiceError, services, type World } from "../services/index.ts";
import type { Fleet, HolderKeyring } from "../keys.ts";
import type { AuthMode, Call, Ctx, Decision } from "./types.ts";

type Executor = ProtectedTool<{ execute: (args: Record<string, unknown>) => unknown }>;

export class TenuoMode implements AuthMode {
  readonly name = "tenuo" as const;
  readonly fleet: Fleet;
  readonly #holderKeys: HolderKeyring;
  readonly #issuanceErrors = new Map<string, { readonly code?: string; readonly message: string }>();
  /** Session per (agent, task), set at handoff by the participant's chain code. */
  private readonly sessions = new Map<string, Session>();
  private readonly tools = new Map<string, Executor>();
  private world: World | undefined;

  constructor(fleet: Fleet, holderKeys: HolderKeyring) {
    this.fleet = fleet;
    this.#holderKeys = holderKeys;
  }

  recordIssuanceError(taskId: string, error: unknown): void {
    const err = error as { code?: string; message?: string };
    this.#issuanceErrors.set(taskId, {
      ...(err.code !== undefined ? { code: err.code } : {}),
      message: err.message ?? String(error),
    });
  }

  issuanceError(taskId: string): { readonly code?: string; readonly message: string } | undefined {
    return this.#issuanceErrors.get(taskId);
  }

  /** Deliver wire data to one agent, which imports it using only that agent's private key. */
  importFor(agent: AgentId, taskId: string, handed: Session): Session {
    return this.importWireFor(agent, taskId, handed.toWire());
  }

  /** Model an agent receiving serialized warrant data without exposing its holder key. */
  importWireFor(agent: AgentId, taskId: string, warrant: readonly string[]): Session {
    const session = this.fleet[agent].tenuo.sessionFromWire({
      warrant,
      holderKey: this.#holderKeys[agent],
    });
    this.setSession(agent, taskId, session);
    return session;
  }

  key(agent: AgentId, taskId: string): string {
    return `${agent}@${taskId}`;
  }

  setSession(agent: AgentId, taskId: string, session: Session): void {
    this.sessions.set(this.key(agent, taskId), session);
  }

  session(agent: AgentId, taskId: string): Session | undefined {
    return this.sessions.get(this.key(agent, taskId));
  }

  private tool(agent: AgentId, action: string, world: World): Executor {
    if (this.world !== world) {
      this.tools.clear();
      this.world = world;
    }
    const id = `${agent}/${action}`;
    let tool = this.tools.get(id);
    if (tool === undefined) {
      const fn = services(world)[action];
      tool = this.fleet[agent].tenuo.tool(
        { execute: (args: Record<string, unknown>) => (fn === undefined ? undefined : fn(args)) },
        { capability: action, allow: {} },
      );
      this.tools.set(id, tool);
    }
    return tool;
  }

  async execute(call: Call, ctx: Ctx): Promise<Decision> {
    const record = (decision: "ALLOWED" | "DENIED", reason: string, code?: string) =>
      ctx.audit.record({
        agent: call.actor,
        task: call.taskId,
        action: call.action,
        resource: resourceOf(call.action, call.args),
        mode: "tenuo",
        decision,
        reason,
        ...(code !== undefined ? { code } : {}),
        centralCalls: 0,
        source: call.source,
      });
    const session = this.session(call.actor, call.taskId);
    if (session === undefined) {
      const reason = `${call.actor} holds no session for ${call.taskId}: nothing was delegated to it`;
      record("DENIED", reason, "NO_SESSION");
      return { allowed: false, reason, code: "NO_SESSION", centralCalls: 0 };
    }
    const tool = this.tool(call.actor, call.action, ctx.world);
    try {
      const result = await this.fleet[call.actor].tenuo.withSession(session, () => tool.execute(call.args));
      record("ALLOWED", `warrant ${session.inspect().warrantIds.at(-1) ?? "?"} permits ${call.action}`);
      return { allowed: true, reason: "warrant permits", centralCalls: 0, result };
    } catch (error) {
      if (error instanceof ServiceError) {
        record("ALLOWED", `warrant permits; service error: ${error.message}`);
        return { allowed: true, reason: "warrant permits", centralCalls: 0, error: error.message };
      }
      if (error instanceof AuthorizationDeniedError || error instanceof ApprovalRequiredError || error instanceof TenuoError) {
        const reason = describeDenial(error, call);
        record("DENIED", reason, error.code);
        return { allowed: false, reason, code: error.code, centralCalls: 0 };
      }
      throw error;
    }
  }

  async describe(): Promise<Record<string, unknown>> {
    const out: Record<string, unknown> = {};
    for (const agent of AGENTS) {
      const held: Record<string, unknown> = {};
      for (const [key, session] of this.sessions) {
        if (key.startsWith(`${agent}@`)) {
          const info = session.inspect();
          held[key.slice(agent.length + 1)] = {
            tools: info.tools,
            depth: info.depth,
            maxDepth: info.maxDepth,
            terminal: info.terminal,
            expiresIn: `${Math.max(0, info.expiresAt - Math.floor(Date.now() / 1000))}s`,
            holder: `${info.holderPublicKey.slice(0, 12)}…`,
          };
        }
      }
      out[agent] = Object.keys(held).length === 0 ? "no session" : held;
    }
    return out;
  }
}

/** Turn a core error into the reason line the participant reads. */
function describeDenial(error: TenuoError, call: Call): string {
  const field = error instanceof AuthorizationDeniedError ? error.field : undefined;
  const value = field === undefined ? undefined : call.args[field];
  const display = value === undefined
    ? resourceOf(call.action, call.args)
    : typeof value === "string"
      ? value
      : JSON.stringify(value);
  switch (error.code) {
    case "TENUO_TOOL_NOT_AUTHORIZED":
      return `${call.action} is not in ${call.actor}'s warrant`;
    case "TENUO_CONSTRAINT_VIOLATION":
      return field !== undefined
        ? `${field} ${display} is outside the warrant's constraint for ${call.action}`
        : `arguments outside the warrant's constraints for ${call.action}`;
    case "TENUO_UNTRUSTED_ROOT":
      return "warrant chain does not lead back to the control plane's key";
    case "TENUO_INVALID_POP":
      return `warrant is bound to another agent's key; this call was signed with ${call.actor}'s key`;
    case "TENUO_WARRANT_EXPIRED":
      return "warrant has expired";
    case "TENUO_REVOKED":
      return "warrant was revoked";
    default:
      return `${error.code}: ${error.message}`;
  }
}

export const ALL_TOOLS = Object.values(TOOLS);
