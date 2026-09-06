import type { AuditLog } from "../audit.ts";
import type { AgentId } from "../mission.ts";
import type { World } from "../services/index.ts";

/** What an agent carries in modes 1 to 3. A bearer credential: all of its authority or none of it. */
export interface Credential {
  readonly identity: string;
  readonly label: string;
}

export interface Call {
  readonly actor: AgentId;
  readonly action: string;
  readonly args: Record<string, unknown>;
  readonly taskId: string;
  /** Modes 1 to 3. */
  readonly credential?: Credential;
  readonly source: "trip" | "injected" | "probe" | "handoff";
}

export interface Decision {
  readonly allowed: boolean;
  readonly reason: string;
  readonly code?: string;
  readonly roundTrips: number;
  readonly result?: unknown;
  readonly error?: string;
}

export interface Ctx {
  readonly world: World;
  readonly audit: AuditLog;
}

/** One authorization mode. `authorize` decides; `execute` decides and then runs the tool. */
export interface AuthMode {
  readonly name: "shared" | "identity" | "scoped" | "tenuo";
  execute(call: Call, ctx: Ctx): Promise<Decision>;
  /** What each agent can currently do, for `npm run audit`. */
  describe(ctx: Ctx): Promise<Record<string, unknown>>;
}
