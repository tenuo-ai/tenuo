import type { Session as SessionContract, SessionInfo } from "./api.ts";
import { TenuoConfigurationError } from "./errors.ts";
import {
  acknowledgeSessionReceipts,
  drainSessionReceipts,
  peekSessionReceipts,
} from "./runtime.ts";
import type { WasmSession, WasmSessionInfo } from "./wasm.ts";

const inspect = Symbol.for("nodejs.util.inspect.custom");
const nativeSessions = new WeakMap<Session, WasmSession>();

/**
 * Opaque session handle. Structural clones and JSON are not sessions.
 */
export class Session implements SessionContract {
  readonly [Symbol.toStringTag] = "TenuoSession" as const;

  constructor(native: WasmSession) {
    nativeSessions.set(this, native);
  }

  toJSON(): string {
    return "[TenuoSession]";
  }

  toString(): string {
    return "[TenuoSession]";
  }

  [inspect](): string {
    return "[TenuoSession]";
  }

  toWire(): string[] {
    const native = nativeSessions.get(this) as { toWire?: () => unknown } | undefined;
    if (native?.toWire === undefined) {
      throw new TenuoConfigurationError("session is not bound to the WASM core");
    }
    const tokens = native.toWire();
    if (!Array.isArray(tokens) || tokens.some((token) => typeof token !== "string")) {
      throw new TenuoConfigurationError("toWire() did not return warrant tokens");
    }
    return tokens;
  }

  dedupKey(tool: string, args: Readonly<Record<string, unknown>>): string {
    const native = nativeSessions.get(this) as
      | { dedupKey?: (tool: string, args: unknown) => string }
      | undefined;
    if (typeof native?.dedupKey !== "function") {
      throw new TenuoConfigurationError("session is not bound to the WASM core");
    }
    return native.dedupKey(tool, args);
  }

  inspect(): SessionInfo {
    const native = nativeSessions.get(this) as { describe?: () => unknown } | undefined;
    if (typeof native?.describe !== "function") {
      throw new TenuoConfigurationError("session is not bound to the WASM core");
    }
    const info = native.describe() as WasmSessionInfo;
    const out: {
      -readonly [K in keyof SessionInfo]: SessionInfo[K];
    } = {
      kind: info.kind,
      holderPublicKey: info.holder_public_key,
      rootPublicKey: info.root_public_key,
      depth: info.depth,
      maxDepth: info.max_depth,
      terminal: info.terminal,
      expiresAt: info.expires_at,
      tools: [...info.tools],
      warrantIds: [...info.warrant_ids],
      canAuthorize: info.can_authorize,
      approvalGatedTools: [...info.approval_gated_tools],
    };
    if (info.clearance !== undefined) {
      out.clearance = info.clearance;
    }
    if (info.session_id !== undefined) {
      out.sessionId = info.session_id;
    }
    if (info.agent_id !== undefined) {
      out.agentId = info.agent_id;
    }
    if (info.issuable_tools !== undefined) {
      out.issuableTools = [...info.issuable_tools];
    }
    if (info.max_issue_depth !== undefined) {
      out.maxIssueDepth = info.max_issue_depth;
    }
    if (info.required_approvers !== undefined) {
      out.requiredApprovers = [...info.required_approvers];
    }
    if (info.min_approvals !== undefined) {
      out.minApprovals = info.min_approvals;
    }
    return out;
  }

  /**
   * Snapshot of collected receipts. Same as `drainReceipts`; nothing is
   * removed until `acknowledgeReceipts`.
   */
  peekReceipts(): string[] {
    return peekSessionReceipts(this);
  }

  drainReceipts(): string[] {
    return drainSessionReceipts(this);
  }

  acknowledgeReceipts(count: number): number {
    return acknowledgeSessionReceipts(this, count);
  }
}

export function isSession(value: unknown): value is Session {
  return value instanceof Session;
}

export function nativeSession(session: Session): WasmSession {
  const native = nativeSessions.get(session);
  if (!native) {
    throw new TenuoConfigurationError("session is not bound to the WASM core");
  }
  return native;
}
