import type {
  McpAttachOptions,
  McpCallParams,
  McpHandlerPolicy,
  McpJsonRpcError,
  TenuoErrorCode,
  TenuoMcp,
} from "./api.ts";
import { ApprovalRequiredError, AuthorizationDeniedError, TenuoConfigurationError, TenuoError } from "./errors.ts";
import { nativeSession, type Session } from "./session.ts";
import type { WasmContext, WasmDecision } from "./wasm.ts";

export function createMcp(context: WasmContext, decide: (decision: WasmDecision, tool: string) => void): TenuoMcp {
  const mcp: TenuoMcp = {
    attach(session, name, args, options) {
      const native = nativeSession(session as Session);
      const wireArgs = stripNulls(args);
      const local = context.authorize(native, name, wireArgs, options?.approvals);
      emitReceipt(options?.onReceipt, local.receipt);
      decide(local, name);
      const signature = context.signPop(native, name, wireArgs);
      const warrant = stackWire(native);
      const tenuo: McpCallParams["_meta"]["tenuo"] = { warrant, signature };
      if (options?.approvals !== undefined && options.approvals.length > 0) {
        return {
          name,
          arguments: wireArgs,
          _meta: {
            tenuo: {
              ...tenuo,
              approvals: options.approvals.map(approvalWire),
            },
          },
        };
      }
      return { name, arguments: wireArgs, _meta: { tenuo } };
    },

    verify(name, args, meta, options) {
      const envelope = tenuoEnvelope(meta);
      if (envelope === undefined) {
        throw new TenuoConfigurationError(
          "MCP call is missing _meta.tenuo. The client must call tenuo.mcp.attach().",
        );
      }
      const decision = context.authorizePresented(
        envelope.warrant,
        name,
        stripNulls(args),
        envelope.signature,
        envelope.approvals,
        options?.allow,
      );
      if (
        decision.outcome === "allow" &&
        options?.nonceStore !== undefined &&
        !options.nonceStore.checkAndRecord(envelope.signature)
      ) {
        throw new AuthorizationDeniedError(
          "TENUO_INVALID_POP",
          "PoP replay detected — this exact authorization token was already consumed.",
        );
      }
      emitReceipt(options?.onReceipt, decision.receipt);
      decide(decision, name);
      return plainArgs(decision.args);
    },

    handler(name, policyOrExecute, maybeExecute?) {
      const policy = isHandlerPolicy(policyOrExecute) ? policyOrExecute : undefined;
      const execute = isHandlerPolicy(policyOrExecute) ? maybeExecute : policyOrExecute;
      if (typeof execute !== "function") {
        throw new TenuoConfigurationError("mcp.handler() requires an execute function");
      }
      return async (args, extra) => {
        const authorized = mcp.verify(name, args, extra?._meta ?? extra?.meta, {
          ...(policy?.allow !== undefined ? { allow: policy.allow } : {}),
          ...(policy?.onReceipt !== undefined ? { onReceipt: policy.onReceipt } : {}),
          ...(policy?.nonceStore !== undefined ? { nonceStore: policy.nonceStore } : {}),
        });
        return execute(authorized as never);
      };
    },

    jsonRpcError(error) {
      return jsonRpcError(error);
    },
  };
  return mcp;
}

function stackWire(native: object): string {
  const session = native as { toStackWire?: () => unknown };
  if (typeof session.toStackWire !== "function") {
    throw new TenuoConfigurationError("session is not bound to the WASM core");
  }
  const wire = session.toStackWire();
  if (typeof wire !== "string" || wire.length === 0) {
    throw new TenuoConfigurationError("toStackWire() did not return a warrant stack");
  }
  return wire;
}

function approvalWire(value: string | Uint8Array): string {
  if (typeof value === "string") {
    return value;
  }
  return Buffer.from(value).toString("base64");
}

function tenuoEnvelope(
  meta: unknown,
): { warrant: string; signature: string; approvals?: string[] } | undefined {
  if (meta === null || typeof meta !== "object") {
    return undefined;
  }
  const root = meta as { tenuo?: unknown; _meta?: unknown };
  const block = root.tenuo ?? (root._meta as { tenuo?: unknown } | undefined)?.tenuo;
  if (block === null || typeof block !== "object") {
    return undefined;
  }
  const tenuo = block as { warrant?: unknown; signature?: unknown; approvals?: unknown };
  if (typeof tenuo.warrant !== "string" || tenuo.warrant.length === 0) {
    return undefined;
  }
  if (typeof tenuo.signature !== "string" || tenuo.signature.length === 0) {
    return undefined;
  }
  const approvals = Array.isArray(tenuo.approvals)
    ? tenuo.approvals.filter((item): item is string => typeof item === "string")
    : undefined;
  return {
    warrant: tenuo.warrant,
    signature: tenuo.signature,
    ...(approvals !== undefined && approvals.length > 0 ? { approvals } : {}),
  };
}

const HANDLER_POLICY_KEYS = new Set(["allow", "onReceipt", "nonceStore"]);

function isHandlerPolicy(value: unknown): value is McpHandlerPolicy {
  if (value === null || typeof value !== "object" || Array.isArray(value) || typeof value === "function") {
    return false;
  }
  const keys = Object.keys(value);
  const known = keys.filter((key) => HANDLER_POLICY_KEYS.has(key));
  const unknown = keys.filter((key) => !HANDLER_POLICY_KEYS.has(key));
  if (unknown.length > 0 && known.length === 0) {
    throw new TenuoConfigurationError(
      `mcp.handler() policy has unknown key '${unknown[0]}'. Use allow, onReceipt, or nonceStore.`,
    );
  }
  const record = value as { allow?: unknown; onReceipt?: unknown; nonceStore?: unknown };
  const hasAllow =
    "allow" in record && record.allow !== null && typeof record.allow === "object" && !Array.isArray(record.allow);
  const hasReceipt = "onReceipt" in record && typeof record.onReceipt === "function";
  const hasNonce = "nonceStore" in record && record.nonceStore !== null && typeof record.nonceStore === "object";
  return hasAllow || hasReceipt || hasNonce;
}

function emitReceipt(onReceipt: ((receipt: string) => void) | undefined, receipt: string | undefined): void {
  if (onReceipt !== undefined && receipt !== undefined) {
    onReceipt(receipt);
  }
}

function plainArgs(value: unknown): Record<string, unknown> {
  if (value instanceof Map) {
    return Object.fromEntries(value);
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return { ...(value as Record<string, unknown>) };
  }
  return {};
}

/** Same rule as Python `strip_none_values`: drop null so optional MCP args do not break PoP. */
function stripNulls(args: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args)) {
    if (value === null || value === undefined) {
      continue;
    }
    out[key] = Array.isArray(value) ? cleanList(value) : value;
  }
  return out;
}

function cleanList(value: readonly unknown[]): unknown[] {
  const cleaned: unknown[] = [];
  for (const item of value) {
    if (item === null || item === undefined) {
      continue;
    }
    cleaned.push(Array.isArray(item) ? cleanList(item) : item);
  }
  return cleaned;
}

function jsonRpcError(error: unknown): McpJsonRpcError {
  if (error instanceof TenuoError) {
    const code: TenuoErrorCode = error.code;
    const rpc = code === "TENUO_APPROVAL_REQUIRED" ? -32002 : code === "TENUO_CANONICALIZATION" ? -32602 : -32001;
    return { code: rpc, message: error.message, data: { tenuo: { code } } };
  }
  const message = error instanceof Error ? error.message : String(error);
  return { code: -32001, message };
}
