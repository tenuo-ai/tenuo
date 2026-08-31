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
      if (options !== undefined) {
        assertKnownKeys(options, ATTACH_OPTION_KEYS, "mcp.attach() options");
      }
      const native = nativeSession(session as Session);
      const wireArgs = stripNulls(args);
      const local = context.authorize(
        native,
        name,
        wireArgs,
        options?.approvals,
        undefined,
        options?.requestId,
      );
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

    async verify(name, args, meta, options) {
      if (options !== undefined) {
        assertKnownKeys(options, VERIFY_OPTION_KEYS, "mcp.verify() options");
      }
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
        options?.requestId,
      );
      // Rust already signed this envelope. Emit before the nonce store can
      // refuse a replay — otherwise an attacker leaves no audit artifact.
      emitReceipt(options?.onReceipt, decision.receipt);
      if (decision.outcome === "allow") {
        await admitPop(options?.nonceStore, envelope.signature, options?.onNonceStoreError);
      }
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
        const authorized = await mcp.verify(name, args, extra?._meta ?? extra?.meta, {
          ...(policy?.allow !== undefined ? { allow: policy.allow } : {}),
          ...(policy?.onReceipt !== undefined ? { onReceipt: policy.onReceipt } : {}),
          ...(policy?.nonceStore !== undefined ? { nonceStore: policy.nonceStore } : {}),
          ...(policy?.onNonceStoreError !== undefined ? { onNonceStoreError: policy.onNonceStoreError } : {}),
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

const HANDLER_POLICY_KEYS = new Set(["allow", "onReceipt", "nonceStore", "onNonceStoreError"]);
const VERIFY_OPTION_KEYS = new Set([
  "allow",
  "onReceipt",
  "nonceStore",
  "onNonceStoreError",
  "requestId",
]);
const REPLAY_STORE_UNAVAILABLE = "Replay store unavailable";
const ATTACH_OPTION_KEYS = new Set(["approvals", "onReceipt", "requestId"]);
const MAX_STRIP_DEPTH = 32;
const MAX_STRIP_LEN = 1024;

function assertKnownKeys(value: object, known: ReadonlySet<string>, label: string): void {
  const unknown = Object.keys(value).filter((key) => !known.has(key));
  if (unknown[0] !== undefined) {
    throw new TenuoConfigurationError(
      `${label} has unknown key '${unknown[0]}'. Use ${[...known].join(", ")}.`,
    );
  }
}

function isHandlerPolicy(value: unknown): value is McpHandlerPolicy {
  if (value === null || typeof value !== "object" || Array.isArray(value) || typeof value === "function") {
    return false;
  }
  const keys = Object.keys(value);
  assertKnownKeys(value, HANDLER_POLICY_KEYS, "mcp.handler() policy");
  const record = value as {
    allow?: unknown;
    onReceipt?: unknown;
    nonceStore?: unknown;
    onNonceStoreError?: unknown;
  };
  const hasAllow =
    "allow" in record && record.allow !== null && typeof record.allow === "object" && !Array.isArray(record.allow);
  const hasReceipt = "onReceipt" in record && typeof record.onReceipt === "function";
  const hasNonce = "nonceStore" in record && record.nonceStore !== null && typeof record.nonceStore === "object";
  const hasStoreError = "onNonceStoreError" in record && typeof record.onNonceStoreError === "function";
  return keys.length === 0 || hasAllow || hasReceipt || hasNonce || hasStoreError;
}

async function admitPop(
  store: { checkAndRecord(popSignature: string): boolean | Promise<boolean> } | undefined,
  signature: string,
  onNonceStoreError?: (error: unknown) => void | Promise<void>,
): Promise<void> {
  if (store === undefined) {
    return;
  }
  let admitted: boolean | Promise<boolean>;
  try {
    admitted = store.checkAndRecord(signature);
  } catch (error) {
    throw replayStoreUnavailable(error, onNonceStoreError);
  }
  if (isThenable(admitted)) {
    try {
      admitted = await admitted;
    } catch (error) {
      throw replayStoreUnavailable(error, onNonceStoreError);
    }
  }
  if (typeof admitted !== "boolean") {
    throw replayStoreUnavailable(
      new TenuoConfigurationError("NonceStore.checkAndRecord() must return boolean or Promise<boolean>"),
      onNonceStoreError,
    );
  }
  if (!admitted) {
    throw new AuthorizationDeniedError(
      "TENUO_INVALID_POP",
      "PoP replay detected — this exact authorization token was already consumed.",
    );
  }
}

function replayStoreUnavailable(
  cause: unknown,
  onNonceStoreError?: (error: unknown) => void | Promise<void>,
): TenuoConfigurationError {
  emitIsolated(onNonceStoreError, cause);
  const error = new TenuoConfigurationError(REPLAY_STORE_UNAVAILABLE);
  if (cause !== undefined) {
    error.cause = cause;
  }
  return error;
}

function emitIsolated(
  hook: ((error: unknown) => void | Promise<void>) | undefined,
  error: unknown,
): void {
  if (hook === undefined) {
    return;
  }
  try {
    const result = hook(error);
    if (isThenable(result)) {
      void Promise.resolve(result).catch(() => undefined);
    }
  } catch {
    // Isolated — must not change the public error.
  }
}

function isThenable(value: unknown): value is Promise<boolean> {
  return value !== null && typeof value === "object" && "then" in value && typeof value.then === "function";
}

function emitReceipt(
  onReceipt: ((receipt: string) => void | Promise<void>) | undefined,
  receipt: string | undefined,
): void {
  if (onReceipt === undefined || receipt === undefined) {
    return;
  }
  try {
    const result = onReceipt(receipt);
    if (isThenable(result)) {
      void Promise.resolve(result).catch(() => undefined);
    }
  } catch {
    // Receipt hooks must not deny or fail the tool.
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
  const keys = Object.keys(args);
  if (keys.length > MAX_STRIP_LEN) {
    throw new TenuoConfigurationError("arguments exceed the TypeScript input budget");
  }
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args)) {
    if (value === null || value === undefined) {
      continue;
    }
    out[key] = Array.isArray(value) ? cleanList(value, 1) : value;
  }
  return out;
}

function cleanList(value: readonly unknown[], depth: number): unknown[] {
  if (depth > MAX_STRIP_DEPTH) {
    throw new TenuoConfigurationError("arguments exceed the TypeScript nesting budget");
  }
  if (value.length > MAX_STRIP_LEN) {
    throw new TenuoConfigurationError("arguments exceed the TypeScript input budget");
  }
  const cleaned: unknown[] = [];
  for (const item of value) {
    if (item === null || item === undefined) {
      continue;
    }
    cleaned.push(Array.isArray(item) ? cleanList(item, depth + 1) : item);
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
