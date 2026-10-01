import type {
  McpAttachOptions,
  McpCallParams,
  McpHandlerPolicy,
  McpJsonRpcError,
  McpVerifyOptions,
  PresentedCall,
  Session as SessionContract,
  TenuoErrorCode,
  TenuoMcp,
} from "./api.ts";
import { AuthorizationDeniedError, TenuoConfigurationError, TenuoError } from "./errors.ts";
import { collectReceipt, emitIsolatedReceipt } from "./receipts.ts";
import { nativeSession, type Session } from "./session.ts";
import type { WasmContext, WasmDecision } from "./wasm.ts";

export type Decide = (decision: WasmDecision, tool: string, native?: object, args?: Record<string, unknown>) => void;

/**
 * Transport-agnostic half of `attach`: authorize locally, then sign
 * proof-of-possession over the call. Shared by `tenuo.present()` and
 * `tenuo.mcp.attach()`.
 */
export function presentCall(
  context: WasmContext,
  decide: Decide,
  session: SessionContract,
  name: string,
  args: Readonly<Record<string, unknown>>,
  options: McpAttachOptions | undefined,
  label: string,
  host?: object,
): { readonly presented: PresentedCall; readonly wireArgs: Record<string, unknown> } {
  if (options !== undefined) {
    assertKnownKeys(options, ATTACH_OPTION_KEYS, `${label} options`);
  }
  const native = nativeSession(session as Session);
  const argsJson = argumentJson(args);
  const local = context.authorize(
    native,
    name,
    argsJson,
    options?.approvals,
    undefined,
    options?.requestId,
  );
  emitReceipt(options?.onReceipt, local.receipt, session, host);
  decide(local, name, native, args);
  const envelope = context.signMeta(
    native,
    name,
    argsJson,
    Math.floor(Date.now() / 1000),
    options?.approvals ?? null,
  );
  const presented = {
    warrant: envelope.warrant,
    signature: envelope.signature,
    ...(envelope.approvals !== undefined && envelope.approvals.length > 0
      ? { approvals: envelope.approvals }
      : {}),
  };
  return { presented, wireArgs: JSON.parse(argsJson) as Record<string, unknown> };
}

/**
 * Transport-agnostic half of `verify`: check a presented warrant chain and
 * proof-of-possession, then apply the host ceiling. Shared by
 * `tenuo.verify()` and `tenuo.mcp.verify()`.
 */
export async function verifyPresented(
  context: WasmContext,
  decide: Decide,
  presented: PresentedCall,
  name: string,
  args: Readonly<Record<string, unknown>>,
  options: McpVerifyOptions | undefined,
  label: string,
  host?: object,
): Promise<Readonly<Record<string, unknown>>> {
  if (options !== undefined) {
    assertKnownKeys(options, VERIFY_OPTION_KEYS, `${label} options`);
  }
  const envelope = presentedEnvelope(presented);
  if (envelope === undefined) {
    throw new TenuoConfigurationError(
      `${label} needs { warrant, signature } from tenuo.present() or tenuo.mcp.attach()`,
    );
  }
  const decision = context.authorizePresented(
    envelope.warrant,
    name,
    argumentJson(args),
    envelope.signature,
    envelope.approvals,
    options?.allow,
    options?.requestId,
  );
  // Rust already signed this envelope. Emit before the nonce store can
  // refuse a replay — otherwise an attacker leaves no audit artifact.
  emitReceipt(options?.onReceipt, decision.receipt, undefined, host);
  if (decision.outcome === "allow") {
    await admitPop(options?.nonceStore, envelope.signature, options?.onNonceStoreError);
  }
  decide(decision, name);
  // Run the host parse of the JSON text the proof covers. The raw host
  // object can contain values that JSON drops.
  return plainArgs(JSON.parse(argumentJson(args)) as Record<string, unknown>);
}

export function createMcp(context: WasmContext, decide: Decide, host?: object): TenuoMcp {
  const mcp: TenuoMcp = {
    attach(session, name, args, options) {
      const { presented, wireArgs } = presentCall(
        context,
        decide,
        session,
        name,
        args,
        options,
        "mcp.attach()",
        host,
      );
      return { name, arguments: wireArgs, _meta: { tenuo: presented } };
    },

    async verify(name, args, meta, options) {
      const envelope = tenuoEnvelope(meta);
      if (envelope === undefined) {
        throw new TenuoConfigurationError(
          "MCP call is missing _meta.tenuo. The client must call tenuo.mcp.attach().",
        );
      }
      return verifyPresented(context, decide, envelope, name, args, options, "mcp.verify()", host);
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

function argumentJson(args: Readonly<Record<string, unknown>>): string {
  const text = JSON.stringify(args);
  if (typeof text !== "string") {
    throw new TenuoConfigurationError("arguments must be JSON");
  }
  return text;
}

function presentedEnvelope(
  value: unknown,
): { warrant: string; signature: string; approvals?: string[] } | undefined {
  if (value === null || typeof value !== "object") {
    return undefined;
  }
  const tenuo = value as { warrant?: unknown; signature?: unknown; approvals?: unknown };
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

function tenuoEnvelope(
  meta: unknown,
): { warrant: string; signature: string; approvals?: string[] } | undefined {
  if (meta === null || typeof meta !== "object") {
    return undefined;
  }
  const root = meta as { tenuo?: unknown; _meta?: unknown };
  const block = root.tenuo ?? (root._meta as { tenuo?: unknown } | undefined)?.tenuo;
  return presentedEnvelope(block);
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
  session?: SessionContract,
  host?: object,
): void {
  collectReceipt(receipt, session, host);
  emitIsolatedReceipt(onReceipt, receipt);
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

function jsonRpcError(error: unknown): McpJsonRpcError {
  if (error instanceof TenuoError) {
    const code: TenuoErrorCode = error.code;
    const rpc = code === "TENUO_APPROVAL_REQUIRED" ? -32002 : code === "TENUO_CANONICALIZATION" ? -32602 : -32001;
    return { code: rpc, message: error.message, data: { tenuo: { code } } };
  }
  const message = error instanceof Error ? error.message : String(error);
  return { code: -32001, message };
}
