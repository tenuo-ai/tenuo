import { createHash } from "node:crypto";
import type { NonceStore } from "./api.ts";
import { AuthorizationDeniedError, TenuoConfigurationError } from "./errors.ts";
import { loadWasm, type WasmApprovalInfo } from "./wasm.ts";

const REPLAY_STORE_UNAVAILABLE = "Replay store unavailable";

/**
 * Record `key` in a `NonceStore`. Throws `replayed()` when the store has
 * already seen it, and the constant "Replay store unavailable" when the
 * store throws, rejects, or returns a non-boolean. Shared by the MCP PoP
 * check and approval consumption.
 */
export async function admitNonce(
  store: NonceStore | undefined,
  key: string,
  onNonceStoreError: ((error: unknown) => void | Promise<void>) | undefined,
  replayed: () => Error,
): Promise<void> {
  if (store === undefined) {
    return;
  }
  let admitted: boolean | Promise<boolean>;
  try {
    admitted = store.checkAndRecord(key);
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
    throw replayed();
  }
}

/**
 * Make approvals one-use: record every approval envelope that counts for
 * this call (valid signature and, when `requestHash` is known, bound to this
 * exact request). Run only after core allowed the call. Do not apply a second
 * expiry check here: core intentionally accepts its configured clock-skew
 * grace window, and an approval it accepted must still be consumed.
 *
 * Keys come from signed approval fields, so re-encoding an envelope (hex,
 * base64, bytes) does not make it fresh again.
 */
export async function consumeApprovals(
  store: NonceStore | undefined,
  approvals: unknown,
  requestHash: string | undefined,
  tool: string,
  onNonceStoreError: ((error: unknown) => void | Promise<void>) | undefined,
): Promise<void> {
  if (store === undefined || !Array.isArray(approvals) || approvals.length === 0) {
    return;
  }
  const expected = requestHash?.toLowerCase();
  const keys = new Set<string>();
  for (const envelope of approvals as unknown[]) {
    const info = inspect(envelope);
    if (!info.signature_valid) {
      continue;
    }
    if (expected !== undefined && info.request_hash.toLowerCase() !== expected) {
      continue;
    }
    keys.add(approvalKey(info));
  }
  for (const key of keys) {
    await admitNonce(store, key, onNonceStoreError, () =>
      new AuthorizationDeniedError(
        "TENUO_INSUFFICIENT_APPROVALS",
        `Approval already used: an approval for ${tool} was consumed by an earlier call. Request a new approval.`,
      ),
    );
  }
}

export function snapshotApprovals(approvals: unknown): unknown {
  if (!Array.isArray(approvals)) {
    return approvals;
  }
  return approvals.map((envelope) =>
    envelope instanceof Uint8Array ? new Uint8Array(envelope) : envelope,
  );
}

function inspect(envelope: unknown): WasmApprovalInfo {
  if (typeof envelope !== "string" && !(envelope instanceof Uint8Array)) {
    throw new TenuoConfigurationError("could not inspect an authorized approval for replay protection");
  }
  try {
    return loadWasm().sdkInspectApproval(envelope);
  } catch (error) {
    const wrapped = new TenuoConfigurationError(
      "could not inspect an authorized approval for replay protection",
    );
    wrapped.cause = error;
    throw wrapped;
  }
}

function approvalKey(info: WasmApprovalInfo): string {
  const digest = createHash("sha256")
    .update(
      JSON.stringify([
        info.approver_public_key.toLowerCase(),
        info.request_hash.toLowerCase(),
        info.nonce.toLowerCase(),
      ]),
    )
    .digest("hex");
  return `tenuo-approval-v1:${digest}`;
}

function replayStoreUnavailable(
  cause: unknown,
  onNonceStoreError?: (error: unknown) => void | Promise<void>,
): TenuoConfigurationError {
  if (onNonceStoreError !== undefined) {
    try {
      const result = onNonceStoreError(cause);
      if (isThenable(result)) {
        void Promise.resolve(result).catch(() => undefined);
      }
    } catch {
      // Isolated — must not change the public error.
    }
  }
  const error = new TenuoConfigurationError(REPLAY_STORE_UNAVAILABLE);
  if (cause !== undefined) {
    error.cause = cause;
  }
  return error;
}

function isThenable(value: unknown): value is Promise<unknown> {
  return value !== null && typeof value === "object" && "then" in value && typeof value.then === "function";
}
