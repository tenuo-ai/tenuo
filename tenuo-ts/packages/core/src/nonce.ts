import { createHash } from "node:crypto";
import type { NonceStore } from "./api.ts";
import { TenuoConfigurationError } from "./errors.ts";

/**
 * In-process PoP replay store. Same shape as Python `NonceStore`.
 * Not on by default. Does not work across processes — implement
 * `NonceStore` with an async Redis `checkAndRecord` (return
 * `Promise<boolean>`). A rejected Promise fails closed.
 *
 * `ttlSeconds` defaults to 180 and must be greater than zero and finite.
 * Values too large to convert to milliseconds are also rejected.
 *
 * @throws {TenuoConfigurationError} If `ttlSeconds` is not a supported
 * positive, finite duration.
 */
export function memoryNonceStore(options?: { readonly ttlSeconds?: number }): NonceStore {
  const ttlSeconds = options?.ttlSeconds ?? 180;
  const ttlMs = ttlSeconds * 1000;
  if (ttlSeconds <= 0 || !Number.isFinite(ttlSeconds) || !Number.isFinite(ttlMs)) {
    throw new TenuoConfigurationError(
      "memoryNonceStore() ttlSeconds must be positive, finite, and representable in milliseconds",
    );
  }
  const seen = new Map<string, number>();
  return {
    checkAndRecord(popSignature: string): boolean {
      const now = Date.now();
      for (const [key, expiry] of seen) {
        if (expiry <= now) {
          seen.delete(key);
        }
      }
      const key = createHash("sha256").update(popSignature).digest("hex");
      if (seen.has(key)) {
        return false;
      }
      seen.set(key, now + ttlMs);
      return true;
    },
  };
}
