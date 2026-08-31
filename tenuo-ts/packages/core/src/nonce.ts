import { createHash } from "node:crypto";
import type { NonceStore } from "./api.ts";

/**
 * In-process PoP replay store. Same shape as Python `NonceStore`.
 * Not on by default. Does not work across processes — implement
 * `NonceStore` with an async Redis `checkAndRecord` (return
 * `Promise<boolean>`). A rejected Promise fails closed.
 */
export function memoryNonceStore(options?: { readonly ttlSeconds?: number }): NonceStore {
  const ttlMs = (options?.ttlSeconds ?? 180) * 1000;
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
