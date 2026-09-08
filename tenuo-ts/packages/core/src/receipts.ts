import type { Session as SessionContract } from "./api.ts";

/**
 * In-memory receipt buffer with a drain cursor.
 *
 * Delivery: receipts are appended in emission order. `peek()` is
 * non-consuming. `drain()` returns everything after the cursor and advances
 * it (at-most-once from this buffer). A hosted adapter that retries uploads
 * should `peek()`, copy into its own retry buffer, then `acknowledge()`.
 * Process crash after drain and before the caller persists the batch loses
 * those receipts here. Upload remains the caller's job.
 */
export class ReceiptCollector {
  readonly #items: string[] = [];
  #cursor = 0;

  push(receipt: string): void {
    this.#items.push(receipt);
  }

  peek(): string[] {
    return this.#items.slice(this.#cursor);
  }

  drain(): string[] {
    const batch = this.peek();
    this.#cursor = this.#items.length;
    return batch;
  }

  acknowledge(count: number): number {
    if (!Number.isInteger(count) || count < 0) {
      return 0;
    }
    const available = this.#items.length - this.#cursor;
    const n = Math.min(count, available);
    this.#cursor += n;
    return n;
  }
}

const sessionCollectors = new WeakMap<object, ReceiptCollector>();
const hostCollectors = new WeakMap<object, ReceiptCollector>();

export function bindSessionCollector(session: object, collector: ReceiptCollector): void {
  sessionCollectors.set(session, collector);
}

export function bindHostCollector(host: object, collector: ReceiptCollector): void {
  hostCollectors.set(host, collector);
}

export function sessionCollector(session: object | undefined): ReceiptCollector | undefined {
  if (session === undefined) {
    return undefined;
  }
  return sessionCollectors.get(session);
}

export function hostCollector(host: object | undefined): ReceiptCollector | undefined {
  if (host === undefined) {
    return undefined;
  }
  return hostCollectors.get(host);
}

export function collectReceipt(
  receipt: string | undefined,
  session?: SessionContract,
  host?: object,
): void {
  if (receipt === undefined) {
    return;
  }
  sessionCollector(session)?.push(receipt);
  if (session === undefined) {
    hostCollector(host)?.push(receipt);
  }
}

export function emitIsolatedReceipt(
  onReceipt: ((receipt: string) => void | Promise<void>) | undefined,
  receipt: string | undefined,
): void {
  if (onReceipt === undefined || receipt === undefined) {
    return;
  }
  try {
    const result = onReceipt(receipt);
    if (result !== null && typeof result === "object" && "then" in result && typeof result.then === "function") {
      void Promise.resolve(result).catch(() => undefined);
    }
  } catch {
    // Explicit onReceipt remains isolated. Collectors are sync and do not use this path.
  }
}
