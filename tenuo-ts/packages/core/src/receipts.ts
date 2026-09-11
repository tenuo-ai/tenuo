import type { Session as SessionContract } from "./api.ts";

/**
 * In-memory receipt buffer containing only unacknowledged receipts.
 *
 * Delivery: receipts are appended in emission order. `peek()` and `drain()`
 * are the same non-consuming snapshot. Only `acknowledge()` removes items.
 */
export class ReceiptCollector {
  readonly #items: string[] = [];
  readonly #max: number;
  #overflowed = 0;

  constructor(max = 10_000) {
    this.#max = Number.isInteger(max) && max > 0 ? max : 10_000;
  }

  get overflowed(): number {
    return this.#overflowed;
  }

  push(receipt: string): void {
    if (this.#items.length >= this.#max) {
      this.#overflowed += 1;
      return;
    }
    this.#items.push(receipt);
  }

  peek(): string[] {
    return [...this.#items];
  }

  drain(): string[] {
    return this.peek();
  }

  acknowledge(count: number): number {
    if (!Number.isInteger(count) || count < 0) {
      return 0;
    }
    const n = Math.min(count, this.#items.length);
    this.#items.splice(0, n);
    return n;
  }

  /** Remove receipts by wire identity, preserving remaining order. */
  removeMatching(wires: readonly string[]): number {
    if (wires.length === 0) {
      return 0;
    }
    const drop = new Set(wires);
    const kept: string[] = [];
    let removed = 0;
    for (const item of this.#items) {
      if (drop.has(item)) {
        removed += 1;
      } else {
        kept.push(item);
      }
    }
    this.#items.length = 0;
    this.#items.push(...kept);
    return removed;
  }
}

const sessionCollectors = new WeakMap<object, ReceiptCollector>();
const hostCollectors = new WeakMap<object, ReceiptCollector>();
const linkedHostCollectors = new WeakMap<object, ReceiptCollector>();

export function bindSessionCollector(
  session: object,
  collector: ReceiptCollector,
  host?: ReceiptCollector,
): void {
  sessionCollectors.set(session, collector);
  if (host !== undefined) {
    linkedHostCollectors.set(session, host);
  }
}

/** Derived sessions share the parent's outbox so acknowledge frees both. */
export function inheritSessionCollector(parent: object, child: object): void {
  const parentCollector = sessionCollectors.get(parent);
  if (parentCollector !== undefined) {
    sessionCollectors.set(child, parentCollector);
  }
  const host = linkedHostCollectors.get(parent);
  if (host !== undefined) {
    linkedHostCollectors.set(child, host);
  }
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

export function linkedHostCollector(session: object | undefined): ReceiptCollector | undefined {
  if (session === undefined) {
    return undefined;
  }
  return linkedHostCollectors.get(session);
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
  hostCollector(host)?.push(receipt);
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
