import type { PublicKeyHandle, Session, Tenuo, WarrantPart } from "./api.ts";
import { TenuoConfigurationError } from "./errors.ts";
import type { HolderIdentity } from "./identity.ts";
import {
  bindHostCollector,
  bindSessionCollector,
  hostCollector,
  linkedHostCollector,
  ReceiptCollector,
  sessionCollector,
} from "./receipts.ts";

export type ReceiptsMode = "collect" | "off";

export type RuntimeOptions = {
  readonly identity: HolderIdentity;
  readonly trustedRoots: readonly PublicKeyHandle[];
  /** Published SignedRevocationList. Fetching it is the caller's job. */
  readonly revocationList?: string | Uint8Array;
  /**
   * `collect` retains receipts produced through this runtime's sessions
   * (tools, present, MCP attach) and through this runtime's tenuo
   * (verify, MCP verify/handler) until `acknowledgeReceipts()`.
   * `drainReceipts()` is a snapshot. Default `off`.
   */
  readonly receipts?: ReceiptsMode;
  /** Bound on each receipt outbox. Default 10_000. */
  readonly receiptMax?: number;
};

export type SessionWarrant = string | readonly string[] | readonly WarrantPart[];

/**
 * Long-lived holder runtime. Owns identity, trusted roots, the current
 * revocation list, and optional receipt collection. Does not perform
 * network I/O or invent hosted-service defaults.
 */
export class Runtime {
  readonly identity: HolderIdentity;
  readonly tenuo: Tenuo;
  readonly #collect: boolean;
  readonly #max: number;
  readonly #sessionCollectors: ReceiptCollector[] = [];

  constructor(
    tenuo: Tenuo,
    identity: HolderIdentity,
    collect: boolean,
    max = 10_000,
  ) {
    this.tenuo = tenuo;
    this.identity = identity;
    this.#collect = collect;
    this.#max = max;
    if (collect) {
      bindHostCollector(tenuo, new ReceiptCollector(max));
    }
  }

  applyRevocationList(list: string | Uint8Array): void {
    this.tenuo.revoke(list);
  }

  sessionFromWire(warrant: SessionWarrant): Session {
    const session = this.tenuo.sessionFromWire({
      warrant,
      holderKey: this.identity.holderKey,
    });
    if (this.#collect) {
      const collector = new ReceiptCollector(this.#max);
      this.#sessionCollectors.push(collector);
      bindSessionCollector(session, collector, hostCollector(this.tenuo));
    }
    return session;
  }

  /** Undrained receipts from every session and presented call handled by this runtime. */
  peekReceipts(): string[] {
    return hostCollector(this.tenuo)?.peek() ?? [];
  }

  /**
   * Snapshot of receipts across holder sessions and presented-path
   * verification. Same as `peekReceipts`; nothing is removed until
   * `acknowledgeReceipts`.
   */
  drainReceipts(): string[] {
    return this.peekReceipts();
  }

  acknowledgeReceipts(count: number): number {
    const host = hostCollector(this.tenuo);
    if (host === undefined) {
      return 0;
    }
    const taken = host.peek().slice(0, count);
    const removed = host.acknowledge(count);
    const acked = taken.slice(0, removed);
    for (const collector of this.#sessionCollectors) {
      collector.removeMatching(acked);
    }
    return removed;
  }

  /** Receipts dropped because the shared outbox was full. */
  receiptOverflows(): number {
    return hostCollector(this.tenuo)?.overflowed ?? 0;
  }
}

export function createRuntime(
  createTenuo: (options: {
    trustedRoots: readonly PublicKeyHandle[];
    revocationList?: string | Uint8Array;
  }) => Tenuo,
  options: RuntimeOptions,
): Runtime {
  if (options.trustedRoots.length === 0) {
    throw new TenuoConfigurationError(
      "createTenuo.runtime() requires at least one trusted root.",
    );
  }
  const tenuoOptions: {
    trustedRoots: readonly PublicKeyHandle[];
    revocationList?: string | Uint8Array;
  } = { trustedRoots: options.trustedRoots };
  if (options.revocationList !== undefined) {
    tenuoOptions.revocationList = options.revocationList;
  }
  const tenuo = createTenuo(tenuoOptions);
  if (options.receiptMax === 0) {
    throw new TenuoConfigurationError("createTenuo.runtime() receiptMax must be a positive integer.");
  }
  return new Runtime(
    tenuo,
    options.identity,
    options.receipts === "collect",
    options.receiptMax ?? 10_000,
  );
}

export function drainSessionReceipts(session: object): string[] {
  return sessionCollector(session)?.drain() ?? [];
}

export function peekSessionReceipts(session: object): string[] {
  return sessionCollector(session)?.peek() ?? [];
}

export function acknowledgeSessionReceipts(session: object, count: number): number {
  const collector = sessionCollector(session);
  if (collector === undefined) {
    return 0;
  }
  const taken = collector.peek().slice(0, count);
  const removed = collector.acknowledge(count);
  linkedHostCollector(session)?.removeMatching(taken.slice(0, removed));
  return removed;
}
