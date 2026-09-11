import type { PublicKeyHandle, Session, Tenuo, WarrantPart } from "./api.ts";
import { TenuoConfigurationError } from "./errors.ts";
import type { HolderIdentity } from "./identity.ts";
import {
  bindHostCollector,
  bindSessionCollector,
  hostCollector,
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
      bindSessionCollector(session, collector);
    }
    return session;
  }

  /** Undrained receipts from every session and presented call handled by this runtime. */
  peekReceipts(): string[] {
    const host = hostCollector(this.tenuo)?.peek() ?? [];
    return [...host, ...this.#sessionCollectors.flatMap((collector) => collector.peek())];
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
    let left = count;
    let removed = 0;
    const host = hostCollector(this.tenuo);
    if (host !== undefined && left > 0) {
      const took = host.acknowledge(left);
      removed += took;
      left -= took;
    }
    for (const collector of this.#sessionCollectors) {
      if (left <= 0) {
        break;
      }
      const took = collector.acknowledge(left);
      removed += took;
      left -= took;
    }
    return removed;
  }

  /** Receipts dropped because an outbox was full. */
  receiptOverflows(): number {
    const host = hostCollector(this.tenuo)?.overflowed ?? 0;
    return (
      host + this.#sessionCollectors.reduce((sum, collector) => sum + collector.overflowed, 0)
    );
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
  return sessionCollector(session)?.acknowledge(count) ?? 0;
}
