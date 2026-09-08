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
   * (verify, MCP verify/handler) until `drainReceipts()`. Default `off`.
   */
  readonly receipts?: ReceiptsMode;
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

  constructor(tenuo: Tenuo, identity: HolderIdentity, collect: boolean) {
    this.tenuo = tenuo;
    this.identity = identity;
    this.#collect = collect;
    if (collect) {
      bindHostCollector(tenuo, new ReceiptCollector());
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
      bindSessionCollector(session, new ReceiptCollector());
    }
    return session;
  }

  /** Undrained receipts from presented-path verify / MCP handlers on this runtime. */
  peekReceipts(): string[] {
    return hostCollector(this.tenuo)?.peek() ?? [];
  }

  /**
   * Receipts since the last drain on the presented-path collector.
   * Holder-session receipts live on `session.drainReceipts()`.
   */
  drainReceipts(): string[] {
    return hostCollector(this.tenuo)?.drain() ?? [];
  }

  acknowledgeReceipts(count: number): number {
    return hostCollector(this.tenuo)?.acknowledge(count) ?? 0;
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
      "createTenuo.runtime() requires at least one trusted root. Discovery stays in the hosted adapter.",
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
  return new Runtime(tenuo, options.identity, options.receipts === "collect");
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
