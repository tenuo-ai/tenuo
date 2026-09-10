import type { PublicKeyHandle } from "./api.ts";
import { TenuoConfigurationError } from "./errors.ts";
import { loadWasm, publicKeyHexFromHolderKey } from "./wasm.ts";

const inspect = Symbol.for("nodejs.util.inspect.custom");
const secrets = new WeakMap<HolderIdentity, Uint8Array>();

/**
 * Holder keypair. Core owns the representation; persistence is the caller's
 * job (or a later Node adapter). The secret never appears in stringification,
 * inspection, or JSON.
 */
export class HolderIdentity {
  readonly publicKey: PublicKeyHandle;

  constructor(holderKey: Uint8Array) {
    if (!(holderKey instanceof Uint8Array) || holderKey.length !== 32) {
      throw new TenuoConfigurationError("HolderIdentity requires a 32-byte holder key");
    }
    loadWasm();
    secrets.set(this, new Uint8Array(holderKey));
    this.publicKey = {
      kind: "public-key",
      source: "bytes",
      hex: publicKeyHexFromHolderKey(holderKey),
    };
  }

  /** Copy of the 32-byte Ed25519 secret. */
  get holderKey(): Uint8Array {
    const secret = secrets.get(this);
    if (secret === undefined) {
      throw new TenuoConfigurationError("identity is not bound to a holder key");
    }
    return new Uint8Array(secret);
  }

  toJSON(): { readonly publicKey: string } {
    return { publicKey: this.publicKey.hex };
  }

  toString(): string {
    return `TenuoIdentity(${this.publicKey.hex.slice(0, 8)}…)`;
  }

  [inspect](): { readonly publicKey: string } {
    return this.toJSON();
  }
}

/** Import a 32-byte holder secret. */
export function identityFromKey(holderKey: Uint8Array): HolderIdentity {
  if (!(holderKey instanceof Uint8Array) || holderKey.length !== 32) {
    throw new TenuoConfigurationError("identity() requires a 32-byte holder key");
  }
  loadWasm();
  return new HolderIdentity(holderKey);
}

/** Fresh holder identity. Uses Web Crypto; does not touch the filesystem. */
export function generateIdentity(): HolderIdentity {
  return identityFromKey(randomSecret());
}

function randomSecret(): Uint8Array {
  const cryptoObj = globalThis.crypto;
  if (cryptoObj === undefined || typeof cryptoObj.getRandomValues !== "function") {
    throw new TenuoConfigurationError(
      "generateIdentity() needs Web Crypto (globalThis.crypto.getRandomValues).",
    );
  }
  return cryptoObj.getRandomValues(new Uint8Array(32));
}
