import type { Session as SessionContract } from "./api.ts";
import type { WasmSession } from "./wasm.ts";

const inspect = Symbol.for("nodejs.util.inspect.custom");
const nativeSessions = new WeakMap<Session, WasmSession>();

/**
 * Opaque session handle. Structural clones and JSON are not sessions.
 */
export class Session implements SessionContract {
  readonly [Symbol.toStringTag] = "TenuoSession" as const;

  constructor(native: WasmSession) {
    nativeSessions.set(this, native);
  }

  toJSON(): string {
    return "[TenuoSession]";
  }

  toString(): string {
    return "[TenuoSession]";
  }

  [inspect](): string {
    return "[TenuoSession]";
  }

  toWire(): string[] {
    const native = nativeSessions.get(this) as { toWire?: () => unknown } | undefined;
    if (native?.toWire === undefined) {
      throw new Error("session is not bound to the WASM core");
    }
    const tokens = native.toWire();
    if (!Array.isArray(tokens) || tokens.some((token) => typeof token !== "string")) {
      throw new Error("toWire() did not return warrant tokens");
    }
    return tokens;
  }
}

export function isSession(value: unknown): value is Session {
  return value instanceof Session;
}

export function nativeSession(session: Session): WasmSession {
  const native = nativeSessions.get(session);
  if (!native) {
    throw new Error("session is not bound to the WASM core");
  }
  return native;
}
