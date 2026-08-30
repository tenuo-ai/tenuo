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
