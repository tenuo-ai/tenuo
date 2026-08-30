import type { Session as SessionContract } from "./api.ts";

const inspect = Symbol.for("nodejs.util.inspect.custom");

/**
 * Opaque session handle. A warrant + holder key will live behind this once
 * WASM is wired. Structural clones and JSON are not sessions.
 */
export class Session implements SessionContract {
  readonly [Symbol.toStringTag] = "TenuoSession" as const;

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
