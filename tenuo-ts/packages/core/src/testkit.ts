/**
 * Non-exported test seam. Application code must not import this.
 * `asOf` is how published vectors replay a 2024 decision against today's clock.
 */
import type { Session as SessionContract } from "./api.ts";
import { Session, nativeSession } from "./session.ts";
import {
  createVerifierContext,
  importSessionFromChain,
  importSessionFromParts,
  importSessionFromWire,
  inspectParts,
  inspectWarrant,
  type WasmContext,
  type WasmDecision,
  type WasmInspect,
} from "./wasm.ts";

export type { WasmDecision, WasmInspect };

export function verifierContext(rootHexes: readonly string[]): WasmContext {
  return createVerifierContext(rootHexes);
}

export function sessionFromWire(warrant: string, holderKey: Uint8Array): Session {
  return new Session(importSessionFromWire(warrant, holderKey));
}

export function sessionFromParts(
  payloadHex: string,
  signatureHex: string,
  holderKey: Uint8Array,
): Session {
  return new Session(importSessionFromParts(payloadHex, signatureHex, holderKey));
}

export function sessionFromChain(
  parts: ReadonlyArray<string | { payload_hex: string; signature_hex: string }>,
  holderKey: Uint8Array,
): Session {
  return new Session(importSessionFromChain(parts, holderKey));
}

export function authorizeAsOf(
  context: WasmContext,
  session: Session,
  tool: string,
  args: unknown,
  asOf: number,
): WasmDecision {
  return context.authorizeAsOf(nativeSession(session), tool, args, asOf);
}

export type ExportedSession = {
  warrants: string[];
  holder_hex: string;
  root_hex: string;
};

/** Test / interop seam. Application Session stays opaque. */
export function exportSession(session: SessionContract): ExportedSession {
  const native = nativeSession(session as Session) as { exportWire(): ExportedSession };
  return native.exportWire();
}

export { inspectParts, inspectWarrant };
