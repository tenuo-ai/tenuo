/**
 * Non-exported test seam. Application code must not import this.
 * `asOf` is how published vectors replay a 2024 decision against today's clock.
 */
import type { Session as SessionContract } from "./api.ts";
import { Session, nativeSession } from "./session.ts";
import type { WasmSession } from "./wasm.ts";
import {
  createDevContext,
  createVerifierContext,
  importSessionFromChain,
  importSessionFromParts,
  importSessionFromWire,
  inspectParts,
  inspectWarrant,
  loadWasm,
  type WasmContext,
  type WasmDecision,
  type WasmInspect,
  type WasmReceipt,
} from "./wasm.ts";

export type { WasmDecision, WasmInspect, WasmReceipt };

export function devContext(): WasmContext {
  return createDevContext();
}

export function verifierContext(
  rootHexes: readonly string[],
  options?: { revocationList?: string },
): WasmContext {
  return createVerifierContext(rootHexes, options?.revocationList);
}

export function wrapSession(native: WasmSession): Session {
  return new Session(native);
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
  session: SessionContract,
  tool: string,
  args: unknown,
  asOf: number,
  approvals?: unknown,
  toolAllow?: unknown,
): WasmDecision {
  return context.authorizeAsOf(
    nativeSession(session as Session),
    tool,
    args,
    asOf,
    approvals,
    toolAllow,
  );
}

/** Signs a SignedApproval envelope. Does not authorize. */
export function signApproval(
  session: SessionContract,
  tool: string,
  args: unknown,
  approverSecret: Uint8Array,
  options?: { externalId?: string; asOf?: number },
): string {
  return loadWasm().sdkSignApproval(
    nativeSession(session as Session),
    tool,
    args,
    approverSecret,
    options?.externalId ?? "test-approver",
    options?.asOf,
  );
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

/** Warrant IDs, root first. */
export function warrantIds(session: SessionContract): string[] {
  const native = nativeSession(session as Session) as { warrantIds(): unknown };
  const ids = native.warrantIds();
  if (!Array.isArray(ids) || ids.some((id) => typeof id !== "string")) {
    throw new Error("warrantIds() did not return warrant ids");
  }
  return ids;
}

/** Signs an SRL with the context issuer (devRoot) or a provided secret. Does not authorize. */
export function signRevocationList(
  issuer: WasmContext | Uint8Array,
  ids: readonly string[],
): string {
  if (issuer instanceof Uint8Array) {
    return loadWasm().sdkSignRevocationList([...ids], issuer);
  }
  return issuer.signRevocationList([...ids]);
}

/** Signs the published generator SRL envelope. Does not load it. */
export function signPublishedRevocationList(
  issuerSecret: Uint8Array,
  ids: readonly string[],
  version: number,
): string {
  return loadWasm().sdkSignPublishedRevocationList([...ids], version, issuerSecret);
}

/** Signature authenticity only. Not authorization. */
export function verifyReceipt(wire: string): WasmReceipt {
  return loadWasm().sdkVerifyReceipt(wire);
}

export { inspectParts, inspectWarrant };
