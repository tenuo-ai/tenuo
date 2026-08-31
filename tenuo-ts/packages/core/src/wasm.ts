import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TenuoConfigurationError } from "./errors.ts";
import type { TenuoErrorCode } from "./api.ts";

export type WasmDecision = {
  outcome: "allow" | "deny" | "approval_required";
  code?: TenuoErrorCode;
  field?: string;
  message?: string;
  args?: Record<string, unknown>;
  tool?: string;
  required?: number;
  received?: number;
  receipt?: string;
};

export type WasmInspect = {
  payload_hex: string;
  signature_hex: string;
  id: string;
};

export type WasmReceipt = {
  authentic: true;
  outcome: "allow" | "deny";
  action: string;
  decision_code?: string;
  request_id: string;
  /** Version of the revocation list in force, when it carried one. */
  srl_version?: number;
  /**
   * SHA-256 (hex) of the revocation list bytes in force at decision time.
   * Absent means no revocation data was loaded — a different claim from a
   * loaded list that revoked nothing.
   */
  srl_hash?: string;
  /** SHA-256 (hex) of the host ceiling applied to this decision. */
  policy_definition_hash?: string;
  /**
   * SHA-256 (hex) of the previous receipt from this signer. Absent on the
   * first receipt, or when the deployment does not chain. A broken link means
   * a receipt was removed from the stream.
   */
  prev_receipt_hash?: string;
  /** SHA-256 (hex) of the trusted root set in force at decision time. */
  trusted_roots_hash?: string;
};

export type WasmSession = object;

export type WasmContext = {
  mint(allow: unknown, ttlSeconds: number, requireApproval?: unknown): WasmSession;
  narrow(session: WasmSession, allow: unknown): WasmSession;
  authorize(
    session: WasmSession,
    tool: string,
    args: unknown,
    approvals?: unknown,
    toolAllow?: unknown,
  ): WasmDecision;
  authorizeAsOf(
    session: WasmSession,
    tool: string,
    args: unknown,
    asOf: number,
    approvals?: unknown,
    toolAllow?: unknown,
  ): WasmDecision;
  loadRevocationList(srl: string): void;
  signRevocationList(ids: string[]): string;
  signPop(session: WasmSession, tool: string, args: unknown): string;
  authorizePresented(
    warrants: unknown,
    tool: string,
    args: unknown,
    pop: string,
    approvals?: unknown,
    toolAllow?: unknown,
  ): WasmDecision;
};

type Generated = {
  SdkContext: {
    new (): WasmContext;
    fromTrustedRoots(roots: string[]): WasmContext;
  };
  SdkSession: {
    fromWire(warrant: string, holder: Uint8Array): WasmSession;
    fromParts(payloadHex: string, signatureHex: string, holder: Uint8Array): WasmSession;
    fromChain(parts: unknown, holder: Uint8Array): WasmSession;
  };
  sdkInspectWarrant(wire: string): WasmInspect;
  sdkInspectParts(payloadHex: string, signatureHex: string): WasmInspect;
  sdkSignApproval(
    session: WasmSession,
    tool: string,
    args: unknown,
    approverSecret: Uint8Array,
    externalId: string,
    asOf?: number,
  ): string;
  sdkSignRevocationList(ids: string[], issuerSecret: Uint8Array): string;
  sdkSignPublishedRevocationList(ids: string[], version: number, issuerSecret: Uint8Array): string;
  sdkVerifyReceipt(wire: string): WasmReceipt;
};

let loaded: Generated | undefined;

function generatedPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "generated", "tenuo_wasm.js");
}

export function wasmAvailable(): boolean {
  return existsSync(generatedPath());
}

const WASM_LOAD_HINT =
  "WASM core is missing from this @tenuo/core install. @tenuo/core is Node 20+ only (not a bundler target). If this is Next.js/webpack, set serverExternalPackages: ['@tenuo/core']. Do not run wasm-pack in the consuming app.";

export function loadWasm(): Generated {
  if (loaded) {
    return loaded;
  }
  const path = generatedPath();
  if (!existsSync(path)) {
    throw new TenuoConfigurationError(WASM_LOAD_HINT, "TENUO_NOT_READY");
  }
  try {
    const require = createRequire(import.meta.url);
    loaded = require(path) as Generated;
    return loaded;
  } catch (error) {
    const wrapped = new TenuoConfigurationError(WASM_LOAD_HINT, "TENUO_NOT_READY");
    wrapped.cause = error;
    throw wrapped;
  }
}

export function createDevContext(): WasmContext {
  const { SdkContext } = loadWasm();
  return new SdkContext();
}

export function createVerifierContext(
  rootHexes: readonly string[],
  revocationList?: string,
): WasmContext {
  const { SdkContext } = loadWasm();
  const context = SdkContext.fromTrustedRoots([...rootHexes]);
  if (revocationList !== undefined && revocationList.length > 0) {
    context.loadRevocationList(revocationList);
  }
  return context;
}

export function importSessionFromWire(warrant: string, holderKey: Uint8Array): WasmSession {
  const { SdkSession } = loadWasm();
  return SdkSession.fromWire(warrant, holderKey);
}

export function importSessionFromParts(
  payloadHex: string,
  signatureHex: string,
  holderKey: Uint8Array,
): WasmSession {
  const { SdkSession } = loadWasm();
  return SdkSession.fromParts(payloadHex, signatureHex, holderKey);
}

export function importSessionFromChain(parts: unknown, holderKey: Uint8Array): WasmSession {
  const { SdkSession } = loadWasm();
  return SdkSession.fromChain(parts, holderKey);
}

export function inspectWarrant(wire: string): WasmInspect {
  return loadWasm().sdkInspectWarrant(wire);
}

export function inspectParts(payloadHex: string, signatureHex: string): WasmInspect {
  return loadWasm().sdkInspectParts(payloadHex, signatureHex);
}
