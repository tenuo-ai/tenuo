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
};

export type WasmSession = object;

export type WasmContext = {
  mint(allow: unknown, ttlSeconds: number, requireApproval?: unknown): WasmSession;
  narrow(session: WasmSession, allow: unknown): WasmSession;
  authorize(session: WasmSession, tool: string, args: unknown, approvals?: unknown): WasmDecision;
  authorizeAsOf(
    session: WasmSession,
    tool: string,
    args: unknown,
    asOf: number,
    approvals?: unknown,
  ): WasmDecision;
  loadRevocationList(srl: string): void;
  signRevocationList(ids: string[]): string;
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

export function loadWasm(): Generated {
  if (loaded) {
    return loaded;
  }
  const path = generatedPath();
  if (!existsSync(path)) {
    throw new TenuoConfigurationError(
      "WASM core is not built. From tenuo-ts run: pnpm build:wasm",
      "TENUO_NOT_READY",
    );
  }
  const require = createRequire(import.meta.url);
  loaded = require(path) as Generated;
  return loaded;
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
