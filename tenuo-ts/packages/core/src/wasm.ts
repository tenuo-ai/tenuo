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
  /** Hex key the receipt is signed under — resolve against your authorizer set. */
  signer_key: string;
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
  /**
   * SHA-256 (hex) commitment to the canonical invocation this decision was
   * made over. Absent when the arguments could not be canonicalized — never
   * zero-filled, so absence is a claim rather than a value.
   */
  request_hash?: string;
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

export type WasmReceiptChain = {
  signer_key: string;
  outcome: "allow" | "deny";
  decision_code?: string;
  timestamp: number;
  /** The embedded chain verifies to a supplied root at the decision instant. */
  chain_valid: boolean;
  /** Canonical error name when it does not. */
  chain_error?: string;
  /**
   * Deny receipts only: the chain failure matches the stated decision_code,
   * so the embedded authority independently corroborates the refusal.
   */
  corroborates_denial?: boolean;
  root_issuer?: string;
  leaf_holder?: string;
};

export type WasmSession = object;

/** Mirrors `SessionInfoDto` in tenuo-wasm. Snake case is the WASM boundary. */
export type WasmSessionInfo = {
  kind: "execution" | "issuer";
  holder_public_key: string;
  root_public_key: string;
  depth: number;
  max_depth: number;
  terminal: boolean;
  expires_at: number;
  tools: string[];
  warrant_ids: string[];
  can_authorize: boolean;
  clearance?: number;
  session_id?: string;
  agent_id?: string;
  issuable_tools?: string[];
  max_issue_depth?: number;
  required_approvers?: string[];
  min_approvals?: number;
  approval_gated_tools: string[];
};

/** Security limits exported by tenuo-core; TypeScript must not redefine them. */
export type WasmProtocolLimits = {
  max_delegation_depth: number;
  max_warrant_ttl_seconds: number;
};

/** Mirrors `NarrowOptions` in tenuo-wasm. Unknown keys are rejected there. */
export type WasmNarrowOptions = {
  holder?: string;
  ttlSeconds?: number;
  terminal?: boolean;
  maxDepth?: number;
  clearance?: number | string;
  agentId?: string;
  addApprovers?: string[];
  minApprovals?: number;
};

export type WasmRequireApproval = {
  approvers: string[];
  min: number;
  tools?: string[];
  gates?: Record<string, { message?: string; args?: Record<string, unknown> }>;
};

/** Mirrors `MintOptions` in tenuo-wasm. */
export type WasmMintOptions = {
  kind?: "execution" | "issuer";
  allow?: unknown;
  ttlSeconds?: number;
  holder?: string;
  maxDepth?: number;
  clearance?: number | string;
  sessionId?: string;
  agentId?: string;
  requireApproval?: WasmRequireApproval;
  issuableTools?: string[];
  constraintBounds?: unknown;
  maxIssueDepth?: number;
};

/** Mirrors `IssueOptions` in tenuo-wasm. */
export type WasmIssueOptions = {
  allow: unknown;
  holder: string;
  ttlSeconds?: number;
  maxDepth?: number;
  clearance?: number | string;
  sessionId?: string;
  agentId?: string;
  requireApproval?: { approvers: string[]; min: number };
};

export type WasmExplainField = {
  field: string;
  kind: string;
  constraint: unknown;
  value?: unknown;
  satisfied: boolean;
  reason?: string;
};

export type WasmExplain = {
  tool: string;
  kind: "execution" | "issuer";
  outcome: "allow" | "deny";
  code?: TenuoErrorCode;
  field?: string;
  message?: string;
  tool_granted: boolean;
  fields: WasmExplainField[];
  unknown_fields: string[];
  missing_fields: string[];
  expired: boolean;
  expires_at: number;
  chain_valid: boolean;
  chain_error?: TenuoErrorCode;
};

export type WasmApprovalRequest = {
  request_id: string;
  warrant_id: string;
  tool: string;
  args: Record<string, unknown>;
  request_hash: string;
  holder_public_key: string;
  required_approvers: string[];
  min_approvals: number;
  warrant_expires_at: number;
  created_at: number;
  message: string;
};

export type WasmAttestation = {
  version: number;
  canonicalization: string;
  warrant_id: string;
  tool: string;
  request_hash: string;
  holder_key_hex: string;
  args_canonical_cbor_b64: string;
  signer_key_hex: string;
  signature_b64: string;
};

export type WasmApprovalInfo = {
  approver_public_key: string;
  request_hash: string;
  external_id: string;
  approved_at: number;
  expires_at: number;
  expired: boolean;
  signature_valid: boolean;
  error?: string;
};

export type WasmSrlInfo = {
  version: number;
  issued_at: number;
  issuer_public_key: string;
  revoked_ids: string[];
  signature_valid: boolean;
};

export type WasmContext = {
  mint(
    allow: unknown,
    ttlSeconds: number,
    requireApproval?: unknown,
    holderHex?: string,
    maxDepth?: number,
  ): WasmSession;
  mintExtended(options: WasmMintOptions): WasmSession;
  narrow(session: WasmSession, allow: unknown, options?: WasmNarrowOptions): WasmSession;
  issue(issuer: WasmSession, options: WasmIssueOptions): WasmSession;
  issuerPublicKey(): string;
  explain(session: WasmSession, tool: string, args: unknown): WasmExplain;
  approvalRequest(session: WasmSession, tool: string, args: unknown): WasmApprovalRequest;
  approvalContextAttestation(session: WasmSession, tool: string, args: unknown): WasmAttestation;
  signRevocationListVersioned(ids: string[], version?: number): string;
  authorize(
    session: WasmSession,
    tool: string,
    args: unknown,
    approvals?: unknown,
    toolAllow?: unknown,
    requestId?: string,
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
    requestId?: string,
  ): WasmDecision;
};

type Generated = {
  SdkContext: {
    new (): WasmContext;
    fromTrustedRoots(roots: string[]): WasmContext;
    fromIssuerSecret(secret: Uint8Array, extraRoots?: string[]): WasmContext;
  };
  SdkSession: {
    fromWire(warrant: string, holder: Uint8Array): WasmSession;
    fromParts(payloadHex: string, signatureHex: string, holder: Uint8Array): WasmSession;
    fromChain(parts: unknown, holder: Uint8Array): WasmSession;
  };
  sdkInspectWarrant(wire: string): WasmInspect;
  sdkInspectParts(payloadHex: string, signatureHex: string): WasmInspect;
  sdkProtocolLimits(): WasmProtocolLimits;
  sdkPublicKeyFromHolderKey(holderSecret: Uint8Array): string;
  sdkSignApproval(
    session: WasmSession,
    tool: string,
    args: unknown,
    approverSecret: Uint8Array,
    externalId: string,
    asOf?: number,
  ): string;
  sdkSignApprovalForRequest(
    requestHashHex: string,
    approverSecret: Uint8Array,
    externalId: string,
    ttlSeconds?: number,
    warrantExpiresAt?: number,
  ): string;
  sdkInspectApproval(envelope: string): WasmApprovalInfo;
  sdkSignRevocationList(ids: string[], issuerSecret: Uint8Array): string;
  sdkSignRevocationListVersioned(ids: string[], version: number | undefined, issuerSecret: Uint8Array): string;
  sdkSignPublishedRevocationList(ids: string[], version: number, issuerSecret: Uint8Array): string;
  sdkInspectRevocationList(wire: string): WasmSrlInfo;
  sdkVerifyReceipt(wire: string): WasmReceipt;
  sdkVerifyReceiptChain(wire: string, roots: string[]): WasmReceiptChain;
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

export function protocolLimits(): WasmProtocolLimits {
  return loadWasm().sdkProtocolLimits();
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

export function createIssuerContext(secret: Uint8Array, extraRootHexes: readonly string[]): WasmContext {
  const { SdkContext } = loadWasm();
  return SdkContext.fromIssuerSecret(secret, [...extraRootHexes]);
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

/** Hex public key for a 32-byte holder secret. Ed25519, derived in Rust. */
export function publicKeyHexFromHolderKey(holderSecret: Uint8Array): string {
  return loadWasm().sdkPublicKeyFromHolderKey(holderSecret);
}

export type ApprovalRequirementStatus = "not_gated" | "exempt" | "required" | "denied";

export type ApprovalRequirement = {
  status: ApprovalRequirementStatus;
  tool: string;
  kind?: "whole_tool" | "argument";
  argument?: string;
  arguments: string[];
  message?: string;
  code?: string;
  reason?: string;
};

export type ApprovalGateInspection = {
  kind: "none" | "whole_tool" | "conditional" | "unknown";
  tool: string;
  arguments: string[];
  message?: string;
};

type ApprovalWasm = {
  approval_requirement(
    warrantB64: string,
    tool: string,
    args: unknown,
  ): ApprovalRequirement & { error?: string };
  inspect_approval_gate(
    warrantB64: string,
    tool: string,
  ): ApprovalGateInspection & { error?: string };
  evaluate_approval_gates(
    warrantB64: string,
    tool: string,
    args: unknown,
  ): { approval_required: boolean; tool: string; error?: string };
};

function loadApprovalWasm(): ApprovalWasm {
  return loadWasm() as unknown as ApprovalWasm;
}

function throwIfGateError(error: string | undefined): void {
  if (error) {
    throw new TenuoConfigurationError(error);
  }
}

/**
 * Typed preflight of a warrant's approval gates for `(tool, args)`.
 *
 * Capability constraints are checked first. `denied` means the authorizer
 * will refuse the call — do not collect approval. Malformed encodings throw
 * (fail-closed).
 */
export function approvalRequirement(
  warrantB64: string,
  tool: string,
  args: Record<string, unknown>,
): ApprovalRequirement {
  const result = loadApprovalWasm().approval_requirement(warrantB64, tool, args);
  throwIfGateError(result.error);
  return result;
}

/** Inspect how a warrant gates `tool`, without evaluating arguments. */
export function inspectApprovalGate(warrantB64: string, tool: string): ApprovalGateInspection {
  const result = loadApprovalWasm().inspect_approval_gate(warrantB64, tool);
  throwIfGateError(result.error);
  return result;
}

/**
 * Boolean wrapper around {@link approvalRequirement}.
 * `true` iff the typed status is `required`.
 */
export function evaluateApprovalGates(
  warrantB64: string,
  tool: string,
  args: Record<string, unknown>,
): boolean {
  const result = loadApprovalWasm().evaluate_approval_gates(warrantB64, tool, args);
  throwIfGateError(result.error);
  return result.approval_required;
}
