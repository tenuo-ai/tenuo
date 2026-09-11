import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import type {
  AllowPolicy,
  ApprovalContextAttestation,
  ApprovalInfo,
  ApprovalRequest,
  Clearance,
  ControlPlaneApprovalRequestV1,
  ControlPlaneApprovalResponseV1,
  CreateTenuoOptions,
  DevRoot,
  Explanation,
  IssueInput,
  IssuerKey,
  McpAttachOptions,
  McpVerifyOptions,
  NarrowInput,
  NarrowOptions,
  PresentedCall,
  ProtectedTool,
  PublicKeyHandle,
  ReceiptChainInfo,
  ReceiptInfo,
  RequireApproval,
  RevocationListInfo,
  RevocationListInput,
  SessionFromWireInput,
  SessionInput,
  SignApprovalOptions,
  Tenuo,
  TenuoErrorCode,
  TenuoMcp,
  ToolPolicy,
} from "./api.ts";
import { parseConnectToken } from "./connect.ts";
import { generateIdentity, identityFromKey } from "./identity.ts";
import { createMcp, presentCall, verifyPresented, type Decide } from "./mcp.ts";
import { collectReceipt, emitIsolatedReceipt, inheritSessionCollector } from "./receipts.ts";
import { createRuntime } from "./runtime.ts";
import { AuthorizationDeniedError, ApprovalRequiredError, TenuoConfigurationError, TenuoError } from "./errors.ts";
import { Session, isSession, nativeSession } from "./session.ts";
import {
  createDevContext,
  createIssuerContext,
  createVerifierContext,
  importSessionFromChain,
  importSessionFromWire,
  loadWasm,
  protocolLimits,
  publicKeyHexFromHolderKey,
  type WasmApprovalRequest,
  type WasmAttestation,
  type WasmContext,
  type WasmExplain,
  type WasmIssueOptions,
  type WasmMintOptions,
  type WasmNarrowOptions,
  type WasmRequireApproval,
} from "./wasm.ts";

const currentSession = new AsyncLocalStorage<Session>();
const toolPolicies = new WeakMap<object, { capability: string; allow: AllowPolicy }>();
const wrappedInners = new WeakSet<object>();

const CLEARANCE_NAMES = new Set(["untrusted", "external", "partner", "internal", "privileged", "system"]);

function nodeEnv(): string | undefined {
  if (typeof process === "undefined") {
    return undefined;
  }
  return process.env.NODE_ENV;
}

function allowDev(): boolean {
  if (typeof process === "undefined") {
    return false;
  }
  return process.env.TENUO_ALLOW_DEV === "1";
}

export function devRoot(options?: { readonly allowInProduction?: boolean }): DevRoot {
  const root: DevRoot = {
    kind: "dev-root",
    ...(options?.allowInProduction === true ? { allowInProduction: true } : {}),
  };
  if (!devRootAllowed(root)) {
    throw new TenuoConfigurationError(devRootBlockedMessage());
  }
  return root;
}

function devRootAllowed(root: DevRoot): boolean {
  if (root.allowInProduction === true || allowDev()) {
    return true;
  }
  const env = nodeEnv();
  return env === "development" || env === "test";
}

function devRootBlockedMessage(): string {
  return "createTenuo.devRoot() is for development. Set NODE_ENV=development or test, pass devRoot({ allowInProduction: true }), or TENUO_ALLOW_DEV=1. Unset NODE_ENV is not treated as development.";
}

function normalizeHex(value: string): string {
  const hex = value.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new TenuoConfigurationError(
      "Trusted root must be a 32-byte hex public key (64 hex characters)",
    );
  }
  return hex;
}

function envValue(name: string, what: string): string {
  if (name.length === 0) {
    throw new TenuoConfigurationError(`${what} requires an environment variable name`);
  }
  if (typeof process === "undefined") {
    throw new TenuoConfigurationError(
      `Environment variable ${name} is not available. Tenuo fails closed without a ${what}.`,
    );
  }
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new TenuoConfigurationError(
      `Environment variable ${name} is not set or empty. Tenuo fails closed without a ${what}.`,
    );
  }
  return value;
}

export function publicKeyFromEnv(name: string): PublicKeyHandle {
  return { kind: "public-key", source: "env", hex: normalizeHex(envValue(name, "trusted root")) };
}

export function publicKeyFromHex(hex: string): PublicKeyHandle {
  return { kind: "public-key", source: "hex", hex: normalizeHex(hex) };
}

export function publicKeyFromBytes(bytes: Uint8Array): PublicKeyHandle {
  if (bytes.length !== 32) {
    throw new TenuoConfigurationError("publicKeyFromBytes() requires a 32-byte public key");
  }
  return { kind: "public-key", source: "bytes", hex: bytesToHex(bytes) };
}

function normalizeSecretHex(value: string, what: string): string {
  const hex = value.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new TenuoConfigurationError(`${what} must be a 32-byte hex secret (64 hex characters)`);
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function holderKeyFromEnv(name: string): Uint8Array {
  return hexToBytes(normalizeSecretHex(envValue(name, "holder key"), "Holder key"));
}

export function holderKeyFromHex(hex: string): Uint8Array {
  return hexToBytes(normalizeSecretHex(hex, "Holder key"));
}

/**
 * A fresh 32-byte Ed25519 secret. One per agent, kept in that agent's
 * process; only its public key (see `publicKeyFromHolderKey`) travels.
 */
export function generateHolderKey(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

/** Same shape as a holder key. Named separately so a control plane's key reads as one. */
export function generateIssuerKey(): Uint8Array {
  return generateHolderKey();
}

/** The public half of a holder or issuer secret. */
export function publicKeyFromHolderKey(holderKey: Uint8Array): PublicKeyHandle {
  if (!(holderKey instanceof Uint8Array) || holderKey.length !== 32) {
    throw new TenuoConfigurationError("publicKeyFromHolderKey() requires a 32-byte holder key");
  }
  loadWasm();
  return { kind: "public-key", source: "bytes", hex: publicKeyHexFromHolderKey(holderKey) };
}

const MAX_WASM_U32 = 0xffff_ffff;

function requireUint32(value: number, name: string, minimum = 0): number {
  if (!Number.isInteger(value) || value < minimum || value > MAX_WASM_U32) {
    throw new TenuoConfigurationError(
      `${name} must be an integer between ${minimum} and ${MAX_WASM_U32}`,
    );
  }
  return value;
}

/** Stable control-plane key from the environment. This process becomes an issuer. */
export function issuerKeyFromEnv(name: string): IssuerKey {
  return { kind: "issuer-key", secret: hexToBytes(normalizeSecretHex(envValue(name, "issuer key"), "Issuer key")) };
}

export function issuerKeyFromHex(hex: string): IssuerKey {
  return { kind: "issuer-key", secret: hexToBytes(normalizeSecretHex(hex, "Issuer key")) };
}

export function issuerKeyFromBytes(secret: Uint8Array): IssuerKey {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) {
    throw new TenuoConfigurationError("issuerKeyFromBytes() requires a 32-byte secret");
  }
  return { kind: "issuer-key", secret: new Uint8Array(secret) };
}

function requireDepth(value: number, name: string): number {
  requireUint32(value, name);
  const maximum = protocolLimits().max_delegation_depth;
  if (value > maximum) {
    throw new TenuoConfigurationError(
      `${name} ${value} exceeds the protocol maximum of ${maximum}`,
    );
  }
  return value;
}

function requireTtl(value: number, name: string, minimum = 0): number {
  requireUint32(value, name, minimum);
  const maximum = protocolLimits().max_warrant_ttl_seconds;
  if (value > maximum) {
    throw new TenuoConfigurationError(
      `${name} ${value} exceeds the protocol maximum of ${maximum}`,
    );
  }
  return value;
}

function requirePublicKey(value: unknown, name: string): PublicKeyHandle {
  if (
    value === null ||
    typeof value !== "object" ||
    (value as { kind?: unknown }).kind !== "public-key" ||
    typeof (value as { hex?: unknown }).hex !== "string"
  ) {
    throw new TenuoConfigurationError(
      `${name} must be a public key handle (createTenuo.publicKeyFromHolderKey / publicKeyFromHex / publicKeyFromEnv)`,
    );
  }
  return value as PublicKeyHandle;
}

function clearanceJson(value: Clearance, name: string): number | string {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      throw new TenuoConfigurationError(`${name} must be an integer 0-255 or a level name`);
    }
    return value;
  }
  if (typeof value === "string" && CLEARANCE_NAMES.has(value)) {
    return value;
  }
  throw new TenuoConfigurationError(
    `${name} must be one of ${[...CLEARANCE_NAMES].join(", ")} or an integer 0-255`,
  );
}

function rootHexes(options: CreateTenuoOptions): string[] {
  const handles: PublicKeyHandle[] = [];
  if (options.root !== undefined && options.root.kind === "public-key") {
    handles.push(options.root);
  }
  for (const root of options.trustedRoots ?? []) {
    handles.push(root);
  }
  return handles.map((h) => h.hex);
}

function hasTrustAnchor(options: CreateTenuoOptions): boolean {
  if (options.root !== undefined) {
    return true;
  }
  return (options.trustedRoots?.length ?? 0) > 0;
}

function capabilityName(inner: object, policy: Pick<ToolPolicy, "capability">): string {
  if (policy.capability !== undefined && policy.capability.length > 0) {
    return policy.capability;
  }
  const named = inner as { name?: unknown; id?: unknown };
  if (typeof named.name === "string" && named.name.length > 0) {
    return named.name;
  }
  if (typeof named.id === "string" && named.id.length > 0) {
    return named.id;
  }
  throw new TenuoConfigurationError(
    "tenuo.tool() needs a capability name (policy.capability, or tool.name / tool.id)",
  );
}

class TenuoClient implements Tenuo {
  private readonly context: WasmContext;
  private readonly canMint: boolean;
  readonly mcp: TenuoMcp;
  private readonly decide: Decide;

  constructor(options: CreateTenuoOptions) {
    if (options.root?.kind === "dev-root") {
      this.context = createDevContext();
      this.canMint = true;
    } else if (options.root?.kind === "issuer-key") {
      if (!(options.root.secret instanceof Uint8Array) || options.root.secret.length !== 32) {
        throw new TenuoConfigurationError("root: issuer key must be a 32-byte secret");
      }
      this.context = createIssuerContext(options.root.secret, rootHexes(options));
      this.canMint = true;
    } else {
      this.context = createVerifierContext(
        rootHexes(options),
        undefined,
        options.receiptSigner,
      );
      this.canMint = false;
    }
    if (options.revocationList !== undefined) {
      this.context.loadRevocationList(normalizeWireBytes(options.revocationList));
    }
    this.decide = (decision, tool, native, args) => {
      this.applyDecision(decision, tool, native, args);
    };
    this.mcp = createMcp(this.context, this.decide, this);
  }

  private applyDecision(
    decision: { outcome: string; code?: string; field?: string; message?: string; tool?: string; required?: number; received?: number },
    tool: string,
    native?: object,
    args?: Record<string, unknown>,
  ): void {
    if (decision.outcome === "allow") {
      return;
    }
    if (decision.outcome === "approval_required") {
      let request: ApprovalRequest | undefined;
      if (native !== undefined && args !== undefined) {
        try {
          request = approvalRequestFromWasm(this.context.approvalRequest(native, tool, args));
        } catch {
          request = undefined;
        }
      }
      throw new ApprovalRequiredError(
        decision.tool ?? tool,
        decision.required ?? 1,
        decision.received ?? 0,
        decision.message,
        request,
      );
    }
    throw new AuthorizationDeniedError(
      (decision.code as TenuoErrorCode | undefined) ?? "TENUO_TOOL_NOT_AUTHORIZED",
      explainDeny(decision.message ?? "Authorization denied", decision.field),
      decision.field,
    );
  }

  tool<T extends { execute: (args: never) => unknown }>(
    inner: T,
    policy: ToolPolicy<Parameters<T["execute"]>[0]>,
  ): ProtectedTool<T> {
    if (toolPolicies.has(inner) || wrappedInners.has(inner)) {
      throw new TenuoConfigurationError("tenuo.tool() already wrapped this tool");
    }
    const capability = capabilityName(inner, policy);
    const original = inner.execute as (
      args: Record<string, unknown>,
      options?: unknown,
    ) => unknown;
    const execute = async (args: never, callOptions?: unknown) => {
      const session = resolveSession(callOptions);
      const native = nativeSession(session);
      const decision = this.context.authorize(
        native,
        capability,
        args,
        approvalsFrom(callOptions),
        policy.allow,
        requestIdFrom(callOptions),
      );
      emitReceipt(callOptions, decision.receipt, session, this);
      if (decision.outcome === "allow") {
        return original(plainArgs(decision.args), forwardExecuteOptions(callOptions));
      }
      this.applyDecision(decision, capability, native, plainArgs(args));
      throw new TenuoConfigurationError("unreachable: decision was neither allow nor deny");
    };

    const wrapped = Object.assign(Object.create(Object.getPrototypeOf(inner)), inner, {
      execute,
    }) as ProtectedTool<T>;
    wrappedInners.add(inner);
    toolPolicies.set(wrapped, { capability, allow: { ...policy.allow } as AllowPolicy });
    return wrapped;
  }

  session(input: SessionInput): Session {
    const allow = collectSessionAllow(input);
    const kind = input.kind ?? "execution";
    if (kind !== "execution" && kind !== "issuer") {
      throw new TenuoConfigurationError('session().kind must be "execution" or "issuer"');
    }
    if (Object.keys(allow).length === 0 && kind === "execution") {
      throw new TenuoConfigurationError(
        "tenuo.session() requires tools from tenuo.tool() or at least one capability in allow",
      );
    }
    if (!this.canMint) {
      throw new TenuoConfigurationError(
        "session() mints a warrant and needs a local issuer. Use createTenuo({ root: createTenuo.devRoot() }) or an issuer key.",
      );
    }
    const options: WasmMintOptions = { kind, allow };
    if (input.ttlSeconds !== undefined) {
      options.ttlSeconds = requireTtl(input.ttlSeconds, "session().ttlSeconds");
    }
    if (input.holder !== undefined) {
      options.holder = requirePublicKey(input.holder, "session().holder").hex;
    }
    if (input.maxDepth !== undefined) {
      options.maxDepth = requireDepth(input.maxDepth, "session().maxDepth");
    }
    if (input.clearance !== undefined) {
      options.clearance = clearanceJson(input.clearance, "session().clearance");
    }
    if (input.sessionId !== undefined) {
      options.sessionId = requireLabel(input.sessionId, "session().sessionId");
    }
    if (input.agentId !== undefined) {
      options.agentId = requireLabel(input.agentId, "session().agentId");
    }
    if (input.requireApproval !== undefined) {
      options.requireApproval = requireApprovalJson(input.requireApproval);
    }
    if (input.issuableTools !== undefined) {
      options.issuableTools = [...input.issuableTools];
    }
    if (input.constraintBounds !== undefined) {
      options.constraintBounds = input.constraintBounds;
    }
    if (input.maxIssueDepth !== undefined) {
      options.maxIssueDepth = requireDepth(input.maxIssueDepth, "session().maxIssueDepth");
    }
    try {
      return new Session(this.context.mintExtended(options));
    } catch (error) {
      throw new TenuoConfigurationError(errorMessage(error));
    }
  }

  issue(issuer: Session, input: IssueInput): Session {
    if (!isSession(issuer)) {
      throw new TenuoConfigurationError("issue() requires a Tenuo Session, not a plain object");
    }
    if (input === null || typeof input !== "object" || input.allow === undefined || Object.keys(input.allow).length === 0) {
      throw new TenuoConfigurationError("issue() requires at least one capability in allow");
    }
    const options: WasmIssueOptions = {
      allow: input.allow,
      holder: requirePublicKey(input.holder, "issue().holder").hex,
    };
    if (input.ttlSeconds !== undefined) {
      options.ttlSeconds = requireTtl(input.ttlSeconds, "issue().ttlSeconds", 1);
    }
    if (input.maxDepth !== undefined) {
      options.maxDepth = requireDepth(input.maxDepth, "issue().maxDepth");
    }
    if (input.clearance !== undefined) {
      options.clearance = clearanceJson(input.clearance, "issue().clearance");
    }
    if (input.sessionId !== undefined) {
      options.sessionId = requireLabel(input.sessionId, "issue().sessionId");
    }
    if (input.agentId !== undefined) {
      options.agentId = requireLabel(input.agentId, "issue().agentId");
    }
    if (input.requireApproval !== undefined) {
      options.requireApproval = requireApprovalJson(input.requireApproval);
    }
    try {
      return new Session(this.context.issue(nativeSession(issuer), options));
    } catch (error) {
      throw chainError(error);
    }
  }

  issuerPublicKey(): PublicKeyHandle {
    if (!this.canMint) {
      throw new TenuoConfigurationError(
        "issuerPublicKey() needs a local issuer. This context verifies against trustedRoots and does not mint.",
      );
    }
    return { kind: "public-key", source: "bytes", hex: this.context.issuerPublicKey() };
  }

  sessionFromWire(input: SessionFromWireInput): Session {
    if (!(input.holderKey instanceof Uint8Array) || input.holderKey.length !== 32) {
      throw new TenuoConfigurationError("sessionFromWire() requires a 32-byte holderKey");
    }
    if (typeof input.warrant === "string" && input.warrant.trim().length === 0) {
      throw new TenuoConfigurationError("sessionFromWire() requires a warrant");
    }
    try {
      if (typeof input.warrant === "string") {
        return new Session(importSessionFromWire(input.warrant, input.holderKey));
      }
      if (input.warrant.length === 0) {
        throw new TenuoConfigurationError("sessionFromWire() requires a warrant");
      }
      return new Session(importSessionFromChain([...input.warrant], input.holderKey));
    } catch (error) {
      throw importWireError(error);
    }
  }

  withSession<R>(session: Session, fn: () => R): R {
    if (!isSession(session)) {
      throw new TenuoConfigurationError("withSession() requires a Tenuo Session, not a plain object");
    }
    return currentSession.run(session, fn);
  }

  narrow(session: Session, allow: NarrowInput, options?: NarrowOptions): Session {
    if (Object.keys(allow).length === 0) {
      throw new TenuoConfigurationError("tenuo.narrow() requires a non-empty allow policy");
    }
    if (!isSession(session)) {
      throw new TenuoConfigurationError("narrow() requires a Tenuo Session, not a plain object");
    }
    const native = options === undefined ? undefined : narrowOptionsJson(options);
    try {
      const child = new Session(this.context.narrow(nativeSession(session), allow, native));
      inheritSessionCollector(session, child);
      return child;
    } catch (error) {
      throw chainError(error);
    }
  }

  explain(session: Session, tool: string, args: Readonly<Record<string, unknown>>): Explanation {
    if (!isSession(session)) {
      throw new TenuoConfigurationError("explain() requires a Tenuo Session, not a plain object");
    }
    let raw: WasmExplain;
    try {
      raw = this.context.explain(nativeSession(session), tool, args);
    } catch (error) {
      throw new TenuoConfigurationError(errorMessage(error));
    }
    const out: { -readonly [K in keyof Explanation]: Explanation[K] } = {
      tool: raw.tool,
      kind: raw.kind,
      outcome: raw.outcome,
      toolGranted: raw.tool_granted,
      fields: raw.fields.map((f) => {
        const field: { -readonly [K in keyof Explanation["fields"][number]]: Explanation["fields"][number][K] } = {
          field: f.field,
          kind: f.kind,
          constraint: f.constraint,
          satisfied: f.satisfied,
        };
        if (f.value !== undefined) {
          field.value = f.value;
        }
        if (f.reason !== undefined) {
          field.reason = f.reason;
        }
        return field;
      }),
      unknownFields: [...raw.unknown_fields],
      missingFields: [...raw.missing_fields],
      expired: raw.expired,
      expiresAt: raw.expires_at,
      chainValid: raw.chain_valid,
    };
    if (raw.code !== undefined) {
      out.code = raw.code;
    }
    if (raw.field !== undefined) {
      out.field = raw.field;
    }
    if (raw.message !== undefined) {
      out.message = raw.message;
    }
    if (raw.chain_error !== undefined) {
      out.chainError = raw.chain_error;
    }
    return out;
  }

  approvalRequest(session: Session, tool: string, args: Readonly<Record<string, unknown>>): ApprovalRequest {
    if (!isSession(session)) {
      throw new TenuoConfigurationError("approvalRequest() requires a Tenuo Session, not a plain object");
    }
    try {
      return approvalRequestFromWasm(this.context.approvalRequest(nativeSession(session), tool, args));
    } catch (error) {
      throw new TenuoConfigurationError(errorMessage(error));
    }
  }

  attestApprovalRequest(
    session: Session,
    tool: string,
    args: Readonly<Record<string, unknown>>,
  ): ApprovalContextAttestation {
    if (!isSession(session)) {
      throw new TenuoConfigurationError("attestApprovalRequest() requires a Tenuo Session, not a plain object");
    }
    let raw: WasmAttestation;
    try {
      raw = this.context.approvalContextAttestation(nativeSession(session), tool, args);
    } catch (error) {
      throw new TenuoConfigurationError(errorMessage(error));
    }
    return {
      version: raw.version,
      canonicalization: raw.canonicalization,
      warrantId: raw.warrant_id,
      tool: raw.tool,
      requestHash: raw.request_hash,
      holderKeyHex: raw.holder_key_hex,
      argsCanonicalCborB64: raw.args_canonical_cbor_b64,
      signerKeyHex: raw.signer_key_hex,
      signatureB64: raw.signature_b64,
    };
  }

  present(
    session: Session,
    tool: string,
    args: Readonly<Record<string, unknown>>,
    options?: McpAttachOptions,
  ): PresentedCall {
    if (!isSession(session)) {
      throw new TenuoConfigurationError("present() requires a Tenuo Session, not a plain object");
    }
    return presentCall(this.context, this.decide, session, tool, args, options, "present()", this)
      .presented;
  }

  verify(
    presented: PresentedCall,
    tool: string,
    args: Readonly<Record<string, unknown>>,
    options?: McpVerifyOptions,
  ): Promise<Readonly<Record<string, unknown>>> {
    return verifyPresented(
      this.context,
      this.decide,
      presented,
      tool,
      args,
      options,
      "verify()",
      this,
    );
  }

  revocationList(input: RevocationListInput): string {
    if (!this.canMint) {
      throw new TenuoConfigurationError(
        "revocationList() needs a local issuer key. Use createTenuo.signRevocationList() with an explicit secret, or an issuer-key root.",
      );
    }
    const { ids, version } = revocationInput(input);
    try {
      return this.context.signRevocationListVersioned(ids, version);
    } catch (error) {
      throw new TenuoConfigurationError(errorMessage(error));
    }
  }

  revoke(list: string | Uint8Array): void {
    this.context.loadRevocationList(normalizeWireBytes(list));
  }

  ready(): void {
    loadWasm();
  }
}

function requireLabel(value: string, name: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TenuoConfigurationError(`${name} must be a non-empty string`);
  }
  return value;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Map a prefixed core message from narrow()/issue() to the matching error class. */
function chainError(error: unknown): TenuoError {
  if (error instanceof TenuoError) {
    return error;
  }
  const message = explainChainFailure(errorMessage(error));
  for (const code of ["TENUO_CHAIN_INVALID", "TENUO_DEPTH_EXCEEDED", "TENUO_WARRANT_EXPIRED"] as const) {
    if (message.startsWith(code)) {
      return new AuthorizationDeniedError(code, message);
    }
  }
  return new TenuoConfigurationError(message);
}

function explainChainFailure(message: string): string {
  const tool = /tool '([^']+)' not in parent's tools/.exec(message)?.[1];
  if (tool !== undefined) {
    return `${message}. narrow() cannot add '${tool}': remove it or delegate from a parent that grants it.`;
  }
  if (
    message.includes("parent's allowed set") ||
    message.includes("range expanded") ||
    message.includes("would expand permissions") ||
    message.includes("clearance cannot increase")
  ) {
    return `${message}. narrow() only accepts a child policy that is equal to or stricter than its parent.`;
  }
  return message;
}

function revocationInput(input: RevocationListInput): { ids: string[]; version: number | undefined } {
  if (input === null || typeof input !== "object" || !Array.isArray(input.revoke)) {
    throw new TenuoConfigurationError("revocation list input must be { revoke: string[], version? }");
  }
  const ids = input.revoke.filter((id): id is string => typeof id === "string" && id.length > 0);
  if (ids.length === 0 || ids.length !== input.revoke.length) {
    throw new TenuoConfigurationError("revoke must be a non-empty array of warrant ids");
  }
  if (input.version !== undefined && (!Number.isInteger(input.version) || input.version < 1)) {
    throw new TenuoConfigurationError("revocation list version must be a positive integer");
  }
  return { ids, version: input.version };
}

function plainArgs(value: unknown): Record<string, unknown> {
  if (value instanceof Map) {
    return Object.fromEntries(value);
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return { ...(value as Record<string, unknown>) };
  }
  return {};
}

function requireApprovalJson(require: RequireApproval): WasmRequireApproval {
  if (require === null || typeof require !== "object") {
    throw new TenuoConfigurationError("requireApproval must be an object");
  }
  if (!Array.isArray(require.approvers) || require.approvers.length === 0) {
    throw new TenuoConfigurationError("requireApproval.approvers must not be empty");
  }
  if (!Number.isInteger(require.min) || require.min < 1) {
    throw new TenuoConfigurationError("requireApproval.min must be at least 1");
  }
  const payload: WasmRequireApproval = {
    approvers: require.approvers.map((approver, i) => requirePublicKey(approver, `requireApproval.approvers[${i}]`).hex),
    min: require.min,
  };
  if (require.tools !== undefined) {
    payload.tools = [...require.tools];
  }
  if (require.gates !== undefined) {
    const gates: NonNullable<WasmRequireApproval["gates"]> = {};
    for (const [tool, gate] of Object.entries(require.gates)) {
      const out: { message?: string; args?: Record<string, unknown> } = {};
      if (gate.message !== undefined) {
        out.message = gate.message;
      }
      if (gate.args !== undefined) {
        out.args = { ...gate.args };
      }
      gates[tool] = out;
    }
    payload.gates = gates;
  }
  return payload;
}

function narrowOptionsJson(options: NarrowOptions): WasmNarrowOptions {
  if (options === null || typeof options !== "object") {
    throw new TenuoConfigurationError("narrow() options must be an object");
  }
  const known = ["holder", "ttlSeconds", "terminal", "maxDepth", "clearance", "agentId", "addApprovers", "minApprovals"];
  for (const key of Object.keys(options)) {
    if (!known.includes(key)) {
      throw new TenuoConfigurationError(
        `narrow() options: unknown key '${key}' (expected ${known.join(", ")})`,
      );
    }
  }
  const out: WasmNarrowOptions = {};
  if (options.holder !== undefined) {
    out.holder = requirePublicKey(options.holder, "narrow().holder").hex;
  }
  if (options.ttlSeconds !== undefined) {
    out.ttlSeconds = requireTtl(options.ttlSeconds, "narrow().ttlSeconds", 1);
  }
  if (options.terminal !== undefined) {
    if (typeof options.terminal !== "boolean") {
      throw new TenuoConfigurationError("narrow().terminal must be a boolean");
    }
    out.terminal = options.terminal;
  }
  if (options.maxDepth !== undefined) {
    out.maxDepth = requireDepth(options.maxDepth, "narrow().maxDepth");
  }
  if (out.terminal === true && out.maxDepth !== undefined) {
    throw new TenuoConfigurationError("narrow() options: pass terminal or maxDepth, not both");
  }
  if (options.clearance !== undefined) {
    out.clearance = clearanceJson(options.clearance, "narrow().clearance");
  }
  if (options.agentId !== undefined) {
    out.agentId = requireLabel(options.agentId, "narrow().agentId");
  }
  if (options.addApprovers !== undefined) {
    out.addApprovers = options.addApprovers.map((a, i) => requirePublicKey(a, `narrow().addApprovers[${i}]`).hex);
  }
  if (options.minApprovals !== undefined) {
    if (!Number.isInteger(options.minApprovals) || options.minApprovals < 1) {
      throw new TenuoConfigurationError("narrow().minApprovals must be at least 1");
    }
    out.minApprovals = options.minApprovals;
  }
  return out;
}

function approvalRequestFromWasm(raw: WasmApprovalRequest): ApprovalRequest {
  return {
    requestId: raw.request_id,
    warrantId: raw.warrant_id,
    tool: raw.tool,
    args: { ...raw.args },
    requestHash: raw.request_hash,
    holderPublicKey: raw.holder_public_key,
    requiredApprovers: [...raw.required_approvers],
    minApprovals: raw.min_approvals,
    warrantExpiresAt: raw.warrant_expires_at,
    createdAt: raw.created_at,
    message: raw.message,
  };
}

function explainDeny(message: string, field?: string): string {
  if (!message.includes("unknown field not allowed")) {
    return message;
  }
  const named = field !== undefined && field.length > 0 ? `'${field}'` : "this argument";
  return `${message}. Zero-trust: name ${named} in allow (for example ${named}: pattern("*")), or remove it from the call; constrained policies reject omitted fields.`;
}

function forwardExecuteOptions(callOptions: unknown): unknown {
  if (callOptions === null || typeof callOptions !== "object") {
    return callOptions;
  }
  const rest: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(callOptions as Record<string, unknown>)) {
    if (
      key === "session" ||
      key === "approvals" ||
      key === "onReceipt" ||
      key === "requestId"
    ) {
      continue;
    }
    rest[key] = value;
  }
  return Object.keys(rest).length === 0 ? undefined : rest;
}

function importWireError(error: unknown): TenuoError {
  const message = errorMessage(error);
  if (message.startsWith("TENUO_CHAIN_INVALID") || message.includes("invalid warrant")) {
    return new TenuoError("TENUO_CHAIN_INVALID", message);
  }
  if (message.startsWith("TENUO_SIGNATURE_INVALID")) {
    return new TenuoError("TENUO_SIGNATURE_INVALID", message);
  }
  if (message.startsWith("TENUO_UNTRUSTED_ROOT")) {
    return new TenuoError("TENUO_UNTRUSTED_ROOT", message);
  }
  if (message.startsWith("TENUO_INVALID_POP")) {
    // The warrant is fine; the key is not the one it was issued to.
    const separator = /[.!?]$/.test(message.trim()) ? "" : ".";
    return new AuthorizationDeniedError(
      "TENUO_INVALID_POP",
      `${message}${separator} If this followed narrow(), set { holder: receiverPublicKey } for the agent that imports the child.`,
    );
  }
  return new TenuoConfigurationError(message);
}

function normalizeWireBytes(value: string | Uint8Array): string {
  if (typeof value === "string") {
    return value;
  }
  return bytesToHex(value);
}

function emitReceipt(
  callOptions: unknown,
  receipt: string | undefined,
  session: Session,
  host: object,
): void {
  collectReceipt(receipt, session, host);
  if (receipt === undefined || callOptions === null || typeof callOptions !== "object") {
    return;
  }
  if (!("onReceipt" in callOptions)) {
    return;
  }
  const onReceipt = (callOptions as { onReceipt?: unknown }).onReceipt;
  if (typeof onReceipt !== "function") {
    return;
  }
  emitIsolatedReceipt(onReceipt as (receipt: string) => void | Promise<void>, receipt);
}

function requestIdFrom(callOptions: unknown): string | undefined {
  if (callOptions !== null && typeof callOptions === "object" && "requestId" in callOptions) {
    const value = (callOptions as { requestId?: unknown }).requestId;
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

function approvalsFrom(callOptions: unknown): unknown {
  if (callOptions !== null && typeof callOptions === "object" && "approvals" in callOptions) {
    return (callOptions as { approvals?: unknown }).approvals;
  }
  return undefined;
}

function resolveSession(callOptions: unknown): Session {
  if (callOptions !== null && typeof callOptions === "object" && "session" in callOptions) {
    const explicit = (callOptions as { session: unknown }).session;
    if (!isSession(explicit)) {
      throw new TenuoConfigurationError("options.session must be a Tenuo Session");
    }
    return explicit;
  }
  const ambient = currentSession.getStore();
  if (ambient === undefined) {
    throw new TenuoConfigurationError(
      "No session. Wrap the call in tenuo.withSession(session, ...) or pass { session }.",
    );
  }
  return ambient;
}

function collectSessionAllow(input: SessionInput): { [capability: string]: AllowPolicy } {
  const allow: { [capability: string]: AllowPolicy } = { ...(input.allow ?? {}) };
  for (const tool of input.tools ?? []) {
    if (tool === null || typeof tool !== "object") {
      throw new TenuoConfigurationError("session({ tools }) requires tools from tenuo.tool()");
    }
    const policy = toolPolicies.get(tool);
    if (policy === undefined) {
      throw new TenuoConfigurationError("session({ tools }) requires tools from tenuo.tool()");
    }
    const existing = allow[policy.capability];
    if (existing !== undefined && !sameAllow(existing, policy.allow)) {
      throw new TenuoConfigurationError(
        `session() allow and tools disagree on ${policy.capability}`,
      );
    }
    allow[policy.capability] = policy.allow;
  }
  return allow;
}

function sameAllow(left: AllowPolicy, right: AllowPolicy): boolean {
  return JSON.stringify(sortedAllow(left)) === JSON.stringify(sortedAllow(right));
}

function sortedAllow(allow: AllowPolicy): AllowPolicy {
  const keys = Object.keys(allow).sort();
  const out: { [field: string]: AllowPolicy[string] } = {};
  for (const key of keys) {
    const value = allow[key];
    if (value !== undefined) {
      out[key] = value;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Static helpers: approvals, revocation, receipts, control-plane wire shapes
// ---------------------------------------------------------------------------

function requestHashOf(request: ApprovalRequest | string): string {
  const hash = typeof request === "string" ? request : request.requestHash;
  const hex = hash.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new TenuoConfigurationError("signApproval() needs an ApprovalRequest or a 64-hex request hash");
  }
  return hex;
}

/** Sign an approval as an approver. The approver never needs the warrant or the holder key. */
export function signApproval(
  request: ApprovalRequest | string,
  approverSecret: Uint8Array,
  options: SignApprovalOptions,
): string {
  if (!(approverSecret instanceof Uint8Array) || approverSecret.length !== 32) {
    throw new TenuoConfigurationError("signApproval() requires a 32-byte approver secret");
  }
  if (options === null || typeof options !== "object" || typeof options.externalId !== "string" || options.externalId.trim().length === 0) {
    throw new TenuoConfigurationError("signApproval() requires options.externalId: who approved");
  }
  if (options.ttlSeconds !== undefined && (!Number.isInteger(options.ttlSeconds) || options.ttlSeconds < 1)) {
    throw new TenuoConfigurationError("signApproval().ttlSeconds must be a positive integer");
  }
  const warrantExpiresAt =
    options.warrantExpiresAt ?? (typeof request === "object" ? request.warrantExpiresAt : undefined);
  try {
    return loadWasm().sdkSignApprovalForRequest(
      requestHashOf(request),
      approverSecret,
      options.externalId,
      options.ttlSeconds,
      warrantExpiresAt,
    );
  } catch (error) {
    throw new TenuoConfigurationError(errorMessage(error));
  }
}

/** Decode an approval envelope. Not authorization: the call path still decides. */
export function inspectApproval(envelope: string | Uint8Array): ApprovalInfo {
  const text = typeof envelope === "string" ? envelope : Buffer.from(envelope).toString("base64");
  let raw;
  try {
    raw = loadWasm().sdkInspectApproval(text);
  } catch (error) {
    throw new TenuoConfigurationError(errorMessage(error));
  }
  const out: { -readonly [K in keyof ApprovalInfo]: ApprovalInfo[K] } = {
    approverPublicKey: raw.approver_public_key,
    requestHash: raw.request_hash,
    externalId: raw.external_id,
    approvedAt: raw.approved_at,
    expiresAt: raw.expires_at,
    expired: raw.expired,
    signatureValid: raw.signature_valid,
  };
  if (raw.error !== undefined) {
    out.error = raw.error;
  }
  return out;
}

/** Sign a revocation list with an explicit issuer secret. */
export function signRevocationList(input: RevocationListInput, issuerSecret: Uint8Array): string {
  if (!(issuerSecret instanceof Uint8Array) || issuerSecret.length !== 32) {
    throw new TenuoConfigurationError("signRevocationList() requires a 32-byte issuer secret");
  }
  const { ids, version } = revocationInput(input);
  try {
    return loadWasm().sdkSignRevocationListVersioned(ids, version, issuerSecret);
  } catch (error) {
    throw new TenuoConfigurationError(errorMessage(error));
  }
}

export function inspectRevocationList(wire: string | Uint8Array): RevocationListInfo {
  let raw;
  try {
    raw = loadWasm().sdkInspectRevocationList(normalizeWireBytes(wire));
  } catch (error) {
    throw new TenuoConfigurationError(errorMessage(error));
  }
  return {
    version: raw.version,
    issuedAt: raw.issued_at,
    issuerPublicKey: raw.issuer_public_key,
    revokedIds: [...raw.revoked_ids],
    signatureValid: raw.signature_valid,
  };
}

/** Signature authenticity of a receipt. Not authorization. */
export function verifyReceipt(wire: string | Uint8Array): ReceiptInfo {
  let raw;
  try {
    raw = loadWasm().sdkVerifyReceipt(normalizeWireBytes(wire));
  } catch (error) {
    throw new TenuoConfigurationError(errorMessage(error));
  }
  const out: { -readonly [K in keyof ReceiptInfo]: ReceiptInfo[K] } = {
    authentic: true,
    signerKey: raw.signer_key,
    outcome: raw.outcome,
    action: raw.action,
    requestId: raw.request_id,
  };
  if (raw.decision_code !== undefined) out.decisionCode = raw.decision_code;
  if (raw.srl_version !== undefined) out.srlVersion = raw.srl_version;
  if (raw.srl_hash !== undefined) out.srlHash = raw.srl_hash;
  if (raw.request_hash !== undefined) out.requestHash = raw.request_hash;
  if (raw.policy_definition_hash !== undefined) out.policyDefinitionHash = raw.policy_definition_hash;
  if (raw.prev_receipt_hash !== undefined) out.prevReceiptHash = raw.prev_receipt_hash;
  if (raw.trusted_roots_hash !== undefined) out.trustedRootsHash = raw.trusted_roots_hash;
  return out;
}

/**
 * Root-anchored receipt check: the embedded warrant chain against `roots`
 * at the receipt's own decision instant. Needs no trust in the signer.
 */
export function verifyReceiptChain(wire: string | Uint8Array, roots: readonly PublicKeyHandle[]): ReceiptChainInfo {
  if (!Array.isArray(roots) || roots.length === 0) {
    throw new TenuoConfigurationError("verifyReceiptChain() requires at least one trusted root");
  }
  let raw;
  try {
    raw = loadWasm().sdkVerifyReceiptChain(
      normalizeWireBytes(wire),
      roots.map((r, i) => requirePublicKey(r, `roots[${i}]`).hex),
    );
  } catch (error) {
    throw new TenuoConfigurationError(errorMessage(error));
  }
  const out: { -readonly [K in keyof ReceiptChainInfo]: ReceiptChainInfo[K] } = {
    signerKey: raw.signer_key,
    outcome: raw.outcome,
    timestamp: raw.timestamp,
    chainValid: raw.chain_valid,
  };
  if (raw.decision_code !== undefined) out.decisionCode = raw.decision_code;
  if (raw.chain_error !== undefined) out.chainError = raw.chain_error;
  if (raw.corroborates_denial !== undefined) out.corroboratesDenial = raw.corroborates_denial;
  if (raw.root_issuer !== undefined) out.rootIssuer = raw.root_issuer;
  if (raw.leaf_holder !== undefined) out.leafHolder = raw.leaf_holder;
  return out;
}

/**
 * The v1 JSON body a control plane's approval API accepts. Same shape the
 * Python SDK produces, so one approval service serves both.
 */
export function controlPlaneApprovalRequestV1(
  request: ApprovalRequest,
  options?: {
    readonly attestation?: ApprovalContextAttestation;
    readonly temporal?: Readonly<Record<string, string>>;
  },
): ControlPlaneApprovalRequestV1 {
  if (request === null || typeof request !== "object" || typeof request.requestHash !== "string") {
    throw new TenuoConfigurationError("controlPlaneApprovalRequestV1() needs an ApprovalRequest from tenuo.approvalRequest()");
  }
  const body: { -readonly [K in keyof ControlPlaneApprovalRequestV1]: ControlPlaneApprovalRequestV1[K] } = {
    schema_version: 1,
    request_id_hex: request.requestId,
    warrant_id: request.warrantId,
    tool: request.tool,
    arguments: { ...request.args },
    request_hash_hex: request.requestHash,
    holder_public_key_hex: request.holderPublicKey,
    required_approver_keys_hex: [...request.requiredApprovers],
    min_approvals: Math.max(1, request.minApprovals),
    warrant_expires_at_unix: request.warrantExpiresAt,
    created_at_unix: request.createdAt,
  };
  if (options?.attestation !== undefined) {
    const a = options.attestation;
    body.attestation = {
      version: a.version,
      canonicalization: a.canonicalization,
      warrant_id: a.warrantId,
      tool: a.tool,
      request_hash: a.requestHash,
      holder_key_hex: a.holderKeyHex,
      args_canonical_cbor_b64: a.argsCanonicalCborB64,
      signer_key_hex: a.signerKeyHex,
      signature_b64: a.signatureB64,
      // Python readers look for these two names.
      signer_key: a.signerKeyHex,
      signature: a.signatureB64,
    };
  }
  if (options?.temporal !== undefined && Object.keys(options.temporal).length > 0) {
    body.temporal = { ...options.temporal };
  }
  if (request.message.length > 0) {
    body.message = request.message;
  }
  return body;
}

/** Approval envelopes from a v1 response, ready for `{ approvals }` on the call. Empty unless status is a success. */
export function signedApprovalsFromResponseV1(response: ControlPlaneApprovalResponseV1): string[] {
  if (response === null || typeof response !== "object" || typeof response.status !== "string") {
    throw new TenuoConfigurationError("approval response must be an object with a status");
  }
  if (response.status !== "approved") {
    return [];
  }
  const list = response.signed_approvals_b64;
  if (list === undefined || list === null) {
    return [];
  }
  if (!Array.isArray(list) || list.some((item) => typeof item !== "string" || item.length === 0)) {
    throw new TenuoConfigurationError("signed_approvals_b64 must be an array of base64 strings");
  }
  return [...list];
}

function createTenuoImpl(options: CreateTenuoOptions = {}): Tenuo {
  if (!hasTrustAnchor(options)) {
    throw new TenuoConfigurationError(
      "createTenuo() requires trustedRoots or root: createTenuo.devRoot(). An empty trust set is not a configuration.",
    );
  }
  if (options.root?.kind === "dev-root" && !devRootAllowed(options.root)) {
    throw new TenuoConfigurationError(devRootBlockedMessage());
  }
  loadWasm();
  return new TenuoClient(options);
}

export const createTenuo: ((options?: CreateTenuoOptions) => Tenuo) & {
  devRoot: typeof devRoot;
  publicKeyFromEnv: typeof publicKeyFromEnv;
  publicKeyFromHex: typeof publicKeyFromHex;
  publicKeyFromBytes: typeof publicKeyFromBytes;
  holderKeyFromEnv: typeof holderKeyFromEnv;
  holderKeyFromHex: typeof holderKeyFromHex;
  generateHolderKey: typeof generateHolderKey;
  generateIssuerKey: typeof generateIssuerKey;
  publicKeyFromHolderKey: typeof publicKeyFromHolderKey;
  issuerKeyFromEnv: typeof issuerKeyFromEnv;
  issuerKeyFromHex: typeof issuerKeyFromHex;
  issuerKeyFromBytes: typeof issuerKeyFromBytes;
  signApproval: typeof signApproval;
  inspectApproval: typeof inspectApproval;
  signRevocationList: typeof signRevocationList;
  inspectRevocationList: typeof inspectRevocationList;
  verifyReceipt: typeof verifyReceipt;
  verifyReceiptChain: typeof verifyReceiptChain;
  controlPlaneApprovalRequestV1: typeof controlPlaneApprovalRequestV1;
  signedApprovalsFromResponseV1: typeof signedApprovalsFromResponseV1;
  parseConnectToken: typeof parseConnectToken;
  identity: typeof identityFromKey;
  generateIdentity: typeof generateIdentity;
  runtime: (options: Parameters<typeof createRuntime>[1]) => ReturnType<typeof createRuntime>;
} = Object.assign(createTenuoImpl, {
  devRoot,
  publicKeyFromEnv,
  publicKeyFromHex,
  publicKeyFromBytes,
  holderKeyFromEnv,
  holderKeyFromHex,
  generateHolderKey,
  generateIssuerKey,
  publicKeyFromHolderKey,
  issuerKeyFromEnv,
  issuerKeyFromHex,
  issuerKeyFromBytes,
  signApproval,
  inspectApproval,
  signRevocationList,
  inspectRevocationList,
  verifyReceipt,
  verifyReceiptChain,
  controlPlaneApprovalRequestV1,
  signedApprovalsFromResponseV1,
  parseConnectToken,
  identity: identityFromKey,
  generateIdentity,
  runtime: (options: Parameters<typeof createRuntime>[1]) => createRuntime(createTenuoImpl, options),
});
