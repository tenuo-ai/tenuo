import { AsyncLocalStorage } from "node:async_hooks";
import type {
  AllowPolicy,
  CreateTenuoOptions,
  DevRoot,
  ProtectedTool,
  PublicKeyHandle,
  NarrowInput,
  SessionFromWireInput,
  SessionInput,
  Tenuo,
  TenuoErrorCode,
  TenuoMcp,
  ToolPolicy,
} from "./api.ts";
import { createMcp } from "./mcp.ts";
import { AuthorizationDeniedError, ApprovalRequiredError, TenuoConfigurationError, TenuoError } from "./errors.ts";
import { Session, isSession, nativeSession } from "./session.ts";
import {
  createDevContext,
  createVerifierContext,
  importSessionFromChain,
  importSessionFromWire,
  loadWasm,
  type WasmContext,
} from "./wasm.ts";

const currentSession = new AsyncLocalStorage<Session>();
const toolPolicies = new WeakMap<object, { capability: string; allow: AllowPolicy }>();
const wrappedInners = new WeakSet<object>();

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

export function publicKeyFromEnv(name: string): PublicKeyHandle {
  if (name.length === 0) {
    throw new TenuoConfigurationError("publicKeyFromEnv() requires an environment variable name");
  }
  if (typeof process === "undefined") {
    throw new TenuoConfigurationError(
      `Environment variable ${name} is not available. Tenuo fails closed without a trusted root.`,
    );
  }
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new TenuoConfigurationError(
      `Environment variable ${name} is not set or empty. Tenuo fails closed without a trusted root.`,
    );
  }
  return { kind: "public-key", source: "env", hex: normalizeHex(value) };
}

export function publicKeyFromHex(hex: string): PublicKeyHandle {
  return { kind: "public-key", source: "hex", hex: normalizeHex(hex) };
}

export function publicKeyFromBytes(bytes: Uint8Array): PublicKeyHandle {
  if (bytes.length !== 32) {
    throw new TenuoConfigurationError("publicKeyFromBytes() requires a 32-byte public key");
  }
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return { kind: "public-key", source: "bytes", hex };
}

function normalizeSecretHex(value: string): string {
  const hex = value.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new TenuoConfigurationError(
      "Holder key must be a 32-byte hex secret (64 hex characters)",
    );
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

export function holderKeyFromEnv(name: string): Uint8Array {
  if (name.length === 0) {
    throw new TenuoConfigurationError("holderKeyFromEnv() requires an environment variable name");
  }
  if (typeof process === "undefined") {
    throw new TenuoConfigurationError(
      `Environment variable ${name} is not available. Tenuo fails closed without a holder key.`,
    );
  }
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new TenuoConfigurationError(
      `Environment variable ${name} is not set or empty. Tenuo fails closed without a holder key.`,
    );
  }
  return hexToBytes(normalizeSecretHex(value));
}

export function holderKeyFromHex(hex: string): Uint8Array {
  return hexToBytes(normalizeSecretHex(hex));
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

function capabilityName(inner: object, policy: ToolPolicy): string {
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

  constructor(options: CreateTenuoOptions) {
    if (options.root?.kind === "dev-root") {
      this.context = createDevContext();
      this.canMint = true;
    } else {
      this.context = createVerifierContext(rootHexes(options));
      this.canMint = false;
    }
    if (options.revocationList !== undefined) {
      this.context.loadRevocationList(normalizeWireBytes(options.revocationList));
    }
    this.mcp = createMcp(this.context, (decision, tool) => applyDecision(decision, tool));
  }

  tool<T extends { execute: (args: never) => unknown }>(
    inner: T,
    policy: ToolPolicy,
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
      const decision = this.context.authorize(
        nativeSession(session),
        capability,
        args,
        approvalsFrom(callOptions),
        policy.allow,
      );
      emitReceipt(callOptions, decision.receipt);
      if (decision.outcome === "allow") {
        return original(plainArgs(decision.args), forwardExecuteOptions(callOptions));
      }
      if (decision.outcome === "approval_required") {
        throw new ApprovalRequiredError(
          decision.tool ?? capability,
          decision.required ?? 1,
          decision.received ?? 0,
          decision.message,
        );
      }
      throw new AuthorizationDeniedError(
        decision.code ?? "TENUO_TOOL_NOT_AUTHORIZED",
        explainDeny(decision.message ?? "Authorization denied", decision.field),
        decision.field,
      );
    };

    const wrapped = Object.assign(Object.create(Object.getPrototypeOf(inner)), inner, {
      execute,
    }) as ProtectedTool<T>;
    wrappedInners.add(inner);
    toolPolicies.set(wrapped, { capability, allow: { ...policy.allow } });
    return wrapped;
  }

  session(input: SessionInput): Session {
    const allow = collectSessionAllow(input);
    if (Object.keys(allow).length === 0) {
      throw new TenuoConfigurationError(
        "tenuo.session() requires tools from tenuo.tool() or at least one capability in allow",
      );
    }
    if (!this.canMint) {
      throw new TenuoConfigurationError(
        "session() mints a warrant and needs a local issuer. Use createTenuo({ root: createTenuo.devRoot() }).",
      );
    }
    const ttl = input.ttlSeconds ?? 0;
    if (input.requireApproval !== undefined) {
      if (input.requireApproval.approvers.length === 0) {
        throw new TenuoConfigurationError("requireApproval.approvers must not be empty");
      }
      if (input.requireApproval.min < 1) {
        throw new TenuoConfigurationError("requireApproval.min must be at least 1");
      }
    }
    const native = this.context.mint(allow, ttl, requireApprovalJson(input.requireApproval));
    return new Session(native);
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

  narrow(session: Session, allow: NarrowInput): Session {
    if (Object.keys(allow).length === 0) {
      throw new TenuoConfigurationError("tenuo.narrow() requires a non-empty allow policy");
    }
    if (!isSession(session)) {
      throw new TenuoConfigurationError("narrow() requires a Tenuo Session, not a plain object");
    }
    try {
      return new Session(this.context.narrow(nativeSession(session), allow));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.startsWith("TENUO_CHAIN_INVALID")) {
        throw new AuthorizationDeniedError("TENUO_CHAIN_INVALID", message);
      }
      throw new TenuoConfigurationError(message);
    }
  }

  revoke(list: string | Uint8Array): void {
    this.context.loadRevocationList(normalizeWireBytes(list));
  }

  ready(): void {
    loadWasm();
  }
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

function requireApprovalJson(
  require: SessionInput["requireApproval"],
): { approvers: string[]; min: number; tools?: string[] } | undefined {
  if (require === undefined) {
    return undefined;
  }
  const payload: { approvers: string[]; min: number; tools?: string[] } = {
    approvers: require.approvers.map((approver) => approver.hex),
    min: require.min,
  };
  if (require.tools !== undefined) {
    payload.tools = [...require.tools];
  }
  return payload;
}

function applyDecision(decision: { outcome: string; code?: string; field?: string; message?: string; tool?: string; required?: number; received?: number }, tool: string): void {
  if (decision.outcome === "allow") {
    return;
  }
  if (decision.outcome === "approval_required") {
    throw new ApprovalRequiredError(
      decision.tool ?? tool,
      decision.required ?? 1,
      decision.received ?? 0,
      decision.message,
    );
  }
  throw new AuthorizationDeniedError(
    (decision.code as TenuoErrorCode | undefined) ?? "TENUO_TOOL_NOT_AUTHORIZED",
    explainDeny(decision.message ?? "Authorization denied", decision.field),
    decision.field,
  );
}

function explainDeny(message: string, field?: string): string {
  if (!message.includes("unknown field not allowed")) {
    return message;
  }
  const named = field !== undefined && field.length > 0 ? `'${field}'` : "this argument";
  return `${message}. Zero-trust: name ${named} in allow (e.g. ${named}: pattern("*")), or drop it from the call. Empty allow: {} adds no extra ceiling.`;
}

function forwardExecuteOptions(callOptions: unknown): unknown {
  if (callOptions === null || typeof callOptions !== "object") {
    return callOptions;
  }
  const rest: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(callOptions as Record<string, unknown>)) {
    if (key === "session" || key === "approvals" || key === "onReceipt") {
      continue;
    }
    rest[key] = value;
  }
  return Object.keys(rest).length === 0 ? undefined : rest;
}

function importWireError(error: unknown): TenuoError {
  const message = error instanceof Error ? error.message : String(error);
  if (message.startsWith("TENUO_CHAIN_INVALID") || message.includes("invalid warrant")) {
    return new TenuoError("TENUO_CHAIN_INVALID", message);
  }
  if (message.startsWith("TENUO_SIGNATURE_INVALID")) {
    return new TenuoError("TENUO_SIGNATURE_INVALID", message);
  }
  if (message.startsWith("TENUO_UNTRUSTED_ROOT")) {
    return new TenuoError("TENUO_UNTRUSTED_ROOT", message);
  }
  return new TenuoConfigurationError(message);
}

function normalizeWireBytes(value: string | Uint8Array): string {
  if (typeof value === "string") {
    return value;
  }
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function emitReceipt(callOptions: unknown, receipt: string | undefined): void {
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
  try {
    const result = onReceipt(receipt);
    if (result !== null && typeof result === "object" && "then" in result && typeof result.then === "function") {
      void Promise.resolve(result).catch(() => undefined);
    }
  } catch {
    // Receipt hooks must not deny or fail the tool.
  }
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
} = Object.assign(createTenuoImpl, {
  devRoot,
  publicKeyFromEnv,
  publicKeyFromHex,
  publicKeyFromBytes,
  holderKeyFromEnv,
  holderKeyFromHex,
});
