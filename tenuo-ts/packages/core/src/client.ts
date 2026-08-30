import { AsyncLocalStorage } from "node:async_hooks";
import type {
  AllowPolicy,
  CreateTenuoOptions,
  DevRoot,
  ProtectedTool,
  PublicKeyHandle,
  SessionInput,
  Tenuo,
  ToolPolicy,
} from "./api.ts";
import { AuthorizationDeniedError, ApprovalRequiredError, TenuoConfigurationError } from "./errors.ts";
import { Session, isSession, nativeSession } from "./session.ts";
import { createDevContext, loadWasm, wasmAvailable, type WasmContext } from "./wasm.ts";

const currentSession = new AsyncLocalStorage<Session>();

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

export function devRoot(): DevRoot {
  if (nodeEnv() === "production" && !allowDev()) {
    throw new TenuoConfigurationError(
      "createTenuo.devRoot() is disabled when NODE_ENV=production. Set TENUO_ALLOW_DEV=1 only for explicit break-glass.",
    );
  }
  return { kind: "dev-root" };
}

export function publicKeyFromEnv(name: string): PublicKeyHandle {
  if (name.length === 0) {
    throw new TenuoConfigurationError("PublicKey.fromEnv() requires an environment variable name");
  }
  return { kind: "public-key", source: "env" };
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
  private readonly context: WasmContext | undefined;

  constructor(private readonly options: CreateTenuoOptions) {
    if (options.root?.kind === "dev-root") {
      this.context = createDevContext();
    }
  }

  tool<T extends { execute: (args: never, options?: never) => unknown }>(
    inner: T,
    policy: ToolPolicy,
  ): ProtectedTool<T> {
    if (Object.keys(policy.allow).length === 0) {
      throw new TenuoConfigurationError(
        "tenuo.tool() requires a non-empty allow policy. Zod parameters are not authority.",
      );
    }
    const capability = capabilityName(inner, policy);
    const original = inner.execute as (
      args: Record<string, unknown>,
      options?: unknown,
    ) => unknown;
    const execute = async (args: never, callOptions?: unknown) => {
      const session = resolveSession(callOptions);
      const ctx = this.requireContext();
      const decision = ctx.authorize(nativeSession(session), capability, args);
      if (decision.outcome === "allow") {
        return original(plainArgs(decision.args), callOptions);
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
        decision.message ?? "Authorization denied",
        decision.field,
      );
    };

    return Object.assign(Object.create(Object.getPrototypeOf(inner)), inner, {
      execute,
    }) as ProtectedTool<T>;
  }

  session(input: SessionInput): Session {
    if (Object.keys(input.allow).length === 0) {
      throw new TenuoConfigurationError("tenuo.session() requires at least one capability in allow");
    }
    const ctx = this.requireContext();
    const ttl = input.ttlSeconds ?? 0;
    const native = ctx.mint(input.allow, ttl);
    return new Session(native);
  }

  withSession<R>(session: Session, fn: () => R): R {
    if (!isSession(session)) {
      throw new TenuoConfigurationError("withSession() requires a Tenuo Session, not a plain object");
    }
    return currentSession.run(session, fn);
  }

  narrow(_session: Session, allow: AllowPolicy): Session {
    if (Object.keys(allow).length === 0) {
      throw new TenuoConfigurationError("tenuo.narrow() requires a non-empty allow policy");
    }
    throw new TenuoConfigurationError(
      "tenuo.narrow() is not implemented in this slice",
      "TENUO_NOT_IMPLEMENTED",
    );
  }

  ready(): void {
    loadWasm();
  }

  private requireContext(): WasmContext {
    if (this.context === undefined) {
      throw new TenuoConfigurationError(
        "session() mints a warrant and needs a local issuer. Use createTenuo({ root: createTenuo.devRoot() }). Loading an issued session is not in this slice.",
      );
    }
    return this.context;
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

function createTenuoImpl(options: CreateTenuoOptions = {}): Tenuo {
  if (!hasTrustAnchor(options)) {
    throw new TenuoConfigurationError(
      "createTenuo() requires trustedRoots or root: createTenuo.devRoot(). An empty trust set is not a configuration.",
    );
  }
  if (options.root?.kind === "dev-root" && nodeEnv() === "production" && !allowDev()) {
    throw new TenuoConfigurationError(
      "createTenuo.devRoot() is disabled when NODE_ENV=production. Set TENUO_ALLOW_DEV=1 only for explicit break-glass.",
    );
  }
  if (!wasmAvailable() && options.root?.kind === "dev-root") {
    loadWasm();
  }
  return new TenuoClient(options);
}

export const createTenuo: ((options?: CreateTenuoOptions) => Tenuo) & {
  devRoot: typeof devRoot;
  publicKeyFromEnv: typeof publicKeyFromEnv;
} = Object.assign(createTenuoImpl, { devRoot, publicKeyFromEnv });
