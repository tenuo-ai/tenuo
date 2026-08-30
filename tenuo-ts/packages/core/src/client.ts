import type {
  CreateTenuoOptions,
  DevRoot,
  ProtectedTool,
  PublicKeyHandle,
  SessionInput,
  Tenuo,
  ToolPolicy,
  AllowPolicy,
} from "./api.ts";
import { TenuoConfigurationError } from "./errors.ts";
import { Session } from "./session.ts";

const NOT_IMPLEMENTED =
  "WASM core is not wired yet. @tenuo/core currently ships the public API contract only.";

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

class TenuoClient implements Tenuo {
  constructor(private readonly options: CreateTenuoOptions) {}

  tool<T extends { execute: (...args: never[]) => unknown }>(
    inner: T,
    policy: ToolPolicy,
  ): ProtectedTool<T> {
    if (Object.keys(policy.allow).length === 0) {
      throw new TenuoConfigurationError(
        "tenuo.tool() requires a non-empty allow policy. Zod parameters are not authority.",
      );
    }
    void inner;
    throw new TenuoConfigurationError(NOT_IMPLEMENTED, "TENUO_NOT_IMPLEMENTED");
  }

  session(input: SessionInput): Session {
    if (Object.keys(input.allow).length === 0) {
      throw new TenuoConfigurationError("tenuo.session() requires at least one capability in allow");
    }
    throw new TenuoConfigurationError(NOT_IMPLEMENTED, "TENUO_NOT_IMPLEMENTED");
  }

  withSession<R>(_session: Session, _fn: () => R): R {
    throw new TenuoConfigurationError(NOT_IMPLEMENTED, "TENUO_NOT_IMPLEMENTED");
  }

  narrow(_session: Session, allow: AllowPolicy): Session {
    if (Object.keys(allow).length === 0) {
      throw new TenuoConfigurationError("tenuo.narrow() requires a non-empty allow policy");
    }
    throw new TenuoConfigurationError(NOT_IMPLEMENTED, "TENUO_NOT_IMPLEMENTED");
  }

  ready(): void {
    throw new TenuoConfigurationError(NOT_IMPLEMENTED, "TENUO_NOT_READY");
  }
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
  return new TenuoClient(options);
}

export const createTenuo: ((options?: CreateTenuoOptions) => Tenuo) & {
  devRoot: typeof devRoot;
  publicKeyFromEnv: typeof publicKeyFromEnv;
} = Object.assign(createTenuoImpl, { devRoot, publicKeyFromEnv });
