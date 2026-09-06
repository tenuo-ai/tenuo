/**
 * Frozen public contract for `@tenuo/core`.
 *
 * Names and shapes here are the review surface — do not grow this file with
 * protocol vocabulary (`Warrant`, `mint`, `guard`) as the lead API.
 */

export type TenuoErrorCode =
  | "TENUO_NOT_READY"
  | "TENUO_CONFIGURATION"
  | "TENUO_CONSTRAINT_VIOLATION"
  | "TENUO_TOOL_NOT_AUTHORIZED"
  | "TENUO_WARRANT_EXPIRED"
  | "TENUO_UNTRUSTED_ROOT"
  | "TENUO_INVALID_POP"
  | "TENUO_SIGNATURE_INVALID"
  | "TENUO_CHAIN_INVALID"
  | "TENUO_DEPTH_EXCEEDED"
  | "TENUO_REVOKED"
  | "TENUO_APPROVAL_REQUIRED"
  | "TENUO_INSUFFICIENT_APPROVALS"
  | "TENUO_CANONICALIZATION"
  | "TENUO_NOT_IMPLEMENTED";

/** Path-traversal-safe prefix. Core evaluates this; TypeScript does not. */
export type UnderConstraint = {
  readonly kind: "under";
  readonly root: string;
};

export type EmailConstraint = {
  readonly kind: "email";
  readonly domain: string;
};

export type MaxConstraint = {
  readonly kind: "max";
  readonly value: number;
};

export type OneOfConstraint = {
  readonly kind: "oneOf";
  readonly values: readonly string[];
};

export type PatternConstraint = {
  readonly kind: "pattern";
  readonly pattern: string;
};

export type ExactConstraint = {
  readonly kind: "exact";
  readonly value: string | number | boolean;
};

export type ConstraintExpr =
  | UnderConstraint
  | EmailConstraint
  | MaxConstraint
  | OneOfConstraint
  | PatternConstraint
  | ExactConstraint;

/** Per-argument allow policy. Not a Zod schema. */
export type AllowPolicy = {
  readonly [field: string]: ConstraintExpr;
};

/**
 * Framework tool shape we wrap. No dependency on `ai` / Mastra.
 * `parameters` is host-schema (usually Zod) and is never treated as authority.
 */
export type ToolLike<
  TArgs extends Record<string, unknown> = Record<string, unknown>,
  TResult = unknown,
> = {
  readonly description?: string;
  readonly parameters?: unknown;
  execute: (args: TArgs, options?: unknown) => TResult | Promise<TResult>;
};

export type ToolPolicy = {
  /**
   * Host ceiling. AND'd with the session in Rust.
   * Non-empty maps are zero-trust: every call argument must be named here.
   * `{}` means no extra ceiling (session/warrant only).
   */
  readonly allow: AllowPolicy;
  readonly capability?: string;
};

/** Compile-time brand only — never assigned at runtime. Do not `in`/`has` this key. */
declare const protectedBrand: unique symbol;

export type ExecuteOptions = {
  readonly session?: Session;
  /** Already-signed approval envelopes (hex, standard base64, or CBOR bytes). */
  readonly approvals?: readonly (string | Uint8Array)[];
  /**
   * Signed evidence of the decision. Not a security hook.
   * Exceptions (sync or rejected Promise) are isolated and never deny or
   * fail the tool.
   */
  readonly onReceipt?: (receipt: string) => void | Promise<void>;
  /**
   * Correlation handle written to the receipt. Use whatever id the host
   * already has — a JSON-RPC id, a trace or span id — so a receipt can be
   * matched against your own logs. Not an identity: nothing enforces
   * uniqueness, and distinguishing repeated calls is the receipt chain's job.
   */
  readonly requestId?: string;
};

type ExtraExecuteOptions<T extends { execute: (args: never) => unknown }> =
  T["execute"] extends (args: never, options?: infer O) => unknown
    ? unknown extends O
      ? object
      : Omit<NonNullable<O>, keyof ExecuteOptions>
    : object;

/** Wrapped tool. `execute` still authorizes; optional `{ session }` overrides ALS. */
export type ProtectedTool<T extends { execute: (args: never) => unknown }> = Omit<T, "execute"> & {
  execute: (
    args: Parameters<T["execute"]>[0],
    options?: ExecuteOptions & ExtraExecuteOptions<T>,
  ) => Promise<Awaited<ReturnType<T["execute"]>>>;
  readonly [protectedBrand]: true;
};

/** Whole-tool approval gate. Host collects SignedApproval bytes; Rust decides. */
export type RequireApproval = {
  readonly approvers: readonly PublicKeyHandle[];
  readonly min: number;
  readonly tools?: readonly string[];
};

export type SessionAllow = {
  readonly [capability: string]: AllowPolicy;
};

export type SessionInput = {
  /** Capability map. Optional when `tools` is set. */
  readonly allow?: SessionAllow;
  /** Wrapped tools from `tenuo.tool()`. Their `allow` is minted into the session. */
  readonly tools?: readonly object[];
  readonly ttlSeconds?: number;
  readonly requireApproval?: RequireApproval;
  /**
   * Issue to another agent's key instead of a fresh local holder. The
   * returned session cannot authorize here (it has no holder secret); send
   * `toWire()` to that agent, which imports it with `sessionFromWire()`.
   */
  readonly holder?: PublicKeyHandle;
  /**
   * How many times this authority may be delegated below the root.
   * `0` makes the session terminal. Omit for the protocol maximum.
   * Delegation can lower this ceiling and never raise it.
   */
  readonly maxDepth?: number;
};

/** Options for `tenuo.narrow()`. All optional; the default keeps the holder. */
export type NarrowOptions = {
  /**
   * Bind the child to another agent's key. This is delegation: the current
   * holder signs, the child belongs to `holder`, and the returned session
   * cannot authorize here. Hand `toWire()` to that agent.
   */
  readonly holder?: PublicKeyHandle;
  /** Child lifetime. Clamped to what the parent has left. */
  readonly ttlSeconds?: number;
  /** The child's holder cannot delegate further. */
  readonly terminal?: boolean;
  /** Lower the delegation ceiling. Cannot exceed the parent's. */
  readonly maxDepth?: number;
};

/** Public view of a session's leaf. Never includes the holder secret. */
export type SessionInfo = {
  /** Hex public key the leaf is bound to. */
  readonly holderPublicKey: string;
  /** Hex public key that signed the root of the chain. */
  readonly rootPublicKey: string;
  /** 0 for a root session, +1 per delegation. */
  readonly depth: number;
  /** Delegation ceiling in force for this leaf. */
  readonly maxDepth: number;
  /** True when `depth >= maxDepth`: cannot be narrowed further. */
  readonly terminal: boolean;
  /** Unix seconds. */
  readonly expiresAt: number;
  readonly tools: readonly string[];
  /** Warrant ids, root first. */
  readonly warrantIds: readonly string[];
  /**
   * True when this process holds the leaf's holder secret. False for a
   * session issued or delegated to another agent: `toWire()` works,
   * `execute` and `narrow` do not.
   */
  readonly canAuthorize: boolean;
};

export type DevRoot = {
  readonly kind: "dev-root";
  /**
   * Required when `NODE_ENV` is unset or is not `development` / `test`.
   * Unset `NODE_ENV` is not treated as development.
   */
  readonly allowInProduction?: boolean;
};

export type PublicKeyHandle = {
  readonly kind: "public-key";
  readonly source: "env" | "hex" | "bytes";
  readonly hex: string;
};

export type WarrantPart = {
  readonly payload_hex: string;
  readonly signature_hex: string;
};

export type SessionFromWireInput = {
  readonly warrant: string | readonly string[] | readonly WarrantPart[];
  readonly holderKey: Uint8Array;
};

/** Field-level (`{ path: under("/data") }`) or per-capability (`{ read_file: { path: ... } }`). */
export type NarrowInput = AllowPolicy | SessionAllow;

export type CreateTenuoOptions = {
  readonly trustedRoots?: readonly PublicKeyHandle[];
  readonly root?: DevRoot | PublicKeyHandle;
  /** Published SignedRevocationList (hex or standard base64). Verified against a trusted root. */
  readonly revocationList?: string | Uint8Array;
};

export type ApprovalRequest = {
  readonly tool: string;
  readonly required: number;
  readonly received: number;
};

export type Decision =
  | { readonly outcome: "allow"; readonly args: Readonly<Record<string, unknown>> }
  | { readonly outcome: "deny"; readonly code: TenuoErrorCode; readonly field?: string }
  | { readonly outcome: "approval_required"; readonly request: ApprovalRequest };

export interface Session {
  readonly [Symbol.toStringTag]: "TenuoSession";
  /** Warrant tokens, root first. Does not include the holder secret. */
  toWire(): readonly string[];
  /** SHA-256 of `(warrant_id, tool, canonical args)`. App-level idempotency, not PoP. */
  dedupKey(tool: string, args: Readonly<Record<string, unknown>>): string;
  /** Holder public key, depth, ceiling, lifetime, tools. Never the secret. */
  inspect(): SessionInfo;
}

export interface Tenuo {
  /**
   * Wrap any `{ execute }` tool (Vercel AI SDK, Mastra, plain object).
   * `parameters` / Zod stay on the inner tool and are never treated as authority.
   */
  tool<T extends { execute: (args: never) => unknown }>(
    inner: T,
    policy: ToolPolicy,
  ): ProtectedTool<T>;
  session(input: SessionInput): Session;
  /** Import a warrant minted elsewhere (Rust / Python / another process). */
  sessionFromWire(input: SessionFromWireInput): Session;
  withSession<R>(session: Session, fn: () => R): R;
  /**
   * Child session with less authority. Without options the same holder keeps
   * it; with `options.holder` it is delegated to another agent's key. Core
   * rejects any child that is not within its parent before a token exists.
   */
  narrow(session: Session, allow: NarrowInput, options?: NarrowOptions): Session;
  /**
   * Public key of the local issuer (devRoot contexts only). Other processes
   * put it in `trustedRoots` to accept warrants this context mints.
   */
  issuerPublicKey(): PublicKeyHandle;
  /** Load a published SignedRevocationList. Rust verifies the issuer against trusted roots. */
  revoke(list: string | Uint8Array): void;
  /** MCP `_meta.tenuo` attach / verify. No MCP SDK dependency. */
  readonly mcp: TenuoMcp;
  ready(): void;
}

/** Wire envelope Python and TypeScript both read from `params._meta`. */
export type TenuoMcpMeta = {
  readonly tenuo: {
    readonly warrant: string;
    readonly signature: string;
    readonly approvals?: readonly string[];
  };
};

export type McpAttachOptions = {
  readonly approvals?: readonly (string | Uint8Array)[];
  readonly onReceipt?: (receipt: string) => void | Promise<void>;
  /**
   * Correlation handle written to the receipt. Use whatever id the host
   * already has — a JSON-RPC id, a trace or span id — so a receipt can be
   * matched against your own logs. Not an identity: nothing enforces
   * uniqueness, and distinguishing repeated calls is the receipt chain's job.
   */
  readonly requestId?: string;
};

/** Host ceiling and optional receipt hook on `mcp.handler()`. */
export type McpHandlerPolicy = {
  readonly allow?: AllowPolicy;
  readonly onReceipt?: (receipt: string) => void | Promise<void>;
  readonly nonceStore?: NonceStore;
  /**
   * Isolated. Called when `nonceStore.checkAndRecord` throws or rejects.
   * The client only ever sees "Replay store unavailable".
   */
  readonly onNonceStoreError?: (error: unknown) => void | Promise<void>;
};

export type McpVerifyOptions = {
  readonly allow?: AllowPolicy;
  readonly onReceipt?: (receipt: string) => void | Promise<void>;
  /**
   * Opt-in exact-PoP replay check. `checkAndRecord` may return a Promise
   * (Redis). A rejected Promise fails closed. In-memory stores do not work
   * across processes. PoP v1 is otherwise replayable in-window, including
   * envelopes that already carry approvals.
   */
  readonly nonceStore?: NonceStore;
  /**
   * Isolated. Called when `nonceStore.checkAndRecord` throws or rejects.
   * The client only ever sees "Replay store unavailable".
   */
  readonly onNonceStoreError?: (error: unknown) => void | Promise<void>;
  /**
   * Correlation handle written to the receipt. Use whatever id the host
   * already has — a JSON-RPC id, a trace or span id — so a receipt can be
   * matched against your own logs. Not an identity: nothing enforces
   * uniqueness, and distinguishing repeated calls is the receipt chain's job.
   */
  readonly requestId?: string;
};

/**
 * Returns true if the PoP is fresh and recorded; false if this exact token
 * was already consumed. Async stores (Redis) return `Promise<boolean>`.
 * `verify()` / handlers await the result. Never return a Promise from a
 * store that is only consulted synchronously — that used to fail open.
 */
export type NonceStore = {
  checkAndRecord(popSignature: string): boolean | Promise<boolean>;
};

export type McpCallParams = {
  readonly name: string;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly _meta: TenuoMcpMeta;
};

export type McpJsonRpcError = {
  readonly code: -32602 | -32001 | -32002;
  readonly message: string;
  readonly data?: { readonly tenuo?: { readonly code: TenuoErrorCode } };
};

export interface TenuoMcp {
  /** Local authorize, then put warrant + PoP on `_meta.tenuo`. */
  attach(
    session: Session,
    name: string,
    args: Readonly<Record<string, unknown>>,
    options?: McpAttachOptions,
  ): McpCallParams;
  /**
   * Server path. Verifies a presented warrant + PoP. Tool handler must not
   * run unless this returns.
   */
  verify(
    name: string,
    args: Readonly<Record<string, unknown>>,
    meta: unknown,
    options?: McpVerifyOptions,
  ): Promise<Readonly<Record<string, unknown>>>;
  /** Wrap a handler: verify from `extra._meta` / `extra.meta`, then execute. */
  handler<TArgs extends Record<string, unknown>, TResult>(
    name: string,
    execute: (args: TArgs) => TResult | Promise<TResult>,
  ): (
    args: TArgs,
    extra?: { readonly _meta?: unknown; readonly meta?: unknown },
  ) => Promise<TResult>;
  handler<TArgs extends Record<string, unknown>, TResult>(
    name: string,
    policy: McpHandlerPolicy,
    execute: (args: TArgs) => TResult | Promise<TResult>,
  ): (
    args: TArgs,
    extra?: { readonly _meta?: unknown; readonly meta?: unknown },
  ) => Promise<TResult>;
  jsonRpcError(error: unknown): McpJsonRpcError;
}
