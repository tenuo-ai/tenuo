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
  readonly allow: AllowPolicy;
  readonly capability?: string;
};

declare const protectedBrand: unique symbol;

export type ExecuteOptions = {
  readonly session?: Session;
  /** Already-signed approval envelopes (hex, standard base64, or CBOR bytes). */
  readonly approvals?: readonly (string | Uint8Array)[];
  /** Signed evidence of the decision. Not a security hook — the tool already ran or was denied. */
  readonly onReceipt?: (receipt: string) => void;
};

/** Wrapped tool. `execute` still authorizes; optional `{ session }` overrides ALS. */
export type ProtectedTool<T extends { execute: (args: never, options?: never) => unknown }> = Omit<
  T,
  "execute"
> & {
  execute: (
    args: Parameters<T["execute"]>[0],
    options?: ExecuteOptions,
  ) => ReturnType<T["execute"]>;
  readonly [protectedBrand]: true;
};

/** Whole-tool approval gate. Host collects SignedApproval bytes; Rust decides. */
export type RequireApproval = {
  readonly approvers: readonly PublicKeyHandle[];
  readonly min: number;
  readonly tools?: readonly string[];
};

export type SessionInput = {
  readonly allow: {
    readonly [capability: string]: AllowPolicy;
  };
  readonly ttlSeconds?: number;
  readonly requireApproval?: RequireApproval;
};

export type DenyMode = "tool-error" | "abort";

export type DevRoot = {
  readonly kind: "dev-root";
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
export type NarrowInput = AllowPolicy | SessionInput["allow"];

export type CreateTenuoOptions = {
  readonly trustedRoots?: readonly PublicKeyHandle[];
  readonly root?: DevRoot | PublicKeyHandle;
  readonly onDeny?: DenyMode;
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
}

export interface Tenuo {
  /**
   * Wrap any `{ execute }` tool (Vercel AI SDK, Mastra, plain object).
   * `parameters` / Zod stay on the inner tool and are never treated as authority.
   */
  tool<T extends { execute: (args: never, options?: never) => unknown }>(
    inner: T,
    policy: ToolPolicy,
  ): ProtectedTool<T>;
  session(input: SessionInput): Session;
  /** Import a warrant minted elsewhere (Rust / Python / another process). */
  sessionFromWire(input: SessionFromWireInput): Session;
  withSession<R>(session: Session, fn: () => R): R;
  narrow(session: Session, allow: NarrowInput): Session;
  /** Load a published SignedRevocationList. Rust verifies the issuer against trusted roots. */
  revoke(list: string | Uint8Array): void;
  ready(): void;
}
