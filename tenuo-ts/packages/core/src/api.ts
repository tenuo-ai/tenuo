/**
 * Frozen public contract for `@tenuo/core`.
 *
 * Implementation is stubbed until WASM bindings land. Names and shapes here
 * are the review surface — do not grow this file with protocol vocabulary
 * (`Warrant`, `mint`, `guard`) as the lead API.
 */

export type TenuoErrorCode =
  | "TENUO_NOT_READY"
  | "TENUO_CONFIGURATION"
  | "TENUO_CONSTRAINT_VIOLATION"
  | "TENUO_TOOL_NOT_AUTHORIZED"
  | "TENUO_WARRANT_EXPIRED"
  | "TENUO_UNTRUSTED_ROOT"
  | "TENUO_INVALID_POP"
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

/** Wrapped tool. Assignable to the original type; not forgeable as a plain object. */
export type ProtectedTool<T> = T & {
  readonly [protectedBrand]: true;
};

export type SessionInput = {
  readonly allow: {
    readonly [capability: string]: AllowPolicy;
  };
  readonly ttlSeconds?: number;
};

export type DenyMode = "tool-error" | "abort";

export type DevRoot = {
  readonly kind: "dev-root";
};

export type PublicKeyHandle = {
  readonly kind: "public-key";
  readonly source: "env" | "bytes";
};

export type CreateTenuoOptions = {
  readonly trustedRoots?: readonly PublicKeyHandle[];
  readonly root?: DevRoot | PublicKeyHandle;
  readonly onDeny?: DenyMode;
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
}

export interface Tenuo {
  /**
   * Wrap any `{ execute }` tool (Vercel AI SDK, Mastra, plain object).
   * `parameters` / Zod stay on the inner tool and are never treated as authority.
   */
  tool<T extends { execute: (...args: never[]) => unknown }>(
    inner: T,
    policy: ToolPolicy,
  ): ProtectedTool<T>;
  session(input: SessionInput): Session;
  withSession<R>(session: Session, fn: () => R): R;
  narrow(session: Session, allow: AllowPolicy): Session;
  ready(): void;
}
