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

// ---------------------------------------------------------------------------
// Constraints. Every kind is evaluated in the Rust core; TypeScript only
// builds the marker object. The set matches the core `Constraint` enum.
// ---------------------------------------------------------------------------

/** Path-traversal-safe prefix. Core evaluates this; TypeScript does not. */
export type UnderConstraint = {
  readonly kind: "under";
  readonly root: string;
  /** Default true. */
  readonly caseSensitive?: boolean;
  /** Whether the root itself is allowed. Default true. */
  readonly allowEqual?: boolean;
};

export type EmailConstraint = {
  readonly kind: "email";
  readonly domain: string;
};

export type MaxConstraint = {
  readonly kind: "max";
  readonly value: number;
};

export type MinConstraint = {
  readonly kind: "min";
  readonly value: number;
};

export type RangeConstraint = {
  readonly kind: "range";
  readonly min?: number;
  readonly max?: number;
  readonly minExclusive?: boolean;
  readonly maxExclusive?: boolean;
};

export type OneOfConstraint = {
  readonly kind: "oneOf";
  readonly values: readonly string[];
};

export type NotOneOfConstraint = {
  readonly kind: "notOneOf";
  readonly values: readonly string[];
};

export type PatternConstraint = {
  readonly kind: "pattern";
  readonly pattern: string;
};

export type RegexConstraint = {
  readonly kind: "regex";
  readonly source: string;
};

export type ExactConstraint = {
  readonly kind: "exact";
  readonly value: string | number | boolean;
};

export type WildcardConstraint = {
  readonly kind: "wildcard";
};

export type CidrConstraint = {
  readonly kind: "cidr";
  readonly network: string;
};

export type UrlPatternConstraint = {
  readonly kind: "urlPattern";
  readonly pattern: string;
};

export type UrlSafeConstraint = {
  readonly kind: "urlSafe";
  readonly schemes?: readonly string[];
  readonly allowDomains?: readonly string[];
  readonly denyDomains?: readonly string[];
};

export type ShlexConstraint = {
  readonly kind: "shlex";
  readonly allow: readonly string[];
};

export type ContainsConstraint = {
  readonly kind: "contains";
  readonly values: readonly (string | number | boolean)[];
};

export type SubsetConstraint = {
  readonly kind: "subset";
  readonly values: readonly (string | number | boolean)[];
};

export type AnyOfConstraint = {
  readonly kind: "anyOf";
  readonly constraints: readonly ConstraintExpr[];
};

export type AllConstraint = {
  readonly kind: "all";
  readonly constraints: readonly ConstraintExpr[];
};

export type NotConstraint = {
  readonly kind: "not";
  readonly constraint: ConstraintExpr;
};

export type CelConstraint = {
  readonly kind: "cel";
  readonly expression: string;
};

export type ConstraintExpr =
  | UnderConstraint
  | EmailConstraint
  | MaxConstraint
  | MinConstraint
  | RangeConstraint
  | OneOfConstraint
  | NotOneOfConstraint
  | PatternConstraint
  | RegexConstraint
  | ExactConstraint
  | WildcardConstraint
  | CidrConstraint
  | UrlPatternConstraint
  | UrlSafeConstraint
  | ShlexConstraint
  | ContainsConstraint
  | SubsetConstraint
  | AnyOfConstraint
  | AllConstraint
  | NotConstraint
  | CelConstraint;

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

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

/** Per-argument trigger for an approval gate. */
export type ArgApprovalGate =
  /** Every value of this argument fires the gate. */
  | "all"
  /** Only values satisfying the constraint fire the gate. */
  | { readonly when: ConstraintExpr }
  /** Every value except those satisfying the constraint fires the gate. Narrowable across delegation. */
  | { readonly exempt: ConstraintExpr };

/** Gate on one tool: a message for the approver and optional per-argument triggers. */
export type ToolApprovalGate = {
  readonly message?: string;
  /** Absent: the whole tool is gated. */
  readonly args?: { readonly [field: string]: ArgApprovalGate };
};

/** Approval requirement. Host collects SignedApproval envelopes; Rust decides. */
export type RequireApproval = {
  readonly approvers: readonly PublicKeyHandle[];
  readonly min: number;
  /** Whole-tool gates. Defaults to every tool in the session when `gates` is absent too. */
  readonly tools?: readonly string[];
  /** Per-tool gates with messages and per-argument triggers. */
  readonly gates?: { readonly [tool: string]: ToolApprovalGate };
};

/** What an approval service needs to present a call to a human. Not a signed artifact. */
export type ApprovalRequest = {
  readonly requestId: string;
  readonly warrantId: string;
  readonly tool: string;
  readonly args: Readonly<Record<string, unknown>>;
  /** Hex SHA-256 committing to warrant id, tool, canonical args, and holder. */
  readonly requestHash: string;
  readonly holderPublicKey: string;
  readonly requiredApprovers: readonly string[];
  readonly minApprovals: number;
  /** Unix seconds. An approval cannot outlive the warrant. */
  readonly warrantExpiresAt: number;
  readonly createdAt: number;
  readonly message: string;
};

/** Holder-signed statement that it is the one asking. Carried in a control-plane request. */
export type ApprovalContextAttestation = {
  readonly version: number;
  readonly canonicalization: string;
  readonly warrantId: string;
  readonly tool: string;
  readonly requestHash: string;
  readonly holderKeyHex: string;
  readonly argsCanonicalCborB64: string;
  readonly signerKeyHex: string;
  readonly signatureB64: string;
};

/** Wire body for a control-plane approval API. Field names are the wire names. */
export type ControlPlaneApprovalRequestV1 = {
  readonly schema_version: 1;
  readonly request_id_hex: string;
  readonly warrant_id: string;
  readonly tool: string;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly request_hash_hex: string;
  readonly holder_public_key_hex: string;
  readonly required_approver_keys_hex: readonly string[];
  readonly min_approvals: number;
  readonly warrant_expires_at_unix: number;
  readonly created_at_unix: number;
  readonly attestation?: Readonly<Record<string, unknown>>;
  readonly temporal?: Readonly<Record<string, string>>;
  readonly message?: string;
};

export type ControlPlaneApprovalResponseV1 = {
  readonly status: string;
  readonly signed_approvals_b64?: readonly string[];
  readonly error?: string;
  readonly server_request_id?: string;
};

export type SignApprovalOptions = {
  /** Who approved, in the approver system's own terms. Required. */
  readonly externalId: string;
  /** Approval lifetime. Default one hour, always clamped to the warrant's expiry when given. */
  readonly ttlSeconds?: number;
  readonly warrantExpiresAt?: number;
};

/** Decoded approval envelope. Not authorization. */
export type ApprovalInfo = {
  readonly approverPublicKey: string;
  readonly requestHash: string;
  readonly externalId: string;
  readonly approvedAt: number;
  readonly expiresAt: number;
  readonly expired: boolean;
  readonly signatureValid: boolean;
  readonly error?: string;
};

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export type SessionAllow = {
  readonly [capability: string]: AllowPolicy;
};

/** Named level or a number 0-255. Delegation can only lower it. */
export type Clearance =
  | number
  | "untrusted"
  | "external"
  | "partner"
  | "internal"
  | "privileged"
  | "system";

export type SessionInput = {
  /** Capability map. Optional when `tools` is set. Issuer sessions may omit it. */
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
  /**
   * `"execution"` (default) can call tools. `"issuer"` cannot call tools; its
   * holder can mint execution sessions with `tenuo.issue()` for the tools in
   * `issuableTools`, within `constraintBounds`, without the root key.
   */
  readonly kind?: "execution" | "issuer";
  readonly clearance?: Clearance;
  /** Free-form task correlation id. Inherited unchanged through delegation. */
  readonly sessionId?: string;
  /** Free-form agent label. Delegation may change it. */
  readonly agentId?: string;
  /** Issuer sessions only. */
  readonly issuableTools?: readonly string[];
  /** Issuer sessions only: ceiling on the constraints of anything issued, by field. */
  readonly constraintBounds?: AllowPolicy;
  /** Issuer sessions only: how deep issued sessions may themselves delegate. */
  readonly maxIssueDepth?: number;
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
  /** Lower the clearance. Cannot exceed the parent's. */
  readonly clearance?: Clearance;
  readonly agentId?: string;
  /** Approvers can only be added. */
  readonly addApprovers?: readonly PublicKeyHandle[];
  /** The threshold can only go up. */
  readonly minApprovals?: number;
};

/** Options for `tenuo.issue()`: an execution session minted from an issuer session. */
export type IssueInput = {
  readonly allow: SessionAllow;
  /** The agent that will use it. Pass the issuer's own key to keep it local. */
  readonly holder: PublicKeyHandle;
  readonly ttlSeconds?: number;
  readonly maxDepth?: number;
  readonly clearance?: Clearance;
  readonly sessionId?: string;
  readonly agentId?: string;
  readonly requireApproval?: { readonly approvers: readonly PublicKeyHandle[]; readonly min: number };
};

/** Public view of a session's leaf. Never includes the holder secret. */
export type SessionInfo = {
  readonly kind: "execution" | "issuer";
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
  readonly clearance?: number;
  readonly sessionId?: string;
  readonly agentId?: string;
  readonly issuableTools?: readonly string[];
  readonly maxIssueDepth?: number;
  readonly requiredApprovers?: readonly string[];
  readonly minApprovals?: number;
  readonly approvalGatedTools: readonly string[];
};

/** One constrained argument in an `explain()` result. */
export type ExplainedField = {
  readonly field: string;
  /** Core constraint type name, e.g. `"Subpath"`, `"Range"`. */
  readonly kind: string;
  /** The constraint as core serializes it. */
  readonly constraint: unknown;
  /** Absent when the argument was not supplied. */
  readonly value?: unknown;
  readonly satisfied: boolean;
  readonly reason?: string;
};

/** What a session would decide for `tool(args)`, field by field. No proof-of-possession involved. */
export type Explanation = {
  readonly tool: string;
  readonly kind: "execution" | "issuer";
  readonly outcome: "allow" | "deny";
  readonly code?: TenuoErrorCode;
  readonly field?: string;
  readonly message?: string;
  readonly toolGranted: boolean;
  readonly fields: readonly ExplainedField[];
  /** Arguments the session does not name. Zero-trust policies reject these. */
  readonly unknownFields: readonly string[];
  /** Constrained arguments the call did not supply. */
  readonly missingFields: readonly string[];
  readonly expired: boolean;
  readonly expiresAt: number;
  readonly chainValid: boolean;
  readonly chainError?: TenuoErrorCode;
};

export type DevRoot = {
  readonly kind: "dev-root";
  /**
   * Required when `NODE_ENV` is unset or is not `development` / `test`.
   * Unset `NODE_ENV` is not treated as development.
   */
  readonly allowInProduction?: boolean;
};

/** A stable issuer secret: this process is a control plane. */
export type IssuerKey = {
  readonly kind: "issuer-key";
  readonly secret: Uint8Array;
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
  /**
   * `devRoot()` for development; an `issuerKey*` for a control plane that
   * mints with a stable key; a public key for a verifier. An issuer key
   * trusts itself plus `trustedRoots`.
   */
  readonly root?: DevRoot | IssuerKey | PublicKeyHandle;
  /** Published SignedRevocationList (hex or standard base64). Verified against a trusted root. */
  readonly revocationList?: string | Uint8Array;
};

export type ApprovalRequestSummary = {
  readonly tool: string;
  readonly required: number;
  readonly received: number;
};

export type Decision =
  | { readonly outcome: "allow"; readonly args: Readonly<Record<string, unknown>> }
  | { readonly outcome: "deny"; readonly code: TenuoErrorCode; readonly field?: string }
  | { readonly outcome: "approval_required"; readonly request: ApprovalRequestSummary };

// ---------------------------------------------------------------------------
// Revocation and receipts
// ---------------------------------------------------------------------------

export type RevocationListInput = {
  readonly revoke: readonly string[];
  /** Monotonic; verifiers refuse an older version. Default 1. */
  readonly version?: number;
};

export type RevocationListInfo = {
  readonly version: number;
  readonly issuedAt: number;
  readonly issuerPublicKey: string;
  readonly revokedIds: readonly string[];
  readonly signatureValid: boolean;
};

/** Signature authenticity of a receipt. Not authorization. */
export type ReceiptInfo = {
  readonly authentic: true;
  /** Hex key the receipt is signed under — resolve against your own authorizer set. */
  readonly signerKey: string;
  readonly outcome: "allow" | "deny";
  readonly action: string;
  readonly decisionCode?: string;
  readonly requestId: string;
  readonly srlVersion?: number;
  readonly srlHash?: string;
  readonly requestHash?: string;
  readonly policyDefinitionHash?: string;
  readonly prevReceiptHash?: string;
  readonly trustedRootsHash?: string;
};

/** Root-anchored receipt check: the embedded chain against trusted roots at decision time. */
export type ReceiptChainInfo = {
  readonly signerKey: string;
  readonly outcome: "allow" | "deny";
  readonly decisionCode?: string;
  readonly timestamp: number;
  readonly chainValid: boolean;
  readonly chainError?: string;
  readonly corroboratesDenial?: boolean;
  readonly rootIssuer?: string;
  readonly leafHolder?: string;
};

// ---------------------------------------------------------------------------
// Presenting authority across any boundary
// ---------------------------------------------------------------------------

/** Warrant chain plus proof-of-possession for one call. Transport-agnostic. */
export type PresentedCall = {
  readonly warrant: string;
  readonly signature: string;
  readonly approvals?: readonly string[];
};

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
   * Mint an execution session from an issuer session, signed by the issuer
   * session's holder. Core checks tools against `issuableTools`, constraints
   * against `constraintBounds`, clearance, and issue depth. No root key.
   */
  issue(issuer: Session, input: IssueInput): Session;
  /**
   * Public key of the local issuer (dev root or issuer key). Other processes
   * put it in `trustedRoots` to accept warrants this context mints.
   */
  issuerPublicKey(): PublicKeyHandle;
  /** What the session would decide for `tool(args)`, field by field. Never runs the tool. */
  explain(session: Session, tool: string, args: Readonly<Record<string, unknown>>): Explanation;
  /** Everything an approval service needs to present `tool(args)` to a human. */
  approvalRequest(session: Session, tool: string, args: Readonly<Record<string, unknown>>): ApprovalRequest;
  /** Holder-signed proof that this session is the one asking for `tool(args)`. */
  attestApprovalRequest(
    session: Session,
    tool: string,
    args: Readonly<Record<string, unknown>>,
  ): ApprovalContextAttestation;
  /** Authorize locally, then produce warrant + proof-of-possession for another boundary to verify. */
  present(
    session: Session,
    tool: string,
    args: Readonly<Record<string, unknown>>,
    options?: McpAttachOptions,
  ): PresentedCall;
  /** Verify a presented call at any boundary. Resolves with the authorized arguments; the tool must not run otherwise. */
  verify(
    presented: PresentedCall,
    tool: string,
    args: Readonly<Record<string, unknown>>,
    options?: McpVerifyOptions,
  ): Promise<Readonly<Record<string, unknown>>>;
  /** Sign a revocation list with this context's issuer key. Load it with `revoke()` where this issuer is trusted. */
  revocationList(input: RevocationListInput): string;
  /** Load a published SignedRevocationList. Rust verifies the issuer against trusted roots. */
  revoke(list: string | Uint8Array): void;
  /** MCP `_meta.tenuo` attach / verify. No MCP SDK dependency. */
  readonly mcp: TenuoMcp;
  ready(): void;
}

/** Wire envelope Python and TypeScript both read from `params._meta`. */
export type TenuoMcpMeta = {
  readonly tenuo: PresentedCall;
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
