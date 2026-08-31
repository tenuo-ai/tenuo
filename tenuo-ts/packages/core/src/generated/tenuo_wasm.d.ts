/* tslint:disable */
/* eslint-disable */

/**
 * Issuer + authorizer for `createTenuo({ root: devRoot() })`.
 * Verifier-only contexts have `issuer: None` and cannot mint.
 */
export class SdkContext {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Sign PoP and authorize in one call. Never returns allow without a core allow.
     */
    authorize(session: SdkSession, tool: string, args_json: any, approvals: any): any;
    /**
     * Test / replay seam. Not exposed on `createTenuo` or `execute`.
     */
    authorizeAsOf(session: SdkSession, tool: string, args_json: any, as_of: number, approvals: any): any;
    /**
     * Authorize a warrant + PoP presented on the wire. No holder secret.
     */
    authorizePresented(warrants: any, tool: string, args_json: any, pop: string, approvals: any): any;
    /**
     * Authorizer-only context. `mint()` fails; import a session from the wire.
     */
    static fromTrustedRoots(roots: any): SdkContext;
    /**
     * Load a published SignedRevocationList. The SRL must be signed by a trusted root.
     */
    loadRevocationList(wire: string): void;
    /**
     * Mint a short-lived session from an allow map:
     * `{ "read_file": { "path": { "kind": "under", "root": "/data" } } }`
     *
     * `require_approval` is optional:
     * `{ "approvers": ["hex..."], "min": 2, "tools": ["transfer"] }`
     */
    mint(allow_json: any, ttl_seconds: number, require_approval: any): SdkSession;
    /**
     * Attenuate the leaf. The current holder signs; the same holder keeps the child.
     */
    narrow(session: SdkSession, allow_json: any): SdkSession;
    constructor();
    /**
     * Holder PoP only. Does not authorize. Used to fill `_meta.tenuo.signature`.
     */
    signPop(session: SdkSession, tool: string, args_json: any): string;
    /**
     * Test / host seam. Signs an SRL with the local issuer. Does not load it.
     */
    signRevocationList(ids: any): string;
}

/**
 * Opaque warrant chain (root first) + leaf holder key. Not JSON-serializable from JS.
 */
export class SdkSession {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Test / interop seam. Not on the public TypeScript Session type.
     */
    exportWire(): any;
    /**
     * Import a chain: string[] of wire tokens, or `{ payload_hex, signature_hex }[]`.
     */
    static fromChain(parts: any, holder_secret: Uint8Array): SdkSession;
    /**
     * Reconstruct a warrant from published payload + signature hex (A.14).
     */
    static fromParts(payload_hex: string, signature_hex: string, holder_secret: Uint8Array): SdkSession;
    /**
     * Import a published warrant (base64 or envelope hex) plus the holder secret.
     */
    static fromWire(warrant: string, holder_secret: Uint8Array): SdkSession;
    /**
     * CBOR warrant stack as standard base64. Matches Python `encode_warrant_stack`.
     */
    toStackWire(): string;
    /**
     * Warrant tokens, root first. Does not include the holder secret.
     */
    toWire(): any;
    /**
     * Warrant IDs, root first. Test / revoke seam.
     */
    warrantIds(): any;
}

export function check_access(warrant_b64: string, tool: string, args_json: any, trusted_root_hex: string, dry_run: boolean): any;

/**
 * Check authorization with a real PoP signature
 */
export function check_access_with_pop(warrant_b64: string, tool: string, args_json: any, trusted_root_hex: string, pop_signature_hex: string): any;

export function check_chain_access(warrant_b64_list: string[], tool: string, args_json: any, trusted_root_hex: string, dry_run: boolean): any;

/**
 * Check a warrant chain with signed approvals and optional revocation list.
 *
 * Extends `check_chain_access` with:
 * - `approvals_b64`: JS array of base64-encoded CBOR `SignedApproval` blobs for M-of-N
 *   approval verification (pass `[]` if not needed).
 * - `srl_b64`: optional base64-encoded CBOR `SignedRevocationList`. When provided, the
 *   SRL is verified (using the trusted root as its issuer) and applied before chain checks.
 *   Pass `null`/`undefined` to skip revocation checking.
 */
export function check_chain_access_with_approvals(warrant_b64_list: string[], tool: string, args_json: any, trusted_root_hex: string, approvals_b64: any, srl_b64?: string | null): any;

/**
 * Check if a warrant ID appears in a signed revocation list.
 *
 * Does not verify the SRL signature — call `verify_srl` first if you need
 * signature assurance. Returns `{ revoked, error? }`.
 */
export function check_revocation(warrant_id: string, srl_cbor_b64: string): any;

/**
 * Compute the canonical request hash for a (warrant, tool, args) tuple.
 *
 * The hash is SHA-256(warrant_id | tool | CBOR(sorted_args) | holder_key) and is
 * what every SignedApproval must cover. Use this to build the payload for
 * POST /v1/approvals/requests so the backend can verify it matches.
 *
 * Returns `{ "hash": "<hex>" }` on success, or `{ "hash": null, "error": "..." }` on failure.
 */
export function compute_request_hash_wasm(warrant_b64: string, tool: string, args_json: any): any;

/**
 * Create a self-signed root Issuer warrant for use as a persistent trust anchor.
 * This is called once during plugin setup and stored on disk.
 * The Issuer warrant's keypair replaces per-session signing keys — all Execution
 * warrants (depth ≥ 1) are derived from it, enabling proper WASM chain verification
 * across plugin restarts.
 *
 * Config: { signing_key_hex?: string, issuable_tools: string[], max_issue_depth?: number, ttl_seconds?: number }
 */
export function create_issuer_warrant(config_json: any): any;

/**
 * Create a fresh sample warrant with the given tool and TTL
 * This generates new keys each time, ensuring the warrant is never expired
 */
export function create_sample_warrant(tool: string, constraint_field: string, constraint_pattern: string, ttl_seconds: bigint): any;

/**
 * Create a warrant from the full builder config (multiple tools, multiple constraints)
 * This is more flexible than create_sample_warrant
 */
export function create_warrant_from_config(config_json: any): any;

/**
 * Decode a PEM chain (or single warrant) and return detailed chain analysis
 */
export function decode_pem_chain_wasm(input: string): any;

export function decode_warrant(base64_warrant: string): any;

/**
 * Evaluate whether a tool call requires approval based on the warrant's embedded approval gates.
 *
 * Returns `{ approval_required: true/false, tool, error }`.
 * This reads `extensions["tenuo.approval_gates"]` from the warrant, parses it,
 * and runs the gate evaluation logic from tenuo-core.
 */
export function evaluate_approval_gates(warrant_b64: string, tool: string, args_json: any): any;

/**
 * Generate a new Ed25519 keypair for testing PoP
 */
export function generate_keypair(): any;

export function init_panic_hook(): void;

/**
 * Parse a `TENUO_CONNECT_TOKEN` string into its component fields.
 *
 * The token is a base64url-encoded JSON blob: `{ v, e, k, a?, t? }`.
 * This WASM binding keeps the parsing canonical so TypeScript doesn't need
 * to duplicate the decode logic.
 *
 * Returns `{ endpoint, apiKey, agentId?, registrationToken?, error? }`.
 */
export function parse_connect_token(token: string): any;

export function sdkInspectParts(payload_hex: string, signature_hex: string): any;

export function sdkInspectWarrant(wire: string): any;

/**
 * Test / host seam. Signs a SignedApproval envelope; does not authorize.
 */
export function sdkSignApproval(session: SdkSession, tool: string, args_json: any, approver_secret: Uint8Array, external_id: string, as_of?: number | null): string;

/**
 * Test / host seam. Signs an SRL with a provided issuer secret. Does not load it.
 */
export function sdkSignRevocationList(ids: any, issuer_secret: Uint8Array): string;

/**
 * Signature authenticity only. Not authorization.
 */
export function sdkVerifyReceipt(wire: string): any;

/**
 * Create a Proof-of-Possession signature for a warrant
 */
export function sign(private_key_hex: string, warrant_b64: string, tool: string, args_json: any): any;

/**
 * Sign an authorization receipt for audit ingestion.
 *
 * Produces the same CBOR+Ed25519 format used by the authorizer binary, allowing
 * browser/Node plugins to generate verifiable forensic receipts.
 *
 * `payload_json` — `{ authorizer_id, warrant_chain_b64, action, outcome, timestamp, root_principal? }`
 * `authorizer_key_hex` — hex-encoded Ed25519 private key (32 bytes).
 *
 * Returns `{ signature_hex, signing_payload_cbor_hex, error? }`.
 */
export function sign_receipt(payload_json: any, authorizer_key_hex: string): any;

/**
 * Verify that enough valid signed approvals cover a known request hash.
 *
 * Use this when you already have a pre-computed `request_hash_hex` and want
 * to check the approval set independently of tool/args re-parsing.
 *
 * `warrant_b64` — the leaf warrant (provides `required_approvers` and threshold).
 * `request_hash_hex` — hex-encoded 32-byte hash from `compute_request_hash_wasm`.
 * `approvals_b64` — JS array of base64-encoded CBOR `SignedApproval` blobs.
 *
 * Returns `{ satisfied, valid_count, required, error? }`.
 */
export function verify_approval_set(warrant_b64: string, request_hash_hex: string, approvals_b64: any): any;

/**
 * Verify a single signed approval blob and return its payload.
 *
 * `approval_cbor_b64` — base64-encoded CBOR `SignedApproval`.
 *
 * Returns `{ valid, approver_hex, request_hash_hex, approved_at, expires_at, error? }`.
 */
export function verify_signed_approval(approval_cbor_b64: string): any;

/**
 * Verify a signed revocation list and return its metadata.
 *
 * `srl_cbor_b64` — base64-encoded CBOR `SignedRevocationList`.
 * `expected_issuer_hex` — hex-encoded Ed25519 public key of the expected SRL issuer.
 *
 * Returns `{ valid, version, revoked_count, issued_at, error? }`.
 */
export function verify_srl(srl_cbor_b64: string, expected_issuer_hex: string): any;
