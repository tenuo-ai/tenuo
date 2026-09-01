/* @ts-self-types="./tenuo_wasm.d.ts" */

/**
 * Issuer + authorizer for `createTenuo({ root: devRoot() })`.
 * Verifier-only contexts have `issuer: None` and cannot mint.
 */
class SdkContext {
    static __wrap(ptr) {
        const obj = Object.create(SdkContext.prototype);
        obj.__wbg_ptr = ptr;
        SdkContextFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SdkContextFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_sdkcontext_free(ptr, 0);
    }
    /**
     * Sign PoP and authorize in one call. Never returns allow without a core allow.
     *
     * `tool_allow` is the wrapper ceiling (`tenuo.tool(..., { allow })`). Null/undefined
     * means no extra ceiling. Session and ceiling are AND'd; Rust decides both.
     * @param {SdkSession} session
     * @param {string} tool
     * @param {any} args_json
     * @param {any} approvals
     * @param {any} tool_allow
     * @param {string | null} [request_id]
     * @returns {any}
     */
    authorize(session, tool, args_json, approvals, tool_allow, request_id) {
        _assertClass(session, SdkSession);
        const ptr0 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(request_id) ? 0 : passStringToWasm0(request_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        const ret = wasm.sdkcontext_authorize(this.__wbg_ptr, session.__wbg_ptr, ptr0, len0, args_json, approvals, tool_allow, ptr1, len1);
        return ret;
    }
    /**
     * Test / replay seam. Not exposed on `createTenuo` or `execute`.
     * @param {SdkSession} session
     * @param {string} tool
     * @param {any} args_json
     * @param {number} as_of
     * @param {any} approvals
     * @param {any} tool_allow
     * @returns {any}
     */
    authorizeAsOf(session, tool, args_json, as_of, approvals, tool_allow) {
        _assertClass(session, SdkSession);
        const ptr0 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sdkcontext_authorizeAsOf(this.__wbg_ptr, session.__wbg_ptr, ptr0, len0, args_json, as_of, approvals, tool_allow);
        return ret;
    }
    /**
     * Authorize a warrant + PoP presented on the wire. No holder secret.
     *
     * `tool_allow` is the server host ceiling (`mcp.handler(..., { allow })`).
     * Null/undefined: no extra ceiling. Empty object: open.
     * @param {any} warrants
     * @param {string} tool
     * @param {any} args_json
     * @param {string} pop
     * @param {any} approvals
     * @param {any} tool_allow
     * @param {string | null} [request_id]
     * @returns {any}
     */
    authorizePresented(warrants, tool, args_json, pop, approvals, tool_allow, request_id) {
        const ptr0 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(pop, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(request_id) ? 0 : passStringToWasm0(request_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.sdkcontext_authorizePresented(this.__wbg_ptr, warrants, ptr0, len0, args_json, ptr1, len1, approvals, tool_allow, ptr2, len2);
        return ret;
    }
    /**
     * Authorizer-only context. `mint()` fails; import a session from the wire.
     * @param {any} roots
     * @returns {SdkContext}
     */
    static fromTrustedRoots(roots) {
        const ret = wasm.sdkcontext_fromTrustedRoots(roots);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SdkContext.__wrap(ret[0]);
    }
    /**
     * Load a published SignedRevocationList. The SRL must be signed by a trusted root.
     * @param {string} wire
     */
    loadRevocationList(wire) {
        const ptr0 = passStringToWasm0(wire, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sdkcontext_loadRevocationList(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Mint a short-lived session from an allow map:
     * `{ "read_file": { "path": { "kind": "under", "root": "/data" } } }`
     *
     * `require_approval` is optional:
     * `{ "approvers": ["hex..."], "min": 2, "tools": ["transfer"] }`
     * @param {any} allow_json
     * @param {number} ttl_seconds
     * @param {any} require_approval
     * @returns {SdkSession}
     */
    mint(allow_json, ttl_seconds, require_approval) {
        const ret = wasm.sdkcontext_mint(this.__wbg_ptr, allow_json, ttl_seconds, require_approval);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SdkSession.__wrap(ret[0]);
    }
    /**
     * Attenuate the leaf. The current holder signs; the same holder keeps the child.
     * @param {SdkSession} session
     * @param {any} allow_json
     * @returns {SdkSession}
     */
    narrow(session, allow_json) {
        _assertClass(session, SdkSession);
        const ret = wasm.sdkcontext_narrow(this.__wbg_ptr, session.__wbg_ptr, allow_json);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SdkSession.__wrap(ret[0]);
    }
    constructor() {
        const ret = wasm.sdkcontext_new();
        this.__wbg_ptr = ret;
        SdkContextFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Holder PoP only. Does not authorize. Used to fill `_meta.tenuo.signature`.
     * @param {SdkSession} session
     * @param {string} tool
     * @param {any} args_json
     * @returns {string}
     */
    signPop(session, tool, args_json) {
        let deferred3_0;
        let deferred3_1;
        try {
            _assertClass(session, SdkSession);
            const ptr0 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.sdkcontext_signPop(this.__wbg_ptr, session.__wbg_ptr, ptr0, len0, args_json);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Test / host seam. Signs an SRL with the local issuer. Does not load it.
     * @param {any} ids
     * @returns {string}
     */
    signRevocationList(ids) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.sdkcontext_signRevocationList(this.__wbg_ptr, ids);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
}
if (Symbol.dispose) SdkContext.prototype[Symbol.dispose] = SdkContext.prototype.free;
exports.SdkContext = SdkContext;

/**
 * Opaque warrant chain (root first) + leaf holder key. Not JSON-serializable from JS.
 */
class SdkSession {
    static __wrap(ptr) {
        const obj = Object.create(SdkSession.prototype);
        obj.__wbg_ptr = ptr;
        SdkSessionFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SdkSessionFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_sdksession_free(ptr, 0);
    }
    /**
     * Application idempotency key: SHA-256 of `(warrant_id, tool, canonical args)`.
     * Not a PoP. MCP replay uses the PoP signature, not this key.
     * @param {string} tool
     * @param {any} args_json
     * @returns {string}
     */
    dedupKey(tool, args_json) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.sdksession_dedupKey(this.__wbg_ptr, ptr0, len0, args_json);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Test / interop seam. Not on the public TypeScript Session type.
     * @returns {any}
     */
    exportWire() {
        const ret = wasm.sdksession_exportWire(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Import a chain: string[] of wire tokens, or `{ payload_hex, signature_hex }[]`.
     * @param {any} parts
     * @param {Uint8Array} holder_secret
     * @returns {SdkSession}
     */
    static fromChain(parts, holder_secret) {
        const ptr0 = passArray8ToWasm0(holder_secret, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sdksession_fromChain(parts, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SdkSession.__wrap(ret[0]);
    }
    /**
     * Reconstruct a warrant from published payload + signature hex (A.14).
     * @param {string} payload_hex
     * @param {string} signature_hex
     * @param {Uint8Array} holder_secret
     * @returns {SdkSession}
     */
    static fromParts(payload_hex, signature_hex, holder_secret) {
        const ptr0 = passStringToWasm0(payload_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(signature_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(holder_secret, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.sdksession_fromParts(ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SdkSession.__wrap(ret[0]);
    }
    /**
     * Import a published warrant (base64 or envelope hex) plus the holder secret.
     * @param {string} warrant
     * @param {Uint8Array} holder_secret
     * @returns {SdkSession}
     */
    static fromWire(warrant, holder_secret) {
        const ptr0 = passStringToWasm0(warrant, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(holder_secret, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.sdksession_fromWire(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SdkSession.__wrap(ret[0]);
    }
    /**
     * CBOR warrant stack as standard base64. Matches Python `encode_warrant_stack`.
     * @returns {string}
     */
    toStackWire() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.sdksession_toStackWire(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Warrant tokens, root first. Does not include the holder secret.
     * @returns {any}
     */
    toWire() {
        const ret = wasm.sdksession_toWire(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Warrant IDs, root first. Test / revoke seam.
     * @returns {any}
     */
    warrantIds() {
        const ret = wasm.sdksession_warrantIds(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
}
if (Symbol.dispose) SdkSession.prototype[Symbol.dispose] = SdkSession.prototype.free;
exports.SdkSession = SdkSession;

/**
 * @param {string} warrant_b64
 * @param {string} tool
 * @param {any} args_json
 * @param {string} trusted_root_hex
 * @param {boolean} dry_run
 * @returns {any}
 */
function check_access(warrant_b64, tool, args_json, trusted_root_hex, dry_run) {
    const ptr0 = passStringToWasm0(warrant_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(trusted_root_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.check_access(ptr0, len0, ptr1, len1, args_json, ptr2, len2, dry_run);
    return ret;
}
exports.check_access = check_access;

/**
 * Check authorization with a real PoP signature
 * @param {string} warrant_b64
 * @param {string} tool
 * @param {any} args_json
 * @param {string} trusted_root_hex
 * @param {string} pop_signature_hex
 * @returns {any}
 */
function check_access_with_pop(warrant_b64, tool, args_json, trusted_root_hex, pop_signature_hex) {
    const ptr0 = passStringToWasm0(warrant_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(trusted_root_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(pop_signature_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.check_access_with_pop(ptr0, len0, ptr1, len1, args_json, ptr2, len2, ptr3, len3);
    return ret;
}
exports.check_access_with_pop = check_access_with_pop;

/**
 * @param {string[]} warrant_b64_list
 * @param {string} tool
 * @param {any} args_json
 * @param {string} trusted_root_hex
 * @param {boolean} dry_run
 * @returns {any}
 */
function check_chain_access(warrant_b64_list, tool, args_json, trusted_root_hex, dry_run) {
    const ptr0 = passArrayJsValueToWasm0(warrant_b64_list, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(trusted_root_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.check_chain_access(ptr0, len0, ptr1, len1, args_json, ptr2, len2, dry_run);
    return ret;
}
exports.check_chain_access = check_chain_access;

/**
 * Check a warrant chain with signed approvals and optional revocation list.
 *
 * Extends `check_chain_access` with:
 * - `approvals_b64`: JS array of base64-encoded CBOR `SignedApproval` blobs for M-of-N
 *   approval verification (pass `[]` if not needed).
 * - `srl_b64`: optional base64-encoded CBOR `SignedRevocationList`. When provided, the
 *   SRL is verified (using the trusted root as its issuer) and applied before chain checks.
 *   Pass `null`/`undefined` to skip revocation checking.
 * @param {string[]} warrant_b64_list
 * @param {string} tool
 * @param {any} args_json
 * @param {string} trusted_root_hex
 * @param {any} approvals_b64
 * @param {string | null} [srl_b64]
 * @returns {any}
 */
function check_chain_access_with_approvals(warrant_b64_list, tool, args_json, trusted_root_hex, approvals_b64, srl_b64) {
    const ptr0 = passArrayJsValueToWasm0(warrant_b64_list, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(trusted_root_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(srl_b64) ? 0 : passStringToWasm0(srl_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.check_chain_access_with_approvals(ptr0, len0, ptr1, len1, args_json, ptr2, len2, approvals_b64, ptr3, len3);
    return ret;
}
exports.check_chain_access_with_approvals = check_chain_access_with_approvals;

/**
 * Check if a warrant ID appears in a signed revocation list.
 *
 * Does not verify the SRL signature — call `verify_srl` first if you need
 * signature assurance. Returns `{ revoked, error? }`.
 * @param {string} warrant_id
 * @param {string} srl_cbor_b64
 * @returns {any}
 */
function check_revocation(warrant_id, srl_cbor_b64) {
    const ptr0 = passStringToWasm0(warrant_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(srl_cbor_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.check_revocation(ptr0, len0, ptr1, len1);
    return ret;
}
exports.check_revocation = check_revocation;

/**
 * Compute the canonical request hash for a (warrant, tool, args) tuple.
 *
 * The hash is SHA-256(warrant_id | tool | CBOR(sorted_args) | holder_key) and is
 * what every SignedApproval must cover. Use this to build the payload for
 * POST /v1/approvals/requests so the backend can verify it matches.
 *
 * Returns `{ "hash": "<hex>" }` on success, or `{ "hash": null, "error": "..." }` on failure.
 * @param {string} warrant_b64
 * @param {string} tool
 * @param {any} args_json
 * @returns {any}
 */
function compute_request_hash_wasm(warrant_b64, tool, args_json) {
    const ptr0 = passStringToWasm0(warrant_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.compute_request_hash_wasm(ptr0, len0, ptr1, len1, args_json);
    return ret;
}
exports.compute_request_hash_wasm = compute_request_hash_wasm;

/**
 * Create a self-signed root Issuer warrant for use as a persistent trust anchor.
 * This is called once during plugin setup and stored on disk.
 * The Issuer warrant's keypair replaces per-session signing keys — all Execution
 * warrants (depth ≥ 1) are derived from it, enabling proper WASM chain verification
 * across plugin restarts.
 *
 * Config: { signing_key_hex?: string, issuable_tools: string[], max_issue_depth?: number, ttl_seconds?: number }
 * @param {any} config_json
 * @returns {any}
 */
function create_issuer_warrant(config_json) {
    const ret = wasm.create_issuer_warrant(config_json);
    return ret;
}
exports.create_issuer_warrant = create_issuer_warrant;

/**
 * Create a fresh sample warrant with the given tool and TTL
 * This generates new keys each time, ensuring the warrant is never expired
 * @param {string} tool
 * @param {string} constraint_field
 * @param {string} constraint_pattern
 * @param {bigint} ttl_seconds
 * @returns {any}
 */
function create_sample_warrant(tool, constraint_field, constraint_pattern, ttl_seconds) {
    const ptr0 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(constraint_field, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(constraint_pattern, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.create_sample_warrant(ptr0, len0, ptr1, len1, ptr2, len2, ttl_seconds);
    return ret;
}
exports.create_sample_warrant = create_sample_warrant;

/**
 * Create a warrant from the full builder config (multiple tools, multiple constraints)
 * This is more flexible than create_sample_warrant
 * @param {any} config_json
 * @returns {any}
 */
function create_warrant_from_config(config_json) {
    const ret = wasm.create_warrant_from_config(config_json);
    return ret;
}
exports.create_warrant_from_config = create_warrant_from_config;

/**
 * Decode a PEM chain (or single warrant) and return detailed chain analysis
 * @param {string} input
 * @returns {any}
 */
function decode_pem_chain_wasm(input) {
    const ptr0 = passStringToWasm0(input, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.decode_pem_chain_wasm(ptr0, len0);
    return ret;
}
exports.decode_pem_chain_wasm = decode_pem_chain_wasm;

/**
 * @param {string} base64_warrant
 * @returns {any}
 */
function decode_warrant(base64_warrant) {
    const ptr0 = passStringToWasm0(base64_warrant, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.decode_warrant(ptr0, len0);
    return ret;
}
exports.decode_warrant = decode_warrant;

/**
 * Evaluate whether a tool call requires approval based on the warrant's embedded approval gates.
 *
 * Returns `{ approval_required: true/false, tool, error }`.
 * This reads `extensions["tenuo.approval_gates"]` from the warrant, parses it,
 * and runs the gate evaluation logic from tenuo-core.
 * @param {string} warrant_b64
 * @param {string} tool
 * @param {any} args_json
 * @returns {any}
 */
function evaluate_approval_gates(warrant_b64, tool, args_json) {
    const ptr0 = passStringToWasm0(warrant_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.evaluate_approval_gates(ptr0, len0, ptr1, len1, args_json);
    return ret;
}
exports.evaluate_approval_gates = evaluate_approval_gates;

/**
 * Generate a new Ed25519 keypair for testing PoP
 * @returns {any}
 */
function generate_keypair() {
    const ret = wasm.generate_keypair();
    return ret;
}
exports.generate_keypair = generate_keypair;

function init_panic_hook() {
    wasm.init_panic_hook();
}
exports.init_panic_hook = init_panic_hook;

/**
 * Parse a `TENUO_CONNECT_TOKEN` string into its component fields.
 *
 * The token is a base64url-encoded JSON blob: `{ v, e, k, a?, t? }`.
 * This WASM binding keeps the parsing canonical so TypeScript doesn't need
 * to duplicate the decode logic.
 *
 * Returns `{ endpoint, apiKey, agentId?, registrationToken?, error? }`.
 * @param {string} token
 * @returns {any}
 */
function parse_connect_token(token) {
    const ptr0 = passStringToWasm0(token, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parse_connect_token(ptr0, len0);
    return ret;
}
exports.parse_connect_token = parse_connect_token;

/**
 * @param {string} payload_hex
 * @param {string} signature_hex
 * @returns {any}
 */
function sdkInspectParts(payload_hex, signature_hex) {
    const ptr0 = passStringToWasm0(payload_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(signature_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.sdkInspectParts(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}
exports.sdkInspectParts = sdkInspectParts;

/**
 * @param {string} wire
 * @returns {any}
 */
function sdkInspectWarrant(wire) {
    const ptr0 = passStringToWasm0(wire, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkInspectWarrant(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}
exports.sdkInspectWarrant = sdkInspectWarrant;

/**
 * Test / host seam. Signs a SignedApproval envelope; does not authorize.
 * @param {SdkSession} session
 * @param {string} tool
 * @param {any} args_json
 * @param {Uint8Array} approver_secret
 * @param {string} external_id
 * @param {number | null} [as_of]
 * @returns {string}
 */
function sdkSignApproval(session, tool, args_json, approver_secret, external_id, as_of) {
    let deferred5_0;
    let deferred5_1;
    try {
        _assertClass(session, SdkSession);
        const ptr0 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(approver_secret, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(external_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.sdkSignApproval(session.__wbg_ptr, ptr0, len0, args_json, ptr1, len1, ptr2, len2, !isLikeNone(as_of), isLikeNone(as_of) ? 0 : as_of);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.sdkSignApproval = sdkSignApproval;

/**
 * Test seam. Signs the published generator envelope (not the in-memory SRL codec).
 * @param {any} ids
 * @param {number} version
 * @param {Uint8Array} issuer_secret
 * @returns {string}
 */
function sdkSignPublishedRevocationList(ids, version, issuer_secret) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(issuer_secret, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sdkSignPublishedRevocationList(ids, version, ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}
exports.sdkSignPublishedRevocationList = sdkSignPublishedRevocationList;

/**
 * Test / host seam. Signs an SRL with a provided issuer secret. Does not load it.
 * @param {any} ids
 * @param {Uint8Array} issuer_secret
 * @returns {string}
 */
function sdkSignRevocationList(ids, issuer_secret) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(issuer_secret, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sdkSignRevocationList(ids, ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}
exports.sdkSignRevocationList = sdkSignRevocationList;

/**
 * Signature authenticity only. Not authorization.
 * @param {string} wire
 * @returns {any}
 */
function sdkVerifyReceipt(wire) {
    const ptr0 = passStringToWasm0(wire, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkVerifyReceipt(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}
exports.sdkVerifyReceipt = sdkVerifyReceipt;

/**
 * Verify a receipt's embedded warrant chain against trusted roots, at the
 * receipt's own decision instant.
 *
 * This is the root-anchored half of receipt verification: it needs no trust
 * in `signer_key` at all, because the chain is signed by the root and the
 * holder, not by the enforcement point. The signature over the receipt is
 * still checked first — an unauthenticated payload is never parsed into a
 * chain to verify.
 *
 * A deny receipt whose chain fails with the same error it states is
 * *corroborated*: the embedded authority independently supports the refusal.
 * A deny whose chain verifies is not inconsistent — constraint and
 * possession failures deny over a valid chain, and chain-level verification
 * does not evaluate those.
 * @param {string} wire
 * @param {any} roots
 * @returns {any}
 */
function sdkVerifyReceiptChain(wire, roots) {
    const ptr0 = passStringToWasm0(wire, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sdkVerifyReceiptChain(ptr0, len0, roots);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}
exports.sdkVerifyReceiptChain = sdkVerifyReceiptChain;

/**
 * Create a Proof-of-Possession signature for a warrant
 * @param {string} private_key_hex
 * @param {string} warrant_b64
 * @param {string} tool
 * @param {any} args_json
 * @returns {any}
 */
function sign(private_key_hex, warrant_b64, tool, args_json) {
    const ptr0 = passStringToWasm0(private_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(warrant_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(tool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.sign(ptr0, len0, ptr1, len1, ptr2, len2, args_json);
    return ret;
}
exports.sign = sign;

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
 * @param {any} payload_json
 * @param {string} authorizer_key_hex
 * @returns {any}
 */
function sign_receipt(payload_json, authorizer_key_hex) {
    const ptr0 = passStringToWasm0(authorizer_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sign_receipt(payload_json, ptr0, len0);
    return ret;
}
exports.sign_receipt = sign_receipt;

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
 * @param {string} warrant_b64
 * @param {string} request_hash_hex
 * @param {any} approvals_b64
 * @returns {any}
 */
function verify_approval_set(warrant_b64, request_hash_hex, approvals_b64) {
    const ptr0 = passStringToWasm0(warrant_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(request_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.verify_approval_set(ptr0, len0, ptr1, len1, approvals_b64);
    return ret;
}
exports.verify_approval_set = verify_approval_set;

/**
 * Verify a single signed approval blob and return its payload.
 *
 * `approval_cbor_b64` — base64-encoded CBOR `SignedApproval`.
 *
 * Returns `{ valid, approver_hex, request_hash_hex, approved_at, expires_at, error? }`.
 * @param {string} approval_cbor_b64
 * @returns {any}
 */
function verify_signed_approval(approval_cbor_b64) {
    const ptr0 = passStringToWasm0(approval_cbor_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.verify_signed_approval(ptr0, len0);
    return ret;
}
exports.verify_signed_approval = verify_signed_approval;

/**
 * Verify a signed revocation list and return its metadata.
 *
 * `srl_cbor_b64` — base64-encoded CBOR `SignedRevocationList`.
 * `expected_issuer_hex` — hex-encoded Ed25519 public key of the expected SRL issuer.
 *
 * Returns `{ valid, version, revoked_count, issued_at, error? }`.
 * @param {string} srl_cbor_b64
 * @param {string} expected_issuer_hex
 * @returns {any}
 */
function verify_srl(srl_cbor_b64, expected_issuer_hex) {
    const ptr0 = passStringToWasm0(srl_cbor_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(expected_issuer_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.verify_srl(ptr0, len0, ptr1, len1);
    return ret;
}
exports.verify_srl = verify_srl;
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_fdd633d4bb5dd76a: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_Number_c4bdf66bb78f7977: function(arg0) {
            const ret = Number(arg0);
            return ret;
        },
        __wbg_String_8564e559799eccda: function(arg0, arg1) {
            const ret = String(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_bigint_get_as_i64_d9e915702856f831: function(arg0, arg1) {
            const v = arg1;
            const ret = typeof(v) === 'bigint' ? v : undefined;
            getDataViewMemory0().setBigInt64(arg0 + 8 * 1, isLikeNone(ret) ? BigInt(0) : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_boolean_get_edaed31a367ce1bd: function(arg0) {
            const v = arg0;
            const ret = typeof(v) === 'boolean' ? v : undefined;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_8a447059637473e2: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_in_4990f46af709e33c: function(arg0, arg1) {
            const ret = arg0 in arg1;
            return ret;
        },
        __wbg___wbindgen_is_bigint_90b5ccfe67c78460: function(arg0) {
            const ret = typeof(arg0) === 'bigint';
            return ret;
        },
        __wbg___wbindgen_is_function_acc5528be2b923f2: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_null_6d937fbfb6478470: function(arg0) {
            const ret = arg0 === null;
            return ret;
        },
        __wbg___wbindgen_is_object_0beba4a1980d3eea: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_1fca8072260dd261: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_721f8decd50c87a3: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_jsval_eq_4e8c38722cb8ff51: function(arg0, arg1) {
            const ret = arg0 === arg1;
            return ret;
        },
        __wbg___wbindgen_jsval_loose_eq_4b9aba9e5b3c4582: function(arg0, arg1) {
            const ret = arg0 == arg1;
            return ret;
        },
        __wbg___wbindgen_number_get_1cc01dd708740256: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'number' ? obj : undefined;
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_string_get_71bb4348194e31f0: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_ea4887a5f8f9a9db: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg___wbindgen_typeof_fee77315c05833ec: function(arg0) {
            const ret = typeof arg0;
            return ret;
        },
        __wbg_call_8e98ed2f3c86c4b5: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_done_b62d4a7d2286852a: function(arg0) {
            const ret = arg0.done;
            return ret;
        },
        __wbg_entries_c261c3fa1f281256: function(arg0) {
            const ret = Object.entries(arg0);
            return ret;
        },
        __wbg_error_a6fa202b58aa1cd3: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_from_50138b2ca136f50c: function(arg0) {
            const ret = Array.from(arg0);
            return ret;
        },
        __wbg_getRandomValues_a697888e9ba1eee3: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_cc7f052a444bb2ce: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getTime_7a770f8a2ec8d634: function(arg0) {
            const ret = arg0.getTime();
            return ret;
        },
        __wbg_get_197a3fe98f169e38: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_9a29be2cb383ed9a: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_dddb90ff5d27a080: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_unchecked_54a4374c38e08460: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_with_ref_key_6412cf3094599694: function(arg0, arg1) {
            const ret = arg0[arg1];
            return ret;
        },
        __wbg_instanceof_ArrayBuffer_2a7bb09fee70c2da: function(arg0) {
            let result;
            try {
                result = arg0 instanceof ArrayBuffer;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Map_afa18d5840c04c15: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Map;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Uint8Array_f080092dc70f5d58: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_isArray_145a34fd0a38d37b: function(arg0) {
            const ret = Array.isArray(arg0);
            return ret;
        },
        __wbg_isSafeInteger_a3389a198582f5f6: function(arg0) {
            const ret = Number.isSafeInteger(arg0);
            return ret;
        },
        __wbg_iterator_cc47ba25a2be735a: function() {
            const ret = Symbol.iterator;
            return ret;
        },
        __wbg_keys_e2132f5645c137bf: function(arg0) {
            const ret = Object.keys(arg0);
            return ret;
        },
        __wbg_length_589238bdcf171f0e: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_c6054974c0a6cdb9: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_new_0_1b32bedde98fef4b: function() {
            const ret = new Date();
            return ret;
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_2e117a478906f062: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_3444eb7412549f0b: function() {
            const ret = new Map();
            return ret;
        },
        __wbg_new_36e147a8ced3c6e0: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_81880fb5002cb255: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_next_0c4066e251d2eff9: function() { return handleError(function (arg0) {
            const ret = arg0.next();
            return ret;
        }, arguments); },
        __wbg_next_402fa10b59ab20c3: function(arg0) {
            const ret = arg0.next;
            return ret;
        },
        __wbg_now_ad5c9ea5a44932af: function() { return handleError(function () {
            const ret = Date.now();
            return ret;
        }, arguments); },
        __wbg_prototypesetcall_d721637c7ca66eb8: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_set_6be42768c690e380: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_set_9a1d61e17de7054c: function(arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        },
        __wbg_set_dc601f4a69da0bc2: function(arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_value_49f783bb59765962: function(arg0) {
            const ret = arg0.value;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0) {
            // Cast intrinsic for `I64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./tenuo_wasm_bg.js": import0,
    };
}

const SdkContextFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_sdkcontext_free(ptr, 1));
const SdkSessionFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_sdksession_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    for (let i = 0; i < array.length; i++) {
        const add = addToExternrefTable0(array[i]);
        getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
function decodeText(ptr, len) {
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

const wasmPath = `${__dirname}/tenuo_wasm_bg.wasm`;
const wasmBytes = require('fs').readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
let wasmInstance = new WebAssembly.Instance(wasmModule, __wbg_get_imports());
let wasm = wasmInstance.exports;
wasm.__wbindgen_start();
