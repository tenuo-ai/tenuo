//! Production TypeScript SDK bindings.
//!
//! One WASM call signs PoP and authorizes — the same sequence as the Python
//! SDK, without exposing the intermediate signature to JavaScript.
//! Explorer-facing JSON helpers stay in `lib.rs`.

use base64::Engine;
use chrono::Utc;
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tenuo::approval::{compute_request_hash, ApprovalPayload, SignedApproval};
use tenuo::constraints::Subpath;
use tenuo::payload::WarrantPayload;
use tenuo::receipt::{Receipt, ReceiptPayload};
use tenuo::wire::WarrantStack;
use tenuo::{
    encode_approval_gate_map, wire, ApprovalGateMap, Authorizer, Constraint, ConstraintSet,
    ConstraintValue, Error, Exact, OneOf, Pattern, PublicKey, Range, Signature,
    SignedRevocationList, SigningKey, ToolApprovalGate, Warrant, APPROVAL_GATE_EXTENSION_KEY,
    MAX_CONSTRAINT_DEPTH, MAX_DELEGATION_DEPTH, MAX_WARRANT_SIZE,
};
use wasm_bindgen::prelude::*;

use crate::init_panic_hook;

const DEFAULT_TTL_SECS: u64 = 300;
/// Bound JS values before they become Rust allocations. Core still enforces
/// [`MAX_WARRANT_SIZE`] / [`MAX_CONSTRAINT_DEPTH`] after decode.
const MAX_ARG_KEYS: usize = 256;
const MAX_COLLECTION_LEN: usize = 1024;
const MAX_INPUT_NODES: usize = 2048;
const MAX_INPUT_KEY_BYTES: usize = MAX_WARRANT_SIZE;
const MAX_INPUT_VALUE_BYTES: usize = MAX_WARRANT_SIZE;
const MAX_POP_CHARS: usize = 256;
const MAX_ENCODED_WARRANT_CHARS: usize = MAX_WARRANT_SIZE * 2;
/// Encoded chain cap follows core [`wire::MAX_STACK_SIZE`], not depth × warrant.
const MAX_ENCODED_CHAIN_CHARS: usize = wire::MAX_STACK_SIZE * 2;

#[derive(Default)]
struct InputBudget {
    nodes: usize,
    key_bytes: usize,
    value_bytes: usize,
}

impl InputBudget {
    fn charge_node(&mut self) -> Result<(), String> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_INPUT_NODES {
            return Err(format!(
                "arguments exceed the WASM node budget of {MAX_INPUT_NODES}"
            ));
        }
        Ok(())
    }

    fn charge_key(&mut self, len: usize) -> Result<(), String> {
        self.key_bytes = self.key_bytes.saturating_add(len);
        if self.key_bytes > MAX_INPUT_KEY_BYTES {
            return Err(format!(
                "arguments exceed the WASM key budget of {MAX_INPUT_KEY_BYTES} bytes"
            ));
        }
        Ok(())
    }

    fn charge_value(&mut self, len: usize) -> Result<(), String> {
        self.value_bytes = self.value_bytes.saturating_add(len);
        if self.value_bytes > MAX_INPUT_VALUE_BYTES {
            return Err(format!(
                "arguments exceed the WASM value budget of {MAX_INPUT_VALUE_BYTES} bytes"
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct DecisionDto {
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    args: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    received: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<String>,
}

#[derive(Serialize)]
struct InspectDto {
    payload_hex: String,
    signature_hex: String,
    id: String,
}

#[derive(Serialize)]
struct ReceiptInspectDto {
    authentic: bool,
    outcome: String,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision_code: Option<String>,
    request_id: String,
    /// Absent when the enforcement point held no revocation data at all —
    /// a different claim from holding a list that revoked nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    srl_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    srl_hash: Option<String>,
    /// Commitment to the host ceiling applied to this decision.
    /// Commitment to the canonical invocation this decision was made over.
    #[serde(skip_serializing_if = "Option::is_none")]
    request_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_definition_hash: Option<String>,
    /// Link to the previous receipt from this signer. Absent on the first, or
    /// when the deployment does not chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_receipt_hash: Option<String>,
    /// Commitment to the trusted root set in force.
    #[serde(skip_serializing_if = "Option::is_none")]
    trusted_roots_hash: Option<String>,
}

#[derive(Serialize)]
struct ExportDto {
    warrants: Vec<String>,
    holder_hex: String,
    root_hex: String,
}

/// Issuer + authorizer for `createTenuo({ root: devRoot() })`.
/// Verifier-only contexts have `issuer: None` and cannot mint.
#[wasm_bindgen]
pub struct SdkContext {
    issuer: Option<SigningKey>,
    authorizer: Authorizer,
    trusted_roots: Vec<PublicKey>,
    receipt_signer: SigningKey,
    /// `(version, sha256(wire bytes))` of the revocation list currently loaded.
    /// `None` until one is installed — receipts then omit keys 12 and 13, which
    /// is the honest claim that revocation was never consulted.
    srl_commitment: Option<(Option<u64>, [u8; 32])>,
    /// Commitment to the trusted root set (receipt key 15). Fixed at
    /// construction because the trust anchors do not change over a context's
    /// life.
    trusted_roots_hash: [u8; 32],
    /// Digest of the last receipt this context emitted (receipt key 14).
    ///
    /// `Cell` because authorization takes `&self` and chaining is inherently
    /// stateful. Single-threaded by construction: wasm has no threads, and one
    /// context serves one enforcement point.
    last_receipt_hash: std::cell::Cell<Option<[u8; 32]>>,
}

/// Opaque warrant chain (root first) + leaf holder key. Not JSON-serializable from JS.
#[wasm_bindgen]
pub struct SdkSession {
    chain: Vec<Warrant>,
    holder: SigningKey,
}

impl Default for SdkContext {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl SdkContext {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SdkContext {
        init_panic_hook();
        let issuer = SigningKey::generate();
        let root = issuer.public_key();
        let authorizer = Authorizer::new().with_trusted_root(root.clone());
        SdkContext {
            srl_commitment: None,
            trusted_roots_hash: tenuo::trusted_roots_digest(&[root.to_bytes()]),
            last_receipt_hash: std::cell::Cell::new(None),
            issuer: Some(issuer.clone()),
            authorizer,
            trusted_roots: vec![root],
            receipt_signer: issuer,
        }
    }

    /// Authorizer-only context. `mint()` fails; import a session from the wire.
    #[wasm_bindgen(js_name = fromTrustedRoots)]
    pub fn from_trusted_roots(roots: JsValue) -> Result<SdkContext, JsError> {
        init_panic_hook();
        let hexes: Vec<String> = serde_wasm_bindgen::from_value(roots).map_err(|e| {
            JsError::new(&format!("trustedRoots must be an array of hex keys: {e}"))
        })?;
        if hexes.is_empty() {
            return Err(JsError::new("trustedRoots must not be empty"));
        }
        let mut authorizer = Authorizer::new();
        let mut trusted_roots = Vec::with_capacity(hexes.len());
        for hex in hexes {
            let key = parse_public_key_hex(&hex)?;
            authorizer = authorizer.with_trusted_root(key.clone());
            trusted_roots.push(key);
        }
        Ok(SdkContext {
            srl_commitment: None,
            trusted_roots_hash: tenuo::trusted_roots_digest(
                &trusted_roots.iter().map(|r| r.to_bytes()).collect::<Vec<_>>(),
            ),
            last_receipt_hash: std::cell::Cell::new(None),
            issuer: None,
            authorizer,
            trusted_roots,
            receipt_signer: SigningKey::generate(),
        })
    }

    /// Load a published SignedRevocationList. The SRL must be signed by a trusted root.
    #[wasm_bindgen(js_name = loadRevocationList)]
    pub fn load_revocation_list(&mut self, wire: &str) -> Result<(), JsError> {
        init_panic_hook();
        let bytes = parse_srl_bytes(wire)?;
        let digest = tenuo::srl_commitment_digest(&bytes);
        match SignedRevocationList::from_bytes(&bytes) {
            Ok(srl) => {
                let mut last = None;
                for root in &self.trusted_roots {
                    match self.authorizer.set_revocation_list(srl.clone(), root) {
                        Ok(()) => {
                            self.srl_commitment = Some((None, digest));
                            return Ok(());
                        }
                        Err(e) => last = Some(e),
                    }
                }
                Err(JsError::new(&format!(
                    "revocation list is not signed by a trusted root: {}",
                    last.map(|e| e.to_string())
                        .unwrap_or_else(|| "no trusted roots".into())
                )))
            }
            Err(_) => {
                let published = verify_published_srl(&bytes, &self.trusted_roots)?;
                let version = published.version;
                self.authorizer
                    .install_verified_revocation_ids(published.revoked_ids, version)
                    .map_err(|e| JsError::new(&format!("failed to install revocation list: {e}")))?;
                self.srl_commitment = Some((Some(version), digest));
                Ok(())
            }
        }
    }

    /// Test / host seam. Signs an SRL with the local issuer. Does not load it.
    #[wasm_bindgen(js_name = signRevocationList)]
    pub fn sign_revocation_list(&self, ids: JsValue) -> Result<String, JsError> {
        init_panic_hook();
        let issuer = self.issuer.as_ref().ok_or_else(|| {
            JsError::new("signRevocationList() needs a local issuer (devRoot context)")
        })?;
        sign_srl_hex(ids, issuer)
    }

    /// Mint a short-lived session from an allow map:
    /// `{ "read_file": { "path": { "kind": "under", "root": "/data" } } }`
    ///
    /// `require_approval` is optional:
    /// `{ "approvers": ["hex..."], "min": 2, "tools": ["transfer"] }`
    #[wasm_bindgen]
    pub fn mint(
        &self,
        allow_json: JsValue,
        ttl_seconds: u32,
        require_approval: JsValue,
    ) -> Result<SdkSession, JsError> {
        init_panic_hook();
        let holder = SigningKey::generate();
        let ttl = if ttl_seconds == 0 {
            DEFAULT_TTL_SECS
        } else {
            u64::from(ttl_seconds)
        };

        let allow: HashMap<String, HashMap<String, serde_json::Value>> =
            serde_wasm_bindgen::from_value(allow_json)
                .map_err(|e| JsError::new(&format!("invalid allow policy: {e}")))?;

        if allow.is_empty() {
            return Err(JsError::new(
                "allow policy must name at least one capability",
            ));
        }

        let tool_names: Vec<String> = allow.keys().cloned().collect();
        let mut builder = Warrant::builder()
            .ttl(Duration::from_secs(ttl))
            .holder(holder.public_key());

        for (tool, fields) in allow {
            let mut set = ConstraintSet::new();
            for (field, expr) in fields {
                let constraint = constraint_from_expr(&expr)
                    .map_err(|e| JsError::new(&format!("allow.{tool}.{field}: {e}")))?;
                set.insert(field, constraint);
            }
            builder = builder.capability(tool, set);
        }

        builder = apply_require_approval(builder, &require_approval, &tool_names)?;

        let issuer = self.issuer.as_ref().ok_or_else(|| {
            JsError::new(
                "session() mints a warrant and needs a local issuer. Use createTenuo({ root: createTenuo.devRoot() }).",
            )
        })?;

        let warrant = builder
            .build(issuer)
            .map_err(|e| JsError::new(&format!("failed to mint session: {e}")))?;

        Ok(SdkSession {
            chain: vec![warrant],
            holder,
        })
    }

    /// Attenuate the leaf. The current holder signs; the same holder keeps the child.
    #[wasm_bindgen]
    pub fn narrow(&self, session: &SdkSession, allow_json: JsValue) -> Result<SdkSession, JsError> {
        init_panic_hook();
        let leaf = session.leaf()?;
        let tools = tools_for_narrow(leaf, &allow_json)?;
        if tools.is_empty() {
            return Err(JsError::new("narrow() requires at least one capability"));
        }

        let mut builder = leaf.attenuate();
        for (tool, set) in tools {
            builder = builder.capability(tool, set);
        }
        let child = builder
            .build(&session.holder)
            .map_err(|e| JsError::new(&format!("TENUO_CHAIN_INVALID: {e}")))?;

        let mut chain = session.chain.clone();
        chain.push(child);
        Ok(SdkSession {
            chain,
            holder: session.holder.clone(),
        })
    }

    /// Sign PoP and authorize in one call. Never returns allow without a core allow.
    ///
    /// `tool_allow` is the wrapper ceiling (`tenuo.tool(..., { allow })`). Null/undefined
    /// means no extra ceiling. Session and ceiling are AND'd; Rust decides both.
    #[wasm_bindgen]
    pub fn authorize(
        &self,
        session: &SdkSession,
        tool: &str,
        args_json: JsValue,
        approvals: JsValue,
        tool_allow: JsValue,
        request_id: Option<String>,
    ) -> JsValue {
        self.authorize_inner(
            session,
            tool,
            args_json,
            approvals,
            tool_allow,
            None,
            request_id,
        )
    }

    /// Test / replay seam. Not exposed on `createTenuo` or `execute`.
    #[wasm_bindgen(js_name = authorizeAsOf)]
    pub fn authorize_as_of(
        &self,
        session: &SdkSession,
        tool: &str,
        args_json: JsValue,
        as_of: f64,
        approvals: JsValue,
        tool_allow: JsValue,
    ) -> JsValue {
        self.authorize_inner(
            session,
            tool,
            args_json,
            approvals,
            tool_allow,
            Some(as_of as i64),
            None,
        )
    }

    /// Holder PoP only. Does not authorize. Used to fill `_meta.tenuo.signature`.
    #[wasm_bindgen(js_name = signPop)]
    pub fn sign_pop(
        &self,
        session: &SdkSession,
        tool: &str,
        args_json: JsValue,
    ) -> Result<String, JsError> {
        init_panic_hook();
        let args = js_to_args(&args_json).map_err(|e| JsError::new(&e))?;
        let leaf = session.leaf()?;
        let signature = leaf
            .sign(&session.holder, tool, &args)
            .map_err(|e| JsError::new(&format!("failed to sign proof-of-possession: {e}")))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
    }

    /// Authorize a warrant + PoP presented on the wire. No holder secret.
    ///
    /// `tool_allow` is the server host ceiling (`mcp.handler(..., { allow })`).
    /// Null/undefined: no extra ceiling. Empty object: open.
    #[wasm_bindgen(js_name = authorizePresented)]
    pub fn authorize_presented(
        &self,
        warrants: JsValue,
        tool: &str,
        args_json: JsValue,
        pop: &str,
        approvals: JsValue,
        tool_allow: JsValue,
        request_id: Option<String>,
    ) -> JsValue {
        self.authorize_presented_inner(
            warrants,
            tool,
            args_json,
            pop,
            approvals,
            tool_allow,
            None,
            request_id,
        )
    }
}

#[wasm_bindgen]
impl SdkSession {
    /// Import a published warrant (base64 or envelope hex) plus the holder secret.
    #[wasm_bindgen(js_name = fromWire)]
    pub fn from_wire(warrant: &str, holder_secret: &[u8]) -> Result<SdkSession, JsError> {
        init_panic_hook();
        session_from_chain(parse_chain(warrant)?, holder_secret)
    }

    /// Reconstruct a warrant from published payload + signature hex (A.14).
    #[wasm_bindgen(js_name = fromParts)]
    pub fn from_parts(
        payload_hex: &str,
        signature_hex: &str,
        holder_secret: &[u8],
    ) -> Result<SdkSession, JsError> {
        init_panic_hook();
        session_from_chain(
            vec![warrant_from_parts(payload_hex, signature_hex)?],
            holder_secret,
        )
    }

    /// Import a chain: string[] of wire tokens, or `{ payload_hex, signature_hex }[]`.
    #[wasm_bindgen(js_name = fromChain)]
    pub fn from_chain(parts: JsValue, holder_secret: &[u8]) -> Result<SdkSession, JsError> {
        init_panic_hook();
        session_from_chain(parse_chain_parts(parts)?, holder_secret)
    }

    /// Warrant IDs, root first. Test / revoke seam.
    #[wasm_bindgen(js_name = warrantIds)]
    pub fn warrant_ids(&self) -> Result<JsValue, JsError> {
        init_panic_hook();
        let ids: Vec<String> = self.chain.iter().map(|w| w.id().to_string()).collect();
        Ok(to_js_value(&ids))
    }

    /// CBOR warrant stack as standard base64. Matches Python `encode_warrant_stack`.
    #[wasm_bindgen(js_name = toStackWire)]
    pub fn to_stack_wire(&self) -> Result<String, JsError> {
        init_panic_hook();
        let bytes = wire::encode_stack(&WarrantStack(self.chain.clone()))
            .map_err(|e| JsError::new(&format!("failed to encode warrant stack: {e}")))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    /// Application idempotency key: SHA-256 of `(warrant_id, tool, canonical args)`.
    /// Not a PoP. MCP replay uses the PoP signature, not this key.
    #[wasm_bindgen(js_name = dedupKey)]
    pub fn dedup_key(&self, tool: &str, args_json: JsValue) -> Result<String, JsError> {
        init_panic_hook();
        let args = js_to_args(&args_json).map_err(|e| JsError::new(&e))?;
        let leaf = self.leaf()?;
        Ok(leaf.dedup_key(tool, &args))
    }

    /// Warrant tokens, root first. Does not include the holder secret.
    #[wasm_bindgen(js_name = toWire)]
    pub fn to_wire(&self) -> Result<JsValue, JsError> {
        init_panic_hook();
        let mut warrants = Vec::with_capacity(self.chain.len());
        for warrant in &self.chain {
            warrants.push(
                wire::encode_base64(warrant)
                    .map_err(|e| JsError::new(&format!("failed to encode warrant: {e}")))?,
            );
        }
        Ok(to_js_value(&warrants))
    }

    /// Test / interop seam. Not on the public TypeScript Session type.
    #[wasm_bindgen(js_name = exportWire)]
    pub fn export_wire(&self) -> Result<JsValue, JsError> {
        init_panic_hook();
        let root = self
            .chain
            .first()
            .ok_or_else(|| JsError::new("session chain is empty"))?;
        let mut warrants = Vec::with_capacity(self.chain.len());
        for warrant in &self.chain {
            warrants.push(
                wire::encode_base64(warrant)
                    .map_err(|e| JsError::new(&format!("failed to encode warrant: {e}")))?,
            );
        }
        Ok(to_js_value(&ExportDto {
            warrants,
            holder_hex: hex::encode(self.holder.secret_key_bytes()),
            root_hex: hex::encode(root.issuer().to_bytes()),
        }))
    }
}

impl SdkSession {
    fn leaf(&self) -> Result<&Warrant, JsError> {
        self.chain
            .last()
            .ok_or_else(|| JsError::new("session chain is empty"))
    }
}

#[wasm_bindgen(js_name = sdkInspectWarrant)]
pub fn sdk_inspect_warrant(wire: &str) -> Result<JsValue, JsError> {
    init_panic_hook();
    let warrant = parse_warrant(wire)?;
    Ok(inspect_js(&warrant))
}

#[wasm_bindgen(js_name = sdkInspectParts)]
pub fn sdk_inspect_parts(payload_hex: &str, signature_hex: &str) -> Result<JsValue, JsError> {
    init_panic_hook();
    let warrant = warrant_from_parts(payload_hex, signature_hex)?;
    Ok(inspect_js(&warrant))
}

/// Test / host seam. Signs an SRL with a provided issuer secret. Does not load it.
#[wasm_bindgen(js_name = sdkSignRevocationList)]
pub fn sdk_sign_revocation_list(ids: JsValue, issuer_secret: &[u8]) -> Result<String, JsError> {
    init_panic_hook();
    let issuer = parse_holder_secret(issuer_secret)?;
    sign_srl_hex(ids, &issuer)
}

/// Test seam. Signs the published generator envelope (not the in-memory SRL codec).
#[wasm_bindgen(js_name = sdkSignPublishedRevocationList)]
pub fn sdk_sign_published_revocation_list(
    ids: JsValue,
    version: u32,
    issuer_secret: &[u8],
) -> Result<String, JsError> {
    init_panic_hook();
    let issuer = parse_holder_secret(issuer_secret)?;
    sign_published_srl_hex(ids, u64::from(version), &issuer)
}

/// Signature authenticity only. Not authorization.
#[wasm_bindgen(js_name = sdkVerifyReceipt)]
pub fn sdk_verify_receipt(wire: &str) -> Result<JsValue, JsError> {
    init_panic_hook();
    let bytes = parse_srl_bytes(wire)?;
    let receipt: Receipt = ciborium::from_reader(bytes.as_slice())
        .map_err(|e| JsError::new(&format!("invalid receipt: {e}")))?;
    let payload = receipt
        .verify_signature()
        .map_err(|e| JsError::new(&format!("receipt signature does not verify: {e}")))?;
    Ok(to_js_value(&ReceiptInspectDto {
        authentic: true,
        outcome: match payload.outcome {
            tenuo::receipt::Outcome::Allow => "allow".into(),
            tenuo::receipt::Outcome::Deny => "deny".into(),
        },
        action: payload.action,
        decision_code: payload.decision_code,
        request_id: payload.request_id,
        srl_version: payload.srl_version,
        srl_hash: payload.srl_hash.map(hex::encode),
        request_hash: payload.request_hash.map(hex::encode),
        policy_definition_hash: payload.policy_definition_hash.map(hex::encode),
        prev_receipt_hash: payload.prev_receipt_hash.map(hex::encode),
        trusted_roots_hash: payload.trusted_roots_hash.map(hex::encode),
    }))
}

/// Test / host seam. Signs a SignedApproval envelope; does not authorize.
#[wasm_bindgen(js_name = sdkSignApproval)]
pub fn sdk_sign_approval(
    session: &SdkSession,
    tool: &str,
    args_json: JsValue,
    approver_secret: &[u8],
    external_id: &str,
    as_of: Option<f64>,
) -> Result<String, JsError> {
    init_panic_hook();
    let leaf = session.leaf()?;
    let args = js_to_args(&args_json).map_err(|e| JsError::new(&e))?;
    let approver = parse_holder_secret(approver_secret)?;
    let now = as_of
        .map(|t| t as i64)
        .unwrap_or_else(|| Utc::now().timestamp());
    if now < 0 {
        return Err(JsError::new("asOf must be a non-negative unix timestamp"));
    }
    let approved_at = now as u64;
    let warrant_expires = leaf.expires_at().timestamp().max(0) as u64;
    let expires_at = warrant_expires.min(approved_at.saturating_add(3600));
    let request_hash = compute_request_hash(
        &leaf.id().to_string(),
        tool,
        &args,
        Some(leaf.authorized_holder()),
    );
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&now.to_le_bytes());
    nonce[8..].copy_from_slice(&approver.public_key().to_bytes()[..8]);
    let payload = ApprovalPayload {
        version: 1,
        request_hash,
        nonce,
        external_id: if external_id.is_empty() {
            "test-approver".into()
        } else {
            external_id.to_string()
        },
        approved_at,
        expires_at,
        extensions: None,
    };
    let signed = SignedApproval::create(payload, &approver);
    let mut buf = Vec::new();
    ciborium::into_writer(&signed, &mut buf)
        .map_err(|e| JsError::new(&format!("failed to encode SignedApproval: {e}")))?;
    Ok(hex::encode(buf))
}

impl SdkContext {
    fn authorize_inner(
        &self,
        session: &SdkSession,
        tool: &str,
        args_json: JsValue,
        approvals_json: JsValue,
        tool_allow: JsValue,
        as_of: Option<i64>,
        request_id: Option<String>,
    ) -> JsValue {
        init_panic_hook();
        let timestamp = as_of.unwrap_or_else(|| Utc::now().timestamp());
        // The host's own identifier when it has one, so a receipt can be
        // matched against its logs. The derived fallback is a correlation aid,
        // not an identity: repeats within a second collide, which is why
        // distinguishing them is the chain link's job.
        let request_id =
            request_id.unwrap_or_else(|| format!("{tool}:{timestamp}"));
        let policy_hash = policy_digest(&tool_allow);
        // Filled once the leaf and arguments resolve. Stays None when the
        // arguments could not be canonicalized — a receipt must not claim to
        // commit to arguments it never parsed.
        let mut request_hash: Option<[u8; 32]> = None;

        let args = match js_to_args(&args_json) {
            Ok(a) => a,
            Err(e) => {
                return self.finish_decision(
                    &session.chain,
                    tool,
                    timestamp,
                    &request_id,
                    request_hash,
            policy_hash,
                    DecisionDto {
                        outcome: "deny".into(),
                        code: Some("TENUO_CANONICALIZATION".into()),
                        field: None,
                        message: Some(e),
                        args: None,
                        tool: None,
                        required: None,
                        received: None,
                        receipt: None,
                    },
                    None,
                    false,
                    Some("canonicalization"),
                )
            }
        };

        let leaf = match session.leaf() {
            Ok(w) => w,
            Err(e) => {
                return self.finish_decision(
                    &session.chain,
                    tool,
                    timestamp,
                    &request_id,
                    request_hash,
            policy_hash,
                    DecisionDto {
                        outcome: "deny".into(),
                        code: Some("TENUO_CONFIGURATION".into()),
                        field: None,
                        message: Some(format!("{e:?}")),
                        args: None,
                        tool: None,
                        required: None,
                        received: None,
                        receipt: None,
                    },
                    None,
                    false,
                    Some("configuration"),
                )
            }
        };

        request_hash = Some(compute_request_hash(
            &leaf.id().to_string(),
            tool,
            &args,
            Some(leaf.authorized_holder()),
        ));

        let signature = match as_of {
            Some(t) => leaf.sign_with_timestamp(&session.holder, tool, &args, Some(t)),
            None => leaf.sign(&session.holder, tool, &args),
        };
        let signature = match signature {
            Ok(s) => s,
            Err(e) => {
                return self.finish_decision(
                    &session.chain,
                    tool,
                    timestamp,
                    &request_id,
                    request_hash,
            policy_hash,
                    deny_from_error(&e),
                    None,
                    false,
                    Some(e.name()),
                )
            }
        };

        let approvals = match parse_approvals(&approvals_json) {
            Ok(a) => a,
            Err(e) => {
                return self.finish_decision(
                    &session.chain,
                    tool,
                    timestamp,
                    &request_id,
                    request_hash,
            policy_hash,
                    DecisionDto {
                        outcome: "deny".into(),
                        code: Some("TENUO_CANONICALIZATION".into()),
                        field: None,
                        message: Some(e),
                        args: None,
                        tool: None,
                        required: None,
                        received: None,
                        receipt: None,
                    },
                    Some(&signature),
                    false,
                    Some("canonicalization"),
                )
            }
        };

        let result = match as_of {
            Some(t) => self.authorizer.check_chain_with_pop_args_as_of(
                &session.chain,
                tool,
                &args,
                &args,
                Some(&signature),
                &approvals,
                t,
            ),
            None => self.authorizer.check_chain_with_pop_args(
                &session.chain,
                tool,
                &args,
                &args,
                Some(&signature),
                &approvals,
            ),
        };

        match result {
            Ok(_) => {
                if let Err(e) = apply_tool_ceiling(&tool_allow, &args) {
                    return self.finish_decision(
                        &session.chain,
                        tool,
                        timestamp,
                        &request_id,
                        request_hash,
            policy_hash,
                        deny_from_error(&e),
                        Some(&signature),
                        true,
                        Some(e.name()),
                    );
                }
                let mut obj = serde_json::Map::new();
                for (k, v) in &args {
                    obj.insert(k.clone(), cv_to_json(v));
                }
                self.finish_decision(
                    &session.chain,
                    tool,
                    timestamp,
                    &request_id,
                    request_hash,
            policy_hash,
                    DecisionDto {
                        outcome: "allow".into(),
                        code: None,
                        field: None,
                        message: None,
                        args: Some(serde_json::Value::Object(obj)),
                        tool: None,
                        required: None,
                        received: None,
                        receipt: None,
                    },
                    Some(&signature),
                    true,
                    None,
                )
            }
            Err(e) => self.finish_decision(
                &session.chain,
                tool,
                timestamp,
                &request_id,
                request_hash,
            policy_hash,
                deny_from_error(&e),
                Some(&signature),
                pop_established_before_error(&e),
                Some(e.name()),
            ),
        }
    }

    fn authorize_presented_inner(
        &self,
        warrants: JsValue,
        tool: &str,
        args_json: JsValue,
        pop: &str,
        approvals_json: JsValue,
        tool_allow: JsValue,
        as_of: Option<i64>,
        request_id: Option<String>,
    ) -> JsValue {
        init_panic_hook();
        let timestamp = as_of.unwrap_or_else(|| Utc::now().timestamp());
        // The host's own identifier when it has one, so a receipt can be
        // matched against its logs. The derived fallback is a correlation aid,
        // not an identity: repeats within a second collide, which is why
        // distinguishing them is the chain link's job.
        let request_id =
            request_id.unwrap_or_else(|| format!("{tool}:{timestamp}"));
        let policy_hash = policy_digest(&tool_allow);
        // Filled once the leaf and arguments resolve. Stays None when the
        // arguments could not be canonicalized — a receipt must not claim to
        // commit to arguments it never parsed.
        let mut request_hash: Option<[u8; 32]> = None;
        let empty: Vec<Warrant> = Vec::new();

        let chain = match parse_presented_chain(&warrants) {
            Ok(c) if !c.is_empty() => c,
            Ok(_) => {
                return self.finish_decision(
                    &empty,
                    tool,
                    timestamp,
                    &request_id,
                    request_hash,
            policy_hash,
                    DecisionDto {
                        outcome: "deny".into(),
                        code: Some("TENUO_CONFIGURATION".into()),
                        field: None,
                        message: Some("warrant chain must not be empty".into()),
                        args: None,
                        tool: None,
                        required: None,
                        received: None,
                        receipt: None,
                    },
                    None,
                    false,
                    Some("configuration"),
                )
            }
            Err(e) => {
                return self.finish_decision(
                    &empty,
                    tool,
                    timestamp,
                    &request_id,
                    request_hash,
            policy_hash,
                    DecisionDto {
                        outcome: "deny".into(),
                        code: Some("TENUO_CHAIN_INVALID".into()),
                        field: None,
                        message: Some(format!("{e:?}")),
                        args: None,
                        tool: None,
                        required: None,
                        received: None,
                        receipt: None,
                    },
                    None,
                    false,
                    Some("chain-broken"),
                )
            }
        };

        let args = match js_to_args(&args_json) {
            Ok(a) => a,
            Err(e) => {
                return self.finish_decision(
                    &chain,
                    tool,
                    timestamp,
                    &request_id,
                    request_hash,
            policy_hash,
                    DecisionDto {
                        outcome: "deny".into(),
                        code: Some("TENUO_CANONICALIZATION".into()),
                        field: None,
                        message: Some(e),
                        args: None,
                        tool: None,
                        required: None,
                        received: None,
                        receipt: None,
                    },
                    None,
                    false,
                    Some("canonicalization"),
                )
            }
        };

        let signature = match parse_pop_signature(pop) {
            Ok(s) => s,
            Err(e) => {
                return self.finish_decision(
                    &chain,
                    tool,
                    timestamp,
                    &request_id,
                    request_hash,
            policy_hash,
                    DecisionDto {
                        outcome: "deny".into(),
                        code: Some("TENUO_INVALID_POP".into()),
                        field: None,
                        message: Some(e),
                        args: None,
                        tool: None,
                        required: None,
                        received: None,
                        receipt: None,
                    },
                    None,
                    false,
                    Some("pop-signature-invalid"),
                )
            }
        };

        let approvals = match parse_approvals(&approvals_json) {
            Ok(a) => a,
            Err(e) => {
                return self.finish_decision(
                    &chain,
                    tool,
                    timestamp,
                    &request_id,
                    request_hash,
            policy_hash,
                    DecisionDto {
                        outcome: "deny".into(),
                        code: Some("TENUO_CANONICALIZATION".into()),
                        field: None,
                        message: Some(e),
                        args: None,
                        tool: None,
                        required: None,
                        received: None,
                        receipt: None,
                    },
                    Some(&signature),
                    false,
                    Some("canonicalization"),
                )
            }
        };

        let result = match as_of {
            Some(t) => self.authorizer.check_chain_with_pop_args_as_of(
                &chain,
                tool,
                &args,
                &args,
                Some(&signature),
                &approvals,
                t,
            ),
            None => self.authorizer.check_chain_with_pop_args(
                &chain,
                tool,
                &args,
                &args,
                Some(&signature),
                &approvals,
            ),
        };

        match result {
            Ok(_) => {
                if let Err(e) = apply_tool_ceiling(&tool_allow, &args) {
                    return self.finish_decision(
                        &chain,
                        tool,
                        timestamp,
                        &request_id,
                        request_hash,
            policy_hash,
                        deny_from_error(&e),
                        Some(&signature),
                        true,
                        Some(e.name()),
                    );
                }
                let mut obj = serde_json::Map::new();
                for (k, v) in &args {
                    obj.insert(k.clone(), cv_to_json(v));
                }
                self.finish_decision(
                    &chain,
                    tool,
                    timestamp,
                    &request_id,
                    request_hash,
            policy_hash,
                    DecisionDto {
                        outcome: "allow".into(),
                        code: None,
                        field: None,
                        message: None,
                        args: Some(serde_json::Value::Object(obj)),
                        tool: None,
                        required: None,
                        received: None,
                        receipt: None,
                    },
                    Some(&signature),
                    true,
                    None,
                )
            }
            Err(e) => self.finish_decision(
                &chain,
                tool,
                timestamp,
                &request_id,
                request_hash,
            policy_hash,
                deny_from_error(&e),
                Some(&signature),
                pop_established_before_error(&e),
                Some(e.name()),
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_decision(
        &self,
        chain: &[Warrant],
        tool: &str,
        timestamp: i64,
        request_id: &str,
        request_hash: Option<[u8; 32]>,
        policy_hash: Option<[u8; 32]>,
        mut dto: DecisionDto,
        pop: Option<&Signature>,
        after_pop: bool,
        decision_code: Option<&str>,
    ) -> JsValue {
        let emitted = encode_receipt(
            &self.receipt_signer,
            chain,
            tool,
            timestamp,
            request_id,
            dto.outcome == "allow",
            after_pop,
            pop,
            decision_code,
            self.srl_commitment,
            request_hash,
            policy_hash,
            self.trusted_roots_hash,
            self.last_receipt_hash.get(),
        );
        // Advance the chain only on a receipt that was actually emitted; a
        // failure to encode must not silently break every later link.
        if let Some((wire, link)) = emitted {
            self.last_receipt_hash.set(Some(link));
            dto.receipt = Some(wire);
        }
        to_js(&dto)
    }
}

#[derive(serde::Deserialize)]
struct RequireApprovalDto {
    approvers: Vec<String>,
    min: u32,
    #[serde(default)]
    tools: Option<Vec<String>>,
}

fn apply_require_approval(
    mut builder: tenuo::WarrantBuilder,
    require_json: &JsValue,
    allow_tools: &[String],
) -> Result<tenuo::WarrantBuilder, JsError> {
    if require_json.is_null() || require_json.is_undefined() {
        return Ok(builder);
    }
    let require: RequireApprovalDto = serde_wasm_bindgen::from_value(require_json.clone())
        .map_err(|e| JsError::new(&format!("invalid requireApproval: {e}")))?;
    if require.approvers.is_empty() {
        return Err(JsError::new("requireApproval.approvers must not be empty"));
    }
    if require.min == 0 {
        return Err(JsError::new("requireApproval.min must be at least 1"));
    }
    let mut keys = Vec::with_capacity(require.approvers.len());
    for hex in &require.approvers {
        keys.push(parse_public_key_hex(hex)?);
    }
    builder = builder.required_approvers(keys).min_approvals(require.min);

    let gated = require.tools.unwrap_or_else(|| allow_tools.to_vec());
    if gated.is_empty() {
        return Err(JsError::new(
            "requireApproval.tools must name at least one capability",
        ));
    }
    let mut gates = ApprovalGateMap::new();
    for tool in gated {
        gates.insert(tool, ToolApprovalGate::whole_tool());
    }
    let encoded = encode_approval_gate_map(&gates)
        .map_err(|e| JsError::new(&format!("failed to encode approval gates: {e}")))?;
    Ok(builder.extension(APPROVAL_GATE_EXTENSION_KEY, encoded))
}

fn parse_approvals(value: &JsValue) -> Result<Vec<SignedApproval>, String> {
    if value.is_null() || value.is_undefined() {
        return Ok(Vec::new());
    }
    if !js_sys::Array::is_array(value) {
        return Err("approvals must be an array of SignedApproval envelopes".into());
    }
    let arr = js_sys::Array::from(value);
    let mut out = Vec::with_capacity(arr.length() as usize);
    for i in 0..arr.length() {
        out.push(parse_one_approval(&arr.get(i))?);
    }
    Ok(out)
}

fn parse_one_approval(value: &JsValue) -> Result<SignedApproval, String> {
    if let Some(text) = value.as_string() {
        return signed_approval_from_text(&text);
    }
    if js_sys::Uint8Array::instanceof(value) {
        let bytes = js_sys::Uint8Array::new(value);
        let mut buf = vec![0u8; bytes.length() as usize];
        bytes.copy_to(&mut buf);
        return signed_approval_from_bytes(&buf);
    }
    Err("each approval must be hex, base64, or bytes".into())
}

fn signed_approval_from_text(text: &str) -> Result<SignedApproval, String> {
    let trimmed = text.trim();
    if let Ok(bytes) = parse_hex(trimmed) {
        if let Ok(approval) = signed_approval_from_bytes(&bytes) {
            return Ok(approval);
        }
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(trimmed.as_bytes()) {
        if let Ok(approval) = signed_approval_from_bytes(&bytes) {
            return Ok(approval);
        }
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed.as_bytes()) {
        return signed_approval_from_bytes(&bytes);
    }
    Err("approval is not valid hex or base64 SignedApproval CBOR".into())
}

fn signed_approval_from_bytes(bytes: &[u8]) -> Result<SignedApproval, String> {
    ciborium::from_reader(bytes).map_err(|e| format!("invalid SignedApproval: {e}"))
}

fn constraint_from_expr(expr: &serde_json::Value) -> Result<Constraint, String> {
    let kind = expr
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or("constraint is missing kind")?;
    match kind {
        "under" => {
            let root = expr
                .get("root")
                .and_then(|v| v.as_str())
                .ok_or("under requires root")?;
            Ok(Subpath::new(root).map_err(|e| e.to_string())?.into())
        }
        "email" => {
            let domain = expr
                .get("domain")
                .and_then(|v| v.as_str())
                .ok_or("email requires domain")?;
            if domain.is_empty() || domain.contains('@') {
                return Err("email domain must be a hostname, not an address".into());
            }
            Ok(Pattern::new(&format!("*@{domain}"))
                .map_err(|e| e.to_string())?
                .into())
        }
        "max" => {
            let value = expr
                .get("value")
                .and_then(|v| v.as_f64())
                .ok_or("max requires a numeric value")?;
            Ok(Range::new(None, Some(value))
                .map_err(|e| e.to_string())?
                .into())
        }
        "oneOf" => {
            let values = expr
                .get("values")
                .and_then(|v| v.as_array())
                .ok_or("oneOf requires values")?;
            let strings: Result<Vec<String>, _> = values
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .ok_or("oneOf values must be strings")
                })
                .collect();
            Ok(OneOf::new(strings?).into())
        }
        "pattern" => {
            let pattern = expr
                .get("pattern")
                .and_then(|v| v.as_str())
                .ok_or("pattern requires pattern")?;
            Ok(Pattern::new(pattern).map_err(|e| e.to_string())?.into())
        }
        "exact" => {
            let value = expr.get("value").ok_or("exact requires value")?;
            let cv = json_to_cv(value, 0, &mut InputBudget::default())?;
            Ok(Exact::new(cv).into())
        }
        other => Err(format!("unknown constraint kind '{other}'")),
    }
}

fn json_to_cv(
    value: &serde_json::Value,
    depth: u32,
    budget: &mut InputBudget,
) -> Result<ConstraintValue, String> {
    if depth > MAX_CONSTRAINT_DEPTH {
        return Err(format!(
            "value nesting exceeds maximum depth {MAX_CONSTRAINT_DEPTH}"
        ));
    }
    budget.charge_node()?;
    match value {
        serde_json::Value::Null => Ok(ConstraintValue::Null),
        serde_json::Value::Bool(b) => Ok(ConstraintValue::Boolean(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(ConstraintValue::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(ConstraintValue::Float(f))
            } else {
                Err("number is not a finite ConstraintValue".into())
            }
        }
        serde_json::Value::String(s) => {
            reject_string_budget(s.len())?;
            budget.charge_value(s.len())?;
            Ok(ConstraintValue::String(s.clone()))
        }
        serde_json::Value::Array(xs) => {
            reject_collection_budget(xs.len())?;
            let mut vals = Vec::with_capacity(xs.len());
            for v in xs {
                vals.push(json_to_cv(v, depth + 1, budget)?);
            }
            Ok(ConstraintValue::List(vals))
        }
        serde_json::Value::Object(map) => {
            reject_collection_budget(map.len())?;
            let mut out = BTreeMap::new();
            for (k, v) in map {
                budget.charge_key(k.len())?;
                out.insert(k.clone(), json_to_cv(v, depth + 1, budget)?);
            }
            Ok(ConstraintValue::Object(out))
        }
    }
}

fn js_to_args(value: &JsValue) -> Result<HashMap<String, ConstraintValue>, String> {
    if value.is_null() || value.is_undefined() {
        return Ok(HashMap::new());
    }
    if js_sys::Array::is_array(value) || !value.is_object() {
        return Err("arguments must be a plain object".into());
    }
    let obj = js_sys::Object::from(value.clone());
    let keys = js_sys::Object::keys(&obj);
    if keys.length() as usize > MAX_ARG_KEYS {
        return Err(format!("arguments exceed maximum of {MAX_ARG_KEYS} keys"));
    }
    let mut budget = InputBudget::default();
    budget.charge_node()?;
    let mut out = HashMap::new();
    for i in 0..keys.length() {
        let key_js = keys.get(i);
        let key = key_js
            .as_string()
            .ok_or_else(|| "argument keys must be strings".to_string())?;
        budget.charge_key(key.len())?;
        let v = js_sys::Reflect::get(&obj, &key_js)
            .map_err(|_| format!("failed to read argument '{key}'"))?;
        if v.is_undefined() {
            return Err(format!(
                "undefined is not allowed for '{key}' (omit the field instead)"
            ));
        }
        if v.js_typeof().as_string().as_deref() == Some("function") {
            return Err(format!("functions are not allowed for '{key}'"));
        }
        if v.js_typeof().as_string().as_deref() == Some("bigint") {
            return Err(format!("bigint is not a ConstraintValue ('{key}')"));
        }
        if v.js_typeof().as_string().as_deref() == Some("symbol") {
            return Err(format!("symbols are not allowed for '{key}'"));
        }
        out.insert(key, js_to_cv(&v, 0, &mut budget)?);
    }
    Ok(out)
}

fn js_to_cv(
    value: &JsValue,
    depth: u32,
    budget: &mut InputBudget,
) -> Result<ConstraintValue, String> {
    if depth > MAX_CONSTRAINT_DEPTH {
        return Err(format!(
            "argument nesting exceeds maximum depth {MAX_CONSTRAINT_DEPTH}"
        ));
    }
    budget.charge_node()?;
    if value.is_null() {
        return Ok(ConstraintValue::Null);
    }
    if let Some(b) = value.as_bool() {
        return Ok(ConstraintValue::Boolean(b));
    }
    if let Some(n) = value.as_f64() {
        if !n.is_finite() {
            return Err("non-finite numbers are not ConstraintValues".into());
        }
        if n.fract() == 0.0 && n >= i64::MIN as f64 && n <= i64::MAX as f64 {
            return Ok(ConstraintValue::Integer(n as i64));
        }
        return Ok(ConstraintValue::Float(n));
    }
    if let Some(s) = value.as_string() {
        reject_string_budget(s.len())?;
        budget.charge_value(s.len())?;
        return Ok(ConstraintValue::String(s));
    }
    if js_sys::Array::is_array(value) {
        let arr = js_sys::Array::from(value);
        reject_collection_budget(arr.length() as usize)?;
        let mut vals = Vec::with_capacity(arr.length() as usize);
        for i in 0..arr.length() {
            vals.push(js_to_cv(&arr.get(i), depth + 1, budget)?);
        }
        return Ok(ConstraintValue::List(vals));
    }
    if value.is_object() {
        let obj = js_sys::Object::from(value.clone());
        let keys = js_sys::Object::keys(&obj);
        reject_collection_budget(keys.length() as usize)?;
        let mut map = BTreeMap::new();
        for i in 0..keys.length() {
            let key_js = keys.get(i);
            let key = key_js
                .as_string()
                .ok_or_else(|| "object keys must be strings".to_string())?;
            budget.charge_key(key.len())?;
            let v = js_sys::Reflect::get(&obj, &key_js)
                .map_err(|_| format!("failed to read '{key}'"))?;
            map.insert(key, js_to_cv(&v, depth + 1, budget)?);
        }
        return Ok(ConstraintValue::Object(map));
    }
    Err("value cannot be represented as a ConstraintValue".into())
}

fn reject_string_budget(len: usize) -> Result<(), String> {
    if len > MAX_WARRANT_SIZE {
        return Err(format!(
            "string exceeds the WASM input budget of {MAX_WARRANT_SIZE} bytes"
        ));
    }
    Ok(())
}

fn reject_collection_budget(len: usize) -> Result<(), String> {
    if len > MAX_COLLECTION_LEN {
        return Err(format!(
            "collection exceeds the WASM input budget of {MAX_COLLECTION_LEN} items"
        ));
    }
    Ok(())
}

fn reject_encoded_budget(input: &str, max: usize, what: &str) -> Result<(), JsError> {
    if input.len() > max {
        return Err(JsError::new(&format!(
            "TENUO_CHAIN_INVALID: {what} exceeds the WASM input budget"
        )));
    }
    Ok(())
}

fn cv_to_json(value: &ConstraintValue) -> serde_json::Value {
    match value {
        ConstraintValue::String(s) => json!(s),
        ConstraintValue::Integer(i) => json!(i),
        ConstraintValue::Float(f) => json!(f),
        ConstraintValue::Boolean(b) => json!(b),
        ConstraintValue::Null => json!(null),
        ConstraintValue::List(xs) => json!(xs.iter().map(cv_to_json).collect::<Vec<_>>()),
        ConstraintValue::Object(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                obj.insert(k.clone(), cv_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
    }
}

fn deny_from_error(e: &Error) -> DecisionDto {
    if let Error::ApprovalRequired { tool, request } = e {
        return DecisionDto {
            outcome: "approval_required".into(),
            code: Some("TENUO_APPROVAL_REQUIRED".into()),
            field: None,
            message: Some(e.to_string()),
            args: None,
            tool: Some(tool.clone()),
            required: Some(request.min_approvals),
            received: Some(0),
            receipt: None,
        };
    }
    if let Error::InsufficientApprovals {
        required, received, ..
    } = e
    {
        return DecisionDto {
            outcome: "deny".into(),
            code: Some("TENUO_INSUFFICIENT_APPROVALS".into()),
            field: None,
            message: Some(e.to_string()),
            args: None,
            tool: None,
            required: Some(*required),
            received: Some(*received),
            receipt: None,
        };
    }

    DecisionDto {
        outcome: "deny".into(),
        code: Some(map_code(e).into()),
        field: error_field(e).map(str::to_string),
        message: Some(e.to_string()),
        args: None,
        tool: None,
        required: None,
        received: None,
        receipt: None,
    }
}

fn pop_established_before_error(e: &Error) -> bool {
    matches!(
        e,
        Error::ConstraintNotSatisfied { .. }
            | Error::PathNotContained { .. }
            | Error::InvalidPath { .. }
            | Error::ValueNotInRange { .. }
            | Error::UrlMismatch { .. }
            | Error::UrlNotSafe { .. }
            | Error::ApprovalRequired { .. }
            | Error::InsufficientApprovals { .. }
            | Error::ApprovalExpired { .. }
            | Error::InvalidApproval(_)
    )
}

#[allow(clippy::too_many_arguments)]
fn encode_receipt(
    signer: &SigningKey,
    chain: &[Warrant],
    tool: &str,
    timestamp: i64,
    request_id: &str,
    allowed: bool,
    after_pop: bool,
    pop: Option<&Signature>,
    decision_code: Option<&str>,
    srl_commitment: Option<(Option<u64>, [u8; 32])>,
    request_hash: Option<[u8; 32]>,
    policy_hash: Option<[u8; 32]>,
    trusted_roots_hash: [u8; 32],
    prev_receipt_hash: Option<[u8; 32]>,
) -> Option<(String, [u8; 32])> {
    let warrant_chain = wire::encode_stack(&WarrantStack(chain.to_vec())).unwrap_or_default();
    let mut payload = if allowed {
        let pop = pop?;
        ReceiptPayload::allow(
            warrant_chain,
            tool.to_string(),
            timestamp,
            request_id.to_string(),
            pop.to_bytes(),
        )
    } else if after_pop {
        let pop = pop?;
        ReceiptPayload::deny(
            warrant_chain,
            tool.to_string(),
            timestamp,
            request_id.to_string(),
            decision_code.unwrap_or("denied").to_string(),
            pop.to_bytes(),
        )
    } else {
        ReceiptPayload::deny_before_pop(
            warrant_chain,
            tool.to_string(),
            timestamp,
            request_id.to_string(),
            decision_code.unwrap_or("denied").to_string(),
        )
    };
    if let Some((version, digest)) = srl_commitment {
        payload.srl_version = version;
        payload.srl_hash = Some(digest);
    }
    // Key 7. Without it a receipt records that a decision happened but not what
    // it was made over, which is most of what makes it evidence.
    payload.request_hash = request_hash;
    payload.policy_definition_hash = policy_hash;
    payload.trusted_roots_hash = Some(trusted_roots_hash);
    payload.prev_receipt_hash = prev_receipt_hash;
    let receipt = Receipt::create(&payload, signer).ok()?;
    let link = receipt.digest().ok()?;
    let mut buf = Vec::new();
    ciborium::into_writer(&receipt, &mut buf).ok()?;
    Some((hex::encode(buf), link))
}

/// Commitment to the host ceiling applied to this decision (receipt key 11).
///
/// `None` when no ceiling was supplied, which is a different claim from an
/// empty ceiling: the first says the host imposed nothing, the second says it
/// deliberately imposed an open policy. serde_json's object map is sorted, so
/// the CBOR encoding is stable for a given policy.
fn policy_digest(tool_allow: &JsValue) -> Option<[u8; 32]> {
    if tool_allow.is_null() || tool_allow.is_undefined() {
        return None;
    }
    let raw: serde_json::Value = serde_wasm_bindgen::from_value(tool_allow.clone()).ok()?;
    if raw.is_null() {
        return None;
    }
    let mut bytes = Vec::new();
    ciborium::into_writer(&raw, &mut bytes).ok()?;
    Some(tenuo::policy_commitment_digest(&bytes))
}

fn sign_srl_hex(ids: JsValue, issuer: &SigningKey) -> Result<String, JsError> {
    let revoked: Vec<String> = serde_wasm_bindgen::from_value(ids)
        .map_err(|e| JsError::new(&format!("revoked ids must be an array of strings: {e}")))?;
    if revoked.is_empty() {
        return Err(JsError::new(
            "revocation list must name at least one warrant id",
        ));
    }
    let srl = SignedRevocationList::builder()
        .revoke_all(revoked)
        .build(issuer)
        .map_err(|e| JsError::new(&format!("failed to sign revocation list: {e}")))?;
    let bytes = srl
        .to_bytes()
        .map_err(|e| JsError::new(&format!("failed to encode revocation list: {e}")))?;
    Ok(hex::encode(bytes))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PublishedSrlPayload {
    revoked_ids: Vec<String>,
    version: u64,
    issued_at: u64,
    issuer: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PublishedSrl {
    payload: PublishedSrlPayload,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

fn published_srl_preimage(payload: &PublishedSrlPayload) -> Result<Vec<u8>, JsError> {
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(payload, &mut payload_bytes)
        .map_err(|e| JsError::new(&format!("failed to encode revocation payload: {e}")))?;
    let mut preimage = Vec::with_capacity(b"tenuo-srl-v1".len() + payload_bytes.len());
    preimage.extend_from_slice(b"tenuo-srl-v1");
    preimage.extend_from_slice(&payload_bytes);
    Ok(preimage)
}

fn sign_published_srl_hex(
    ids: JsValue,
    version: u64,
    issuer: &SigningKey,
) -> Result<String, JsError> {
    let revoked: Vec<String> = serde_wasm_bindgen::from_value(ids)
        .map_err(|e| JsError::new(&format!("revoked ids must be an array of strings: {e}")))?;
    if revoked.is_empty() {
        return Err(JsError::new(
            "revocation list must name at least one warrant id",
        ));
    }
    if version == 0 {
        return Err(JsError::new("revocation list version must be at least 1"));
    }
    let payload = PublishedSrlPayload {
        revoked_ids: revoked,
        version,
        issued_at: Utc::now().timestamp().max(0) as u64,
        issuer: issuer.public_key().to_bytes(),
    };
    let preimage = published_srl_preimage(&payload)?;
    let published = PublishedSrl {
        payload,
        signature: issuer.sign(&preimage).to_bytes().to_vec(),
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&published, &mut bytes)
        .map_err(|e| JsError::new(&format!("failed to encode revocation list: {e}")))?;
    Ok(hex::encode(bytes))
}

fn verify_published_srl(
    bytes: &[u8],
    trusted_roots: &[PublicKey],
) -> Result<PublishedSrlPayload, JsError> {
    let published: PublishedSrl = ciborium::from_reader(bytes)
        .map_err(|e| JsError::new(&format!("invalid revocation list: {e}")))?;
    if published.signature.len() != 64 {
        return Err(JsError::new("revocation list signature must be 64 bytes"));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&published.signature);
    let signature = Signature::from_bytes(&sig)
        .map_err(|e| JsError::new(&format!("invalid revocation list signature: {e}")))?;

    let preimage = published_srl_preimage(&published.payload)?;
    let issuer = PublicKey::from_bytes(&published.payload.issuer)
        .map_err(|e| JsError::new(&format!("invalid revocation list issuer: {e}")))?;
    if !trusted_roots.iter().any(|root| root == &issuer) {
        return Err(JsError::new(
            "revocation list is not signed by a trusted root",
        ));
    }
    issuer
        .verify(&preimage, &signature)
        .map_err(|e| JsError::new(&format!("revocation list signature does not verify: {e}")))?;
    if published.payload.revoked_ids.is_empty() {
        return Err(JsError::new(
            "revocation list must name at least one warrant id",
        ));
    }
    Ok(published.payload)
}

fn parse_srl_bytes(input: &str) -> Result<Vec<u8>, JsError> {
    let trimmed = input.trim();
    if let Ok(bytes) = parse_hex(trimmed) {
        if !bytes.is_empty() {
            return Ok(bytes);
        }
    }
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(compact.as_bytes()) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(compact.as_bytes()) {
        return Ok(bytes);
    }
    Err(JsError::new("invalid revocation list or receipt encoding"))
}

fn map_code(e: &Error) -> &'static str {
    match e {
        Error::WarrantExpired { .. } => "TENUO_WARRANT_EXPIRED",
        Error::WarrantRevoked(_) => "TENUO_REVOKED",
        Error::SignatureInvalid(msg) if msg.contains("not trusted") => "TENUO_UNTRUSTED_ROOT",
        Error::SignatureInvalid(msg) if msg.contains("Proof-of-Possession") => "TENUO_INVALID_POP",
        Error::MissingSignature(_) => "TENUO_INVALID_POP",
        Error::SignatureInvalid(_) => "TENUO_SIGNATURE_INVALID",
        Error::ChainVerificationFailed(_)
        | Error::MonotonicityViolation(_)
        | Error::DelegationAuthorityError { .. }
        | Error::DepthExceeded(_, _)
        | Error::ToolMismatch { .. }
        | Error::IncompatibleConstraintTypes { .. }
        | Error::WildcardExpansion { .. }
        | Error::PatternExpanded { .. }
        | Error::EmptyResultSet { .. }
        | Error::ExclusionRemoved { .. } => "TENUO_CHAIN_INVALID",
        Error::ConstraintNotSatisfied { field, .. } if field == "tool" => {
            "TENUO_TOOL_NOT_AUTHORIZED"
        }
        Error::ConstraintNotSatisfied { .. }
        | Error::PathNotContained { .. }
        | Error::InvalidPath { .. }
        | Error::ValueNotInRange { .. }
        | Error::UrlMismatch { .. }
        | Error::UrlNotSafe { .. } => "TENUO_CONSTRAINT_VIOLATION",
        Error::Unauthorized(_) => "TENUO_TOOL_NOT_AUTHORIZED",
        Error::InvalidApproval(_) => "TENUO_INSUFFICIENT_APPROVALS",
        _ => "TENUO_TOOL_NOT_AUTHORIZED",
    }
}

fn parse_hex(input: &str) -> Result<Vec<u8>, JsError> {
    reject_encoded_budget(input, MAX_ENCODED_CHAIN_CHARS, "hex")?;
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(clean).map_err(|e| JsError::new(&format!("invalid hex: {e}")))
}

fn parse_public_key_hex(hex: &str) -> Result<PublicKey, JsError> {
    let bytes = parse_hex(hex)?;
    if bytes.len() != 32 {
        return Err(JsError::new(
            "trusted root must be a 32-byte hex public key",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    PublicKey::from_bytes(&arr).map_err(|e| JsError::new(&format!("invalid public key: {e}")))
}

fn parse_holder_secret(bytes: &[u8]) -> Result<SigningKey, JsError> {
    if bytes.len() != 32 {
        return Err(JsError::new("holder key must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(SigningKey::from_bytes(&arr))
}

fn session_from_chain(chain: Vec<Warrant>, holder_secret: &[u8]) -> Result<SdkSession, JsError> {
    if chain.is_empty() {
        return Err(JsError::new("chain must not be empty"));
    }
    let holder = parse_holder_secret(holder_secret)?;
    let leaf = chain.last().expect("non-empty chain");
    if holder.public_key() != *leaf.authorized_holder() {
        return Err(JsError::new(
            "holder key does not match the warrant's authorized holder",
        ));
    }
    Ok(SdkSession { chain, holder })
}

fn parse_chain(input: &str) -> Result<Vec<Warrant>, JsError> {
    reject_encoded_budget(input, MAX_ENCODED_CHAIN_CHARS, "encoded warrant chain")?;
    let trimmed = input.trim();
    if let Ok(stack) = wire::decode_pem_chain(trimmed) {
        if !stack.0.is_empty() {
            return Ok(stack.0);
        }
    }
    if let Ok(warrant) = parse_warrant(trimmed) {
        return Ok(vec![warrant]);
    }
    if let Ok(bytes) = parse_hex(trimmed) {
        if let Ok(stack) = wire::decode_stack(&bytes) {
            return Ok(stack.0);
        }
    }
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(compact.as_bytes()) {
        if let Ok(stack) = wire::decode_stack(&bytes) {
            if !stack.0.is_empty() {
                return Ok(stack.0);
            }
        }
    }
    Err(JsError::new(
        "TENUO_CHAIN_INVALID: invalid warrant or warrant chain",
    ))
}

fn parse_presented_chain(warrants: &JsValue) -> Result<Vec<Warrant>, JsError> {
    if let Some(text) = warrants.as_string() {
        return parse_chain(&text);
    }
    parse_chain_parts(warrants.clone())
}

fn parse_pop_signature(input: &str) -> Result<Signature, String> {
    if input.len() > MAX_POP_CHARS {
        return Err("proof-of-possession exceeds the WASM input budget".into());
    }
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(&compact)
        .ok()
        .filter(|b| b.len() == 64)
        .or_else(|| {
            base64::engine::general_purpose::STANDARD
                .decode(compact.as_bytes())
                .ok()
        })
        .or_else(|| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(compact.as_bytes())
                .ok()
        })
        .ok_or_else(|| "invalid proof-of-possession encoding".to_string())?;
    if bytes.len() != 64 {
        return Err("proof-of-possession signature must be 64 bytes".into());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Signature::from_bytes(&arr).map_err(|e| format!("invalid proof-of-possession: {e}"))
}

fn parse_chain_parts(parts: JsValue) -> Result<Vec<Warrant>, JsError> {
    let value: serde_json::Value = serde_wasm_bindgen::from_value(parts)
        .map_err(|e| JsError::new(&format!("invalid chain: {e}")))?;
    let arr = value
        .as_array()
        .ok_or_else(|| JsError::new("chain must be an array"))?;
    if arr.is_empty() {
        return Err(JsError::new("chain must not be empty"));
    }
    if arr.len() > MAX_DELEGATION_DEPTH as usize {
        return Err(JsError::new(
            "TENUO_CHAIN_INVALID: chain exceeds the WASM input budget",
        ));
    }
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        if let Some(s) = item.as_str() {
            out.push(
                parse_warrant(s)
                    .map_err(|_| JsError::new(&format!("chain[{i}] is not a valid warrant")))?,
            );
            continue;
        }
        let obj = item.as_object().ok_or_else(|| {
            JsError::new(&format!(
                "chain[{i}] must be a wire string or payload/signature pair"
            ))
        })?;
        let payload = obj
            .get("payload_hex")
            .or_else(|| obj.get("payloadHex"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsError::new(&format!("chain[{i}] missing payload_hex")))?;
        let signature = obj
            .get("signature_hex")
            .or_else(|| obj.get("signatureHex"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsError::new(&format!("chain[{i}] missing signature_hex")))?;
        out.push(warrant_from_parts(payload, signature)?);
    }
    Ok(out)
}

fn tools_for_narrow(
    leaf: &Warrant,
    allow_json: &JsValue,
) -> Result<HashMap<String, ConstraintSet>, JsError> {
    let raw: serde_json::Value = serde_wasm_bindgen::from_value(allow_json.clone())
        .map_err(|e| JsError::new(&format!("invalid allow policy: {e}")))?;
    let obj = raw
        .as_object()
        .ok_or_else(|| JsError::new("allow must be an object"))?;
    if obj.is_empty() {
        return Err(JsError::new("narrow() requires a non-empty allow policy"));
    }

    let field_level = obj
        .values()
        .all(|v| v.get("kind").and_then(|k| k.as_str()).is_some());

    if field_level {
        let set = constraint_set_from_fields(obj)?;
        let tools = leaf
            .capabilities()
            .ok_or_else(|| JsError::new("leaf has no capabilities to narrow"))?;
        if tools.is_empty() {
            return Err(JsError::new("leaf has no capabilities to narrow"));
        }
        let mut out = HashMap::new();
        for name in tools.keys() {
            out.insert(name.clone(), set.clone());
        }
        return Ok(out);
    }

    let mut out = HashMap::new();
    for (tool, fields) in obj {
        let fields = fields
            .as_object()
            .ok_or_else(|| JsError::new(&format!("allow.{tool} must be an object")))?;
        out.insert(tool.clone(), constraint_set_from_fields(fields)?);
    }
    Ok(out)
}

/// Wrapper `allow` ceiling. Null/undefined: no extra gate. Empty object: open.
fn apply_tool_ceiling(
    tool_allow: &JsValue,
    args: &HashMap<String, ConstraintValue>,
) -> Result<(), Error> {
    if tool_allow.is_null() || tool_allow.is_undefined() {
        return Ok(());
    }
    let raw: serde_json::Value = serde_wasm_bindgen::from_value(tool_allow.clone())
        .map_err(|e| Error::ConfigurationError(format!("invalid tool allow policy: {e}")))?;
    if raw.is_null() {
        return Ok(());
    }
    let obj = raw
        .as_object()
        .ok_or_else(|| Error::ConfigurationError("tool allow must be an object".into()))?;
    if obj.is_empty() {
        return Ok(());
    }
    let mut set = ConstraintSet::new();
    for (field, expr) in obj {
        let constraint = constraint_from_expr(expr)
            .map_err(|e| Error::ConfigurationError(format!("tool allow.{field}: {e}")))?;
        set.insert(field.clone(), constraint);
    }
    set.matches(args)
}

fn constraint_set_from_fields(
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<ConstraintSet, JsError> {
    let mut set = ConstraintSet::new();
    for (field, expr) in fields {
        let constraint =
            constraint_from_expr(expr).map_err(|e| JsError::new(&format!("allow.{field}: {e}")))?;
        set.insert(field.clone(), constraint);
    }
    Ok(set)
}

fn parse_warrant(input: &str) -> Result<Warrant, JsError> {
    reject_encoded_budget(input, MAX_ENCODED_WARRANT_CHARS, "encoded warrant")?;
    let trimmed = input.trim();
    if let Ok(warrant) = wire::decode_base64(trimmed) {
        return Ok(warrant);
    }
    let bytes = parse_hex(trimmed)?;
    wire::decode(&bytes)
        .map_err(|e| JsError::new(&format!("TENUO_CHAIN_INVALID: invalid warrant: {e}")))
}

fn warrant_from_parts(payload_hex: &str, signature_hex: &str) -> Result<Warrant, JsError> {
    let payload_bytes = parse_hex(payload_hex)?;
    let sig_bytes = parse_hex(signature_hex)?;
    if sig_bytes.len() != 64 {
        return Err(JsError::new("signature must be 64 bytes"));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let payload: WarrantPayload = ciborium::de::from_reader(payload_bytes.as_slice())
        .map_err(|e| JsError::new(&format!("invalid warrant payload: {e}")))?;
    let signature = Signature::from_bytes(&sig_arr)
        .map_err(|e| JsError::new(&format!("invalid signature: {e}")))?;
    Ok(Warrant {
        payload,
        signature,
        payload_bytes,
        envelope_version: 1,
    })
}

fn inspect_js(warrant: &Warrant) -> JsValue {
    to_js_inspect(&InspectDto {
        payload_hex: hex::encode(warrant.payload_bytes()),
        signature_hex: hex::encode(warrant.signature().to_bytes()),
        id: warrant.id().to_string(),
    })
}

fn to_js_inspect(dto: &InspectDto) -> JsValue {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    dto.serialize(&serializer)
        .unwrap_or_else(|_| JsValue::from_str("internal serialize error"))
}

fn error_field(e: &Error) -> Option<&str> {
    match e {
        Error::ConstraintNotSatisfied { field, .. } => Some(field.as_str()),
        Error::PathNotContained { .. } | Error::InvalidPath { .. } => Some("path"),
        _ => None,
    }
}

fn to_js(dto: &DecisionDto) -> JsValue {
    to_js_value(dto)
}

fn to_js_value<T: Serialize>(dto: &T) -> JsValue {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    dto.serialize(&serializer)
        .unwrap_or_else(|_| JsValue::from_str("internal serialize error"))
}
