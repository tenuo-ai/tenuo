//! Production TypeScript SDK bindings.
//!
//! One WASM call signs PoP and authorizes — the same sequence as the Python
//! SDK, without exposing the intermediate signature to JavaScript.
//! Explorer-facing JSON helpers stay in `lib.rs`.

use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tenuo::constraints::Subpath;
use tenuo::payload::WarrantPayload;
use tenuo::{
    wire, Authorizer, Constraint, ConstraintSet, ConstraintValue, Error, Exact, OneOf, Pattern,
    PublicKey, Range, Signature, SigningKey, Warrant,
};
use wasm_bindgen::prelude::*;

use crate::init_panic_hook;

const DEFAULT_TTL_SECS: u64 = 300;

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
}

#[derive(Serialize)]
struct InspectDto {
    payload_hex: String,
    signature_hex: String,
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
}

/// Opaque warrant chain (root first) + leaf holder key. Not JSON-serializable from JS.
#[wasm_bindgen]
pub struct SdkSession {
    chain: Vec<Warrant>,
    holder: SigningKey,
}

#[wasm_bindgen]
impl SdkContext {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SdkContext {
        init_panic_hook();
        let issuer = SigningKey::generate();
        let authorizer = Authorizer::new().with_trusted_root(issuer.public_key());
        SdkContext {
            issuer: Some(issuer),
            authorizer,
        }
    }

    /// Authorizer-only context. `mint()` fails; import a session from the wire.
    #[wasm_bindgen(js_name = fromTrustedRoots)]
    pub fn from_trusted_roots(roots: JsValue) -> Result<SdkContext, JsError> {
        init_panic_hook();
        let hexes: Vec<String> = serde_wasm_bindgen::from_value(roots)
            .map_err(|e| JsError::new(&format!("trustedRoots must be an array of hex keys: {e}")))?;
        if hexes.is_empty() {
            return Err(JsError::new("trustedRoots must not be empty"));
        }
        let mut authorizer = Authorizer::new();
        for hex in hexes {
            let key = parse_public_key_hex(&hex)?;
            authorizer = authorizer.with_trusted_root(key);
        }
        Ok(SdkContext {
            issuer: None,
            authorizer,
        })
    }

    /// Mint a short-lived session from an allow map:
    /// `{ "read_file": { "path": { "kind": "under", "root": "/data" } } }`
    #[wasm_bindgen]
    pub fn mint(&self, allow_json: JsValue, ttl_seconds: u32) -> Result<SdkSession, JsError> {
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
            .map_err(|e| JsError::new(&format!("narrow() rejected: {e}")))?;

        let mut chain = session.chain.clone();
        chain.push(child);
        Ok(SdkSession {
            chain,
            holder: session.holder.clone(),
        })
    }

    /// Sign PoP and authorize in one call. Never returns allow without a core allow.
    #[wasm_bindgen]
    pub fn authorize(&self, session: &SdkSession, tool: &str, args_json: JsValue) -> JsValue {
        self.authorize_inner(session, tool, args_json, None)
    }

    /// Test / replay seam. Not exposed on `createTenuo` or `execute`.
    #[wasm_bindgen(js_name = authorizeAsOf)]
    pub fn authorize_as_of(
        &self,
        session: &SdkSession,
        tool: &str,
        args_json: JsValue,
        as_of: f64,
    ) -> JsValue {
        self.authorize_inner(session, tool, args_json, Some(as_of as i64))
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
        session_from_chain(vec![warrant_from_parts(payload_hex, signature_hex)?], holder_secret)
    }

    /// Import a chain: string[] of wire tokens, or `{ payload_hex, signature_hex }[]`.
    #[wasm_bindgen(js_name = fromChain)]
    pub fn from_chain(parts: JsValue, holder_secret: &[u8]) -> Result<SdkSession, JsError> {
        init_panic_hook();
        session_from_chain(parse_chain_parts(parts)?, holder_secret)
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

impl SdkContext {
    fn authorize_inner(
        &self,
        session: &SdkSession,
        tool: &str,
        args_json: JsValue,
        as_of: Option<i64>,
    ) -> JsValue {
        init_panic_hook();

        let args = match js_to_args(&args_json) {
            Ok(a) => a,
            Err(e) => {
                return to_js(&DecisionDto {
                    outcome: "deny".into(),
                    code: Some("TENUO_CANONICALIZATION".into()),
                    field: None,
                    message: Some(e),
                    args: None,
                    tool: None,
                    required: None,
                    received: None,
                })
            }
        };

        let leaf = match session.leaf() {
            Ok(w) => w,
            Err(e) => {
                return to_js(&DecisionDto {
                    outcome: "deny".into(),
                    code: Some("TENUO_CONFIGURATION".into()),
                    field: None,
                    message: Some(format!("{e:?}")),
                    args: None,
                    tool: None,
                    required: None,
                    received: None,
                })
            }
        };

        let signature = match as_of {
            Some(t) => leaf.sign_with_timestamp(&session.holder, tool, &args, Some(t)),
            None => leaf.sign(&session.holder, tool, &args),
        };
        let signature = match signature {
            Ok(s) => s,
            Err(e) => return deny_from_error(&e),
        };

        let result = match as_of {
            Some(t) => self.authorizer.check_chain_with_pop_args_as_of(
                &session.chain,
                tool,
                &args,
                &args,
                Some(&signature),
                &[],
                t,
            ),
            None => self.authorizer.check_chain_with_pop_args(
                &session.chain,
                tool,
                &args,
                &args,
                Some(&signature),
                &[],
            ),
        };

        match result {
            Ok(_) => {
                let mut obj = serde_json::Map::new();
                for (k, v) in &args {
                    obj.insert(k.clone(), cv_to_json(v));
                }
                to_js(&DecisionDto {
                    outcome: "allow".into(),
                    code: None,
                    field: None,
                    message: None,
                    args: Some(serde_json::Value::Object(obj)),
                    tool: None,
                    required: None,
                    received: None,
                })
            }
            Err(e) => deny_from_error(&e),
        }
    }
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
            let cv = json_to_cv(value)?;
            Ok(Exact::new(cv).into())
        }
        other => Err(format!("unknown constraint kind '{other}'")),
    }
}

fn json_to_cv(value: &serde_json::Value) -> Result<ConstraintValue, String> {
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
        serde_json::Value::String(s) => Ok(ConstraintValue::String(s.clone())),
        serde_json::Value::Array(xs) => {
            let vals: Result<Vec<_>, _> = xs.iter().map(json_to_cv).collect();
            Ok(ConstraintValue::List(vals?))
        }
        serde_json::Value::Object(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                out.insert(k.clone(), json_to_cv(v)?);
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
    let mut out = HashMap::new();
    for i in 0..keys.length() {
        let key_js = keys.get(i);
        let key = key_js
            .as_string()
            .ok_or_else(|| "argument keys must be strings".to_string())?;
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
        out.insert(key, js_to_cv(&v)?);
    }
    Ok(out)
}

fn js_to_cv(value: &JsValue) -> Result<ConstraintValue, String> {
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
        return Ok(ConstraintValue::String(s));
    }
    if js_sys::Array::is_array(value) {
        let arr = js_sys::Array::from(value);
        let mut vals = Vec::with_capacity(arr.length() as usize);
        for i in 0..arr.length() {
            vals.push(js_to_cv(&arr.get(i))?);
        }
        return Ok(ConstraintValue::List(vals));
    }
    if value.is_object() {
        let obj = js_sys::Object::from(value.clone());
        let keys = js_sys::Object::keys(&obj);
        let mut map = BTreeMap::new();
        for i in 0..keys.length() {
            let key_js = keys.get(i);
            let key = key_js
                .as_string()
                .ok_or_else(|| "object keys must be strings".to_string())?;
            let v = js_sys::Reflect::get(&obj, &key_js)
                .map_err(|_| format!("failed to read '{key}'"))?;
            map.insert(key, js_to_cv(&v)?);
        }
        return Ok(ConstraintValue::Object(map));
    }
    Err("value cannot be represented as a ConstraintValue".into())
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

fn deny_from_error(e: &Error) -> JsValue {
    if let Error::ApprovalRequired { tool, .. } = e {
        return to_js(&DecisionDto {
            outcome: "approval_required".into(),
            code: Some("TENUO_APPROVAL_REQUIRED".into()),
            field: None,
            message: Some(e.to_string()),
            args: None,
            tool: Some(tool.clone()),
            required: None,
            received: None,
        });
    }
    if let Error::InsufficientApprovals {
        required, received, ..
    } = e
    {
        return to_js(&DecisionDto {
            outcome: "deny".into(),
            code: Some("TENUO_INSUFFICIENT_APPROVALS".into()),
            field: None,
            message: Some(e.to_string()),
            args: None,
            tool: None,
            required: Some(*required),
            received: Some(*received),
        });
    }

    to_js(&DecisionDto {
        outcome: "deny".into(),
        code: Some(map_code(e).into()),
        field: error_field(e).map(str::to_string),
        message: Some(e.to_string()),
        args: None,
        tool: None,
        required: None,
        received: None,
    })
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
        Error::ConstraintNotSatisfied { field, .. } if field == "tool" => "TENUO_TOOL_NOT_AUTHORIZED",
        Error::ConstraintNotSatisfied { .. }
        | Error::PathNotContained { .. }
        | Error::InvalidPath { .. }
        | Error::ValueNotInRange { .. }
        | Error::UrlMismatch { .. }
        | Error::UrlNotSafe { .. } => "TENUO_CONSTRAINT_VIOLATION",
        Error::Unauthorized(_) => "TENUO_TOOL_NOT_AUTHORIZED",
        _ => "TENUO_TOOL_NOT_AUTHORIZED",
    }
}

fn parse_hex(input: &str) -> Result<Vec<u8>, JsError> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(clean).map_err(|e| JsError::new(&format!("invalid hex: {e}")))
}

fn parse_public_key_hex(hex: &str) -> Result<PublicKey, JsError> {
    let bytes = parse_hex(hex)?;
    if bytes.len() != 32 {
        return Err(JsError::new("trusted root must be a 32-byte hex public key"));
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
    Err(JsError::new("invalid warrant or warrant chain"))
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

fn constraint_set_from_fields(
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<ConstraintSet, JsError> {
    let mut set = ConstraintSet::new();
    for (field, expr) in fields {
        let constraint = constraint_from_expr(expr)
            .map_err(|e| JsError::new(&format!("allow.{field}: {e}")))?;
        set.insert(field.clone(), constraint);
    }
    Ok(set)
}

fn parse_warrant(input: &str) -> Result<Warrant, JsError> {
    let trimmed = input.trim();
    if let Ok(warrant) = wire::decode_base64(trimmed) {
        return Ok(warrant);
    }
    let bytes = parse_hex(trimmed)?;
    wire::decode(&bytes).map_err(|e| JsError::new(&format!("invalid warrant: {e}")))
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
