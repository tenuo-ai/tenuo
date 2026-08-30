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
use tenuo::{
    Authorizer, Constraint, ConstraintSet, ConstraintValue, Error, Exact, OneOf, Pattern, Range,
    SigningKey, Warrant,
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

/// Issuer + authorizer for `createTenuo({ root: devRoot() })`.
#[wasm_bindgen]
pub struct SdkContext {
    issuer: SigningKey,
    authorizer: Authorizer,
}

/// Opaque warrant + holder key. Not JSON-serializable from JS.
#[wasm_bindgen]
pub struct SdkSession {
    warrant: Warrant,
    holder: SigningKey,
}

#[wasm_bindgen]
impl SdkContext {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SdkContext {
        init_panic_hook();
        let issuer = SigningKey::generate();
        let authorizer = Authorizer::new().with_trusted_root(issuer.public_key());
        SdkContext { issuer, authorizer }
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

        let warrant = builder
            .build(&self.issuer)
            .map_err(|e| JsError::new(&format!("failed to mint session: {e}")))?;

        Ok(SdkSession { warrant, holder })
    }

    /// Sign PoP and authorize in one call. Never returns allow without a core allow.
    #[wasm_bindgen]
    pub fn authorize(&self, session: &SdkSession, tool: &str, args_json: JsValue) -> JsValue {
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

        let signature = match session.warrant.sign(&session.holder, tool, &args) {
            Ok(s) => s,
            Err(e) => return deny_from_error(&e),
        };

        match self
            .authorizer
            .authorize_one(&session.warrant, tool, &args, Some(&signature), &[])
        {
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
        Error::SignatureInvalid(_) | Error::MissingSignature(_) => "TENUO_INVALID_POP",
        Error::ChainVerificationFailed(_) => "TENUO_UNTRUSTED_ROOT",
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

fn error_field(e: &Error) -> Option<&str> {
    match e {
        Error::ConstraintNotSatisfied { field, .. } => Some(field.as_str()),
        Error::PathNotContained { .. } | Error::InvalidPath { .. } => Some("path"),
        _ => None,
    }
}

fn to_js(dto: &DecisionDto) -> JsValue {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    dto.serialize(&serializer)
        .unwrap_or_else(|_| JsValue::from_str("internal serialize error"))
}
