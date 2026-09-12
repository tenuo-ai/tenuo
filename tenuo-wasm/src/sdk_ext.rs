//! Parity surface for the TypeScript SDK: the full constraint set, a stable
//! issuer key, issuer-type warrants, warrant metadata, approval requests and
//! signatures, revocation lists, and `explain`.
//!
//! Kept apart from `sdk.rs` so the delegation core stays readable. Everything
//! here still decides in the Rust core; TypeScript only shapes inputs.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tenuo::approval::{
    build_approval_context_attestation, compute_request_hash, ApprovalPayload, SignedApproval,
};
use tenuo::constraints::{Shlex, Subpath, UrlSafe};
use tenuo::{
    encode_approval_gate_map, parse_approval_gate_map, All, Any, ApprovalGateMap, ApprovalRequest,
    ArgApprovalGate, Authorizer, CelConstraint, Cidr, Clearance, Constraint, ConstraintSet,
    ConstraintValue, Contains, Error, Not, NotOneOf, PublicKey, Range, RegexConstraint,
    SignedRevocationList, SigningKey, Subset, ToolApprovalGate, UrlPattern, Warrant, WarrantType,
    Wildcard, APPROVAL_GATE_EXTENSION_KEY, MAX_DELEGATION_DEPTH,
};
use wasm_bindgen::prelude::*;

use crate::init_panic_hook;
use crate::sdk::{
    constraint_from_expr, cv_to_json, error_field, js_to_args, json_to_cv, map_code,
    parse_holder_secret, parse_public_key_hex, parse_srl_bytes, signed_approval_from_text,
    to_js_value, InputBudget, SdkContext, SdkSession,
};

const DEFAULT_TTL_SECS: u64 = 300;
const DEFAULT_APPROVAL_TTL_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
// Constraints beyond the six in sdk.rs
// ---------------------------------------------------------------------------

fn str_list(expr: &serde_json::Value, key: &str, what: &str) -> Result<Vec<String>, String> {
    let values = expr
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("{what} requires {key}"))?;
    values
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{what} {key} must be strings"))
        })
        .collect()
}

fn value_list(
    expr: &serde_json::Value,
    key: &str,
    what: &str,
) -> Result<Vec<ConstraintValue>, String> {
    let values = expr
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("{what} requires {key}"))?;
    let mut budget = InputBudget::default();
    values
        .iter()
        .map(|v| json_to_cv(v, 0, &mut budget))
        .collect()
}

fn inner_list(expr: &serde_json::Value, what: &str) -> Result<Vec<Constraint>, String> {
    let items = expr
        .get("constraints")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("{what} requires constraints"))?;
    if items.is_empty() {
        return Err(format!("{what} requires at least one constraint"));
    }
    items.iter().map(constraint_from_expr).collect()
}

/// Kinds `sdk.rs` does not know. Called from `constraint_from_expr`'s
/// fallthrough so the wire vocabulary stays in one place.
pub(crate) fn constraint_from_expr_ext(
    kind: &str,
    expr: &serde_json::Value,
) -> Result<Constraint, String> {
    match kind {
        "min" => {
            let value = expr
                .get("value")
                .and_then(|v| v.as_f64())
                .ok_or("min requires a numeric value")?;
            Ok(Range::new(Some(value), None)
                .map_err(|e| e.to_string())?
                .into())
        }
        "range" => {
            let min = expr.get("min").and_then(|v| v.as_f64());
            let max = expr.get("max").and_then(|v| v.as_f64());
            if min.is_none() && max.is_none() {
                return Err("range requires min, max, or both".into());
            }
            let mut range = Range::new(min, max).map_err(|e| e.to_string())?;
            if expr.get("minExclusive").and_then(|v| v.as_bool()) == Some(true) {
                range = range.min_exclusive();
            }
            if expr.get("maxExclusive").and_then(|v| v.as_bool()) == Some(true) {
                range = range.max_exclusive();
            }
            Ok(range.into())
        }
        "notOneOf" => Ok(NotOneOf::new(str_list(expr, "values", "notOneOf")?).into()),
        "regex" => {
            let source = expr
                .get("source")
                .and_then(|v| v.as_str())
                .ok_or("regex requires source")?;
            Ok(RegexConstraint::new(source)
                .map_err(|e| e.to_string())?
                .into())
        }
        "wildcard" => Ok(Wildcard::new().into()),
        "cidr" => {
            let network = expr
                .get("network")
                .and_then(|v| v.as_str())
                .ok_or("cidr requires network")?;
            Ok(Cidr::new(network).map_err(|e| e.to_string())?.into())
        }
        "urlPattern" => {
            let pattern = expr
                .get("pattern")
                .and_then(|v| v.as_str())
                .ok_or("urlPattern requires pattern")?;
            Ok(UrlPattern::new(pattern).map_err(|e| e.to_string())?.into())
        }
        "urlSafe" => {
            let mut safe = UrlSafe::new();
            if expr.get("schemes").is_some() {
                let schemes = str_list(expr, "schemes", "urlSafe")?;
                if schemes.is_empty() {
                    return Err("urlSafe schemes must not be empty".into());
                }
                safe.schemes = schemes;
            }
            if expr.get("allowDomains").is_some() {
                safe.allow_domains = Some(str_list(expr, "allowDomains", "urlSafe")?);
            }
            if expr.get("denyDomains").is_some() {
                safe.deny_domains = Some(str_list(expr, "denyDomains", "urlSafe")?);
            }
            Ok(safe.into())
        }
        "shlex" => {
            let allow = str_list(expr, "allow", "shlex")?;
            if allow.is_empty() {
                return Err("shlex requires at least one allowed command".into());
            }
            Ok(Shlex::new(allow).into())
        }
        "contains" => Ok(Contains::new(value_list(expr, "values", "contains")?).into()),
        "subset" => Ok(Subset::new(value_list(expr, "values", "subset")?).into()),
        "anyOf" => Ok(Any::new(inner_list(expr, "anyOf")?).into()),
        "all" => Ok(All::new(inner_list(expr, "all")?).into()),
        "not" => {
            let inner = expr.get("constraint").ok_or("not requires constraint")?;
            Ok(Not::new(constraint_from_expr(inner)?).into())
        }
        "cel" => {
            let expression = expr
                .get("expression")
                .and_then(|v| v.as_str())
                .ok_or("cel requires expression")?;
            if expression.trim().is_empty() {
                return Err("cel expression must not be empty".into());
            }
            Ok(CelConstraint::new(expression).into())
        }
        "under" => {
            // Only reached with options; the plain form is handled in sdk.rs.
            let root = expr
                .get("root")
                .and_then(|v| v.as_str())
                .ok_or("under requires root")?;
            let case_sensitive = expr
                .get("caseSensitive")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let allow_equal = expr
                .get("allowEqual")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            Ok(Subpath::with_options(root, case_sensitive, allow_equal)
                .map_err(|e| e.to_string())?
                .into())
        }
        other => Err(format!("unknown constraint kind '{other}'")),
    }
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

/// Clearance as a level name (`"internal"`) or a number 0-255.
pub(crate) fn parse_clearance(value: &serde_json::Value) -> Result<Clearance, JsError> {
    if let Some(n) = value.as_u64() {
        if n > 255 {
            return Err(JsError::new("clearance must be between 0 and 255"));
        }
        return Ok(Clearance(n as u8));
    }
    if let Some(name) = value.as_str() {
        return name
            .parse::<Clearance>()
            .map_err(|e| JsError::new(&format!("invalid clearance: {e}")));
    }
    Err(JsError::new(
        "clearance must be a level name (untrusted, external, partner, internal, privileged, system) or a number 0-255",
    ))
}

/// Tools that carry an approval gate on this warrant.
pub(crate) fn approval_gated_tools(warrant: &Warrant) -> Vec<String> {
    parse_approval_gate_map(warrant.extension(APPROVAL_GATE_EXTENSION_KEY))
        .ok()
        .flatten()
        .map(|gates| gates.tools().cloned().collect())
        .unwrap_or_default()
}

fn gate_message(warrant: &Warrant, tool: &str) -> Option<String> {
    parse_approval_gate_map(warrant.extension(APPROVAL_GATE_EXTENSION_KEY))
        .ok()
        .flatten()
        .and_then(|gates| gates.get(tool).and_then(|g| g.message.clone()))
}

fn issue_error(e: &Error) -> JsError {
    let code = match e {
        Error::DepthExceeded(_, _) | Error::IssueDepthExceeded { .. } => "TENUO_DEPTH_EXCEEDED",
        Error::WarrantExpired { .. } => "TENUO_WARRANT_EXPIRED",
        _ => "TENUO_CHAIN_INVALID",
    };
    JsError::new(&format!("{code}: {e}"))
}

fn allow_map(
    allow: Option<HashMap<String, HashMap<String, serde_json::Value>>>,
) -> Result<BTreeMap<String, ConstraintSet>, JsError> {
    let mut out = BTreeMap::new();
    for (tool, fields) in allow.unwrap_or_default() {
        let mut set = ConstraintSet::new();
        for (field, expr) in fields {
            let constraint = constraint_from_expr(&expr)
                .map_err(|e| JsError::new(&format!("allow.{tool}.{field}: {e}")))?;
            set.insert(field, constraint);
        }
        out.insert(tool, set);
    }
    Ok(out)
}

fn random_nonce() -> [u8; 16] {
    // A throwaway Ed25519 seed is CSPRNG output; no extra dependency needed.
    let seed = SigningKey::generate().secret_key_bytes();
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&seed[..16]);
    nonce
}

// ---------------------------------------------------------------------------
// Approval gates
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(untagged)]
enum ArgGateDto {
    All(String),
    When { when: serde_json::Value },
    Exempt { exempt: serde_json::Value },
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ToolGateDto {
    message: Option<String>,
    args: Option<HashMap<String, ArgGateDto>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RequireApprovalDto {
    approvers: Vec<String>,
    min: u32,
    /// Whole-tool gates. Defaults to every tool in `allow` when `gates` is absent too.
    tools: Option<Vec<String>>,
    /// Per-tool gates with a message and optional per-argument triggers.
    gates: Option<HashMap<String, ToolGateDto>>,
}

fn build_gate_map(
    require: &RequireApprovalDto,
    default_tools: &[String],
) -> Result<ApprovalGateMap, JsError> {
    let mut gates = ApprovalGateMap::new();
    for tool in require.tools.clone().unwrap_or_default() {
        gates.insert(tool, ToolApprovalGate::whole_tool());
    }
    if let Some(map) = &require.gates {
        for (tool, dto) in map {
            let mut gate = match &dto.args {
                None => ToolApprovalGate::whole_tool(),
                Some(args) => {
                    let mut out = BTreeMap::new();
                    for (field, arg) in args {
                        let parsed = match arg {
                            ArgGateDto::All(word) if word == "all" => ArgApprovalGate::All,
                            ArgGateDto::All(other) => {
                                return Err(JsError::new(&format!(
                                    "requireApproval.gates.{tool}.args.{field}: expected \"all\", {{ when }}, or {{ exempt }}, got '{other}'"
                                )))
                            }
                            ArgGateDto::When { when } => ArgApprovalGate::Constraint(
                                constraint_from_expr(when).map_err(|e| {
                                    JsError::new(&format!(
                                        "requireApproval.gates.{tool}.args.{field}.when: {e}"
                                    ))
                                })?,
                            ),
                            ArgGateDto::Exempt { exempt } => {
                                let inner = constraint_from_expr(exempt).map_err(|e| {
                                    JsError::new(&format!(
                                        "requireApproval.gates.{tool}.args.{field}.exempt: {e}"
                                    ))
                                })?;
                                ArgApprovalGate::exempt(inner).map_err(|e| {
                                    JsError::new(&format!(
                                        "requireApproval.gates.{tool}.args.{field}.exempt: {e}"
                                    ))
                                })?
                            }
                        };
                        out.insert(field.clone(), parsed);
                    }
                    ToolApprovalGate::with_args(out)
                }
            };
            if let Some(message) = &dto.message {
                gate = gate.with_message(message);
            }
            gates.insert(tool.clone(), gate);
        }
    }
    if gates.is_empty() {
        for tool in default_tools {
            gates.insert(tool.clone(), ToolApprovalGate::whole_tool());
        }
    }
    if gates.is_empty() {
        return Err(JsError::new(
            "requireApproval must name at least one capability to gate",
        ));
    }
    Ok(gates)
}

fn approver_keys(require: &RequireApprovalDto) -> Result<Vec<PublicKey>, JsError> {
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
    Ok(keys)
}

// ---------------------------------------------------------------------------
// Mint with the full option set
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MintOptions {
    /// `"execution"` (default) or `"issuer"`.
    kind: Option<String>,
    allow: Option<HashMap<String, HashMap<String, serde_json::Value>>>,
    ttl_seconds: Option<u32>,
    holder: Option<String>,
    max_depth: Option<u32>,
    clearance: Option<serde_json::Value>,
    session_id: Option<String>,
    agent_id: Option<String>,
    require_approval: Option<RequireApprovalDto>,
    /// Issuer warrants: tools this holder may issue execution warrants for.
    issuable_tools: Option<Vec<String>>,
    /// Issuer warrants: ceiling on the constraints of issued warrants, by field.
    constraint_bounds: Option<HashMap<String, serde_json::Value>>,
    /// Issuer warrants: how deep issued warrants may themselves delegate.
    max_issue_depth: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct IssueOptions {
    allow: HashMap<String, HashMap<String, serde_json::Value>>,
    holder: String,
    ttl_seconds: Option<u32>,
    max_depth: Option<u32>,
    clearance: Option<serde_json::Value>,
    session_id: Option<String>,
    agent_id: Option<String>,
    require_approval: Option<RequireApprovalDto>,
}

#[wasm_bindgen]
impl SdkContext {
    /// Issuer context from a stable 32-byte Ed25519 secret. Its own public
    /// key is trusted; `extra_roots` (hex) are trusted as well, so one
    /// process can verify chains from several control planes.
    #[wasm_bindgen(js_name = fromIssuerSecret)]
    pub fn from_issuer_secret(secret: &[u8], extra_roots: JsValue) -> Result<SdkContext, JsError> {
        init_panic_hook();
        let issuer = parse_holder_secret(secret)?;
        let mut roots = vec![issuer.public_key()];
        if !(extra_roots.is_undefined() || extra_roots.is_null()) {
            let hexes: Vec<String> = serde_wasm_bindgen::from_value(extra_roots)
                .map_err(|e| JsError::new(&format!("extra roots must be hex keys: {e}")))?;
            for hex in hexes {
                let key = parse_public_key_hex(&hex)?;
                if !roots.contains(&key) {
                    roots.push(key);
                }
            }
        }
        let mut authorizer = Authorizer::new();
        for root in &roots {
            authorizer = authorizer.with_trusted_root(root.clone());
        }
        Ok(SdkContext {
            srl_commitment: None,
            trusted_roots_hash: tenuo::trusted_roots_digest(
                &roots.iter().map(|r| r.to_bytes()).collect::<Vec<_>>(),
            ),
            last_receipt_hash: std::cell::Cell::new(None),
            receipt_signer: issuer.clone(),
            issuer: Some(issuer),
            authorizer,
            trusted_roots: roots,
        })
    }

    /// `mint()` with every option the protocol offers: kind, clearance,
    /// session and agent ids, approval gates with messages and per-argument
    /// triggers, and issuer-warrant fields. Keys are camelCase; unknown keys
    /// are rejected.
    #[wasm_bindgen(js_name = mintExtended)]
    pub fn mint_extended(&self, options: JsValue) -> Result<SdkSession, JsError> {
        init_panic_hook();
        let issuer = self.issuer.as_ref().ok_or_else(|| {
            JsError::new(
                "session() mints a warrant and needs a local issuer. Use createTenuo({ root: createTenuo.devRoot() }) or an issuer key.",
            )
        })?;
        let options: MintOptions = serde_wasm_bindgen::from_value(options)
            .map_err(|e| JsError::new(&format!("invalid session options: {e}")))?;

        let kind = match options.kind.as_deref() {
            None | Some("execution") => WarrantType::Execution,
            Some("issuer") => WarrantType::Issuer,
            Some(other) => {
                return Err(JsError::new(&format!(
                    "session kind must be \"execution\" or \"issuer\", got '{other}'"
                )))
            }
        };
        let (holder_public, holder_secret) = match &options.holder {
            Some(hex) => (parse_public_key_hex(hex)?, None),
            None => {
                let key = SigningKey::generate();
                (key.public_key(), Some(key))
            }
        };
        let ttl = match options.ttl_seconds {
            None | Some(0) => DEFAULT_TTL_SECS,
            Some(s) => u64::from(s),
        };

        let allow = allow_map(options.allow)?;
        let tool_names: Vec<String> = allow.keys().cloned().collect();
        if kind == WarrantType::Execution && allow.is_empty() {
            return Err(JsError::new(
                "allow policy must name at least one capability",
            ));
        }

        let mut builder = Warrant::builder()
            .r#type(kind)
            .ttl(Duration::from_secs(ttl))
            .holder(holder_public);
        for (tool, set) in allow {
            builder = builder.capability(tool, set);
        }
        if let Some(depth) = options.max_depth {
            if depth > MAX_DELEGATION_DEPTH {
                return Err(JsError::new(&format!(
                    "maxDepth {depth} exceeds the protocol maximum of {MAX_DELEGATION_DEPTH}"
                )));
            }
            builder = builder.max_depth(depth);
        }
        if let Some(level) = &options.clearance {
            builder = builder.clearance(parse_clearance(level)?);
        }
        if let Some(id) = options.session_id {
            builder = builder.session_id(id);
        }
        if let Some(id) = options.agent_id {
            builder = builder.agent_id(id);
        }
        if kind == WarrantType::Issuer {
            let tools = options.issuable_tools.clone().unwrap_or_default();
            if tools.is_empty() {
                return Err(JsError::new(
                    "an issuer session needs issuableTools: the tools it may issue execution sessions for",
                ));
            }
            builder = builder.issuable_tools(tools);
            if let Some(bounds) = &options.constraint_bounds {
                for (field, expr) in bounds {
                    let constraint = constraint_from_expr(expr)
                        .map_err(|e| JsError::new(&format!("constraintBounds.{field}: {e}")))?;
                    builder = builder.constraint_bound(field.clone(), constraint);
                }
            }
            if let Some(depth) = options.max_issue_depth {
                builder = builder.max_issue_depth(depth);
            }
        } else if options.issuable_tools.is_some()
            || options.constraint_bounds.is_some()
            || options.max_issue_depth.is_some()
        {
            return Err(JsError::new(
                "issuableTools, constraintBounds, and maxIssueDepth apply to kind: \"issuer\" only",
            ));
        }
        if let Some(require) = &options.require_approval {
            let keys = approver_keys(require)?;
            let gates = build_gate_map(require, &tool_names)?;
            let encoded = encode_approval_gate_map(&gates)
                .map_err(|e| JsError::new(&format!("failed to encode approval gates: {e}")))?;
            builder = builder
                .required_approvers(keys)
                .min_approvals(require.min)
                .extension(APPROVAL_GATE_EXTENSION_KEY, encoded);
        }

        let warrant = builder
            .build(issuer)
            .map_err(|e| JsError::new(&format!("failed to mint session: {e}")))?;
        Ok(SdkSession {
            chain: vec![warrant],
            holder: holder_secret,
        })
    }

    /// Issue an execution session from an issuer session. The issuer
    /// session's holder signs; core checks the tools against
    /// `issuableTools`, constraints against `constraintBounds`, clearance,
    /// and issue depth. No control-plane key is involved.
    #[wasm_bindgen]
    pub fn issue(&self, issuer: &SdkSession, options: JsValue) -> Result<SdkSession, JsError> {
        init_panic_hook();
        let leaf = issuer.leaf()?;
        let signer = issuer.holder.as_ref().ok_or_else(|| {
            JsError::new(
                "TENUO_CONFIGURATION: issue() needs the issuer session's holder key. Import it with sessionFromWire() in the holder's process.",
            )
        })?;
        let options: IssueOptions = serde_wasm_bindgen::from_value(options)
            .map_err(|e| JsError::new(&format!("invalid issue options: {e}")))?;
        let allow = allow_map(Some(options.allow))?;
        if allow.is_empty() {
            return Err(JsError::new(
                "issue() requires at least one capability in allow",
            ));
        }
        let tool_names: Vec<String> = allow.keys().cloned().collect();
        let holder = parse_public_key_hex(&options.holder)?;
        let mut builder = leaf
            .issue_execution_warrant()
            .map_err(|e| issue_error(&e))?;
        for (tool, set) in allow {
            builder = builder.capability(tool, set);
        }
        builder = builder.holder(holder.clone());
        if let Some(ttl) = options.ttl_seconds {
            if ttl == 0 {
                return Err(JsError::new("issue options: ttlSeconds must be positive"));
            }
            builder = builder.ttl(Duration::from_secs(u64::from(ttl)));
        }
        if let Some(depth) = options.max_depth {
            builder = builder.max_depth(depth);
        }
        if let Some(level) = &options.clearance {
            builder = builder.clearance(parse_clearance(level)?);
        }
        if let Some(id) = options.session_id {
            builder = builder.session_id(id);
        }
        if let Some(id) = options.agent_id {
            builder = builder.agent_id(id);
        }
        if let Some(require) = &options.require_approval {
            let keys = approver_keys(require)?;
            let gates = build_gate_map(require, &tool_names)?;
            let encoded = encode_approval_gate_map(&gates)
                .map_err(|e| JsError::new(&format!("failed to encode approval gates: {e}")))?;
            builder = builder.required_approvers(keys).min_approvals(require.min);
            builder
                .set_approval_gates_extension(encoded)
                .map_err(|e| JsError::new(&format!("failed to set approval gates: {e}")))?;
        }
        let warrant = builder.build(signer).map_err(|e| issue_error(&e))?;
        let holder_secret = if holder == signer.public_key() {
            Some(signer.clone())
        } else {
            None
        };
        // An issued warrant is a new root of authority for its holder, signed
        // by the issuer warrant's holder; the chain is issuer + issued.
        let mut chain = issuer.chain.clone();
        chain.push(warrant);
        Ok(SdkSession {
            chain,
            holder: holder_secret,
        })
    }

    /// Explain what the leaf would decide for `tool(args)`, field by field.
    /// No proof-of-possession is signed, so this works on any session,
    /// including one issued to another holder.
    #[wasm_bindgen]
    pub fn explain(
        &self,
        session: &SdkSession,
        tool: &str,
        args_json: JsValue,
    ) -> Result<JsValue, JsError> {
        init_panic_hook();
        let args = js_to_args(&args_json).map_err(|e| JsError::new(&e))?;
        let leaf = session.leaf()?;
        let now = Utc::now().timestamp();

        let (chain_valid, chain_error) =
            match self.authorizer.verify_chain_as_of(&session.chain, now) {
                Ok(_) => (true, None),
                Err(e) => (false, Some(map_code(&e).to_string())),
            };

        let capabilities = leaf.capabilities();
        let set = capabilities.and_then(|c| c.get(tool).or_else(|| c.get("*")));
        let tool_granted = set.is_some();
        let mut fields = Vec::new();
        let mut missing = Vec::new();
        if let Some(set) = set {
            for (field, constraint) in set.iter() {
                let expr = serde_json::to_value(constraint).unwrap_or(serde_json::Value::Null);
                match args.get(field) {
                    None => {
                        // Every named field is required, wildcard included:
                        // wildcard admits any value, not the absence of one.
                        missing.push(field.clone());
                        fields.push(ExplainFieldDto {
                            field: field.clone(),
                            kind: constraint.type_name().to_string(),
                            constraint: expr,
                            value: None,
                            satisfied: false,
                            reason: Some("argument not supplied".into()),
                        });
                    }
                    Some(value) => {
                        let (satisfied, reason) = match constraint.matches(value) {
                            Ok(true) => (true, None),
                            Ok(false) => (
                                false,
                                Some(format!(
                                    "{} does not satisfy {}",
                                    value,
                                    constraint.type_name()
                                )),
                            ),
                            Err(e) => (false, Some(e.to_string())),
                        };
                        fields.push(ExplainFieldDto {
                            field: field.clone(),
                            kind: constraint.type_name().to_string(),
                            constraint: expr,
                            value: Some(cv_to_json(value)),
                            satisfied,
                            reason,
                        });
                    }
                }
            }
        }
        let known: Vec<&String> = fields.iter().map(|f| &f.field).collect();
        let unknown: Vec<String> = args
            .keys()
            .filter(|k| !known.contains(k))
            .cloned()
            .collect();

        let (outcome, code, field, message) = if !chain_valid {
            (
                "deny",
                chain_error.clone(),
                None,
                Some("warrant chain does not verify".to_string()),
            )
        } else {
            match leaf.check_constraints(tool, &args) {
                Ok(()) => ("allow", None, None, None),
                Err(e) => (
                    "deny",
                    Some(map_code(&e).to_string()),
                    error_field(&e).map(str::to_string),
                    Some(e.to_string()),
                ),
            }
        };

        Ok(to_js_value(&ExplainDto {
            tool: tool.to_string(),
            outcome: outcome.to_string(),
            code,
            field,
            message,
            tool_granted,
            fields,
            unknown_fields: unknown,
            missing_fields: missing,
            expired: leaf.is_expired(),
            expires_at: leaf.expires_at().timestamp(),
            chain_valid,
            chain_error,
            kind: match leaf.r#type() {
                WarrantType::Issuer => "issuer".into(),
                WarrantType::Execution => "execution".into(),
            },
        }))
    }

    /// Everything an approval service needs to present `tool(args)` to a
    /// human and mint a matching `SignedApproval`. Not a signed artifact.
    #[wasm_bindgen(js_name = approvalRequest)]
    pub fn approval_request(
        &self,
        session: &SdkSession,
        tool: &str,
        args_json: JsValue,
    ) -> Result<JsValue, JsError> {
        init_panic_hook();
        let args = js_to_args(&args_json).map_err(|e| JsError::new(&e))?;
        let leaf = session.leaf()?;
        let request_hash = compute_request_hash(
            &leaf.id().to_string(),
            tool,
            &args,
            Some(leaf.authorized_holder()),
        );
        let approvers = leaf.required_approvers().cloned().unwrap_or_default();
        let min = leaf.approval_threshold().max(1);
        let expires = leaf.expires_at().timestamp().max(0) as u64;
        let request = ApprovalRequest::new(
            &leaf.id().to_string(),
            tool,
            &args,
            request_hash,
            approvers,
            min,
            expires,
        )
        .with_resolved_message(gate_message(leaf, tool).as_deref());
        Ok(to_js_value(&approval_request_dto(&request, leaf)))
    }

    /// Signed statement from this session's holder that it is the one asking
    /// for `tool(args)`. Carried inside a control-plane approval request so
    /// the approver can tell a genuine request from a forged one.
    #[wasm_bindgen(js_name = approvalContextAttestation)]
    pub fn approval_context_attestation(
        &self,
        session: &SdkSession,
        tool: &str,
        args_json: JsValue,
    ) -> Result<JsValue, JsError> {
        init_panic_hook();
        let args = js_to_args(&args_json).map_err(|e| JsError::new(&e))?;
        let leaf = session.leaf()?;
        let signer = session.holder.as_ref().ok_or_else(|| {
            JsError::new("TENUO_CONFIGURATION: attestation needs this session's holder key")
        })?;
        let (_, meta) = build_approval_context_attestation(
            signer,
            &leaf.id().to_string(),
            tool,
            &args,
            leaf.authorized_holder(),
        )
        .map_err(|e| JsError::new(&format!("failed to build attestation: {e}")))?;
        Ok(to_js_value(&AttestationDto {
            version: meta.version,
            canonicalization: meta.canonicalization,
            warrant_id: meta.warrant_id,
            tool: meta.tool,
            request_hash: meta.request_hash,
            holder_key_hex: meta.holder_key_hex,
            args_canonical_cbor_b64: meta.args_canonical_cbor_b64,
            signer_key_hex: meta.signer_key_hex,
            signature_b64: meta.signature_b64,
        }))
    }

    /// Sign a revocation list with this context's issuer key. Load it with
    /// `loadRevocationList` anywhere this issuer is a trusted root.
    #[wasm_bindgen(js_name = signRevocationListVersioned)]
    pub fn sign_revocation_list_versioned(
        &self,
        ids: JsValue,
        version: Option<u32>,
    ) -> Result<String, JsError> {
        init_panic_hook();
        let issuer = self
            .issuer
            .as_ref()
            .ok_or_else(|| JsError::new("signing a revocation list needs a local issuer key"))?;
        srl_hex(ids, version, issuer)
    }
}

fn srl_hex(ids: JsValue, version: Option<u32>, issuer: &SigningKey) -> Result<String, JsError> {
    let revoked: Vec<String> = serde_wasm_bindgen::from_value(ids)
        .map_err(|e| JsError::new(&format!("revoked ids must be an array of strings: {e}")))?;
    if revoked.is_empty() {
        return Err(JsError::new(
            "revocation list must name at least one warrant id",
        ));
    }
    let mut builder = SignedRevocationList::builder().revoke_all(revoked);
    if let Some(v) = version {
        builder = builder.version(u64::from(v));
    }
    let srl = builder
        .build(issuer)
        .map_err(|e| JsError::new(&format!("failed to sign revocation list: {e}")))?;
    let bytes = srl
        .to_bytes()
        .map_err(|e| JsError::new(&format!("failed to encode revocation list: {e}")))?;
    Ok(hex::encode(bytes))
}

/// Sign a revocation list with an explicit issuer secret (control-plane path).
#[wasm_bindgen(js_name = sdkSignRevocationListVersioned)]
pub fn sdk_sign_revocation_list_versioned(
    ids: JsValue,
    version: Option<u32>,
    issuer_secret: &[u8],
) -> Result<String, JsError> {
    init_panic_hook();
    let issuer = parse_holder_secret(issuer_secret)?;
    srl_hex(ids, version, &issuer)
}

#[derive(Serialize)]
struct SrlInspectDto {
    version: u64,
    issued_at: i64,
    issuer_public_key: String,
    revoked_ids: Vec<String>,
    signature_valid: bool,
}

/// Decode a signed revocation list without loading it.
#[wasm_bindgen(js_name = sdkInspectRevocationList)]
pub fn sdk_inspect_revocation_list(wire: &str) -> Result<JsValue, JsError> {
    init_panic_hook();
    let bytes = parse_srl_bytes(wire)?;
    let srl = SignedRevocationList::from_bytes(&bytes)
        .map_err(|e| JsError::new(&format!("invalid revocation list: {e}")))?;
    let issuer = srl.issuer().clone();
    Ok(to_js_value(&SrlInspectDto {
        version: srl.version(),
        issued_at: srl.issued_at().timestamp(),
        issuer_public_key: hex::encode(issuer.to_bytes()),
        revoked_ids: srl.revoked_ids().to_vec(),
        signature_valid: srl.verify(&issuer).is_ok(),
    }))
}

// ---------------------------------------------------------------------------
// Approvals: sign and inspect envelopes
// ---------------------------------------------------------------------------

/// Sign an approval for a request hash. The approver never needs the
/// warrant or the holder key; the hash already commits to both.
#[wasm_bindgen(js_name = sdkSignApprovalForRequest)]
pub fn sdk_sign_approval_for_request(
    request_hash_hex: &str,
    approver_secret: &[u8],
    external_id: &str,
    ttl_seconds: Option<u32>,
    warrant_expires_at: Option<f64>,
) -> Result<String, JsError> {
    init_panic_hook();
    let hash_bytes = hex::decode(request_hash_hex.trim())
        .map_err(|e| JsError::new(&format!("request hash must be hex: {e}")))?;
    if hash_bytes.len() != 32 {
        return Err(JsError::new("request hash must be 32 bytes"));
    }
    let mut request_hash = [0u8; 32];
    request_hash.copy_from_slice(&hash_bytes);
    if external_id.trim().is_empty() {
        return Err(JsError::new(
            "externalId is required: who approved, in the approver system's own terms",
        ));
    }
    let approver = parse_holder_secret(approver_secret)?;
    let now = Utc::now().timestamp().max(0) as u64;
    let ttl = match ttl_seconds {
        None | Some(0) => DEFAULT_APPROVAL_TTL_SECS,
        Some(s) => u64::from(s),
    };
    let mut expires_at = now.saturating_add(ttl);
    if let Some(w) = warrant_expires_at {
        if w > 0.0 {
            expires_at = expires_at.min(w as u64);
        }
    }
    let payload = ApprovalPayload {
        version: 1,
        request_hash,
        nonce: random_nonce(),
        external_id: external_id.to_string(),
        approved_at: now,
        expires_at,
        extensions: None,
    };
    let signed = SignedApproval::create(payload, &approver);
    signed
        .to_cbor_b64()
        .map_err(|e| JsError::new(&format!("failed to encode approval: {e}")))
}

#[derive(Serialize)]
struct ApprovalInspectDto {
    approver_public_key: String,
    request_hash: String,
    external_id: String,
    approved_at: i64,
    expires_at: i64,
    expired: bool,
    signature_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Decode and check an approval envelope. Not authorization.
#[wasm_bindgen(js_name = sdkInspectApproval)]
pub fn sdk_inspect_approval(envelope: &str) -> Result<JsValue, JsError> {
    init_panic_hook();
    let signed = signed_approval_from_text(envelope).map_err(|e| JsError::new(&e))?;
    let approver = hex::encode(signed.approver_key.to_bytes());
    let now = Utc::now().timestamp();
    match signed.verify() {
        Ok(payload) => Ok(to_js_value(&ApprovalInspectDto {
            approver_public_key: approver,
            request_hash: hex::encode(payload.request_hash),
            external_id: payload.external_id,
            approved_at: payload.approved_at as i64,
            expires_at: payload.expires_at as i64,
            expired: (payload.expires_at as i64) <= now,
            signature_valid: true,
            error: None,
        })),
        Err(e) => Ok(to_js_value(&ApprovalInspectDto {
            approver_public_key: approver,
            request_hash: String::new(),
            external_id: String::new(),
            approved_at: 0,
            expires_at: 0,
            expired: true,
            signature_valid: false,
            error: Some(e.to_string()),
        })),
    }
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ExplainFieldDto {
    field: String,
    kind: String,
    constraint: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
    satisfied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize)]
struct ExplainDto {
    tool: String,
    kind: String,
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    tool_granted: bool,
    fields: Vec<ExplainFieldDto>,
    unknown_fields: Vec<String>,
    missing_fields: Vec<String>,
    expired: bool,
    expires_at: i64,
    chain_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_error: Option<String>,
}

#[derive(Serialize)]
struct ApprovalRequestDto {
    request_id: String,
    warrant_id: String,
    tool: String,
    args: serde_json::Value,
    request_hash: String,
    holder_public_key: String,
    required_approvers: Vec<String>,
    min_approvals: u32,
    warrant_expires_at: u64,
    created_at: u64,
    message: String,
}

fn approval_request_dto(request: &ApprovalRequest, leaf: &Warrant) -> ApprovalRequestDto {
    let mut args = serde_json::Map::new();
    for (k, v) in &request.args {
        args.insert(k.clone(), cv_to_json(v));
    }
    ApprovalRequestDto {
        request_id: hex::encode(request.request_id),
        warrant_id: request.warrant_id.clone(),
        tool: request.tool.clone(),
        args: serde_json::Value::Object(args),
        request_hash: hex::encode(request.request_hash),
        holder_public_key: hex::encode(leaf.authorized_holder().to_bytes()),
        required_approvers: request
            .required_approvers
            .iter()
            .map(|k| hex::encode(k.to_bytes()))
            .collect(),
        min_approvals: request.min_approvals,
        warrant_expires_at: request.warrant_expires_at,
        created_at: request.created_at,
        message: request.message.clone(),
    }
}

#[derive(Serialize)]
struct AttestationDto {
    version: u8,
    canonicalization: String,
    warrant_id: String,
    tool: String,
    request_hash: String,
    holder_key_hex: String,
    args_canonical_cbor_b64: String,
    signer_key_hex: String,
    signature_b64: String,
}
