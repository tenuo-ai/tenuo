use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use serde_wasm_bindgen::Serializer;
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tenuo::{
    approval_gate::{
        self, ApprovalGateMap, ArgApprovalGate, ToolApprovalGate,
    },
    constraints::{
        Any, Cidr, Constraint, ConstraintSet, ConstraintValue, Contains, Exact, NotOneOf, OneOf,
        Pattern, Range, RegexConstraint, Shlex, Subpath, UrlPattern, UrlSafe,
    },
    wire, Authorizer, PublicKey, SigningKey, Warrant,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Convert a Constraint to a human-readable JSON value
fn constraint_to_readable(constraint: &Constraint) -> JsonValue {
    match constraint {
        Constraint::Wildcard(_) => json!({ "wildcard": "*" }),
        Constraint::Pattern(p) => json!({ "pattern": &p.pattern }),
        Constraint::Exact(e) => json!({ "exact": constraint_value_to_json(&e.value) }),
        Constraint::Range(r) => {
            let mut obj = serde_json::Map::new();
            if let Some(min) = r.min {
                obj.insert("min".to_string(), json!(min));
            }
            if let Some(max) = r.max {
                obj.insert("max".to_string(), json!(max));
            }
            JsonValue::Object(obj)
        }
        Constraint::OneOf(o) => {
            json!({ "oneof": o.values.iter().map(constraint_value_to_json).collect::<Vec<_>>() })
        }
        Constraint::NotOneOf(n) => {
            json!({ "notoneof": n.excluded.iter().map(constraint_value_to_json).collect::<Vec<_>>() })
        }
        Constraint::Regex(r) => json!({ "regex": &r.pattern }),
        Constraint::Contains(c) => {
            json!({ "contains": c.required.iter().map(constraint_value_to_json).collect::<Vec<_>>() })
        }
        Constraint::Cidr(c) => json!({ "cidr": &c.cidr_string }),
        Constraint::UrlPattern(u) => json!({ "url_pattern": &u.pattern }),
        Constraint::Subset(s) => {
            json!({ "subset": s.allowed.iter().map(constraint_value_to_json).collect::<Vec<_>>() })
        }
        Constraint::All(a) => {
            json!({ "all": a.constraints.iter().map(constraint_to_readable).collect::<Vec<_>>() })
        }
        Constraint::Any(a) => {
            json!({ "any": a.constraints.iter().map(constraint_to_readable).collect::<Vec<_>>() })
        }
        Constraint::Not(n) => json!({ "not": constraint_to_readable(&n.constraint) }),
        Constraint::Cel(c) => json!({ "cel": &c.expression }),
        Constraint::Subpath(s) => {
            let mut obj = serde_json::Map::new();
            obj.insert("root".to_string(), json!(&s.root));
            if !s.case_sensitive {
                obj.insert("case_sensitive".to_string(), json!(false));
            }
            if !s.allow_equal {
                obj.insert("allow_equal".to_string(), json!(false));
            }
            json!({ "subpath": JsonValue::Object(obj) })
        }
        Constraint::UrlSafe(u) => {
            let mut obj = serde_json::Map::new();
            if !u.schemes.is_empty() && u.schemes != vec!["http", "https"] {
                obj.insert("schemes".to_string(), json!(&u.schemes));
            }
            if let Some(ref domains) = u.allow_domains {
                obj.insert("allow_domains".to_string(), json!(domains));
            }
            if let Some(ref domains) = u.deny_domains {
                obj.insert("deny_domains".to_string(), json!(domains));
            }
            if let Some(ref ports) = u.allow_ports {
                obj.insert("allow_ports".to_string(), json!(ports));
            }
            if !u.block_private {
                obj.insert("block_private".to_string(), json!(false));
            }
            if !u.block_loopback {
                obj.insert("block_loopback".to_string(), json!(false));
            }
            if !u.block_metadata {
                obj.insert("block_metadata".to_string(), json!(false));
            }
            if u.block_internal_tlds {
                obj.insert("block_internal_tlds".to_string(), json!(true));
            }
            if obj.is_empty() {
                json!({ "url_safe": {} })
            } else {
                json!({ "url_safe": JsonValue::Object(obj) })
            }
        }
        Constraint::Shlex(sh) => {
            json!({ "shlex": { "allow": &sh.allow } })
        }
        Constraint::Unknown { type_id, .. } => json!({ "unknown": format!("type_id={}", type_id) }),
        _ => json!({ "unknown": "future_variant" }),
    }
}

/// Convert ConstraintValue to JSON
fn constraint_value_to_json(cv: &ConstraintValue) -> JsonValue {
    match cv {
        ConstraintValue::String(s) => JsonValue::String(s.clone()),
        ConstraintValue::Integer(i) => json!(*i),
        ConstraintValue::Float(f) => json!(*f),
        ConstraintValue::Boolean(b) => json!(*b),
        ConstraintValue::List(l) => {
            JsonValue::Array(l.iter().map(constraint_value_to_json).collect())
        }
        ConstraintValue::Object(o) => JsonValue::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), constraint_value_to_json(v)))
                .collect(),
        ),
        ConstraintValue::Null => JsonValue::Null,
    }
}

/// Convert a ConstraintSet to human-readable JSON
fn constraint_set_to_readable(cs: &ConstraintSet) -> HashMap<String, JsonValue> {
    cs.iter()
        .map(|(field, constraint)| (field.clone(), constraint_to_readable(constraint)))
        .collect()
}

/// Result of a warrant decoding (human-readable format)
#[derive(serde::Serialize)]
pub struct DecodedWarrant {
    pub id: String,
    pub issuer: String, // hex
    pub tools: Vec<String>,
    pub capabilities: HashMap<String, HashMap<String, JsonValue>>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub authorized_holder: String, // hex
    pub depth: u32,
    /// Raw extensions as hex-encoded values keyed by extension name.
    pub extensions: HashMap<String, String>,
    /// Parsed approval gates from the `tenuo.approval_gates` extension (if present).
    /// Map of tool_name -> gate spec: { args: null } for whole-tool, { args: { field: "all" | constraint } } for per-arg.
    pub approval_gates: Option<JsonValue>,
    /// Hex-encoded Ed25519 public keys of required approvers.
    pub required_approvers: Option<Vec<String>>,
    /// Minimum number of approvals required.
    pub min_approvals: Option<u32>,
}

/// Convert an ApprovalGateMap to a JSON-serializable representation.
fn approval_gate_map_to_json(gm: &ApprovalGateMap) -> JsonValue {
    let mut map = serde_json::Map::new();
    for (tool, gate) in gm.iter() {
        match &gate.args {
            None => {
                map.insert(tool.clone(), json!({ "args": null }));
            }
            Some(args) => {
                let mut args_map = serde_json::Map::new();
                for (arg, arg_gate) in args {
                    match arg_gate {
                        ArgApprovalGate::All => {
                            args_map.insert(arg.clone(), json!("all"));
                        }
                        ArgApprovalGate::Constraint(c) => {
                            args_map.insert(arg.clone(), constraint_to_readable(c));
                        }
                    }
                }
                map.insert(tool.clone(), json!({ "args": JsonValue::Object(args_map) }));
            }
        }
    }
    JsonValue::Object(map)
}

/// Parse a JSON approval gates object into an ApprovalGateMap for embedding in extensions.
fn parse_approval_gates_json(val: &serde_json::Value) -> Option<ApprovalGateMap> {
    let obj = val.as_object()?;
    let mut gm = ApprovalGateMap::new();
    for (tool, gate_val) in obj {
        if let Some(gate_obj) = gate_val.as_object() {
            if gate_obj.get("args").map(|v| v.is_null()).unwrap_or(false) {
                gm.insert(tool.clone(), ToolApprovalGate::whole_tool());
            } else if let Some(args_val) = gate_obj.get("args").and_then(|v| v.as_object()) {
                let mut args = BTreeMap::new();
                for (arg, ag_val) in args_val {
                    if ag_val.as_str() == Some("all") {
                        args.insert(arg.clone(), ArgApprovalGate::All);
                    }
                    // Future: parse constraint-based arg gates
                }
                gm.insert(tool.clone(), ToolApprovalGate::with_args(args));
            }
        }
    }
    if gm.is_empty() { None } else { Some(gm) }
}

/// Extract decoded warrant fields including extensions and approval gates.
fn extract_decoded_warrant(warrant: &Warrant) -> DecodedWarrant {
    let capabilities: HashMap<String, HashMap<String, JsonValue>> = warrant
        .capabilities()
        .map(|caps| {
            caps.iter()
                .map(|(tool, cs)| (tool.clone(), constraint_set_to_readable(cs)))
                .collect()
        })
        .unwrap_or_default();

    let extensions: HashMap<String, String> = warrant
        .extensions()
        .iter()
        .map(|(k, v)| (k.clone(), hex::encode(v)))
        .collect();

    let approval_gates = approval_gate::parse_approval_gate_map(
        warrant.extension(approval_gate::APPROVAL_GATE_EXTENSION_KEY),
    )
    .ok()
    .flatten()
    .map(|gm| approval_gate_map_to_json(&gm));

    let required_approvers = warrant
        .required_approvers()
        .map(|keys| keys.iter().map(|k| hex::encode(k.to_bytes())).collect());

    let min_approvals = warrant.min_approvals();

    DecodedWarrant {
        id: warrant.id().to_string(),
        issuer: hex::encode(warrant.issuer().to_bytes()),
        tools: warrant.tools(),
        capabilities,
        issued_at: warrant.issued_at().timestamp() as u64,
        expires_at: warrant.expires_at().timestamp() as u64,
        authorized_holder: hex::encode(warrant.authorized_holder().to_bytes()),
        depth: warrant.depth(),
        extensions,
        approval_gates,
        required_approvers,
        min_approvals,
    }
}

#[wasm_bindgen]
pub fn decode_warrant(base64_warrant: &str) -> JsValue {
    match wire::decode_base64(base64_warrant.trim()) {
        Ok(warrant) => {
            let decoded = extract_decoded_warrant(&warrant);
            let serializer = Serializer::new().serialize_maps_as_objects(true);
            decoded.serialize(&serializer).unwrap()
        }
        Err(e) => {
            let error = format!("Failed to decode: {}", e);
             serde_wasm_bindgen::to_value(&error).unwrap()
        }
    }
}

/// Result of an authorization check
#[derive(serde::Serialize)]
pub struct AuthResult {
    pub authorized: bool,
    pub reason: Option<String>,
    pub deny_code: Option<String>,
    pub field: Option<String>,
}

#[wasm_bindgen]
pub fn check_access(
    warrant_b64: &str, 
    tool: &str, 
    args_json: JsValue, 
    trusted_root_hex: &str,
    dry_run: bool,
) -> JsValue {
    init_panic_hook();
    
    // 1. Parse keys
    let root_bytes: [u8; 32] = match hex::decode(trusted_root_hex.trim()) {
        Ok(b) => match b.try_into() {
            Ok(b) => b,
            Err(_) => return to_auth_error("Invalid trusted root key length (must be 32 bytes)"),
        },
        Err(_) => return to_auth_error("Invalid trusted root hex"),
    };
    let root_key = match PublicKey::from_bytes(&root_bytes) {
        Ok(k) => k,
        Err(_) => return to_auth_error("Invalid trusted root key bytes"),
    };

    // 2. Parse warrant
    let warrant = match wire::decode_base64(warrant_b64.trim()) {
        Ok(w) => w,
        Err(e) => return to_auth_error(&format!("Invalid warrant: {}", e)),
    };

    // 3. Parse args
    let args: HashMap<String, ConstraintValue> = match serde_wasm_bindgen::from_value(args_json) {
        Ok(a) => a,
        Err(e) => return to_auth_error(&format!("Invalid arguments JSON: {}", e)),
    };

    // 4. Verification Check
    if let Err(e) = warrant.verify(&root_key) {
         return to_auth_error(&format!("Chain verification failed: {}", e));
    }

    if dry_run {
        // Skip Authorizer::check and do policy check manually to skip PoP
        if let Some(caps) = warrant.capabilities() {
            if let Some(constraints) = caps.get(tool) {
                match constraints.matches(&args) {
                    Ok(_) => serde_wasm_bindgen::to_value(&AuthResult {
                            authorized: true,
                            reason: Some("Dry run: Policy valid (PoP skipped)".to_string()),
                            deny_code: None,
                            field: None,
                    })
                    .unwrap(),
                    Err(e) => serde_wasm_bindgen::to_value(&AuthResult {
                            authorized: false,
                            reason: Some(format!("Policy violation: {}", e)),
                            deny_code: Some("POLICY_VIOLATION".to_string()),
                            field: None,
                    })
                    .unwrap(),
                }
            } else if let Some(constraints) = caps.get("*") {
                match constraints.matches(&args) {
                    Ok(_) => serde_wasm_bindgen::to_value(&AuthResult {
                            authorized: true,
                            reason: Some("Dry run: Policy valid (PoP skipped)".to_string()),
                            deny_code: None,
                            field: None,
                    })
                    .unwrap(),
                    Err(e) => serde_wasm_bindgen::to_value(&AuthResult {
                            authorized: false,
                            reason: Some(format!("Policy violation: {}", e)),
                            deny_code: Some("POLICY_VIOLATION".to_string()),
                            field: None,
                    })
                    .unwrap(),
                }
            } else {
                return to_auth_error(&format!("Tool '{}' not authorized by warrant", tool));
            }
        } else {
             return to_auth_error("Warrant has no capabilities/tools");
        }
    } else {
        // Full Authorizer check (requires PoP)
        let authorizer = Authorizer::new().with_trusted_root(root_key);
        match authorizer.authorize_one(&warrant, tool, &args, None, &[]) {
            Ok(_) => serde_wasm_bindgen::to_value(&AuthResult {
                    authorized: true,
                    reason: None,
                    deny_code: None,
                    field: None,
            })
            .unwrap(),
            Err(e) => serde_wasm_bindgen::to_value(&AuthResult {
                    authorized: false,
                    reason: Some(e.to_string()),
                    deny_code: Some("DENIED".to_string()),
                    field: None,
            })
            .unwrap(),
        }
    }
}

#[wasm_bindgen]
pub fn check_chain_access(
    warrant_b64_list: Vec<String>, 
    tool: &str, 
    args_json: JsValue, 
    trusted_root_hex: &str,
    dry_run: bool,
) -> JsValue {
    init_panic_hook();

    // 1. Parse keys
    let root_bytes: [u8; 32] = match hex::decode(trusted_root_hex.trim()) {
        Ok(b) => match b.try_into() {
            Ok(b) => b,
            Err(_) => return to_auth_error("Invalid trusted root key length (must be 32 bytes)"),
        },
        Err(_) => return to_auth_error("Invalid trusted root hex"),
    };
    let root_key = match PublicKey::from_bytes(&root_bytes) {
        Ok(k) => k,
        Err(_) => return to_auth_error("Invalid trusted root key bytes"),
    };

    // 2. Parse warrants
    let mut chain: Vec<Warrant> = Vec::new();
    for b64 in warrant_b64_list {
        match wire::decode_base64(b64.trim()) {
            Ok(w) => chain.push(w),
            Err(e) => return to_auth_error(&format!("Invalid warrant in chain: {}", e)),
        }
    }

    if chain.is_empty() {
        return to_auth_error("Warrant chain is empty");
    }

    // 3. Parse args
    let args: HashMap<String, ConstraintValue> = match serde_wasm_bindgen::from_value(args_json) {
        Ok(a) => a,
        Err(e) => return to_auth_error(&format!("Invalid arguments JSON: {}", e)),
    };

    // 4. Verify chain structure (signature chain, TTL cascade, monotonic attenuation)
    // This is done regardless of dry_run since it verifies chain integrity
    for i in 1..chain.len() {
        let parent = &chain[i - 1];
        let child = &chain[i];

        // Check holder -> issuer linkage (parent's holder must be child's issuer)
        if parent.authorized_holder() != child.issuer() {
            return serde_wasm_bindgen::to_value(&AuthResult {
                authorized: false,
                reason: Some(format!(
                    "Chain broken at position {}: parent holder != child issuer",
                    i
                )),
                deny_code: Some("CHAIN_BROKEN".to_string()),
                field: None,
            })
            .unwrap();
        }

        // Check TTL cascade (child expires <= parent expires)
        if child.expires_at() > parent.expires_at() {
            return serde_wasm_bindgen::to_value(&AuthResult {
                authorized: false,
                reason: Some(format!(
                    "TTL violation at position {}: child expires after parent",
                    i
                )),
                deny_code: Some("TTL_VIOLATION".to_string()),
                field: None,
            })
            .unwrap();
        }
    }

    // Check root issuer matches trusted root
    if *chain[0].issuer() != root_key {
        return serde_wasm_bindgen::to_value(&AuthResult {
            authorized: false,
            reason: Some("Root warrant issuer does not match trusted root key".to_string()),
            deny_code: Some("UNTRUSTED_ROOT".to_string()),
            field: None,
        })
        .unwrap();
    }

    // 5. Policy check on the leaf warrant (last in chain)
    let leaf = chain.last().unwrap();

    if dry_run {
        // Dry run: check policy only, skip PoP
        if let Some(caps) = leaf.capabilities() {
            if let Some(constraints) = caps.get(tool) {
                match constraints.matches(&args) {
                    Ok(_) => serde_wasm_bindgen::to_value(&AuthResult {
                        authorized: true,
                        reason: Some(format!(
                            "Chain valid ({} warrants). Policy check passed (PoP skipped).",
                            chain.len()
                        )),
                        deny_code: None,
                        field: None,
                    })
                    .unwrap(),
                    Err(e) => serde_wasm_bindgen::to_value(&AuthResult {
                        authorized: false,
                        reason: Some(format!("Policy violation: {}", e)),
                        deny_code: Some("POLICY_VIOLATION".to_string()),
                        field: None,
                    })
                    .unwrap(),
                }
            } else if let Some(constraints) = caps.get("*") {
                match constraints.matches(&args) {
                    Ok(_) => serde_wasm_bindgen::to_value(&AuthResult {
                        authorized: true,
                        reason: Some(format!(
                            "Chain valid ({} warrants). Policy check passed (PoP skipped).",
                            chain.len()
                        )),
                        deny_code: None,
                        field: None,
                    })
                    .unwrap(),
                    Err(e) => serde_wasm_bindgen::to_value(&AuthResult {
                        authorized: false,
                        reason: Some(format!("Policy violation: {}", e)),
                        deny_code: Some("POLICY_VIOLATION".to_string()),
                        field: None,
                    })
                    .unwrap(),
                }
            } else {
                return to_auth_error(&format!("Tool '{}' not authorized by leaf warrant", tool));
            }
        } else {
            return to_auth_error("Leaf warrant has no capabilities");
        }
    } else {
        // Full check with PoP (requires signature)
    let authorizer = Authorizer::new().with_trusted_root(root_key);
    
    match authorizer.check_chain(&chain, tool, &args, None, &[]) {
            Ok(_) => serde_wasm_bindgen::to_value(&AuthResult {
                authorized: true,
                reason: None,
                deny_code: None,
                field: None,
            })
            .unwrap(),
            Err(e) => serde_wasm_bindgen::to_value(&AuthResult {
                authorized: false,
                reason: Some(e.to_string()),
                deny_code: Some("DENIED".to_string()),
                field: None,
            })
            .unwrap(),
        }
    }
}

fn to_auth_error(msg: &str) -> JsValue {
    serde_wasm_bindgen::to_value(&AuthResult {
        authorized: false,
        reason: Some(msg.to_string()),
        deny_code: Some("ERROR".to_string()),
        field: None,
    })
    .unwrap()
}

/// Result of keypair generation
#[derive(serde::Serialize)]
pub struct KeypairResult {
    pub private_key_hex: String,
    pub public_key_hex: String,
}

/// Generate a new Ed25519 keypair for testing PoP
#[wasm_bindgen]
pub fn generate_keypair() -> JsValue {
    let keypair = SigningKey::generate();
    let result = KeypairResult {
        private_key_hex: hex::encode(keypair.secret_key_bytes()),
        public_key_hex: hex::encode(keypair.public_key().to_bytes()),
    };
    serde_wasm_bindgen::to_value(&result).unwrap()
}

/// Result of PoP signature creation
#[derive(serde::Serialize)]
pub struct PopSignatureResult {
    pub signature_hex: String,
    pub error: Option<String>,
}

/// Create a Proof-of-Possession signature for a warrant
#[wasm_bindgen]
pub fn sign(private_key_hex: &str, warrant_b64: &str, tool: &str, args_json: JsValue) -> JsValue {
    init_panic_hook();
    
    // 1. Parse private key
    let key_bytes: [u8; 32] = match hex::decode(private_key_hex.trim()) {
        Ok(b) => match b.try_into() {
            Ok(b) => b,
            Err(_) => return to_pop_error("Invalid private key length (must be 32 bytes)"),
        },
        Err(_) => return to_pop_error("Invalid private key hex"),
    };
    let keypair = SigningKey::from_bytes(&key_bytes);
    
    // 2. Parse warrant
    let warrant = match wire::decode_base64(warrant_b64.trim()) {
        Ok(w) => w,
        Err(e) => return to_pop_error(&format!("Invalid warrant: {}", e)),
    };
    
    // 3. Parse args
    let args: HashMap<String, ConstraintValue> = match serde_wasm_bindgen::from_value(args_json) {
        Ok(a) => a,
        Err(e) => return to_pop_error(&format!("Invalid arguments JSON: {}", e)),
    };
    
    // 4. Create PoP signature
    match warrant.sign(&keypair, tool, &args) {
        Ok(sig) => serde_wasm_bindgen::to_value(&PopSignatureResult {
                signature_hex: hex::encode(sig.to_bytes()),
                error: None,
        })
        .unwrap(),
        Err(e) => to_pop_error(&format!("Failed to create PoP: {}", e)),
    }
}

fn to_pop_error(msg: &str) -> JsValue {
    serde_wasm_bindgen::to_value(&PopSignatureResult {
        signature_hex: String::new(),
        error: Some(msg.to_string()),
    })
    .unwrap()
}

/// Check authorization with a real PoP signature
#[wasm_bindgen]
pub fn check_access_with_pop(
    warrant_b64: &str, 
    tool: &str, 
    args_json: JsValue, 
    trusted_root_hex: &str,
    pop_signature_hex: &str,
) -> JsValue {
    init_panic_hook();
    
    // 1. Parse root key
    let root_bytes: [u8; 32] = match hex::decode(trusted_root_hex.trim()) {
        Ok(b) => match b.try_into() {
            Ok(b) => b,
            Err(_) => return to_auth_error("Invalid trusted root key length (must be 32 bytes)"),
        },
        Err(_) => return to_auth_error("Invalid trusted root hex"),
    };
    let root_key = match PublicKey::from_bytes(&root_bytes) {
        Ok(k) => k,
        Err(_) => return to_auth_error("Invalid trusted root key bytes"),
    };

    // 2. Parse warrant
    let warrant = match wire::decode_base64(warrant_b64.trim()) {
        Ok(w) => w,
        Err(e) => return to_auth_error(&format!("Invalid warrant: {}", e)),
    };

    // 3. Parse args
    let args: HashMap<String, ConstraintValue> = match serde_wasm_bindgen::from_value(args_json) {
        Ok(a) => a,
        Err(e) => return to_auth_error(&format!("Invalid arguments JSON: {}", e)),
    };
    
    // 4. Parse PoP signature (must be exactly 64 bytes)
    let sig_bytes = match hex::decode(pop_signature_hex.trim()) {
        Ok(b) => b,
        Err(_) => return to_auth_error("Invalid PoP signature hex"),
    };
    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return to_auth_error("PoP signature must be exactly 64 bytes"),
    };
    let signature = match tenuo::Signature::from_bytes(&sig_array) {
        Ok(s) => s,
        Err(_) => return to_auth_error("Invalid PoP signature bytes"),
    };

    // 5. Full authorization with PoP
    let authorizer = Authorizer::new().with_trusted_root(root_key);
    match authorizer.authorize_one(&warrant, tool, &args, Some(&signature), &[]) {
        Ok(_) => serde_wasm_bindgen::to_value(&AuthResult {
                authorized: true,
                reason: Some("Full authorization with PoP verified".to_string()),
                deny_code: None,
                field: None,
        })
        .unwrap(),
        Err(e) => serde_wasm_bindgen::to_value(&AuthResult {
                authorized: false,
                reason: Some(e.to_string()),
                deny_code: Some("DENIED".to_string()),
                field: None,
        })
        .unwrap(),
    }
}

/// Result of sample warrant creation
#[derive(serde::Serialize)]
pub struct SampleWarrantResult {
    pub warrant_b64: String,
    pub root_key_hex: String,
    pub holder_private_key_hex: String,
    pub holder_public_key_hex: String,
    pub tool: String,
    pub ttl_seconds: u64,
    pub error: Option<String>,
}

/// Create a fresh sample warrant with the given tool and TTL
/// This generates new keys each time, ensuring the warrant is never expired
#[wasm_bindgen]
pub fn create_sample_warrant(
    tool: &str,
    constraint_field: &str,
    constraint_pattern: &str,
    ttl_seconds: u64,
) -> JsValue {
    init_panic_hook();
    
    // Generate fresh keypairs
    let issuer_key = SigningKey::generate();
    let holder_key = SigningKey::generate();
    
    // Build constraints
    let mut constraint_set = ConstraintSet::new();
    let pattern = match Pattern::new(constraint_pattern) {
        Ok(p) => p,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&SampleWarrantResult {
                warrant_b64: String::new(),
                root_key_hex: String::new(),
                holder_private_key_hex: String::new(),
                holder_public_key_hex: String::new(),
                tool: tool.to_string(),
                ttl_seconds,
                error: Some(format!("Invalid pattern: {}", e)),
            })
            .unwrap();
        }
    };
    constraint_set.insert(constraint_field.to_string(), Constraint::Pattern(pattern));
    
    // Build and sign the warrant
    let warrant = match Warrant::builder()
        .capability(tool, constraint_set)
        .ttl(Duration::from_secs(ttl_seconds))
        .holder(holder_key.public_key())
        .build(&issuer_key) 
    {
        Ok(w) => w,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&SampleWarrantResult {
                warrant_b64: String::new(),
                root_key_hex: String::new(),
                holder_private_key_hex: String::new(),
                holder_public_key_hex: String::new(),
                tool: tool.to_string(),
                ttl_seconds,
                error: Some(format!("Failed to build warrant: {}", e)),
            })
            .unwrap();
        }
    };
    
    // Encode to base64
    let warrant_b64 = match wire::encode_base64(&warrant) {
        Ok(b) => b,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&SampleWarrantResult {
                warrant_b64: String::new(),
                root_key_hex: String::new(),
                holder_private_key_hex: String::new(),
                holder_public_key_hex: String::new(),
                tool: tool.to_string(),
                ttl_seconds,
                error: Some(format!("Failed to encode warrant: {}", e)),
            })
            .unwrap();
        }
    };
    
    serde_wasm_bindgen::to_value(&SampleWarrantResult {
        warrant_b64,
        root_key_hex: hex::encode(issuer_key.public_key().to_bytes()),
        holder_private_key_hex: hex::encode(holder_key.secret_key_bytes()),
        holder_public_key_hex: hex::encode(holder_key.public_key().to_bytes()),
        tool: tool.to_string(),
        ttl_seconds,
        error: None,
    })
    .unwrap()
}

/// Result of warrant creation from builder config
#[derive(serde::Serialize)]
pub struct BuilderWarrantResult {
    pub warrant_b64: String,
    pub issuer_public_key_hex: String,
    pub issuer_private_key_hex: String,
    pub holder_public_key_hex: String,
    pub holder_private_key_hex: String,
    pub tools: Vec<String>,
    pub error: Option<String>,
}

/// Create a warrant from the full builder config (multiple tools, multiple constraints)
/// This is more flexible than create_sample_warrant
#[wasm_bindgen]
pub fn create_warrant_from_config(config_json: JsValue) -> JsValue {
    init_panic_hook();

    #[derive(serde::Deserialize)]
    struct BuilderConfig {
        tools: HashMap<String, HashMap<String, serde_json::Value>>,
        ttl: u64,
        #[allow(dead_code)]
        max_depth: Option<u32>,
        signing_key_hex: Option<String>,
        holder_key_hex: Option<String>,
        parent_warrant_b64: Option<String>,
        /// Approval gates to embed in the warrant's extensions.
        /// JSON object: { "tool_name": { "args": null } } for whole-tool,
        /// { "tool_name": { "args": { "field": "all" } } } for per-arg.
        approval_gates: Option<serde_json::Value>,
        /// Hex-encoded Ed25519 public keys of required approvers.
        required_approvers: Option<Vec<String>>,
        /// Minimum number of approvals required.
        min_approvals: Option<u32>,
    }

    let config: BuilderConfig = match serde_wasm_bindgen::from_value(config_json) {
        Ok(c) => c,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
                warrant_b64: String::new(),
                issuer_public_key_hex: String::new(),
                issuer_private_key_hex: String::new(),
                holder_public_key_hex: String::new(),
                holder_private_key_hex: String::new(),
                tools: vec![],
                error: Some(format!("Invalid config: {}", e)),
            })
            .unwrap();
        }
    };

    // Generate or parse keypairs
    let issuer_key = if let Some(hex_str) = &config.signing_key_hex {
        match hex::decode(hex_str) {
            Ok(bytes) => match bytes.try_into() {
                Ok(arr) => SigningKey::from_bytes(&arr),
                Err(_) => SigningKey::generate(), // Fallback (should handle error ideally)
            },
            Err(_) => SigningKey::generate(),
        }
    } else {
        SigningKey::generate()
    };

    let holder_key = if let Some(hex_str) = &config.holder_key_hex {
        match hex::decode(hex_str) {
            Ok(bytes) => match bytes.try_into() {
                Ok(arr) => SigningKey::from_bytes(&arr),
                Err(_) => SigningKey::generate(),
            },
            Err(_) => SigningKey::generate(),
        }
    } else {
        SigningKey::generate()
    };

    // Collect tool names
    let tool_names: Vec<String> = config.tools.keys().cloned().collect();

    // Helper to parse constraints from JSON into ConstraintSet
    let parse_constraints =
        |constraints: &HashMap<String, serde_json::Value>| -> Result<ConstraintSet, String> {
            let mut constraint_set = ConstraintSet::new();
            for (field, constraint_value) in constraints {
                if let Some(obj) = constraint_value.as_object() {
                    // Pattern constraint
                    if let Some(pattern_val) = obj.get("pattern").and_then(|v| v.as_str()) {
                        if let Ok(p) = Pattern::new(pattern_val) {
                            constraint_set.insert(field.clone(), Constraint::Pattern(p));
                        }
                    }
                    // Exact constraint
                    else if let Some(exact_val) = obj.get("exact").and_then(|v| v.as_str()) {
                        constraint_set.insert(
                            field.clone(),
                            Constraint::Exact(Exact::new(ConstraintValue::String(
                                exact_val.to_string(),
                            ))),
                        );
                    }
                    // Range constraint
                    else if let Some(range_val) = obj.get("range").and_then(|v| v.as_str()) {
                        if range_val.ends_with('-') {
                            let min_str = &range_val[..range_val.len() - 1];
                            if let Ok(min) = min_str.parse::<f64>() {
                                if let Ok(r) = Range::min(min) {
                                    constraint_set.insert(field.clone(), Constraint::Range(r));
                                }
                            }
                        } else if range_val.contains('-') {
                            let mut split_pos = None;
                            for (i, c) in range_val.char_indices().skip(1) {
                                if c == '-' {
                                    split_pos = Some(i);
                                    break;
                                }
                            }
                            if let Some(pos) = split_pos {
                                let min_str = &range_val[..pos];
                                let max_str = &range_val[pos + 1..];
                                if let (Ok(min), Ok(max)) =
                                    (min_str.parse::<f64>(), max_str.parse::<f64>())
                                {
                                    if min <= max {
                                        if let Ok(r) = Range::new(Some(min), Some(max)) {
                                            constraint_set
                                                .insert(field.clone(), Constraint::Range(r));
                                        }
                                    }
                                }
                            }
                        } else if let Ok(max) = range_val.parse::<f64>() {
                            if let Ok(r) = Range::max(max) {
                                constraint_set.insert(field.clone(), Constraint::Range(r));
                            }
                        }
                    }
                    // OneOf constraint
                    else if let Some(oneof_val) = obj.get("oneof").and_then(|v| v.as_str()) {
                        let values: Vec<String> = oneof_val
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        if !values.is_empty() {
                            constraint_set
                                .insert(field.clone(), Constraint::OneOf(OneOf::new(values)));
                        }
                    }
                    // AnyOf constraint
                    else if let Some(anyof_val) = obj.get("anyof").and_then(|v| v.as_str()) {
                        let patterns: Vec<Pattern> = anyof_val
                            .split(',')
                            .filter_map(|s| {
                                let trimmed = s.trim();
                                if trimmed.is_empty() {
                                    None
                                } else {
                                    Pattern::new(trimmed).ok()
                                }
                            })
                            .collect();
                        if !patterns.is_empty() {
                            constraint_set.insert(
                                field.clone(),
                                Constraint::Any(Any::new(
                                    patterns.into_iter().map(Constraint::Pattern),
                                )),
                            );
                        }
                    }
                    // NotOneOf constraint
                    else if let Some(notoneof_val) = obj.get("notoneof").and_then(|v| v.as_str()) {
                        let values: Vec<String> = notoneof_val
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        if !values.is_empty() {
                            constraint_set
                                .insert(field.clone(), Constraint::NotOneOf(NotOneOf::new(values)));
                        }
                    }
                    // CIDR constraint
                    else if let Some(cidr_val) = obj.get("cidr").and_then(|v| v.as_str()) {
                        if let Ok(c) = Cidr::new(cidr_val) {
                            constraint_set.insert(field.clone(), Constraint::Cidr(c));
                        }
                    }
                    // UrlPattern constraint
                    else if let Some(url_val) = obj.get("urlpattern").and_then(|v| v.as_str()) {
                        if let Ok(u) = UrlPattern::new(url_val) {
                            constraint_set.insert(field.clone(), Constraint::UrlPattern(u));
                        }
                    }
                    // Regex constraint
                    else if let Some(regex_val) = obj.get("regex").and_then(|v| v.as_str()) {
                        if let Ok(r) = RegexConstraint::new(regex_val) {
                            constraint_set.insert(field.clone(), Constraint::Regex(r));
                        }
                    }
                    // Wildcard constraint
                    else if let Some(wildcard_val) = obj.get("wildcard").and_then(|v| v.as_str()) {
                        if let Ok(p) = Pattern::new(wildcard_val) {
                            constraint_set.insert(field.clone(), Constraint::Pattern(p));
                        }
                    }
                    // Contains constraint
                    else if let Some(contains_val) = obj.get("contains").and_then(|v| v.as_str()) {
                        let values: Vec<String> = contains_val
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        if !values.is_empty() {
                            constraint_set
                                .insert(field.clone(), Constraint::Contains(Contains::new(values)));
                        }
                    }
                    // Subpath constraint (safe path containment)
                    else if let Some(subpath_obj) = obj.get("subpath") {
                        // Handle both { subpath: "/data" } and { subpath: { root: "/data" } }
                        let root = if let Some(root_str) = subpath_obj.as_str() {
                            Some(root_str.to_string())
                        } else if let Some(subpath_inner) = subpath_obj.as_object() {
                            subpath_inner.get("root").and_then(|v| v.as_str()).map(|s| s.to_string())
                        } else {
                            None
                        };
                        if let Some(root_path) = root {
                            if let Ok(s) = Subpath::new(&root_path) {
                                constraint_set.insert(field.clone(), Constraint::Subpath(s));
                            }
                        }
                    }
                    // UrlSafe constraint (SSRF protection)
                    else if obj.contains_key("url_safe") || obj.contains_key("urlsafe") {
                        let url_safe_obj = obj.get("url_safe").or_else(|| obj.get("urlsafe"));
                        if let Some(inner) = url_safe_obj.and_then(|v| v.as_object()) {
                            let mut us = UrlSafe::new();
                            if let Some(domains_arr) = inner.get("allow_domains").and_then(|v| v.as_array()) {
                                let domains: Vec<String> = domains_arr
                                    .iter()
                                    .filter_map(|d| d.as_str().map(|s| s.to_string()))
                                    .collect();
                                if !domains.is_empty() {
                                    us.allow_domains = Some(domains);
                                }
                            }
                            if let Some(deny_arr) = inner.get("deny_domains").and_then(|v| v.as_array()) {
                                let denied: Vec<String> = deny_arr
                                    .iter()
                                    .filter_map(|d| d.as_str().map(|s| s.to_string()))
                                    .collect();
                                if !denied.is_empty() {
                                    us.deny_domains = Some(denied);
                                }
                            }
                            constraint_set.insert(field.clone(), Constraint::UrlSafe(us));
                        } else {
                            constraint_set.insert(field.clone(), Constraint::UrlSafe(UrlSafe::new()));
                        }
                    }
                    // Shlex constraint (shell command safety)
                    else if obj.contains_key("shlex") {
                        let shlex_obj = obj.get("shlex");
                        if let Some(inner) = shlex_obj.and_then(|v| v.as_object()) {
                            if let Some(allow_arr) = inner.get("allow").and_then(|v| v.as_array()) {
                                let allow: Vec<String> = allow_arr
                                    .iter()
                                    .filter_map(|a| a.as_str().map(|s| s.to_string()))
                                    .collect();
                                if !allow.is_empty() {
                                    constraint_set.insert(
                                        field.clone(),
                                        Constraint::Shlex(Shlex { allow }),
                                    );
                                }
                            }
                        }
                    }
                    // Unrecognized constraint key: fail closed
                    else {
                        let keys: Vec<&String> = obj.keys().collect();
                        return Err(format!(
                            "unrecognized constraint key(s) {:?} for field '{}'; refusing to silently drop",
                            keys, field
                        ));
                    }
                }
            }
            Ok(constraint_set)
        };

    // Check if we're creating a delegated warrant or a root warrant
    if let Some(parent_b64) = &config.parent_warrant_b64 {
        // DELEGATION: Create child warrant from parent
        let parent: Warrant = match wire::decode_base64(parent_b64) {
            Ok(p) => p,
            Err(e) => {
                return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
                    warrant_b64: String::new(),
                    issuer_public_key_hex: String::new(),
                    issuer_private_key_hex: String::new(),
                    holder_public_key_hex: String::new(),
                    holder_private_key_hex: String::new(),
                    tools: tool_names,
                    error: Some(format!("Failed to decode parent warrant: {}", e)),
                })
                .unwrap();
            }
        };

        // Build attenuated warrant
        let mut att_builder = parent.attenuate().holder(holder_key.public_key());

        for (tool_name, constraints) in &config.tools {
            let constraint_set = match parse_constraints(constraints) {
                Ok(cs) => cs,
                Err(e) => {
                    return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
                        warrant_b64: String::new(),
                        issuer_public_key_hex: String::new(),
                        issuer_private_key_hex: String::new(),
                        holder_public_key_hex: String::new(),
                        holder_private_key_hex: String::new(),
                        tools: vec![],
                        error: Some(format!("Constraint parse error: {}", e)),
                    })
                    .unwrap();
                }
            };
            att_builder = att_builder.capability(tool_name, constraint_set);
        }

        att_builder = att_builder.ttl(Duration::from_secs(config.ttl));

        // Note: AttenuationBuilder auto-inherits approval gates and required_approvers
        // from the parent warrant. The monotonicity rules prevent weakening gates.

        let warrant = match att_builder.build(&issuer_key) {
            Ok(w) => w,
            Err(e) => {
                return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
                    warrant_b64: String::new(),
                    issuer_public_key_hex: String::new(),
                    issuer_private_key_hex: String::new(),
                    holder_public_key_hex: String::new(),
                    holder_private_key_hex: String::new(),
                    tools: tool_names,
                    error: Some(format!("Failed to build delegated warrant: {}", e)),
                })
                .unwrap();
            }
        };

        let warrant_b64 = match wire::encode_base64(&warrant) {
            Ok(b) => b,
            Err(e) => {
                return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
                    warrant_b64: String::new(),
                    issuer_public_key_hex: String::new(),
                    issuer_private_key_hex: String::new(),
                    holder_public_key_hex: String::new(),
                    holder_private_key_hex: String::new(),
                    tools: tool_names,
                    error: Some(format!("Failed to encode warrant: {}", e)),
                })
                .unwrap();
            }
        };

        return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
            warrant_b64,
            issuer_public_key_hex: hex::encode(issuer_key.public_key().to_bytes()),
            issuer_private_key_hex: hex::encode(issuer_key.secret_key_bytes()),
            holder_public_key_hex: hex::encode(holder_key.public_key().to_bytes()),
            holder_private_key_hex: hex::encode(holder_key.secret_key_bytes()),
            tools: tool_names,
            error: None,
        })
        .unwrap();
    }

    // ROOT WARRANT: Create new warrant from scratch
    let mut builder = Warrant::builder()
        .ttl(Duration::from_secs(config.ttl))
        .holder(holder_key.public_key());

    for (tool_name, constraints) in &config.tools {
        let constraint_set = match parse_constraints(constraints) {
            Ok(cs) => cs,
            Err(e) => {
                return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
                    warrant_b64: String::new(),
                    issuer_public_key_hex: String::new(),
                    issuer_private_key_hex: String::new(),
                    holder_public_key_hex: String::new(),
                    holder_private_key_hex: String::new(),
                    tools: vec![],
                    error: Some(format!("Constraint parse error: {}", e)),
                })
                .unwrap();
            }
        };
        builder = builder.capability(tool_name, constraint_set);
    }

    // Wire approval gates into extensions
    if let Some(gates_json) = &config.approval_gates {
        if let Some(gm) = parse_approval_gates_json(gates_json) {
            match approval_gate::encode_approval_gate_map(&gm) {
                Ok(encoded) => {
                    builder = builder.extension(
                        approval_gate::APPROVAL_GATE_EXTENSION_KEY,
                        encoded,
                    );
                }
                Err(e) => {
                    return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
                        warrant_b64: String::new(),
                        issuer_public_key_hex: String::new(),
                        issuer_private_key_hex: String::new(),
                        holder_public_key_hex: String::new(),
                        holder_private_key_hex: String::new(),
                        tools: tool_names,
                        error: Some(format!("Failed to encode approval gates: {}", e)),
                    })
                    .unwrap();
                }
            }
        }
    }

    // Wire required approvers
    if let Some(approver_hexes) = &config.required_approvers {
        let mut approvers = Vec::new();
        for hex_str in approver_hexes {
            match hex::decode(hex_str) {
                Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                    Ok(arr) => match PublicKey::from_bytes(&arr) {
                        Ok(pk) => approvers.push(pk),
                        Err(e) => {
                            return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
                                warrant_b64: String::new(),
                                issuer_public_key_hex: String::new(),
                                issuer_private_key_hex: String::new(),
                                holder_public_key_hex: String::new(),
                                holder_private_key_hex: String::new(),
                                tools: tool_names,
                                error: Some(format!("Invalid approver key: {}", e)),
                            })
                            .unwrap();
                        }
                    },
                    Err(_) => {
                        return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
                            warrant_b64: String::new(),
                            issuer_public_key_hex: String::new(),
                            issuer_private_key_hex: String::new(),
                            holder_public_key_hex: String::new(),
                            holder_private_key_hex: String::new(),
                            tools: tool_names,
                            error: Some("Approver key must be 32 bytes".to_string()),
                        })
                        .unwrap();
                    }
                },
                Err(_) => {
                    return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
                        warrant_b64: String::new(),
                        issuer_public_key_hex: String::new(),
                        issuer_private_key_hex: String::new(),
                        holder_public_key_hex: String::new(),
                        holder_private_key_hex: String::new(),
                        tools: tool_names,
                        error: Some("Invalid approver key hex".to_string()),
                    })
                    .unwrap();
                }
            }
        }
        if !approvers.is_empty() {
            builder = builder.required_approvers(approvers);
        }
    }

    if let Some(min) = config.min_approvals {
        builder = builder.min_approvals(min);
    }

    // Build and sign
    let warrant = match builder.build(&issuer_key) {
        Ok(w) => w,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
                warrant_b64: String::new(),
                issuer_public_key_hex: String::new(),
                issuer_private_key_hex: String::new(),
                holder_public_key_hex: String::new(),
                holder_private_key_hex: String::new(),
                tools: tool_names,
                error: Some(format!("Failed to build warrant: {}", e)),
            })
            .unwrap();
        }
    };

    // Encode to base64
    let warrant_b64 = match wire::encode_base64(&warrant) {
        Ok(b) => b,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&BuilderWarrantResult {
                warrant_b64: String::new(),
                issuer_public_key_hex: String::new(),
                issuer_private_key_hex: String::new(),
                holder_public_key_hex: String::new(),
                holder_private_key_hex: String::new(),
                tools: tool_names,
                error: Some(format!("Failed to encode warrant: {}", e)),
            })
            .unwrap();
        }
    };

    serde_wasm_bindgen::to_value(&BuilderWarrantResult {
        warrant_b64,
        issuer_public_key_hex: hex::encode(issuer_key.public_key().to_bytes()),
        issuer_private_key_hex: hex::encode(issuer_key.secret_key_bytes()),
        holder_public_key_hex: hex::encode(holder_key.public_key().to_bytes()),
        holder_private_key_hex: hex::encode(holder_key.secret_key_bytes()),
        tools: tool_names,
        error: None,
    })
    .unwrap()
}

/// Result of decoding a warrant chain
#[derive(serde::Serialize)]
pub struct ChainDecodeResult {
    pub warrants: Vec<DecodedWarrant>,
    pub is_chain: bool,
    pub chain_valid: bool,
    pub chain_errors: Vec<String>,
    pub attenuation_diffs: Vec<AttenuationDiff>,
    pub error: Option<String>,
}

/// Represents how authority attenuates between warrants
#[derive(serde::Serialize)]
pub struct AttenuationDiff {
    pub from_idx: usize,
    pub to_idx: usize,
    pub tools_removed: Vec<String>,
    pub tools_added: Vec<String>,
    pub constraints_narrowed: Vec<ConstraintNarrowing>,
    pub ttl_reduced_by_secs: i64,
}

/// Describes how a constraint narrowed
#[derive(serde::Serialize)]
pub struct ConstraintNarrowing {
    pub tool: String,
    pub field: String,
    pub parent_value: String,
    pub child_value: String,
    pub valid: bool,
}

/// Decode a PEM chain (or single warrant) and return detailed chain analysis
#[wasm_bindgen]
pub fn decode_pem_chain_wasm(input: &str) -> JsValue {
    init_panic_hook();

    let trimmed = input.trim();
    if trimmed.is_empty() {
        return serde_wasm_bindgen::to_value(&ChainDecodeResult {
            warrants: vec![],
            is_chain: false,
            chain_valid: false,
            chain_errors: vec![],
            attenuation_diffs: vec![],
            error: Some("Empty input".to_string()),
        })
        .unwrap();
    }

    // Try to decode as chain (handles single, multiple PEM blocks, or explicit chain)
    match wire::decode_pem_chain(trimmed) {
        Ok(stack) => {
            let warrants_raw = &stack.0;
            let is_chain = warrants_raw.len() > 1;

            // Decode each warrant
            let mut decoded_warrants: Vec<DecodedWarrant> = vec![];
            for w in warrants_raw {
                decoded_warrants.push(extract_decoded_warrant(w));
            }

            // Validate chain linkage and compute diffs
            let mut chain_errors: Vec<String> = vec![];
            let mut attenuation_diffs: Vec<AttenuationDiff> = vec![];

            for i in 0..warrants_raw.len().saturating_sub(1) {
                let parent = &warrants_raw[i];
                let child = &warrants_raw[i + 1];

                // Human-readable labels for chain positions
                let parent_label = if i == 0 {
                    "Root".to_string()
                } else {
                    format!("Level {}", i)
                };
                let child_label = if i + 1 == warrants_raw.len() - 1 {
                    "Leaf".to_string()
                } else {
                    format!("Level {}", i + 1)
                };

                // Check holder → issuer linkage
                let parent_holder = parent.authorized_holder();
                let child_issuer = child.issuer();
                if parent_holder != child_issuer {
                    chain_errors.push(format!(
                        "🔗 Linkage broken: {} holder ({}) ≠ {} issuer ({}). The child must be issued by the parent's holder.",
                        parent_label,
                        &hex::encode(parent_holder.to_bytes())[..8],
                        child_label,
                        &hex::encode(child_issuer.to_bytes())[..8]
                    ));
                }

                // Check TTL cascade
                if child.expires_at() > parent.expires_at() {
                    let excess_secs =
                        child.expires_at().timestamp() - parent.expires_at().timestamp();
                    chain_errors.push(format!(
                        "⏰ TTL violation: {} expires {}s after {}. Delegated warrants cannot outlive their parent.",
                        child_label,
                        excess_secs,
                        parent_label
                    ));
                }

                // Check depth
                if child.depth() <= parent.depth() && parent.depth() > 0 {
                    chain_errors.push(format!(
                        "📊 Depth violation: {} has depth {} but {} has depth {}. Each delegation should increase depth.",
                        child_label,
                        child.depth(),
                        parent_label,
                        parent.depth()
                    ));
                }

                // Compute attenuation diff
                let parent_tools: std::collections::HashSet<_> =
                    parent.tools().into_iter().collect();
                let child_tools: std::collections::HashSet<_> = child.tools().into_iter().collect();

                let tools_removed: Vec<String> =
                    parent_tools.difference(&child_tools).cloned().collect();
                let tools_added: Vec<String> =
                    child_tools.difference(&parent_tools).cloned().collect();

                if !tools_added.is_empty() {
                    chain_errors.push(format!(
                        "🔧 Tool expansion: {} adds tools {:?} not in {}. Authority can only shrink, never expand.",
                        child_label,
                        tools_added,
                        parent_label
                    ));
                }

                // Compute constraint narrowing
                let mut constraints_narrowed: Vec<ConstraintNarrowing> = vec![];
                if let (Some(parent_caps), Some(child_caps)) =
                    (parent.capabilities(), child.capabilities())
                {
                    for (tool, child_cs) in child_caps.iter() {
                        if let Some(parent_cs) = parent_caps.get(tool) {
                            for (field, child_constraint) in child_cs.iter() {
                                if let Some(parent_constraint) = parent_cs.get(field) {
                                    let parent_val = serde_json::to_string(
                                        &constraint_to_readable(parent_constraint),
                                    )
                                    .unwrap_or_default();
                                    let child_val = serde_json::to_string(&constraint_to_readable(
                                        child_constraint,
                                    ))
                                    .unwrap_or_default();
                                    if parent_val != child_val {
                                        constraints_narrowed.push(ConstraintNarrowing {
                                            tool: tool.clone(),
                                            field: field.clone(),
                                            parent_value: parent_val,
                                            child_value: child_val,
                                            valid: true, // Would need full attenuation check
                                        });
                                    }
                                } else {
                                    // Child adds constraint not in parent
                                    let child_val = serde_json::to_string(&constraint_to_readable(
                                        child_constraint,
                                    ))
                                    .unwrap_or_default();
                                    constraints_narrowed.push(ConstraintNarrowing {
                                        tool: tool.clone(),
                                        field: field.clone(),
                                        parent_value: "(none)".to_string(),
                                        child_value: child_val,
                                        valid: true, // Adding constraints is valid narrowing
                                    });
                                }
                            }
                        }
                    }
                }

                let ttl_reduced = parent.expires_at().timestamp() - child.expires_at().timestamp();

                attenuation_diffs.push(AttenuationDiff {
                    from_idx: i,
                    to_idx: i + 1,
                    tools_removed,
                    tools_added,
                    constraints_narrowed,
                    ttl_reduced_by_secs: ttl_reduced,
                });
            }

            let chain_valid = chain_errors.is_empty();

            let serializer = Serializer::new().serialize_maps_as_objects(true);
            ChainDecodeResult {
                warrants: decoded_warrants,
                is_chain,
                chain_valid,
                chain_errors,
                attenuation_diffs,
                error: None,
            }
            .serialize(&serializer)
            .unwrap()
        }
        Err(e) => serde_wasm_bindgen::to_value(&ChainDecodeResult {
            warrants: vec![],
            is_chain: false,
            chain_valid: false,
            chain_errors: vec![],
            attenuation_diffs: vec![],
            error: Some(format!("Failed to decode: {}", e)),
        })
        .unwrap(),
    }
}

// ---------------------------------------------------------------------------
// Approval gate evaluation
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
pub struct ApprovalGateResult {
    pub approval_required: bool,
    pub tool: String,
    pub error: Option<String>,
}

/// Evaluate whether a tool call requires approval based on the warrant's embedded approval gates.
///
/// Returns `{ approval_required: true/false, tool, error }`.
/// This reads `extensions["tenuo.approval_gates"]` from the warrant, parses it,
/// and runs the gate evaluation logic from tenuo-core.
#[wasm_bindgen]
pub fn evaluate_approval_gates(
    warrant_b64: &str,
    tool: &str,
    args_json: JsValue,
) -> JsValue {
    init_panic_hook();

    let warrant = match wire::decode_base64(warrant_b64.trim()) {
        Ok(w) => w,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&ApprovalGateResult {
                approval_required: false,
                tool: tool.to_string(),
                error: Some(format!("Invalid warrant: {}", e)),
            })
            .unwrap();
        }
    };

    let gate_map = match approval_gate::parse_approval_gate_map(
        warrant.extension(approval_gate::APPROVAL_GATE_EXTENSION_KEY),
    ) {
        Ok(gm) => gm,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&ApprovalGateResult {
                approval_required: false,
                tool: tool.to_string(),
                error: Some(format!("Failed to parse approval gates: {}", e)),
            })
            .unwrap();
        }
    };

    let args: HashMap<String, ConstraintValue> = match serde_wasm_bindgen::from_value(args_json) {
        Ok(a) => a,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&ApprovalGateResult {
                approval_required: false,
                tool: tool.to_string(),
                error: Some(format!("Invalid arguments: {}", e)),
            })
            .unwrap();
        }
    };

    let required = match approval_gate::evaluate_approval_gates(
        gate_map.as_ref(),
        tool,
        &args,
    ) {
        Ok(r) => r,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&ApprovalGateResult {
                approval_required: true,
                tool: tool.to_string(),
                error: Some(format!("Gate evaluation error (fail-safe): {}", e)),
            })
            .unwrap();
        }
    };

    serde_wasm_bindgen::to_value(&ApprovalGateResult {
        approval_required: required,
        tool: tool.to_string(),
        error: None,
    })
    .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::time::Duration;
    use tenuo::{
        approval_gate::{self, ApprovalGateMap, ArgApprovalGate, ToolApprovalGate},
        wire, SigningKey, Warrant,
    };

    fn make_approver() -> (SigningKey, String) {
        let key = SigningKey::generate();
        let hex = hex::encode(key.public_key().to_bytes());
        (key, hex)
    }

    fn build_root_warrant(
        tools: &[&str],
        ttl_secs: u64,
        gates: Option<&ApprovalGateMap>,
        approvers: Option<Vec<tenuo::PublicKey>>,
        min_approvals: Option<u32>,
    ) -> (Warrant, SigningKey, SigningKey) {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let mut builder = Warrant::builder()
            .ttl(Duration::from_secs(ttl_secs))
            .holder(holder.public_key());
        for t in tools {
            builder = builder.capability(*t, tenuo::constraints::ConstraintSet::new());
        }
        if let Some(gm) = gates {
            let encoded = approval_gate::encode_approval_gate_map(gm).unwrap();
            builder = builder.extension(approval_gate::APPROVAL_GATE_EXTENSION_KEY, encoded);
        }
        if let Some(approver_list) = approvers {
            builder = builder.required_approvers(approver_list);
        }
        if let Some(min) = min_approvals {
            builder = builder.min_approvals(min);
        }
        let warrant = builder.build(&issuer).unwrap();
        (warrant, issuer, holder)
    }

    // --- parse_approval_gates_json ---

    #[test]
    fn parse_whole_tool_gate() {
        let input = json!({ "exec": { "args": null } });
        let gm = parse_approval_gates_json(&input).unwrap();
        assert!(gm.contains_tool("exec"));
        assert!(gm.get("exec").unwrap().is_whole_tool());
    }

    #[test]
    fn parse_per_arg_gate_all() {
        let input = json!({ "exec": { "args": { "command": "all" } } });
        let gm = parse_approval_gates_json(&input).unwrap();
        let gate = gm.get("exec").unwrap();
        assert!(!gate.is_whole_tool());
        assert!(gate.args.is_some());
        let args = gate.args.as_ref().unwrap();
        assert!(matches!(args.get("command"), Some(ArgApprovalGate::All)));
    }

    #[test]
    fn parse_multi_tool_gates() {
        let input = json!({
            "exec": { "args": null },
            "db.delete": { "args": { "table": "all" } },
        });
        let gm = parse_approval_gates_json(&input).unwrap();
        assert!(gm.contains_tool("exec"));
        assert!(gm.contains_tool("db.delete"));
        assert_eq!(gm.iter().count(), 2);
    }

    #[test]
    fn parse_empty_returns_none() {
        let input = json!({});
        assert!(parse_approval_gates_json(&input).is_none());
    }

    #[test]
    fn parse_invalid_json_returns_none() {
        let input = json!("not an object");
        assert!(parse_approval_gates_json(&input).is_none());
    }

    // --- approval_gate_map_to_json round-trip ---

    #[test]
    fn roundtrip_whole_tool() {
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::whole_tool());

        let json_val = approval_gate_map_to_json(&gm);
        let parsed = parse_approval_gates_json(&json_val).unwrap();
        assert!(parsed.contains_tool("exec"));
        assert!(parsed.get("exec").unwrap().is_whole_tool());
    }

    #[test]
    fn roundtrip_per_arg_all() {
        let mut args = BTreeMap::new();
        args.insert("command".to_string(), ArgApprovalGate::All);
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::with_args(args));

        let json_val = approval_gate_map_to_json(&gm);
        let parsed = parse_approval_gates_json(&json_val).unwrap();
        let gate = parsed.get("exec").unwrap();
        assert!(matches!(
            gate.args.as_ref().unwrap().get("command"),
            Some(ArgApprovalGate::All)
        ));
    }

    #[test]
    fn roundtrip_multi_tool() {
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::whole_tool());
        let mut args = BTreeMap::new();
        args.insert("path".to_string(), ArgApprovalGate::All);
        gm.insert("file.delete".to_string(), ToolApprovalGate::with_args(args));

        let json_val = approval_gate_map_to_json(&gm);
        let parsed = parse_approval_gates_json(&json_val).unwrap();
        assert_eq!(parsed.iter().count(), 2);
        assert!(parsed.get("exec").unwrap().is_whole_tool());
        assert!(!parsed.get("file.delete").unwrap().is_whole_tool());
    }

    // --- extract_decoded_warrant ---

    #[test]
    fn extract_warrant_without_gates() {
        let (w, _issuer, _holder) = build_root_warrant(&["exec"], 300, None, None, None);
        let decoded = extract_decoded_warrant(&w);
        assert!(decoded.approval_gates.is_none());
        assert!(decoded.required_approvers.is_none());
        assert!(decoded.min_approvals.is_none());
        assert!(decoded.tools.contains(&"exec".to_string()));
    }

    #[test]
    fn extract_warrant_with_whole_tool_gate() {
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::whole_tool());
        let (approver_key, _) = make_approver();
        let (w, _, _) = build_root_warrant(
            &["exec", "file.read"],
            300,
            Some(&gm),
            Some(vec![approver_key.public_key()]),
            Some(1),
        );
        let decoded = extract_decoded_warrant(&w);

        assert!(decoded.approval_gates.is_some());
        let gates = decoded.approval_gates.unwrap();
        assert!(gates.get("exec").is_some());

        assert!(decoded.required_approvers.is_some());
        assert_eq!(decoded.required_approvers.unwrap().len(), 1);
        assert_eq!(decoded.min_approvals, Some(1));

        assert!(decoded.extensions.contains_key("tenuo.approval_gates"));
    }

    #[test]
    fn extract_warrant_preserves_tools() {
        let (w, _, _) = build_root_warrant(&["exec", "db.read", "file.write"], 600, None, None, None);
        let decoded = extract_decoded_warrant(&w);
        assert_eq!(decoded.tools.len(), 3);
        assert!(decoded.tools.contains(&"exec".to_string()));
        assert!(decoded.tools.contains(&"db.read".to_string()));
        assert!(decoded.tools.contains(&"file.write".to_string()));
    }

    #[test]
    fn extract_warrant_multiple_approvers() {
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::whole_tool());
        let (a1, _) = make_approver();
        let (a2, _) = make_approver();
        let (w, _, _) = build_root_warrant(
            &["exec"],
            300,
            Some(&gm),
            Some(vec![a1.public_key(), a2.public_key()]),
            Some(2),
        );
        let decoded = extract_decoded_warrant(&w);
        assert_eq!(decoded.required_approvers.as_ref().unwrap().len(), 2);
        assert_eq!(decoded.min_approvals, Some(2));
    }

    // --- Approval gate evaluation (pure Rust, no WASM) ---

    #[test]
    fn evaluate_gated_tool_requires_approval() {
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::whole_tool());
        let args = HashMap::new();
        let result = approval_gate::evaluate_approval_gates(Some(&gm), "exec", &args).unwrap();
        assert!(result);
    }

    #[test]
    fn evaluate_ungated_tool_does_not_require_approval() {
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::whole_tool());
        let args = HashMap::new();
        let result = approval_gate::evaluate_approval_gates(Some(&gm), "file.read", &args).unwrap();
        assert!(!result);
    }

    #[test]
    fn evaluate_no_gates_never_requires_approval() {
        let args = HashMap::new();
        let result = approval_gate::evaluate_approval_gates(None, "exec", &args).unwrap();
        assert!(!result);
    }

    #[test]
    fn evaluate_per_arg_all_requires_approval() {
        let mut args_gates = BTreeMap::new();
        args_gates.insert("command".to_string(), ArgApprovalGate::All);
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::with_args(args_gates));

        let mut args = HashMap::new();
        args.insert(
            "command".to_string(),
            tenuo::constraints::ConstraintValue::String("rm -rf /".to_string()),
        );
        let result = approval_gate::evaluate_approval_gates(Some(&gm), "exec", &args).unwrap();
        assert!(result);
    }

    #[test]
    fn evaluate_per_arg_absent_arg_requires_approval() {
        let mut args_gates = BTreeMap::new();
        args_gates.insert("command".to_string(), ArgApprovalGate::All);
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::with_args(args_gates));

        let args = HashMap::new(); // no "command" arg provided
        let result = approval_gate::evaluate_approval_gates(Some(&gm), "exec", &args).unwrap();
        assert!(result);
    }

    // --- Warrant wire-format round-trip ---

    #[test]
    fn warrant_with_gates_roundtrips_through_wire_format() {
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::whole_tool());
        let (approver, _) = make_approver();
        let (w, _, _) = build_root_warrant(
            &["exec"],
            300,
            Some(&gm),
            Some(vec![approver.public_key()]),
            Some(1),
        );

        let b64 = wire::encode_base64(&w).unwrap();
        let decoded_w = wire::decode_base64(&b64).unwrap();
        let decoded = extract_decoded_warrant(&decoded_w);

        assert!(decoded.approval_gates.is_some());
        assert!(decoded.required_approvers.is_some());
        assert_eq!(decoded.min_approvals, Some(1));
    }

    #[test]
    fn delegated_warrant_inherits_gates() {
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::whole_tool());
        let (approver, _) = make_approver();
        let (parent, _issuer, holder) = build_root_warrant(
            &["exec", "file.read"],
            300,
            Some(&gm),
            Some(vec![approver.public_key()]),
            Some(1),
        );

        let child_holder = SigningKey::generate();
        let child = parent
            .attenuate()
            .holder(child_holder.public_key())
            .capability("exec", tenuo::constraints::ConstraintSet::new())
            .ttl(Duration::from_secs(200))
            .build(&holder)
            .unwrap();

        let child_decoded = extract_decoded_warrant(&child);
        assert!(child_decoded.approval_gates.is_some());
        assert!(child_decoded.required_approvers.is_some());
        assert_eq!(child_decoded.min_approvals, Some(1));
    }

    // --- create_warrant_from_config helpers (test the JSON parsing path) ---

    #[test]
    fn parse_gates_json_with_multiple_args() {
        let input = json!({
            "exec": { "args": { "command": "all", "env": "all" } },
        });
        let gm = parse_approval_gates_json(&input).unwrap();
        let gate = gm.get("exec").unwrap();
        let args = gate.args.as_ref().unwrap();
        assert_eq!(args.len(), 2);
        assert!(matches!(args.get("command"), Some(ArgApprovalGate::All)));
        assert!(matches!(args.get("env"), Some(ArgApprovalGate::All)));
    }

    #[test]
    fn json_output_structure_whole_tool() {
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::whole_tool());
        let json_val = approval_gate_map_to_json(&gm);
        let obj = json_val.as_object().unwrap();
        let exec_gate = obj.get("exec").unwrap().as_object().unwrap();
        assert!(exec_gate.get("args").unwrap().is_null());
    }

    #[test]
    fn json_output_structure_per_arg() {
        let mut args = BTreeMap::new();
        args.insert("cmd".to_string(), ArgApprovalGate::All);
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".to_string(), ToolApprovalGate::with_args(args));
        let json_val = approval_gate_map_to_json(&gm);
        let obj = json_val.as_object().unwrap();
        let exec_gate = obj.get("exec").unwrap().as_object().unwrap();
        let args_obj = exec_gate.get("args").unwrap().as_object().unwrap();
        assert_eq!(args_obj.get("cmd").unwrap().as_str().unwrap(), "all");
    }
}
