use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use serde_wasm_bindgen::Serializer;
use std::collections::HashMap;
use std::time::Duration;
use tenuo::{
    constraints::{
        Any, Cidr, Constraint, ConstraintSet, ConstraintValue, Contains, Exact, NotOneOf, OneOf,
        Pattern, Range, RegexConstraint, UrlPattern,
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
        Constraint::Unknown { type_id, .. } => json!({ "unknown": format!("type_id={}", type_id) }),
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
}

#[wasm_bindgen]
pub fn decode_warrant(base64_warrant: &str) -> JsValue {
    match wire::decode_base64(base64_warrant.trim()) {
        Ok(warrant) => {
            // Convert capabilities to human-readable format
            let capabilities: HashMap<String, HashMap<String, JsonValue>> = warrant
                .capabilities()
                .map(|caps| {
                    caps.iter()
                        .map(|(tool, cs)| (tool.clone(), constraint_set_to_readable(cs)))
                        .collect()
                })
                .unwrap_or_default();

            let decoded = DecodedWarrant {
                id: warrant.id().to_string(),
                issuer: hex::encode(warrant.issuer().to_bytes()),
                tools: warrant.tools(),
                capabilities,
                issued_at: warrant.issued_at().timestamp() as u64,
                expires_at: warrant.expires_at().timestamp() as u64,
                authorized_holder: hex::encode(warrant.authorized_holder().to_bytes()),
                depth: warrant.depth(),
            };
            // Use serialize_maps_as_objects to produce plain JS objects instead of Map
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
        match authorizer.check(&warrant, tool, &args, None, &[]) {
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
    match authorizer.check(&warrant, tool, &args, Some(&signature), &[]) {
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

    // The frontend sends constraints as { "pattern": "value" } or { "exact": "value" } etc.
    // We need to handle this flexible format
    #[derive(serde::Deserialize)]
    struct BuilderConfig {
        tools: HashMap<String, HashMap<String, serde_json::Value>>,
        ttl: u64,
        #[allow(dead_code)]
        max_depth: Option<u32>,
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

    // Generate fresh keypairs
    let issuer_key = SigningKey::generate();
    let holder_key = SigningKey::generate();

    // Collect tool names
    let tool_names: Vec<String> = config.tools.keys().cloned().collect();

    // Build warrant with all tools and constraints
    let mut builder = Warrant::builder()
        .ttl(Duration::from_secs(config.ttl))
        .holder(holder_key.public_key());

    for (tool_name, constraints) in &config.tools {
        let mut constraint_set = ConstraintSet::new();
        for (field, constraint_value) in constraints {
            // constraint_value is like {"pattern": "docs/*"} or {"exact": "foo"} etc.
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
                // Range constraint - parse "min-max", "max", or "min-" format
                else if let Some(range_val) = obj.get("range").and_then(|v| v.as_str()) {
                    if range_val.ends_with('-') {
                        // Format: "min-" (e.g., "100-" means >= 100)
                        let min_str = &range_val[..range_val.len() - 1];
                        if let Ok(min) = min_str.parse::<f64>() {
                            if let Ok(r) = Range::min(min) {
                                constraint_set.insert(field.clone(), Constraint::Range(r));
                            }
                        }
                    } else if range_val.contains('-') {
                        // Format: "min-max" (e.g., "10-100" or "-10-5")
                        // Handle negative numbers by finding the last '-' that's not at position 0
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
                                    // Validate min <= max
                                    if let Ok(r) = Range::new(Some(min), Some(max)) {
                                        constraint_set.insert(field.clone(), Constraint::Range(r));
                                    }
                                }
                            }
                        }
                    } else {
                        // Format: "max" (e.g., "100" means <= 100)
                        if let Ok(max) = range_val.parse::<f64>() {
                            if let Ok(r) = Range::max(max) {
                                constraint_set.insert(field.clone(), Constraint::Range(r));
                            }
                        }
                    }
                }
                // OneOf constraint - parse comma-separated values
                else if let Some(oneof_val) = obj.get("oneof").and_then(|v| v.as_str()) {
                    let values: Vec<String> = oneof_val
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !values.is_empty() {
                        constraint_set.insert(field.clone(), Constraint::OneOf(OneOf::new(values)));
                    }
                }
                // AnyOf constraint - parse comma-separated patterns
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
                                patterns
                                    .into_iter()
                                    .map(Constraint::Pattern)
                                    .collect::<Vec<_>>(),
                            )),
                        );
                    }
                }
                // NotOneOf constraint - parse comma-separated values
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
                // Wildcard constraint (simple * patterns)
                else if let Some(wildcard_val) = obj.get("wildcard").and_then(|v| v.as_str()) {
                    if let Ok(p) = Pattern::new(wildcard_val) {
                        constraint_set.insert(field.clone(), Constraint::Pattern(p));
                    }
                }
                // Contains constraint - parse comma-separated values
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
            }
        }
        builder = builder.capability(tool_name, constraint_set);
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
