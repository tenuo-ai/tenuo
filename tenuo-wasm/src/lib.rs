use wasm_bindgen::prelude::*;
use tenuo::{
    PublicKey, Authorizer, SigningKey, Warrant,
    wire, 
    constraints::{ConstraintValue, ConstraintSet, Constraint, Pattern}
};
use std::collections::HashMap;
use std::time::Duration;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Result of a warrant decoding
#[derive(serde::Serialize)]
pub struct DecodedWarrant {
    pub id: String,
    pub issuer: String, // hex
    pub tools: Vec<String>,
    pub capabilities: HashMap<String, ConstraintSet>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub authorized_holder: String, // hex
    pub depth: u32,
}

#[wasm_bindgen]
pub fn decode_warrant(base64_warrant: &str) -> JsValue {
    match wire::decode_base64(base64_warrant.trim()) {
        Ok(warrant) => {
            let decoded = DecodedWarrant {
                id: warrant.id().to_string(),
                issuer: hex::encode(warrant.issuer().to_bytes()),
                tools: warrant.tools(),
                capabilities: warrant.capabilities().cloned().unwrap_or_default()
                    .into_iter().collect(), // BTreeMap to HashMap
                issued_at: warrant.issued_at().timestamp() as u64,
                expires_at: warrant.expires_at().timestamp() as u64,
                authorized_holder: hex::encode(warrant.authorized_holder().to_bytes()),
                depth: warrant.depth(),
            };
            serde_wasm_bindgen::to_value(&decoded).unwrap()
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
    dry_run: bool
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
                    Ok(_) => {
                         serde_wasm_bindgen::to_value(&AuthResult {
                            authorized: true,
                            reason: Some("Dry run: Policy valid (PoP skipped)".to_string()),
                            deny_code: None,
                            field: None,
                        }).unwrap()
                    },
                    Err(e) => {
                         serde_wasm_bindgen::to_value(&AuthResult {
                            authorized: false,
                            reason: Some(format!("Policy violation: {}", e)),
                            deny_code: Some("POLICY_VIOLATION".to_string()),
                            field: None,
                        }).unwrap()
                    }
                }
            } else if let Some(constraints) = caps.get("*") {
                match constraints.matches(&args) {
                    Ok(_) => {
                         serde_wasm_bindgen::to_value(&AuthResult {
                            authorized: true,
                            reason: Some("Dry run: Policy valid (PoP skipped)".to_string()),
                            deny_code: None,
                            field: None,
                        }).unwrap()
                    },
                    Err(e) => {
                         serde_wasm_bindgen::to_value(&AuthResult {
                            authorized: false,
                            reason: Some(format!("Policy violation: {}", e)),
                            deny_code: Some("POLICY_VIOLATION".to_string()),
                            field: None,
                        }).unwrap()
                    }
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
            Ok(_) => {
                 serde_wasm_bindgen::to_value(&AuthResult {
                    authorized: true,
                    reason: None,
                    deny_code: None,
                    field: None,
                }).unwrap()
            },
            Err(e) => {
                 serde_wasm_bindgen::to_value(&AuthResult {
                    authorized: false,
                    reason: Some(e.to_string()),
                    deny_code: Some("DENIED".to_string()),
                    field: None,
                }).unwrap()
            }
        }
    }
}

#[wasm_bindgen]
pub fn check_chain_access(
    warrant_b64_list: Vec<String>, 
    tool: &str, 
    args_json: JsValue, 
    trusted_root_hex: &str
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
    let mut chain = Vec::new();
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

    // 4. Authorize
    let authorizer = Authorizer::new().with_trusted_root(root_key);
    
    match authorizer.check_chain(&chain, tool, &args, None, &[]) {
        Ok(_) => {
             serde_wasm_bindgen::to_value(&AuthResult {
                authorized: true,
                reason: None,
                deny_code: None,
                field: None,
            }).unwrap()
        },
        Err(e) => {
             serde_wasm_bindgen::to_value(&AuthResult {
                authorized: false,
                reason: Some(e.to_string()),
                deny_code: Some("DENIED".to_string()),
                field: None,
            }).unwrap()
        }
    }
}

fn to_auth_error(msg: &str) -> JsValue {
    serde_wasm_bindgen::to_value(&AuthResult {
        authorized: false,
        reason: Some(msg.to_string()),
        deny_code: Some("ERROR".to_string()),
        field: None,
    }).unwrap()
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
pub fn create_pop_signature(
    private_key_hex: &str,
    warrant_b64: &str,
    tool: &str,
    args_json: JsValue,
) -> JsValue {
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
    match warrant.create_pop_signature(&keypair, tool, &args) {
        Ok(sig) => {
            serde_wasm_bindgen::to_value(&PopSignatureResult {
                signature_hex: hex::encode(sig.to_bytes()),
                error: None,
            }).unwrap()
        },
        Err(e) => to_pop_error(&format!("Failed to create PoP: {}", e)),
    }
}

fn to_pop_error(msg: &str) -> JsValue {
    serde_wasm_bindgen::to_value(&PopSignatureResult {
        signature_hex: String::new(),
        error: Some(msg.to_string()),
    }).unwrap()
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
        Ok(_) => {
            serde_wasm_bindgen::to_value(&AuthResult {
                authorized: true,
                reason: Some("Full authorization with PoP verified".to_string()),
                deny_code: None,
                field: None,
            }).unwrap()
        },
        Err(e) => {
            serde_wasm_bindgen::to_value(&AuthResult {
                authorized: false,
                reason: Some(e.to_string()),
                deny_code: Some("DENIED".to_string()),
                field: None,
            }).unwrap()
        }
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
pub fn create_sample_warrant(tool: &str, constraint_field: &str, constraint_pattern: &str, ttl_seconds: u64) -> JsValue {
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
            }).unwrap();
        }
    };
    constraint_set.insert(constraint_field.to_string(), Constraint::Pattern(pattern));
    
    // Build and sign the warrant
    let warrant = match Warrant::builder()
        .capability(tool, constraint_set)
        .ttl(Duration::from_secs(ttl_seconds))
        .authorized_holder(holder_key.public_key())
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
            }).unwrap();
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
            }).unwrap();
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
    }).unwrap()
}
