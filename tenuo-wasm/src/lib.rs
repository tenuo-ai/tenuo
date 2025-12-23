use wasm_bindgen::prelude::*;
use tenuo::{
    Warrant, PublicKey, Authorizer, 
    wire, 
    constraints::{ConstraintValue, ConstraintSet}
};
use std::collections::HashMap;

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
