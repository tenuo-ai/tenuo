//! Heartbeat module for Tenuo Cloud control plane integration.
//!
//! This module provides automatic registration, heartbeat, and SRL synchronization
//! for authorizers connecting to Tenuo Cloud (enterprise feature).
//!
//! # Usage
//!
//! The heartbeat is enabled when all three environment variables are set:
//! - `TENUO_CONTROL_PLANE_URL`: The Tenuo Cloud API endpoint
//! - `TENUO_API_KEY`: API key for authentication
//! - `TENUO_AUTHORIZER_NAME`: Unique name for this authorizer instance
//!
//! # Behavior
//!
//! 1. On startup, registers with the control plane to get an `authorizer_id`
//! 2. Spawns a background task that sends heartbeats at the configured interval
//! 3. If registration fails after 3 retries, continues in standalone mode
//! 4. If heartbeats fail, logs warnings and continues retrying
//! 5. On each heartbeat, checks if SRL update is needed (version or urgent flag)
//! 6. Fetches and applies new SRL when needed

use crate::planes::Authorizer;
use crate::revocation::SignedRevocationList;
use crate::PublicKey;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{info, warn};

/// Configuration for the heartbeat client.
#[derive(Clone)]
pub struct HeartbeatConfig {
    /// Tenuo Cloud control plane URL (e.g., https://api.tenuo.cloud)
    pub control_plane_url: String,
    /// API key for authentication
    pub api_key: String,
    /// Human-readable name for this authorizer
    pub authorizer_name: String,
    /// Type of authorizer (e.g., "sidecar", "gateway")
    pub authorizer_type: String,
    /// Full version string (e.g., "0.1.0-beta.7+authz.1")
    pub version: String,
    /// Interval between heartbeats in seconds
    pub interval_secs: u64,
    /// Shared authorizer for SRL updates (optional)
    pub authorizer: Option<Arc<RwLock<Authorizer>>>,
    /// Trusted root public key for SRL verification
    pub trusted_root: Option<PublicKey>,
}

/// Request body for authorizer registration.
#[derive(Serialize)]
struct RegisterRequest<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    authorizer_type: &'a str,
    version: &'a str,
}

/// Response from authorizer registration.
#[derive(Deserialize)]
struct RegisterResponse {
    id: String,
}

/// Response from heartbeat endpoint.
#[derive(Deserialize)]
struct HeartbeatResponse {
    /// Status of the authorizer (e.g., "active")
    #[allow(dead_code)]
    status: String,
    /// Latest SRL version available on the control plane
    #[serde(default)]
    latest_srl_version: Option<u64>,
    /// Urgent refresh flag - immediate SRL update needed
    #[serde(default)]
    refresh_required: bool,
}

/// Response from SRL endpoint (CBOR or JSON wrapper).
#[derive(Deserialize)]
struct SrlResponse {
    /// Base64-encoded CBOR SRL
    srl: String,
    /// SRL version
    version: u64,
}

/// Start the heartbeat loop in the background.
///
/// This function will:
/// 1. Attempt to register with the control plane (with retries)
/// 2. If successful, fetch initial SRL
/// 3. Start sending periodic heartbeats
/// 4. If registration fails, log a warning and return (authorizer runs standalone)
/// 5. On each heartbeat, check if SRL needs updating and fetch if needed
///
/// This function is designed to be spawned as a tokio task and will run
/// indefinitely until the process exits.
pub async fn start_heartbeat_loop(config: HeartbeatConfig) {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to create HTTP client");

    // Register with retry
    let authorizer_id = match register_with_retry(&client, &config).await {
        Some(id) => id,
        None => {
            warn!(
                "Failed to register with Tenuo Cloud after 3 attempts. \
                 Authorizer will run in standalone mode without heartbeats."
            );
            return;
        }
    };

    info!(
        authorizer_id = %authorizer_id,
        name = %config.authorizer_name,
        "Registered with Tenuo Cloud"
    );

    // Track local SRL version (0 = no SRL loaded)
    let mut local_srl_version: u64 = 0;

    // Fetch initial SRL
    if let (Some(ref authorizer), Some(ref trusted_root)) =
        (&config.authorizer, &config.trusted_root)
    {
        match fetch_and_apply_srl(&client, &config, authorizer, trusted_root).await {
            Ok(version) => {
                local_srl_version = version;
                info!(srl_version = version, "Initial SRL fetched");
            }
            Err(e) => {
                warn!(error = %e, "Failed to fetch initial SRL, will retry on heartbeat");
            }
        }
    }

    // Heartbeat loop
    let mut ticker = interval(Duration::from_secs(config.interval_secs));

    // Skip the first immediate tick
    ticker.tick().await;

    loop {
        ticker.tick().await;

        match send_heartbeat(&client, &config, &authorizer_id).await {
            Ok(response) => {
                tracing::debug!(
                    authorizer_id = %authorizer_id,
                    "Heartbeat sent successfully"
                );

                // Check if SRL update is needed
                let needs_update = response.refresh_required
                    || response
                        .latest_srl_version
                        .map(|v| v > local_srl_version)
                        .unwrap_or(false);

                if needs_update {
                    if let Some(ref authorizer) = config.authorizer {
                        if let Some(ref trusted_root) = config.trusted_root {
                            match fetch_and_apply_srl(&client, &config, authorizer, trusted_root)
                                .await
                            {
                                Ok(new_version) => {
                                    local_srl_version = new_version;
                                    info!(
                                        srl_version = new_version,
                                        refresh_required = response.refresh_required,
                                        "SRL updated from Tenuo Cloud"
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        error = %e,
                                        "Failed to fetch SRL from Tenuo Cloud"
                                    );
                                }
                            }
                        } else {
                            warn!("SRL update needed but no trusted root configured");
                        }
                    }
                }
            }
            Err(e) => {
                warn!(
                    authorizer_id = %authorizer_id,
                    error = %e,
                    "Heartbeat failed, will retry on next interval"
                );
            }
        }
    }
}

/// Attempt to register with the control plane, retrying up to 3 times.
async fn register_with_retry(client: &Client, config: &HeartbeatConfig) -> Option<String> {
    const MAX_ATTEMPTS: u32 = 3;

    for attempt in 1..=MAX_ATTEMPTS {
        match register(client, config).await {
            Ok(id) => return Some(id),
            Err(e) => {
                let backoff = Duration::from_secs(2u64.pow(attempt));
                warn!(
                    attempt = attempt,
                    max_attempts = MAX_ATTEMPTS,
                    error = %e,
                    backoff_secs = backoff.as_secs(),
                    "Registration attempt failed, retrying..."
                );

                if attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    None
}

/// Register this authorizer with the control plane.
async fn register(client: &Client, config: &HeartbeatConfig) -> Result<String, HeartbeatError> {
    let url = format!("{}/v1/authorizers/register", config.control_plane_url);

    let request_body = RegisterRequest {
        name: &config.authorizer_name,
        authorizer_type: &config.authorizer_type,
        version: &config.version,
    };

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| HeartbeatError::Network(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        return Err(HeartbeatError::Api {
            status: status.as_u16(),
            message: body,
        });
    }

    let register_response: RegisterResponse = response
        .json()
        .await
        .map_err(|e| HeartbeatError::Parse(e.to_string()))?;

    Ok(register_response.id)
}

/// Send a heartbeat to the control plane.
async fn send_heartbeat(
    client: &Client,
    config: &HeartbeatConfig,
    authorizer_id: &str,
) -> Result<HeartbeatResponse, HeartbeatError> {
    let url = format!(
        "{}/v1/authorizers/{}/heartbeat",
        config.control_plane_url, authorizer_id
    );

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .send()
        .await
        .map_err(|e| HeartbeatError::Network(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        return Err(HeartbeatError::Api {
            status: status.as_u16(),
            message: body,
        });
    }

    let heartbeat_response: HeartbeatResponse = response
        .json()
        .await
        .map_err(|e| HeartbeatError::Parse(e.to_string()))?;

    Ok(heartbeat_response)
}

/// Fetch the latest SRL from the control plane and apply it to the authorizer.
async fn fetch_and_apply_srl(
    client: &Client,
    config: &HeartbeatConfig,
    authorizer: &Arc<RwLock<Authorizer>>,
    trusted_root: &PublicKey,
) -> Result<u64, HeartbeatError> {
    let url = format!("{}/v1/revocations/srl/signed", config.control_plane_url);

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .send()
        .await
        .map_err(|e| HeartbeatError::Network(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        return Err(HeartbeatError::Api {
            status: status.as_u16(),
            message: body,
        });
    }

    let srl_response: SrlResponse = response
        .json()
        .await
        .map_err(|e| HeartbeatError::Parse(e.to_string()))?;

    // Decode base64 SRL
    let srl_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &srl_response.srl,
    )
    .map_err(|e| HeartbeatError::Parse(format!("Invalid base64 SRL: {}", e)))?;

    // Parse and verify SRL
    let srl = SignedRevocationList::from_bytes(&srl_bytes)
        .map_err(|e| HeartbeatError::Parse(format!("Invalid SRL format: {}", e)))?;

    // Apply to authorizer (this also verifies the signature)
    let mut auth = authorizer.write().await;
    auth.set_revocation_list(srl, trusted_root)
        .map_err(|e| HeartbeatError::Parse(format!("SRL verification failed: {}", e)))?;

    Ok(srl_response.version)
}

/// Errors that can occur during heartbeat operations.
#[derive(Debug)]
pub enum HeartbeatError {
    /// Network error (connection failed, timeout, etc.)
    Network(String),
    /// API returned an error status
    Api { status: u16, message: String },
    /// Failed to parse response
    Parse(String),
}

impl std::fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeartbeatError::Network(msg) => write!(f, "Network error: {}", msg),
            HeartbeatError::Api { status, message } => {
                write!(f, "API error ({}): {}", status, message)
            }
            HeartbeatError::Parse(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for HeartbeatError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> HeartbeatConfig {
        HeartbeatConfig {
            control_plane_url: "https://api.tenuo.cloud".to_string(),
            api_key: "tc_test".to_string(),
            authorizer_name: "test-auth".to_string(),
            authorizer_type: "sidecar".to_string(),
            version: "0.1.0-beta.7+authz.1".to_string(),
            interval_secs: 30,
            authorizer: None,
            trusted_root: None,
        }
    }

    #[test]
    fn test_heartbeat_config_clone() {
        let config = test_config();

        let cloned = config.clone();
        assert_eq!(cloned.control_plane_url, config.control_plane_url);
        assert_eq!(cloned.api_key, config.api_key);
        assert_eq!(cloned.authorizer_name, config.authorizer_name);
    }

    #[test]
    fn test_heartbeat_error_display() {
        let network_err = HeartbeatError::Network("connection refused".to_string());
        assert!(network_err.to_string().contains("Network error"));

        let api_err = HeartbeatError::Api {
            status: 401,
            message: "Unauthorized".to_string(),
        };
        assert!(api_err.to_string().contains("401"));

        let parse_err = HeartbeatError::Parse("invalid json".to_string());
        assert!(parse_err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_heartbeat_response_deserialization() {
        // Test minimal response (backwards compatible)
        let minimal = r#"{"status": "active"}"#;
        let resp: HeartbeatResponse = serde_json::from_str(minimal).unwrap();
        assert_eq!(resp.status, "active");
        assert_eq!(resp.latest_srl_version, None);
        assert!(!resp.refresh_required);

        // Test full response with SRL info
        let full = r#"{"status": "active", "latest_srl_version": 8, "refresh_required": true}"#;
        let resp: HeartbeatResponse = serde_json::from_str(full).unwrap();
        assert_eq!(resp.status, "active");
        assert_eq!(resp.latest_srl_version, Some(8));
        assert!(resp.refresh_required);
    }

    #[test]
    fn test_srl_response_deserialization() {
        let json = r#"{"srl": "dGVzdA==", "version": 5}"#;
        let resp: SrlResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.srl, "dGVzdA==");
        assert_eq!(resp.version, 5);
    }
}
