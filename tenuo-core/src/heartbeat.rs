//! Heartbeat module for Tenuo Cloud control plane integration.
//!
//! This module provides automatic registration, heartbeat, SRL synchronization,
//! and audit event streaming for authorizers connecting to Tenuo Cloud (enterprise feature).
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
//! 7. Flushes buffered audit events to the control plane

use crate::planes::Authorizer;
use crate::revocation::SignedRevocationList;
use crate::PublicKey;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use tracing::{debug, info, warn};

// ============================================================================
// Audit Event Streaming
// ============================================================================

/// An authorization event to be sent to the control plane for dashboard/analytics.
#[derive(Clone, Debug, Serialize)]
pub struct AuthorizationEvent {
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Authorizer instance ID (assigned by control plane on registration)
    pub authorizer_id: String,
    /// Warrant ID being authorized (leaf warrant)
    pub warrant_id: String,
    /// Decision: "allow" or "deny"
    pub decision: &'static str,
    /// Reason for denial (if denied)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    /// Tool being authorized
    pub tool: String,
    /// Specific constraint that failed (if denied)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_constraint: Option<String>,
    /// Delegation chain depth
    pub chain_depth: u8,
    /// Root principal (issuer of root warrant in chain)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_principal: Option<String>,
    /// Full warrant chain (base64-encoded CBOR WarrantStack)
    /// Contains all warrants from root to leaf for chain reconstruction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warrant_stack: Option<String>,
    /// Authorization latency in microseconds
    pub latency_us: u64,
    /// Unique request ID for tracing
    pub request_id: String,
}

impl AuthorizationEvent {
    /// Create a new "allow" event
    #[allow(clippy::too_many_arguments)]
    pub fn allow(
        authorizer_id: String,
        warrant_id: String,
        tool: String,
        chain_depth: u8,
        root_principal: Option<String>,
        warrant_stack: Option<String>,
        latency_us: u64,
        request_id: String,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            authorizer_id,
            warrant_id,
            decision: "allow",
            deny_reason: None,
            tool,
            failed_constraint: None,
            chain_depth,
            root_principal,
            warrant_stack,
            latency_us,
            request_id,
        }
    }

    /// Create a new "deny" event
    #[allow(clippy::too_many_arguments)]
    pub fn deny(
        authorizer_id: String,
        warrant_id: String,
        tool: String,
        deny_reason: String,
        failed_constraint: Option<String>,
        chain_depth: u8,
        root_principal: Option<String>,
        warrant_stack: Option<String>,
        latency_us: u64,
        request_id: String,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            authorizer_id,
            warrant_id,
            decision: "deny",
            deny_reason: Some(deny_reason),
            tool,
            failed_constraint,
            chain_depth,
            root_principal,
            warrant_stack,
            latency_us,
            request_id,
        }
    }
}

/// Channel-based sender for audit events.
/// Clone this and pass to request handlers.
pub type AuditEventSender = mpsc::Sender<AuthorizationEvent>;

/// Create an audit event channel with the specified buffer size.
/// Returns (sender, receiver). The sender can be cloned for multiple handlers.
pub fn create_audit_channel(
    buffer_size: usize,
) -> (AuditEventSender, mpsc::Receiver<AuthorizationEvent>) {
    mpsc::channel(buffer_size)
}

// ============================================================================
// Heartbeat Configuration
// ============================================================================

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
    /// Maximum events to batch before flushing (default: 100)
    pub audit_batch_size: usize,
    /// Flush interval for audit events in seconds (default: 10)
    pub audit_flush_interval_secs: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            control_plane_url: String::new(),
            api_key: String::new(),
            authorizer_name: String::new(),
            authorizer_type: "sidecar".to_string(),
            version: String::new(),
            interval_secs: 30,
            authorizer: None,
            trusted_root: None,
            audit_batch_size: 100,
            audit_flush_interval_secs: 10,
        }
    }
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

/// Start the heartbeat loop in the background (legacy signature for backwards compatibility).
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
    start_heartbeat_loop_with_audit(config, None).await;
}

/// Start the heartbeat and audit event loops in the background.
///
/// This function will:
/// 1. Attempt to register with the control plane (with retries)
/// 2. If successful, fetch initial SRL and spawn audit event flush task
/// 3. Start sending periodic heartbeats
/// 4. If registration fails, log a warning and return (authorizer runs standalone)
/// 5. On each heartbeat, check if SRL needs updating and fetch if needed
///
/// If `audit_rx` is provided, audit events will be batched and sent to the control plane.
///
/// This function is designed to be spawned as a tokio task and will run
/// indefinitely until the process exits.
pub async fn start_heartbeat_loop_with_audit(
    config: HeartbeatConfig,
    audit_rx: Option<mpsc::Receiver<AuthorizationEvent>>,
) {
    start_heartbeat_loop_with_audit_and_id(config, audit_rx, Arc::new(RwLock::new(None))).await;
}

/// Start the heartbeat and audit event loops in the background, with shared authorizer_id.
///
/// Same as `start_heartbeat_loop_with_audit`, but writes the authorizer_id to the provided
/// shared state after registration. This allows request handlers to include the authorizer_id
/// in audit events.
pub async fn start_heartbeat_loop_with_audit_and_id(
    config: HeartbeatConfig,
    audit_rx: Option<mpsc::Receiver<AuthorizationEvent>>,
    shared_authorizer_id: Arc<RwLock<Option<String>>>,
) {
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

    // Store authorizer_id in shared state for request handlers
    {
        let mut id_guard = shared_authorizer_id.write().await;
        *id_guard = Some(authorizer_id.clone());
    }

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

    // Spawn audit event flush task if receiver provided
    if let Some(rx) = audit_rx {
        let audit_client = client.clone();
        let audit_config = config.clone();
        let audit_authorizer_id = authorizer_id.clone();
        tokio::spawn(async move {
            run_audit_flush_loop(audit_client, audit_config, audit_authorizer_id, rx).await;
        });
        info!("Audit event streaming enabled");
    }

    // Heartbeat loop
    let mut ticker = interval(Duration::from_secs(config.interval_secs));

    // Skip the first immediate tick
    ticker.tick().await;

    loop {
        ticker.tick().await;

        match send_heartbeat(&client, &config, &authorizer_id).await {
            Ok(response) => {
                debug!(
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

/// Run the audit event flush loop.
/// Collects events from the channel and flushes them in batches.
async fn run_audit_flush_loop(
    client: Client,
    config: HeartbeatConfig,
    authorizer_id: String,
    mut rx: mpsc::Receiver<AuthorizationEvent>,
) {
    let mut buffer: Vec<AuthorizationEvent> = Vec::with_capacity(config.audit_batch_size);
    let mut flush_ticker = interval(Duration::from_secs(config.audit_flush_interval_secs));

    // Skip the first immediate tick
    flush_ticker.tick().await;

    loop {
        tokio::select! {
            // Receive events from channel
            event = rx.recv() => {
                match event {
                    Some(e) => {
                        buffer.push(e);

                        // Flush if batch is full
                        if buffer.len() >= config.audit_batch_size {
                            flush_audit_events(&client, &config, &authorizer_id, &mut buffer).await;
                        }
                    }
                    None => {
                        // Channel closed (sender dropped), flush remaining events and exit
                        if !buffer.is_empty() {
                            info!(
                                authorizer_id = %authorizer_id,
                                remaining_events = buffer.len(),
                                "Flushing remaining audit events before shutdown"
                            );
                            flush_audit_events(&client, &config, &authorizer_id, &mut buffer).await;
                        }
                        info!("Audit channel closed, exiting flush loop");
                        break;
                    }
                }
            }
            // Periodic flush
            _ = flush_ticker.tick() => {
                if !buffer.is_empty() {
                    flush_audit_events(&client, &config, &authorizer_id, &mut buffer).await;
                }
            }
        }
    }
}

/// Flush buffered audit events to the control plane.
async fn flush_audit_events(
    client: &Client,
    config: &HeartbeatConfig,
    authorizer_id: &str,
    buffer: &mut Vec<AuthorizationEvent>,
) {
    if buffer.is_empty() {
        return;
    }

    let event_count = buffer.len();
    let url = format!(
        "{}/v1/authorizers/{}/events",
        config.control_plane_url, authorizer_id
    );

    let result = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .header("Content-Type", "application/json")
        .json(&buffer)
        .send()
        .await;

    match result {
        Ok(response) if response.status().is_success() => {
            debug!(
                authorizer_id = %authorizer_id,
                event_count = %event_count,
                "Flushed audit events to control plane"
            );
            buffer.clear();
        }
        Ok(response) => {
            let status = response.status();
            warn!(
                authorizer_id = %authorizer_id,
                event_count = %event_count,
                status = %status,
                "Failed to flush audit events, will retry"
            );
            // Keep events in buffer for retry, but cap size to prevent unbounded growth
            if buffer.len() > config.audit_batch_size * 10 {
                let drain_count = buffer.len() - config.audit_batch_size;
                warn!(
                    dropped_events = %drain_count,
                    "Dropping oldest audit events due to buffer overflow"
                );
                buffer.drain(0..drain_count);
            }
        }
        Err(e) => {
            warn!(
                authorizer_id = %authorizer_id,
                event_count = %event_count,
                error = %e,
                "Network error flushing audit events, will retry"
            );
            // Same overflow protection
            if buffer.len() > config.audit_batch_size * 10 {
                let drain_count = buffer.len() - config.audit_batch_size;
                warn!(
                    dropped_events = %drain_count,
                    "Dropping oldest audit events due to buffer overflow"
                );
                buffer.drain(0..drain_count);
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
            audit_batch_size: 100,
            audit_flush_interval_secs: 10,
        }
    }

    #[test]
    fn test_authorization_event_allow() {
        let event = AuthorizationEvent::allow(
            "auth-123".to_string(),
            "wid-456".to_string(),
            "read_file".to_string(),
            0,
            Some("root-pk".to_string()),
            Some("base64stack".to_string()),
            1234,
            "req-789".to_string(),
        );
        assert_eq!(event.decision, "allow");
        assert!(event.deny_reason.is_none());
        assert_eq!(event.tool, "read_file");
        assert_eq!(event.chain_depth, 0);
        assert_eq!(event.warrant_stack, Some("base64stack".to_string()));
    }

    #[test]
    fn test_authorization_event_deny() {
        let event = AuthorizationEvent::deny(
            "auth-123".to_string(),
            "wid-456".to_string(),
            "write_file".to_string(),
            "constraint_violation".to_string(),
            Some("path".to_string()),
            1,
            Some("root-pk".to_string()),
            Some("base64stack".to_string()),
            5678,
            "req-999".to_string(),
        );
        assert_eq!(event.decision, "deny");
        assert_eq!(event.deny_reason, Some("constraint_violation".to_string()));
        assert_eq!(event.failed_constraint, Some("path".to_string()));
        assert_eq!(event.chain_depth, 1);
        assert_eq!(event.warrant_stack, Some("base64stack".to_string()));
    }

    #[test]
    fn test_authorization_event_serialization() {
        let event = AuthorizationEvent::allow(
            "auth-123".to_string(),
            "wid-456".to_string(),
            "read_file".to_string(),
            0,
            None,
            None, // No warrant stack
            1234,
            "req-789".to_string(),
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"decision\":\"allow\""));
        assert!(json.contains("\"tool\":\"read_file\""));
        // Optional fields should be omitted when None
        assert!(!json.contains("deny_reason"));
        assert!(!json.contains("warrant_stack"));
    }

    #[test]
    fn test_create_audit_channel() {
        let (tx, _rx) = create_audit_channel(100);
        // Should be able to clone the sender
        let _tx2 = tx.clone();
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
