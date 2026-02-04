//! Heartbeat module for control plane integration.
//!
//! This module provides automatic registration, heartbeat, SRL synchronization,
//! and audit event streaming for authorizers connecting to a control plane.
//!
//! # Usage
//!
//! The heartbeat is enabled when all three environment variables are set:
//! - `TENUO_CONTROL_PLANE_URL`: The control plane API endpoint
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
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};
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
// Runtime Metrics (sent with each heartbeat)
// ============================================================================

/// Runtime metrics collected and sent with each heartbeat.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RuntimeMetrics {
    /// Uptime in seconds since authorizer started
    pub uptime_seconds: u64,
    /// Total requests since startup
    pub requests_total: u64,
    /// Requests since last heartbeat
    pub requests_since_last: u64,
    /// Average latency in microseconds (since last heartbeat)
    pub avg_latency_us: u64,
    /// P99 latency in microseconds (since last heartbeat)
    pub p99_latency_us: u64,
    /// Current memory usage in bytes (approximate)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
}

/// Aggregate statistics sent with each heartbeat (reduces event volume).
#[derive(Clone, Debug, Default, Serialize)]
pub struct HeartbeatStats {
    /// Number of allowed requests since last heartbeat
    pub allow_count: u64,
    /// Number of denied requests since last heartbeat
    pub deny_count: u64,
    /// Top denial reasons with counts (max 10)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub top_deny_reasons: Vec<(String, u64)>,
    /// Top tools/actions with counts (max 10)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub top_actions: Vec<(String, u64)>,
    /// Number of unique principals seen since last heartbeat
    pub unique_principals: u64,
    /// Number of unique warrants seen since last heartbeat
    pub unique_warrants: u64,
}

/// SRL synchronization health status.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SrlHealth {
    /// Last successful SRL fetch timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_fetch_at: Option<String>,
    /// Whether the last fetch attempt succeeded
    pub last_fetch_success: bool,
    /// Total fetch failures since startup
    pub fetch_failures_total: u64,
    /// Total SRL verification failures since startup
    pub verification_failures_total: u64,
    /// Current SRL version (None if no SRL loaded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_srl_version: Option<u64>,
}

/// Environment information sent during registration.
#[derive(Clone, Debug, Default, Serialize)]
pub struct EnvironmentInfo {
    // Kubernetes context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s_namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s_pod_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s_node_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s_cluster: Option<String>,

    // Cloud context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_region: Option<String>,

    // Deployment context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deploy_id: Option<String>,
}

impl EnvironmentInfo {
    /// Create environment info from standard environment variables.
    ///
    /// # Security Note
    ///
    /// This function ONLY reads non-sensitive metadata variables:
    /// - Kubernetes identifiers (namespace, pod name, node name)
    /// - Cloud region names (not credentials)
    /// - Deployment identifiers (environment name, build ID)
    ///
    /// It does NOT read any secrets, tokens, keys, passwords, or credentials.
    /// If you add new variables here, ensure they are safe to transmit to
    /// the control plane.
    pub fn from_env() -> Self {
        Self {
            // Kubernetes (standard downward API env vars - non-sensitive identifiers)
            k8s_namespace: std::env::var("TENUO_K8S_NAMESPACE")
                .or_else(|_| std::env::var("POD_NAMESPACE"))
                .ok(),
            k8s_pod_name: std::env::var("TENUO_K8S_POD_NAME")
                .or_else(|_| std::env::var("POD_NAME"))
                .or_else(|_| std::env::var("HOSTNAME"))
                .ok(),
            k8s_node_name: std::env::var("TENUO_K8S_NODE_NAME")
                .or_else(|_| std::env::var("NODE_NAME"))
                .ok(),
            k8s_cluster: std::env::var("TENUO_K8S_CLUSTER").ok(),

            // Cloud context (region names only - NOT credentials)
            cloud_provider: std::env::var("TENUO_CLOUD_PROVIDER").ok(),
            cloud_region: std::env::var("TENUO_CLOUD_REGION")
                .or_else(|_| std::env::var("AWS_REGION"))
                .or_else(|_| std::env::var("GOOGLE_CLOUD_REGION"))
                .ok(),

            // Deployment context (identifiers only - NOT secrets)
            environment: std::env::var("TENUO_ENVIRONMENT")
                .or_else(|_| std::env::var("ENV"))
                .or_else(|_| std::env::var("ENVIRONMENT"))
                .ok(),
            deploy_id: std::env::var("TENUO_DEPLOY_ID")
                .or_else(|_| std::env::var("BUILD_ID"))
                .or_else(|_| std::env::var("CI_COMMIT_SHA"))
                .ok(),
        }
    }
}

// ============================================================================
// Shared Metrics State (updated by request handlers)
// ============================================================================

/// Shared metrics state that can be updated by request handlers.
/// Clone and pass to handlers; updates are thread-safe.
#[derive(Clone)]
pub struct MetricsCollector {
    inner: Arc<MetricsCollectorInner>,
}

struct MetricsCollectorInner {
    start_time: Instant,
    requests_total: AtomicU64,
    requests_since_last: AtomicU64,
    allow_count: AtomicU64,
    deny_count: AtomicU64,

    // Latency tracking (circular buffer for p99)
    latencies: Mutex<LatencyTracker>,

    // Aggregation maps (protected by mutex)
    deny_reasons: Mutex<HashMap<String, u64>>,
    actions: Mutex<HashMap<String, u64>>,
    principals: Mutex<std::collections::HashSet<String>>,
    warrants: Mutex<std::collections::HashSet<String>>,

    // SRL health
    srl_last_fetch_at: Mutex<Option<String>>,
    srl_last_fetch_success: AtomicU64, // 0 = false, 1 = true
    srl_fetch_failures: AtomicU64,
    srl_verification_failures: AtomicU64,
    srl_current_version: AtomicU64,
}

/// Simple latency tracker with circular buffer for percentile estimation.
struct LatencyTracker {
    buffer: Vec<u64>,
    index: usize,
    total_sum: u64,
    total_count: u64,
}

impl LatencyTracker {
    fn new(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            index: 0,
            total_sum: 0,
            total_count: 0,
        }
    }

    fn record(&mut self, latency_us: u64) {
        self.total_sum += latency_us;
        self.total_count += 1;

        if self.buffer.len() < self.buffer.capacity() {
            self.buffer.push(latency_us);
        } else {
            self.buffer[self.index] = latency_us;
            self.index = (self.index + 1) % self.buffer.capacity();
        }
    }

    fn avg(&self) -> u64 {
        if self.total_count == 0 {
            0
        } else {
            self.total_sum / self.total_count
        }
    }

    fn p99(&self) -> u64 {
        if self.buffer.is_empty() {
            return 0;
        }
        let mut sorted = self.buffer.clone();
        sorted.sort_unstable();
        let idx = ((sorted.len() as f64) * 0.99).ceil() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn reset_interval(&mut self) {
        self.total_sum = 0;
        self.total_count = 0;
        // Keep buffer for p99 continuity, just reset sum/count
    }
}

impl MetricsCollector {
    /// Create a new metrics collector.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MetricsCollectorInner {
                start_time: Instant::now(),
                requests_total: AtomicU64::new(0),
                requests_since_last: AtomicU64::new(0),
                allow_count: AtomicU64::new(0),
                deny_count: AtomicU64::new(0),
                latencies: Mutex::new(LatencyTracker::new(1000)), // Keep last 1000 for p99
                deny_reasons: Mutex::new(HashMap::new()),
                actions: Mutex::new(HashMap::new()),
                principals: Mutex::new(std::collections::HashSet::new()),
                warrants: Mutex::new(std::collections::HashSet::new()),
                srl_last_fetch_at: Mutex::new(None),
                srl_last_fetch_success: AtomicU64::new(0),
                srl_fetch_failures: AtomicU64::new(0),
                srl_verification_failures: AtomicU64::new(0),
                srl_current_version: AtomicU64::new(0),
            }),
        }
    }

    /// Record an authorization decision.
    pub async fn record_authorization(
        &self,
        allowed: bool,
        tool: &str,
        latency_us: u64,
        warrant_id: &str,
        principal: Option<&str>,
        deny_reason: Option<&str>,
    ) {
        self.inner.requests_total.fetch_add(1, Ordering::Relaxed);
        self.inner
            .requests_since_last
            .fetch_add(1, Ordering::Relaxed);

        if allowed {
            self.inner.allow_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.deny_count.fetch_add(1, Ordering::Relaxed);
            if let Some(reason) = deny_reason {
                let mut reasons = self.inner.deny_reasons.lock().await;
                *reasons.entry(reason.to_string()).or_insert(0) += 1;
            }
        }

        // Record latency
        {
            let mut latencies = self.inner.latencies.lock().await;
            latencies.record(latency_us);
        }

        // Track unique warrants and principals
        {
            let mut warrants = self.inner.warrants.lock().await;
            warrants.insert(warrant_id.to_string());
        }
        if let Some(p) = principal {
            let mut principals = self.inner.principals.lock().await;
            principals.insert(p.to_string());
        }

        // Track tool usage
        {
            let mut actions = self.inner.actions.lock().await;
            *actions.entry(tool.to_string()).or_insert(0) += 1;
        }
    }

    /// Record SRL fetch result.
    pub async fn record_srl_fetch(&self, success: bool, version: Option<u64>) {
        if success {
            self.inner
                .srl_last_fetch_success
                .store(1, Ordering::Relaxed);
            if let Some(v) = version {
                self.inner.srl_current_version.store(v, Ordering::Relaxed);
            }
            let mut last_fetch = self.inner.srl_last_fetch_at.lock().await;
            *last_fetch = Some(chrono::Utc::now().to_rfc3339());
        } else {
            self.inner
                .srl_last_fetch_success
                .store(0, Ordering::Relaxed);
            self.inner
                .srl_fetch_failures
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record SRL verification failure.
    pub fn record_srl_verification_failure(&self) {
        self.inner
            .srl_verification_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Collect runtime metrics for heartbeat.
    pub async fn collect_runtime_metrics(&self) -> RuntimeMetrics {
        let latencies = self.inner.latencies.lock().await;
        RuntimeMetrics {
            uptime_seconds: self.inner.start_time.elapsed().as_secs(),
            requests_total: self.inner.requests_total.load(Ordering::Relaxed),
            requests_since_last: self.inner.requests_since_last.load(Ordering::Relaxed),
            avg_latency_us: latencies.avg(),
            p99_latency_us: latencies.p99(),
            memory_bytes: get_memory_usage(),
        }
    }

    /// Collect heartbeat stats and reset interval counters.
    pub async fn collect_and_reset_stats(&self) -> HeartbeatStats {
        // Collect deny reasons (top 10)
        let top_deny_reasons = {
            let mut reasons = self.inner.deny_reasons.lock().await;
            let mut sorted: Vec<_> = reasons.drain().collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1));
            sorted.truncate(10);
            sorted
        };

        // Collect top actions (top 10)
        let top_actions = {
            let mut actions = self.inner.actions.lock().await;
            let mut sorted: Vec<_> = actions.drain().collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1));
            sorted.truncate(10);
            sorted
        };

        // Collect unique counts and reset
        let unique_principals = {
            let mut principals = self.inner.principals.lock().await;
            let count = principals.len() as u64;
            principals.clear();
            count
        };

        let unique_warrants = {
            let mut warrants = self.inner.warrants.lock().await;
            let count = warrants.len() as u64;
            warrants.clear();
            count
        };

        // Get counts and reset interval counters
        let allow_count = self.inner.allow_count.swap(0, Ordering::Relaxed);
        let deny_count = self.inner.deny_count.swap(0, Ordering::Relaxed);
        self.inner.requests_since_last.store(0, Ordering::Relaxed);

        // Reset latency interval stats
        {
            let mut latencies = self.inner.latencies.lock().await;
            latencies.reset_interval();
        }

        HeartbeatStats {
            allow_count,
            deny_count,
            top_deny_reasons,
            top_actions,
            unique_principals,
            unique_warrants,
        }
    }

    /// Collect SRL health status.
    pub async fn collect_srl_health(&self) -> SrlHealth {
        let last_fetch_at = self.inner.srl_last_fetch_at.lock().await.clone();
        let version = self.inner.srl_current_version.load(Ordering::Relaxed);
        SrlHealth {
            last_fetch_at,
            last_fetch_success: self.inner.srl_last_fetch_success.load(Ordering::Relaxed) == 1,
            fetch_failures_total: self.inner.srl_fetch_failures.load(Ordering::Relaxed),
            verification_failures_total: self
                .inner
                .srl_verification_failures
                .load(Ordering::Relaxed),
            // Convert 0 to None (0 is internal sentinel for "no SRL")
            current_srl_version: if version == 0 { None } else { Some(version) },
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current process memory usage (platform-dependent).
fn get_memory_usage() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        // Read from /proc/self/statm
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(rss_pages) = statm.split_whitespace().nth(1) {
                if let Ok(pages) = rss_pages.parse::<u64>() {
                    // Page size is typically 4096
                    return Some(pages * 4096);
                }
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, we'd need mach APIs which are complex
        // Return None for now; could add via libc later
        None
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

// ============================================================================
// Heartbeat Configuration
// ============================================================================

/// Configuration for the heartbeat client.
#[derive(Clone)]
pub struct HeartbeatConfig {
    /// Control plane URL
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
    /// Environment information for registration
    pub environment: EnvironmentInfo,
    /// Shared metrics collector (optional, for metrics reporting)
    pub metrics: Option<MetricsCollector>,
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
            environment: EnvironmentInfo::default(),
            metrics: None,
        }
    }
}

/// Request body for authorizer registration.
/// Fields are flattened to match the Go control plane's expected format.
#[derive(Serialize)]
struct RegisterRequest<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    authorizer_type: &'a str,
    version: &'a str,
    // Flattened environment fields (Go control plane expects these at top level)
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    k8s_namespace: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    k8s_pod_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    k8s_cluster: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cloud_provider: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cloud_region: Option<&'a str>,
}

/// Response from authorizer registration.
#[derive(Deserialize)]
struct RegisterResponse {
    id: String,
}

/// Request body for heartbeat with metrics.
#[derive(Serialize)]
struct HeartbeatRequest {
    /// Current SRL version (None if no SRL loaded)
    #[serde(skip_serializing_if = "Option::is_none")]
    srl_version: Option<u64>,
    /// Runtime metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<RuntimeMetrics>,
    /// Aggregate stats since last heartbeat
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<HeartbeatStats>,
    /// SRL synchronization health
    #[serde(skip_serializing_if = "Option::is_none")]
    srl_health: Option<SrlHealth>,
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
                "Failed to register with control plane after 3 attempts. \
                 Authorizer will run in standalone mode without heartbeats."
            );
            return;
        }
    };

    info!(
        authorizer_id = %authorizer_id,
        name = %config.authorizer_name,
        "Registered with control plane"
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
                // Record successful fetch
                if let Some(ref metrics) = config.metrics {
                    metrics.record_srl_fetch(true, Some(version)).await;
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to fetch initial SRL, will retry on heartbeat");
                // Record failed fetch
                if let Some(ref metrics) = config.metrics {
                    metrics.record_srl_fetch(false, None).await;
                }
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
                                        "SRL updated from control plane"
                                    );
                                    // Record successful fetch
                                    if let Some(ref metrics) = config.metrics {
                                        metrics.record_srl_fetch(true, Some(new_version)).await;
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        error = %e,
                                        "Failed to fetch SRL from control plane"
                                    );
                                    // Record failed fetch
                                    if let Some(ref metrics) = config.metrics {
                                        metrics.record_srl_fetch(false, None).await;
                                    }
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

    // Build request with flattened environment fields
    let env = &config.environment;
    let request_body = RegisterRequest {
        name: &config.authorizer_name,
        authorizer_type: &config.authorizer_type,
        version: &config.version,
        environment: env.environment.as_deref(),
        k8s_namespace: env.k8s_namespace.as_deref(),
        k8s_pod_name: env.k8s_pod_name.as_deref(),
        k8s_cluster: env.k8s_cluster.as_deref(),
        cloud_provider: env.cloud_provider.as_deref(),
        cloud_region: env.cloud_region.as_deref(),
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

/// Send a heartbeat to the control plane with metrics.
async fn send_heartbeat(
    client: &Client,
    config: &HeartbeatConfig,
    authorizer_id: &str,
) -> Result<HeartbeatResponse, HeartbeatError> {
    let url = format!(
        "{}/v1/authorizers/{}/heartbeat",
        config.control_plane_url, authorizer_id
    );

    // Collect metrics if collector is available
    let (metrics, stats, srl_health) = if let Some(ref collector) = config.metrics {
        let metrics = collector.collect_runtime_metrics().await;
        let stats = collector.collect_and_reset_stats().await;
        let srl_health = collector.collect_srl_health().await;
        (Some(metrics), Some(stats), Some(srl_health))
    } else {
        (None, None, None)
    };

    // Extract srl_version from srl_health for top-level field (Go control plane convenience)
    let srl_version = srl_health.as_ref().and_then(|h| h.current_srl_version);

    let request_body = HeartbeatRequest {
        srl_version,
        metrics,
        stats,
        srl_health,
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
            environment: EnvironmentInfo::default(),
            metrics: None,
        }
    }

    #[test]
    fn test_environment_info_default() {
        let env = EnvironmentInfo::default();
        assert!(env.k8s_namespace.is_none());
        assert!(env.cloud_provider.is_none());
        assert!(env.environment.is_none());
    }

    #[test]
    fn test_runtime_metrics_default() {
        let metrics = RuntimeMetrics::default();
        assert_eq!(metrics.uptime_seconds, 0);
        assert_eq!(metrics.requests_total, 0);
    }

    #[test]
    fn test_heartbeat_stats_default() {
        let stats = HeartbeatStats::default();
        assert_eq!(stats.allow_count, 0);
        assert_eq!(stats.deny_count, 0);
        assert!(stats.top_deny_reasons.is_empty());
    }

    #[test]
    fn test_srl_health_default() {
        let health = SrlHealth::default();
        assert!(health.last_fetch_at.is_none());
        assert!(!health.last_fetch_success);
        assert_eq!(health.current_srl_version, None);
    }

    #[tokio::test]
    async fn test_metrics_collector_record_authorization() {
        let collector = MetricsCollector::new();

        // Record an allowed request
        collector
            .record_authorization(true, "read_file", 100, "wid-1", Some("user-1"), None)
            .await;

        // Record a denied request
        collector
            .record_authorization(
                false,
                "write_file",
                200,
                "wid-2",
                Some("user-1"),
                Some("constraint_violation"),
            )
            .await;

        let stats = collector.collect_and_reset_stats().await;
        assert_eq!(stats.allow_count, 1);
        assert_eq!(stats.deny_count, 1);
        assert_eq!(stats.unique_principals, 1);
        assert_eq!(stats.unique_warrants, 2);
    }

    #[tokio::test]
    async fn test_metrics_collector_latency() {
        let collector = MetricsCollector::new();

        // Record some latencies
        for i in 1..=100 {
            collector
                .record_authorization(true, "test", i * 10, &format!("wid-{}", i), None, None)
                .await;
        }

        let metrics = collector.collect_runtime_metrics().await;
        assert_eq!(metrics.requests_total, 100);
        assert!(metrics.avg_latency_us > 0);
        assert!(metrics.p99_latency_us >= metrics.avg_latency_us);
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
