#[cfg(feature = "python-server")]
use crate::heartbeat::{
    create_audit_channel, start_heartbeat_loop_with_audit_and_id, AuditEventSender,
    AuthorizationEvent, EnvironmentInfo, HeartbeatConfig,
};
#[cfg(feature = "python-server")]
use crate::python::PySigningKey;
#[cfg(feature = "python-server")]
use pyo3::exceptions::PyValueError;
#[cfg(feature = "python-server")]
use pyo3::prelude::*;
#[cfg(feature = "python-server")]
use std::collections::HashMap;
#[cfg(feature = "python-server")]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(feature = "python-server")]
use tokio::sync::RwLock;

#[cfg(feature = "python-server")]
static TOKIO_RUNTIME: OnceLock<Arc<tokio::runtime::Runtime>> = OnceLock::new();

#[cfg(feature = "python-server")]
fn runtime() -> &'static Arc<tokio::runtime::Runtime> {
    TOKIO_RUNTIME.get_or_init(|| {
        Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name("tenuo-cp")
                .enable_all()
                .build()
                .expect("tenuo: failed to create control plane runtime"),
        )
    })
}

#[cfg(feature = "python-server")]
#[pyclass(name = "ControlPlaneClient", module = "tenuo_core")]
pub struct PyControlPlaneClient {
    sender: AuditEventSender,
    /// Std Mutex for lock-free Python-side reads (no block_on needed).
    /// Populated by a one-shot watcher task after the heartbeat registers with
    /// the control plane and receives an authorizer ID.
    authorizer_id_py: Arc<Mutex<Option<String>>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

#[cfg(feature = "python-server")]
#[pymethods]
impl PyControlPlaneClient {
    /// Create a new control plane client and start the background heartbeat loop.
    ///
    /// The heartbeat loop registers this authorizer with Tenuo Cloud and
    /// periodically sends liveness signals. Authorization events are batched
    /// and flushed at ``audit_flush_interval_secs`` intervals.
    ///
    /// Args:
    ///     url: Tenuo Cloud control plane URL (e.g. ``https://cp.tenuo.dev``).
    ///     api_key: API key for authenticating to the control plane.
    ///     authorizer_name: Human-readable name for this authorizer instance.
    ///     signing_key: Ed25519 signing key used to sign heartbeat payloads.
    ///     authorizer_type: SDK identifier tag (default: ``"python-sdk"``).
    ///     heartbeat_interval_secs: Seconds between heartbeat signals (default: 30).
    ///     audit_batch_size: Maximum events held in the in-memory buffer (default: 100).
    ///     audit_flush_interval_secs: Seconds between audit batch flushes (default: 10).
    ///     metadata: Optional key-value pairs attached to every heartbeat payload.
    ///
    /// Example:
    /// ```text
    ///     from tenuo_core import ControlPlaneClient, SigningKey
    ///
    ///     key = SigningKey.generate()
    ///     client = ControlPlaneClient(
    ///         url="https://cp.tenuo.dev",
    ///         api_key="tk_...",
    ///         authorizer_name="my-service",
    ///         signing_key=key,
    ///     )
    /// ```
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        url,
        api_key,
        authorizer_name,
        signing_key,
        *,
        authorizer_type = "python-sdk",
        heartbeat_interval_secs = 30,
        audit_batch_size = 100,
        audit_flush_interval_secs = 10,
        metadata = None,
    ))]
    fn new(
        url: String,
        api_key: String,
        authorizer_name: String,
        signing_key: &PySigningKey,
        authorizer_type: &str,
        heartbeat_interval_secs: u64,
        audit_batch_size: usize,
        audit_flush_interval_secs: u64,
        metadata: Option<HashMap<String, String>>,
    ) -> PyResult<Self> {
        let (audit_tx, audit_rx) = create_audit_channel(audit_batch_size);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let mut env_info = EnvironmentInfo::from_env();
        if let Some(meta) = metadata {
            env_info.metadata = meta;
        }

        let config = HeartbeatConfig {
            control_plane_url: url,
            api_key,
            authorizer_name,
            authorizer_type: authorizer_type.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            interval_secs: heartbeat_interval_secs,
            authorizer: None,
            trusted_root: None,
            audit_batch_size,
            audit_flush_interval_secs,
            environment: env_info,
            metrics: None,
            signing_key: signing_key.inner.clone(),
        };

        let authorizer_id_async = Arc::new(RwLock::new(None::<String>));
        let authorizer_id_py = Arc::new(Mutex::new(None::<String>));

        let shared_id = authorizer_id_async.clone();
        let py_id_watcher = authorizer_id_py.clone();
        let async_id_watcher = authorizer_id_async.clone();

        runtime().spawn(async move {
            tokio::select! {
                _ = start_heartbeat_loop_with_audit_and_id(config, Some(audit_rx), shared_id) => {}
                _ = shutdown_rx.changed() => {}
            }
        });

        // One-shot watcher: polls the tokio RwLock until the authorizer_id is
        // set (after registration completes), then propagates to the std::Mutex
        // so Python-side reads never need block_on.
        runtime().spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                let id = async_id_watcher.read().await.clone();
                if id.is_some() {
                    *py_id_watcher.lock().unwrap() = id;
                    break;
                }
            }
        });

        Ok(Self {
            sender: audit_tx,
            authorizer_id_py,
            shutdown_tx,
        })
    }

    /// Create a client from environment variables, returning ``None`` if any required
    /// variable is missing.
    ///
    /// Required environment variables:
    ///     ``TENUO_CONTROL_PLANE_URL``, ``TENUO_API_KEY``,
    ///     ``TENUO_AUTHORIZER_NAME``, ``TENUO_SIGNING_KEY`` (base64 Ed25519 key).
    ///
    /// Example:
    /// ```text
    ///     client = ControlPlaneClient.from_env()
    ///     if client is None:
    ///         print("Control plane env vars not set — running without telemetry")
    /// ```
    #[staticmethod]
    fn from_env() -> PyResult<Option<Self>> {
        let url = match std::env::var("TENUO_CONTROL_PLANE_URL") {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let api_key = match std::env::var("TENUO_API_KEY") {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let auth_name = match std::env::var("TENUO_AUTHORIZER_NAME") {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let sign_key_b64 = match std::env::var("TENUO_SIGNING_KEY") {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        use base64::Engine;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(sign_key_b64.trim())
            .map_err(|e| PyValueError::new_err(format!("Invalid signing key: {}", e)))?;

        let mut arr = [0u8; 32];
        if key_bytes.len() != 32 {
            return Err(PyValueError::new_err(
                "Signing key must be exactly 32 bytes",
            ));
        }
        arr.copy_from_slice(&key_bytes);

        let sk = crate::crypto::SigningKey::from_bytes(&arr);

        let py_sk = PySigningKey { inner: sk };

        Self::new(
            url,
            api_key,
            auth_name,
            &py_sk,
            "python-sdk",
            30,
            100,
            10,
            None,
        )
        .map(Some)
    }

    /// Emit an allow event to the control plane.
    ///
    /// Args:
    ///     warrant_id: Unique ID of the leaf warrant that was accepted.
    ///     tool: Name of the tool or resource that was accessed.
    ///     chain_depth: Depth of the warrant chain (1 for single warrants).
    ///     root_principal: Hex-encoded public key of the root issuer, if known.
    ///     warrant_stack: Base64-encoded CBOR warrant stack for non-repudiation.
    ///     latency_us: Authorization check latency in microseconds.
    ///     request_id: Caller-supplied correlation ID (UUID recommended).
    ///     arguments: JSON-encoded tool arguments for the audit record.
    #[allow(clippy::too_many_arguments)]
    fn emit_allow(
        &self,
        warrant_id: String,
        tool: String,
        chain_depth: u8,
        root_principal: Option<String>,
        warrant_stack: Option<String>,
        latency_us: u64,
        request_id: String,
        arguments: Option<String>,
    ) -> PyResult<()> {
        let auth_id = self
            .authorizer_id_py
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_else(|| "pending".to_string());

        let event = AuthorizationEvent::allow(
            auth_id,
            warrant_id,
            tool,
            chain_depth,
            root_principal,
            warrant_stack,
            latency_us,
            request_id,
            arguments,
        );
        let _ = self.sender.try_send(event); // drop if full
        Ok(())
    }

    /// Emit a deny event to the control plane.
    ///
    /// Args:
    ///     warrant_id: Unique ID of the warrant that was presented (empty string if absent).
    ///     tool: Name of the tool or resource that was attempted.
    ///     deny_reason: Human-readable reason for the denial.
    ///     failed_constraint: The specific constraint expression that was violated, if any.
    ///     chain_depth: Depth of the warrant chain (1 for single warrants).
    ///     root_principal: Hex-encoded public key of the root issuer, if known.
    ///     warrant_stack: Base64-encoded CBOR warrant stack for non-repudiation.
    ///     latency_us: Authorization check latency in microseconds.
    ///     request_id: Caller-supplied correlation ID (UUID recommended).
    ///     arguments: JSON-encoded tool arguments for the audit record.
    #[allow(clippy::too_many_arguments)]
    fn emit_deny(
        &self,
        warrant_id: String,
        tool: String,
        deny_reason: String,
        failed_constraint: Option<String>,
        chain_depth: u8,
        root_principal: Option<String>,
        warrant_stack: Option<String>,
        latency_us: u64,
        request_id: String,
        arguments: Option<String>,
    ) -> PyResult<()> {
        let auth_id = self
            .authorizer_id_py
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_else(|| "pending".to_string());

        let event = AuthorizationEvent::deny(
            auth_id,
            warrant_id,
            tool,
            deny_reason,
            failed_constraint,
            chain_depth,
            root_principal,
            warrant_stack,
            latency_us,
            request_id,
            arguments,
        );
        let _ = self.sender.try_send(event); // drop if full
        Ok(())
    }

    /// Flush pending audit events and stop the background heartbeat task.
    ///
    /// Blocks the calling Python thread for up to ``timeout_secs`` to allow
    /// the audit flush loop to drain buffered events before the task is
    /// cancelled. The atexit handler in ``tenuo.control_plane`` calls this
    /// automatically with a 2-second timeout on clean process exit.
    #[pyo3(signature = (timeout_secs = 5.0))]
    fn shutdown(&self, timeout_secs: f64) -> PyResult<()> {
        let secs = timeout_secs.clamp(0.0, 30.0);
        // Block briefly to let the audit flush loop drain before we cancel it.
        runtime().block_on(tokio::time::sleep(std::time::Duration::from_secs_f64(secs)));
        let _ = self.shutdown_tx.send(true);
        Ok(())
    }

    /// The authorizer UUID assigned by the control plane after registration.
    ///
    /// Returns ``None`` until the first heartbeat completes and the control plane
    /// responds with an ID (typically within the first ``heartbeat_interval_secs``).
    ///
    /// Example:
    /// ```text
    ///     import time
    ///     time.sleep(5)  # wait for first heartbeat
    ///     print(client.authorizer_id)  # "tnu_auth_..."
    /// ```
    #[getter]
    fn get_authorizer_id(&self) -> Option<String> {
        self.authorizer_id_py.lock().ok().and_then(|g| g.clone())
    }
}
