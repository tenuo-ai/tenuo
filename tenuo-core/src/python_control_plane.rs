#[cfg(feature = "python-server")]
use crate::connect_token::ConnectToken;
#[cfg(feature = "python-server")]
use crate::heartbeat::{
    create_audit_channel, start_heartbeat_loop_with_audit_and_id, ApprovalRecord, AuditEventSender,
    AuthorizationEvent, EnvironmentInfo, HeartbeatConfig,
};
#[cfg(feature = "python-server")]
use crate::python::{to_py_err, PyChainVerificationResult, PySigningKey};
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

// ---------------------------------------------------------------------------
// PyConnectToken — expose token parsing to Python
// ---------------------------------------------------------------------------

#[cfg(feature = "python-server")]
#[pyclass(name = "ConnectToken", module = "tenuo_core")]
pub struct PyConnectToken {
    inner: ConnectToken,
}

#[cfg(feature = "python-server")]
#[pymethods]
impl PyConnectToken {
    /// Parse a ``tenuo_ct_…`` token string and return its components.
    #[staticmethod]
    fn parse(raw: &str) -> PyResult<Self> {
        let ct = ConnectToken::parse(raw)
            .map_err(|e| PyValueError::new_err(format!("invalid connect token: {}", e)))?;
        Ok(Self { inner: ct })
    }

    #[getter]
    fn version(&self) -> u8 {
        self.inner.version
    }
    #[getter]
    fn endpoint(&self) -> &str {
        &self.inner.endpoint
    }
    #[getter]
    fn api_key(&self) -> &str {
        &self.inner.api_key
    }
    #[getter]
    fn agent_id(&self) -> Option<&str> {
        self.inner.agent_id.as_deref()
    }
    #[getter]
    fn registration_token(&self) -> Option<&str> {
        self.inner.registration_token.as_deref()
    }
}

// ---------------------------------------------------------------------------
// PyControlPlaneClient — main Python-facing control plane client
// ---------------------------------------------------------------------------

#[cfg(feature = "python-server")]
#[pyclass(name = "ControlPlaneClient", module = "tenuo_core")]
pub struct PyControlPlaneClient {
    sender: AuditEventSender,
    authorizer_id_py: Arc<Mutex<Option<String>>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// The key this enforcement point already authenticates with. Reused as the
    /// receipt signer so a deployment has one identity, not two.
    receipt_signer: crate::crypto::SigningKey,
    /// Trust context copied from the authorizer by `bind_authorizer`. Read from
    /// the authorizer rather than configured separately, so a receipt cannot
    /// commit to roots or a revocation list the enforcement point never had.
    trust: Arc<Mutex<Option<TrustContext>>>,
    /// Digest of the last receipt emitted, for the chain link (key 14).
    last_receipt_hash: Arc<Mutex<Option<[u8; 32]>>>,
}

#[cfg(feature = "python-server")]
#[derive(Clone, Copy)]
struct TrustContext {
    trusted_roots_hash: [u8; 32],
    srl_commitment: Option<(Option<u64>, [u8; 32])>,
}

#[cfg(feature = "python-server")]
#[pymethods]
impl PyControlPlaneClient {
    /// Create a new control plane client and start the background heartbeat loop.
    ///
    /// Accepts **either** a connect token (``token``) **or** explicit
    /// ``url`` / ``api_key`` / ``signing_key`` parameters.  When a token is
    /// provided the endpoint, API key, and optional agent binding are extracted
    /// from it and a fresh signing key is generated automatically.
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        url = None,
        api_key = None,
        authorizer_name = None,
        signing_key = None,
        *,
        token = None,
        authorizer_type = "embedded",
        heartbeat_interval_secs = 30,
        audit_batch_size = 100,
        audit_flush_interval_secs = 10,
        metadata = None,
    ))]
    fn new(
        url: Option<String>,
        api_key: Option<String>,
        authorizer_name: Option<String>,
        signing_key: Option<&PySigningKey>,
        token: Option<String>,
        authorizer_type: &str,
        heartbeat_interval_secs: u64,
        audit_batch_size: usize,
        audit_flush_interval_secs: u64,
        metadata: Option<HashMap<String, String>>,
    ) -> PyResult<Self> {
        // ---- resolve configuration from token or explicit args ----
        let parsed_token = token
            .as_deref()
            .map(ConnectToken::parse)
            .transpose()
            .map_err(|e| PyValueError::new_err(format!("invalid connect token: {}", e)))?;

        let resolved_url = url
            .or_else(|| parsed_token.as_ref().map(|t| t.endpoint.clone()))
            .ok_or_else(|| PyValueError::new_err("url is required (or provide a token)"))?;

        let resolved_key = api_key
            .or_else(|| parsed_token.as_ref().map(|t| t.api_key.clone()))
            .ok_or_else(|| PyValueError::new_err("api_key is required (or provide a token)"))?;

        let resolved_name = authorizer_name.unwrap_or_else(|| {
            parsed_token
                .as_ref()
                .and_then(|t| t.agent_id.clone())
                .unwrap_or_else(|| "default".to_string())
        });

        let receipt_signer;
        let resolved_signing_key = match signing_key {
            Some(sk) => sk.inner.clone(),
            None => crate::crypto::SigningKey::generate(),
        };
        receipt_signer = resolved_signing_key.clone();

        let agent_id = parsed_token.as_ref().and_then(|t| t.agent_id.clone());

        // ---- build env / metadata ----
        let mut env_info = EnvironmentInfo::from_env();
        if let Some(meta) = metadata {
            env_info.metadata = meta;
        }
        if let Some(ref aid) = agent_id {
            env_info
                .metadata
                .insert("agent_id".to_string(), aid.clone());
        }

        let (audit_tx, audit_rx) = create_audit_channel(audit_batch_size);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let config = HeartbeatConfig {
            control_plane_url: resolved_url,
            api_key: resolved_key,
            authorizer_name: resolved_name,
            authorizer_type: authorizer_type.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            interval_secs: heartbeat_interval_secs,
            authorizer: None,
            trusted_root: None,
            audit_batch_size,
            audit_flush_interval_secs,
            environment: env_info,
            metrics: None,
            signing_key: resolved_signing_key,
            id_notify: None,
            agent_id,
            connect_token: parsed_token,
        };

        let authorizer_id_async = Arc::new(RwLock::new(None::<String>));
        let authorizer_id_py = Arc::new(Mutex::new(None::<String>));

        let (id_tx, mut id_rx) = tokio::sync::watch::channel(None::<String>);

        let shared_id = authorizer_id_async.clone();
        let py_id_watcher = authorizer_id_py.clone();

        let mut config = config;
        config.id_notify = Some(id_tx);

        let cp_url = config.control_plane_url.clone();
        let auth_name = config.authorizer_name.clone();
        runtime().spawn(async move {
            tokio::select! {
                _ = start_heartbeat_loop_with_audit_and_id(config, Some(audit_rx), shared_id) => {
                    eprintln!(
                        "[tenuo] control plane loop exited for '{}' ({}). \
                         Registration may have failed — check API key and URL.",
                        auth_name, cp_url,
                    );
                }
                _ = shutdown_rx.changed() => {}
            }
        });

        runtime().spawn(async move {
            if id_rx.changed().await.is_ok() {
                let id = id_rx.borrow().clone();
                if id.is_some() {
                    *py_id_watcher.lock().unwrap() = id;
                }
            }
        });

        Ok(Self {
            receipt_signer,
            trust: Arc::new(Mutex::new(None)),
            last_receipt_hash: Arc::new(Mutex::new(None)),
            sender: audit_tx,
            authorizer_id_py,
            shutdown_tx,
        })
    }

    /// Create a client from environment variables.
    ///
    /// Checks ``TENUO_CONNECT_TOKEN`` first. Falls back to the legacy
    /// four-variable set (``TENUO_CONTROL_PLANE_URL``, ``TENUO_API_KEY``,
    /// ``TENUO_AUTHORIZER_NAME``, ``TENUO_SIGNING_KEY``).
    /// Returns ``None`` when neither path provides enough configuration.
    #[staticmethod]
    fn from_env() -> PyResult<Option<Self>> {
        // Fast path: connect token contains everything we need.
        if let Ok(token) = std::env::var("TENUO_CONNECT_TOKEN") {
            if !token.is_empty() {
                return Self::new(
                    None,
                    None,
                    None,
                    None,
                    Some(token),
                    "embedded",
                    30,
                    100,
                    10,
                    None,
                )
                .map(Some);
            }
        }

        // Legacy path: require all four env vars.
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
            Some(url),
            Some(api_key),
            Some(auth_name),
            Some(&py_sk),
            None,
            "embedded",
            30,
            100,
            10,
            None,
        )
        .map(Some)
    }

    /// Copy the enforcement point's trust context from its authorizer.
    ///
    /// Receipts commit to the trusted root set and the revocation list in force
    /// (payload keys 15, 12 and 13). Those values are read from the authorizer
    /// itself rather than configured here, so a receipt cannot claim a trust
    /// context this enforcement point never had. Call again after installing a
    /// new revocation list.
    ///
    /// Until this is called, `issue_receipt` returns None: an enforcement point
    /// that cannot say what it trusted has nothing worth signing.
    fn bind_authorizer(&self, authorizer: &crate::python::PyAuthorizer) -> PyResult<()> {
        let context = TrustContext {
            trusted_roots_hash: authorizer.trusted_roots_hash_bytes(),
            srl_commitment: authorizer.srl_commitment_value(),
        };
        let mut guard = self.trust.lock().map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err("trust context lock poisoned")
        })?;
        *guard = Some(context);
        Ok(())
    }

    /// Public key receipts from this enforcement point are signed under.
    ///
    /// The same key the control plane already knows this authorizer by, so
    /// resolving a receipt's signer against the registry needs no new material.
    #[getter]
    fn receipt_signer_key(&self) -> String {
        hex::encode(self.receipt_signer.public_key().to_bytes())
    }

    /// Build and sign a receipt for a decision, advancing the chain.
    ///
    /// Returns the receipt as hex, or None when the client is not bound to an
    /// authorizer or the verification carries no warrant stack. Every
    /// trust-critical field comes from `chain_result`; Python supplies only the
    /// framing.
    #[pyo3(signature = (chain_result, tool, allowed, timestamp, request_id, decision_code=None))]
    fn issue_receipt(
        &self,
        chain_result: &PyChainVerificationResult,
        tool: &str,
        allowed: bool,
        timestamp: i64,
        request_id: &str,
        decision_code: Option<&str>,
    ) -> PyResult<Option<String>> {
        let trust = {
            let guard = self.trust.lock().map_err(|_| {
                pyo3::exceptions::PyRuntimeError::new_err("trust context lock poisoned")
            })?;
            match *guard {
                Some(t) => t,
                None => return Ok(None),
            }
        };

        let outcome = if allowed {
            crate::receipt::Outcome::Allow
        } else {
            crate::receipt::Outcome::Deny
        };

        let mut payload = match chain_result.inner.to_receipt_payload(
            tool,
            outcome,
            timestamp,
            request_id,
            decision_code,
        ) {
            Some(p) => p,
            None => return Ok(None),
        };

        payload.trusted_roots_hash = Some(trust.trusted_roots_hash);
        if let Some((version, digest)) = trust.srl_commitment {
            payload.srl_version = version;
            payload.srl_hash = Some(digest);
        }

        let mut link = self.last_receipt_hash.lock().map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err("receipt chain lock poisoned")
        })?;
        payload.prev_receipt_hash = *link;

        let receipt =
            crate::receipt::Receipt::create(&payload, &self.receipt_signer).map_err(to_py_err)?;
        let digest = receipt.digest().map_err(to_py_err)?;

        let mut bytes = Vec::new();
        ciborium::into_writer(&receipt, &mut bytes).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("failed to encode receipt: {e}"))
        })?;

        // Advance only once the receipt actually encoded, so a failure cannot
        // silently break every later link.
        *link = Some(digest);
        Ok(Some(hex::encode(bytes)))
    }

    /// Build and sign a receipt for a denial, from the chain that was presented.
    ///
    /// Denials cannot go through `issue_receipt`: `check_chain` returns `Err`
    /// for expiry, revocation, an untrusted root or a constraint miss, so there
    /// is no `ChainVerificationResult` to build from. The chain was still
    /// presented, though, and a denial over presented authority is exactly the
    /// decision most worth recording — without this the receipt stream is a
    /// contiguous run of allows with every refusal silently absent, which is
    /// the incompleteness the chain link exists to make visible.
    ///
    /// `verified_pop` is the holder's signature, supplied only when possession
    /// was established before the failure — that is what separates "an
    /// authenticated party was refused" from "we could not establish who was
    /// asking". It is not inferred: asserting a proof-of-possession that was
    /// never checked and denying one that was are both false claims, so the
    /// caller says which happened by supplying the signature or omitting it.
    ///
    /// Returns None when the client is not bound to an authorizer, or when no
    /// chain was presented at all — a request that carried no authority was
    /// refused at the door rather than authorized against anything, and there
    /// is no chain for a receipt to commit to.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        warrants, tool, args, timestamp, request_id, decision_code, verified_pop=None
    ))]
    fn issue_denial_receipt(
        &self,
        warrants: Vec<PyRef<crate::python::PyWarrant>>,
        tool: &str,
        args: &Bound<'_, pyo3::types::PyDict>,
        timestamp: i64,
        request_id: &str,
        decision_code: &str,
        verified_pop: Option<&[u8]>,
    ) -> PyResult<Option<String>> {
        let trust = {
            let guard = self.trust.lock().map_err(|_| {
                pyo3::exceptions::PyRuntimeError::new_err("trust context lock poisoned")
            })?;
            match *guard {
                Some(t) => t,
                None => return Ok(None),
            }
        };

        let chain: Vec<crate::warrant::Warrant> =
            warrants.iter().map(|w| w.inner_warrant().clone()).collect();
        let Some(leaf) = chain.last() else {
            return Ok(None);
        };

        let warrant_chain = crate::wire::encode_stack(&crate::wire::WarrantStack(chain.clone()))
            .map_err(to_py_err)?;

        let verified_pop = match verified_pop {
            Some(bytes) => {
                let arr: [u8; 64] = bytes.try_into().map_err(|_| {
                    pyo3::exceptions::PyValueError::new_err("verified_pop must be exactly 64 bytes")
                })?;
                Some(arr)
            }
            None => None,
        };
        let mut payload = match verified_pop {
            Some(pop) => crate::receipt::ReceiptPayload::deny(
                warrant_chain,
                tool,
                timestamp,
                request_id,
                decision_code,
                pop,
            ),
            None => crate::receipt::ReceiptPayload::deny_before_pop(
                warrant_chain,
                tool,
                timestamp,
                request_id,
                decision_code,
            ),
        };

        let mut rust_args = std::collections::HashMap::new();
        for (key, value) in args.iter() {
            let k: String = key.extract()?;
            rust_args.insert(k, crate::python::py_to_constraint_value(&value)?);
        }
        payload.request_hash = Some(crate::approval::compute_request_hash(
            &leaf.id().to_string(),
            tool,
            &rust_args,
            Some(leaf.authorized_holder()),
        ));
        payload.root_principal = chain.first().map(|w| hex::encode(w.issuer().to_bytes()));
        payload.trusted_roots_hash = Some(trust.trusted_roots_hash);
        if let Some((version, digest)) = trust.srl_commitment {
            payload.srl_version = version;
            payload.srl_hash = Some(digest);
        }

        let mut link = self.last_receipt_hash.lock().map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err("receipt chain lock poisoned")
        })?;
        payload.prev_receipt_hash = *link;

        let receipt =
            crate::receipt::Receipt::create(&payload, &self.receipt_signer).map_err(to_py_err)?;
        let digest = receipt.digest().map_err(to_py_err)?;
        let mut bytes = Vec::new();
        ciborium::into_writer(&receipt, &mut bytes).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("failed to encode receipt: {e}"))
        })?;

        *link = Some(digest);
        Ok(Some(hex::encode(bytes)))
    }

    /// Emit an allow event to the control plane.
    ///
    /// For authorized calls with a `ChainVerificationResult`, prefer
    /// [`emit_authorized`] — it extracts all trust-critical fields (approvals,
    /// warrant stack, chain depth) from the Rust-side verification result so
    /// Python cannot fabricate receipt data.
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
            None,
        );
        let _ = self.sender.try_send(event);
        Ok(())
    }

    /// Emit an allow event whose trust-critical fields are extracted entirely
    /// from a Rust [`ChainVerificationResult`].
    ///
    /// This is the preferred path for authorized calls — Python only supplies
    /// the tool name, serialized arguments, and timing metadata.  Warrant ID,
    /// chain depth, root issuer, warrant stack, and verified approvals all come
    /// from the Rust verification result, keeping Python out of the trust path
    /// for signed receipts.
    fn emit_authorized(
        &self,
        chain_result: &PyChainVerificationResult,
        tool: String,
        arguments: Option<String>,
        latency_us: u64,
        request_id: String,
    ) -> PyResult<()> {
        let auth_id = self
            .authorizer_id_py
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_else(|| "pending".to_string());

        let cr = &chain_result.inner;

        let warrant_id = cr
            .verified_steps
            .last()
            .map(|s| s.warrant_id.clone())
            .unwrap_or_default();

        let root_principal = cr.root_issuer.map(hex::encode);

        let approval_records: Option<Vec<ApprovalRecord>> = if cr.verified_approvals.is_empty() {
            None
        } else {
            Some(
                cr.verified_approvals
                    .iter()
                    .map(|va| ApprovalRecord {
                        approver_key: hex::encode(va.approver_key),
                        external_id: va.external_id.clone(),
                        approved_at: va.approved_at,
                        expires_at: va.expires_at,
                        request_hash: hex::encode(va.request_hash),
                        signed_approval_cbor_b64: va.signed_approval_cbor_b64.clone(),
                    })
                    .collect(),
            )
        };

        let event = AuthorizationEvent::allow(
            auth_id,
            warrant_id,
            tool,
            cr.leaf_depth as u8,
            root_principal,
            cr.warrant_stack_b64.clone(),
            latency_us,
            request_id,
            arguments,
            approval_records,
        );
        let _ = self.sender.try_send(event);
        Ok(())
    }

    /// Emit a deny event to the control plane.
    ///
    /// Denial events carry no approval records — if a gate was triggered but
    /// not satisfied, the denial reason captures that context.
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
            None,
        );
        let _ = self.sender.try_send(event);
        Ok(())
    }

    /// Flush pending events and stop the background heartbeat task.
    #[pyo3(signature = (timeout_secs = 5.0))]
    fn shutdown(&self, timeout_secs: f64) -> PyResult<()> {
        let secs = timeout_secs.clamp(0.0, 30.0);
        runtime().block_on(tokio::time::sleep(std::time::Duration::from_secs_f64(secs)));
        let _ = self.shutdown_tx.send(true);
        Ok(())
    }

    /// The authorizer UUID assigned by the control plane after registration.
    /// Returns ``None`` until registration completes.
    #[getter]
    fn get_authorizer_id(&self) -> Option<String> {
        self.authorizer_id_py.lock().ok().and_then(|g| g.clone())
    }
}
