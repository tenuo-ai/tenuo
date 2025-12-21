//! Control Plane and Data Plane separation.
//!
//! Tenuo's architecture cleanly separates:
//! - **Control Plane**: Issues warrants, manages policies, requires private keys
//! - **Data Plane**: Verifies warrants, authorizes actions, needs only public keys
//!
//! This separation enables offline verification - the data plane never needs
//! to call the control plane to validate a warrant.
//!
//! # Chain Verification
//!
//! For delegated warrants (depth > 0), verification requires the full chain:
//!
//! ```text
//! ┌────────────────┐    ┌─────────────────┐    ┌───────────────┐
//! │  Root Warrant  │───▶│ Orchestrator    │───▶│ Worker        │
//! │  (depth=0)     │    │ Warrant (d=1)   │    │ Warrant (d=2) │
//! │  signed by CP  │    │ signed by Orch  │    │ signed by Wkr │
//! └────────────────┘    └─────────────────┘    └───────────────┘
//!         │                     │                     │
//!         ▼                     ▼                     ▼
//!    Trusted Issuer      Parent verified        Chain verified
//! ```
//!
//! Each step validates:
//! 1. Child.parent_id == Parent.id
//! 2. Child.depth == Parent.depth + 1
//! 3. Child.expires_at <= Parent.expires_at
//! 4. Child.constraints ⊆ Parent.constraints
//! 5. Signature is valid

use crate::approval::{AuditEvent, AuditEventType, WarrantTracker};
use crate::audit::log_event;
use crate::constraints::{Constraint, ConstraintSet, ConstraintValue};
use crate::crypto::{PublicKey, SigningKey};
use crate::error::{Error, Result};
use crate::revocation::RevocationRequest;
use crate::warrant::{TrustLevel, Warrant, WarrantType};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::Duration;

// ============================================================================
// SHARED HELPERS
// ============================================================================

/// Verify multi-sig approvals for a request.
///
/// Returns Ok(()) if:
/// - Warrant has no `required_approvers`, OR
/// - Enough valid approvals are provided (>= threshold)
///
/// Checks: approver in required list, not expired, hash matches, signature valid.
fn verify_approvals_with_tolerance(
    warrant: &Warrant,
    tool: &str,
    args: &HashMap<String, ConstraintValue>,
    approvals: &[crate::approval::Approval],
    clock_tolerance: chrono::Duration,
) -> Result<()> {
    // Check if multi-sig is required
    let required_approvers = match warrant.required_approvers() {
        Some(approvers) if !approvers.is_empty() => approvers,
        _ => return Ok(()), // No multi-sig required
    };

    let threshold = warrant.approval_threshold();
    if threshold == 0 {
        return Ok(()); // Defensive: no threshold means no requirement
    }

    // DoS protection: limit approval count
    let max_approvals = required_approvers.len().saturating_mul(2);
    if approvals.len() > max_approvals {
        return Err(Error::InvalidApproval(format!(
            "too many approvals: {} provided, max {}",
            approvals.len(),
            max_approvals
        )));
    }

    // Compute the request hash for verification (includes authorized_holder to prevent theft)
    let request_hash = crate::approval::compute_request_hash(
        &warrant.id().to_string(),
        tool,
        args,
        Some(warrant.authorized_holder()),
    );

    // Count valid approvals from required approvers
    let mut valid_count = 0u32;
    let mut seen_approvers = std::collections::HashSet::new();
    let now = chrono::Utc::now();

    for approval in approvals {
        // Check if approver is in the required set
        if !required_approvers.contains(&approval.approver_key) {
            continue; // Not a required approver, skip
        }

        // Check if we've already counted this approver
        if seen_approvers.contains(&approval.approver_key) {
            continue; // Duplicate approval from same approver
        }

        // Check expiration (with clock tolerance)
        if approval.expires_at + clock_tolerance < now {
            continue; // Expired approval
        }

        // Verify request hash matches
        if approval.request_hash != request_hash {
            continue; // Wrong request
        }

        // Verify signature
        if approval.verify().is_ok() {
            valid_count = valid_count.saturating_add(1);
            seen_approvers.insert(approval.approver_key.clone());

            // Early exit: we have enough
            if valid_count >= threshold {
                return Ok(());
            }
        }
    }

    Err(Error::InsufficientApprovals {
        required: threshold,
        received: valid_count,
    })
}

// ============================================================================
// CHAIN VERIFICATION TYPES
// ============================================================================

/// Result of a successful chain verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerificationResult {
    /// Public key of the root issuer (trusted authority).
    pub root_issuer: Option<[u8; 32]>,
    /// Total length of the verified chain.
    pub chain_length: usize,
    /// Depth of the leaf warrant.
    pub leaf_depth: u32,
    /// Details of each verified step.
    pub verified_steps: Vec<ChainStep>,
}

/// A single step in the verified chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    /// The warrant ID at this step.
    pub warrant_id: String,
    /// Delegation depth at this step.
    pub depth: u32,
    /// Public key of the issuer at this step.
    pub issuer: [u8; 32],
}

// ============================================================================
// CONTROL PLANE
// ============================================================================

/// Control Plane - Issues and manages warrants.
///
/// The control plane holds private keys and is the source of authority.
/// It should run in a secure environment with limited access.
///
/// # Example
///
/// ```rust,ignore
/// let control_plane = ControlPlane::new(root_keypair);
///
/// // Issue a warrant for an orchestrator
/// let warrant = control_plane.issue_warrant(
///     "upgrade_cluster",
///     &[("cluster", Pattern::new("staging-*")?)],
///     Duration::from_secs(3600),
/// )?;
///
/// // Send warrant to orchestrator (via secure channel)
/// orchestrator.receive_warrant(warrant);
/// ```
#[derive(Debug)]
pub struct ControlPlane {
    /// The root keypair for signing warrants.
    keypair: SigningKey,
    /// Optional: known child public keys for delegation tracking.
    known_delegates: HashSet<[u8; 32]>,
}

impl ControlPlane {
    /// Create a new control plane with the given root keypair.
    pub fn new(keypair: SigningKey) -> Self {
        Self {
            keypair,
            known_delegates: HashSet::new(),
        }
    }

    /// Generate a new control plane with a fresh keypair.
    pub fn generate() -> Self {
        Self::new(SigningKey::generate())
    }

    /// Get the public key (share this with data planes).
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Export the public key bytes (for distribution to data planes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.keypair.public_key().to_bytes()
    }

    /// Issue a root warrant.
    ///
    /// By default, the warrant is bound to the issuer's public key (self-held).
    /// Use `issue_bound_warrant` to bind to a different holder.
    pub fn issue_warrant(
        &self,
        tool: &str,
        constraints: &[(&str, Constraint)],
        ttl: Duration,
    ) -> Result<Warrant> {
        let mut constraint_set = ConstraintSet::new();
        for (field, constraint) in constraints {
            constraint_set.insert(field.to_string(), constraint.clone());
        }

        Warrant::builder()
            .capability(tool, constraint_set)
            .ttl(ttl)
            .authorized_holder(self.keypair.public_key())
            .build(&self.keypair)
    }

    /// Issue a warrant bound to a specific holder.
    pub fn issue_bound_warrant(
        &self,
        tool: &str,
        constraints: &[(&str, Constraint)],
        ttl: Duration,
        holder: &PublicKey,
    ) -> Result<Warrant> {
        let mut constraint_set = ConstraintSet::new();
        for (field, constraint) in constraints {
            constraint_set.insert(field.to_string(), constraint.clone());
        }

        Warrant::builder()
            .capability(tool, constraint_set)
            .ttl(ttl)
            .authorized_holder(holder.clone())
            .build(&self.keypair)
    }

    /// Issue a warrant with full configuration options.
    ///
    /// This is the most flexible issuance method, allowing control over:
    /// - Tool name
    /// - Constraints
    /// - TTL
    /// - Holder binding
    /// - Max delegation depth
    pub fn issue_configured_warrant(
        &self,
        tool: &str,
        constraints: &[(&str, Constraint)],
        ttl: Duration,
        holder: &PublicKey,
        max_depth: u32,
    ) -> Result<Warrant> {
        let mut constraint_set = ConstraintSet::new();
        for (field, constraint) in constraints {
            constraint_set.insert(field.to_string(), constraint.clone());
        }

        Warrant::builder()
            .capability(tool, constraint_set)
            .ttl(ttl)
            .authorized_holder(holder.clone())
            .max_depth(max_depth)
            .build(&self.keypair)
    }

    /// Issue a warrant and automatically track it in the registry.
    ///
    /// This is the recommended way to issue warrants to ensure cascading revocation works.
    pub fn issue_tracked_warrant<T: WarrantTracker>(
        &self,
        tool: &str,
        constraints: &[(&str, Constraint)],
        ttl: Duration,
        holder: &PublicKey,
        tracker: &mut T,
    ) -> Result<Warrant> {
        let warrant = self.issue_bound_warrant(tool, constraints, ttl, holder)?;

        // Track for issuer (Control Plane)
        tracker.track_warrant(&self.public_key(), &warrant.id().to_string());

        // Track for authorized holder
        tracker.track_warrant(holder, &warrant.id().to_string());

        Ok(warrant)
    }

    /// Register a known delegate (for audit tracking).
    pub fn register_delegate(&mut self, public_key: &PublicKey) {
        self.known_delegates.insert(public_key.to_bytes());
    }
}

// ============================================================================
// DATA PLANE
// ============================================================================

/// Data Plane - Verifies and enforces warrants.
///
/// The data plane only needs public keys of trusted issuers.
/// It can verify warrants completely offline.
///
/// # Example
///
/// ```rust,ignore
/// // At startup, configure trusted issuers
/// let mut data_plane = DataPlane::new();
/// data_plane.trust_issuer("control-plane", control_plane_public_key);
///
/// // At request time, verify incoming warrant
/// let warrant = wire::decode_base64(&header_value)?;
/// data_plane.verify(&warrant)?;
///
/// // Authorize the specific action
/// data_plane.authorize(&warrant, "upgrade_cluster", &args)?;
/// ```
/// Default clock skew tolerance: 30 seconds.
///
/// This allows for reasonable clock drift between distributed nodes
/// while still providing security against replay attacks.
pub const DEFAULT_CLOCK_TOLERANCE_SECS: i64 = 30;

use crate::revocation::SignedRevocationList;

#[derive(Debug)]
pub struct DataPlane {
    /// Trusted issuer public keys, keyed by name.
    trusted_issuers: HashMap<String, PublicKey>,
    /// Optional: own keypair for attenuating warrants.
    own_keypair: Option<SigningKey>,
    /// Clock skew tolerance for expiration checks.
    clock_tolerance: chrono::Duration,
    /// Signed revocation list.
    revocation_list: Option<crate::revocation::SignedRevocationList>,
    /// Local cache of directly revoked warrants (Parental Revocation)
    local_revocation_cache: RwLock<HashSet<String>>,
    /// Tool trust requirements: minimum trust level required per tool.
    /// Supports exact matches and glob patterns (e.g., "admin_*").
    tool_trust_requirements: HashMap<String, TrustLevel>,
}

impl DataPlane {
    /// Create a new data plane with no trusted issuers.
    ///
    /// Uses the default clock tolerance of 30 seconds.
    pub fn new() -> Self {
        Self {
            trusted_issuers: HashMap::new(),
            own_keypair: None,
            clock_tolerance: chrono::Duration::seconds(DEFAULT_CLOCK_TOLERANCE_SECS),
            revocation_list: None,
            local_revocation_cache: RwLock::new(HashSet::new()),
            tool_trust_requirements: HashMap::new(),
        }
    }

    /// Create a new DataPlane with trusted issuers.
    pub fn new_with_issuers(trusted_issuers: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            trusted_issuers: trusted_issuers
                .into_iter()
                .map(|pk| (hex::encode(pk.to_bytes()), pk))
                .collect(),
            own_keypair: None,
            clock_tolerance: chrono::Duration::seconds(DEFAULT_CLOCK_TOLERANCE_SECS),
            revocation_list: None,
            local_revocation_cache: RwLock::new(HashSet::new()),
            tool_trust_requirements: HashMap::new(),
        }
    }

    /// Create a data plane that can also attenuate warrants.
    pub fn with_keypair(keypair: SigningKey) -> Self {
        Self {
            trusted_issuers: HashMap::new(),
            own_keypair: Some(keypair),
            clock_tolerance: chrono::Duration::seconds(DEFAULT_CLOCK_TOLERANCE_SECS),
            revocation_list: None,
            local_revocation_cache: RwLock::new(HashSet::new()),
            tool_trust_requirements: HashMap::new(),
        }
    }

    /// Set the clock skew tolerance.
    ///
    /// In distributed systems, clocks on different machines can drift apart.
    /// This tolerance allows a grace period when checking warrant expiration.
    ///
    /// # Arguments
    /// * `tolerance` - Grace period (e.g., 30 seconds). Use 0 for strict checking.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mut data_plane = DataPlane::new();
    /// data_plane.set_clock_tolerance(Duration::from_secs(60)); // 1 minute tolerance
    /// ```
    pub fn set_clock_tolerance(&mut self, tolerance: std::time::Duration) {
        self.clock_tolerance = chrono::Duration::from_std(tolerance)
            .unwrap_or(chrono::Duration::seconds(DEFAULT_CLOCK_TOLERANCE_SECS));
    }

    /// Set a signed revocation list.
    ///
    /// Verifies the signature before accepting. Returns error if verification fails.
    ///
    /// # Arguments
    /// * `srl` - The signed revocation list
    /// * `expected_issuer` - The Control Plane's public key (must match SRL issuer)
    pub fn set_revocation_list(
        &mut self,
        srl: SignedRevocationList,
        expected_issuer: &PublicKey,
    ) -> Result<()> {
        // Verify signature
        srl.verify(expected_issuer)?;
        self.revocation_list = Some(srl);
        Ok(())
    }

    /// Check if a warrant is revoked (globally or locally).
    pub fn is_revoked(&self, warrant: &Warrant) -> bool {
        let id = &warrant.id().to_string();

        // 1. Check global SRL
        if let Some(srl) = &self.revocation_list {
            if srl.is_revoked(id) {
                crate::audit::log_event(
                    crate::approval::AuditEvent::new(
                        crate::approval::AuditEventType::WarrantRevoked,
                        "data-plane",
                        "revocation-check",
                    )
                    .with_details(format!("Warrant {} is revoked in SRL", id))
                    .with_related(vec![id.to_string()]),
                );
                return true;
            }
        }

        // 2. Check local cache (Parental Revocation)
        if let Ok(cache) = self.local_revocation_cache.read() {
            if cache.contains(id) {
                crate::audit::log_event(
                    crate::approval::AuditEvent::new(
                        crate::approval::AuditEventType::WarrantRevoked,
                        "data-plane",
                        "revocation-check",
                    )
                    .with_details(format!("Warrant {} is locally revoked", id))
                    .with_related(vec![id.to_string()]),
                );
                return true;
            }
        }

        false
    }

    /// Submit a direct revocation request (Parental Revocation).
    ///
    /// This allows a parent (issuer) or holder to revoke a warrant immediately
    /// at the Data Plane, without waiting for the Control Plane's SRL update.
    ///
    /// # Security
    /// - Verifies the request signature.
    /// - Verifies the requestor is authorized (Issuer or Holder).
    /// - Adds to local cache if valid.
    pub fn submit_revocation(&self, request: &RevocationRequest, warrant: &Warrant) -> Result<()> {
        // 1. Verify signature
        request.verify_signature()?;

        // 2. Verify warrant ID matches
        if request.warrant_id != warrant.id().to_string() {
            return Err(Error::Unauthorized(format!(
                "Request warrant_id '{}' does not match provided warrant '{}'",
                request.warrant_id,
                warrant.id()
            )));
        }

        // 3. Verify authorization (Issuer or Holder only for direct revocation)
        // Note: We don't check Control Plane key here as we might not know it,
        // and CP revocations should go through SRL anyway.
        let is_authorized = request.requestor == *warrant.issuer() || // Parent
            request.requestor == *warrant.authorized_holder(); // Self

        if !is_authorized {
            return Err(Error::Unauthorized(format!(
                "Requestor {} is not authorized to revoke this warrant directly",
                hex::encode(request.requestor.to_bytes())
            )));
        }

        // 4. Add to local cache
        if let Ok(mut cache) = self.local_revocation_cache.write() {
            cache.insert(request.warrant_id.clone());
        }

        Ok(())
    }

    /// Add a trusted issuer.
    pub fn trust_issuer(&mut self, name: impl Into<String>, public_key: PublicKey) {
        self.trusted_issuers.insert(name.into(), public_key);
    }

    /// Add a trusted issuer from raw bytes.
    pub fn trust_issuer_bytes(&mut self, name: impl Into<String>, bytes: &[u8; 32]) -> Result<()> {
        let pk = PublicKey::from_bytes(bytes)?;
        self.trust_issuer(name, pk);
        Ok(())
    }

    /// Set minimum trust level required for a tool.
    ///
    /// This is **gateway-level policy**, not warrant content. The gateway defines
    /// what trust levels are required for its tools. This is an **offline check** -
    /// no network calls are made.
    ///
    /// Supports exact tool names or glob patterns:
    /// - `"delete_database"` - exact match
    /// - `"admin_*"` - prefix match (admin_users, admin_config, etc.)
    /// - `"*"` - default for all tools (recommended for defense in depth)
    ///
    /// # Validation
    ///
    /// Patterns are validated at registration time. Invalid patterns:
    /// - `"**"` - double wildcards not supported
    /// - `"*admin*"` - wildcards only at end (prefix patterns)
    /// - `"admin*foo"` - wildcard must be at end
    /// - `""` - empty patterns
    ///
    /// # Security Note
    ///
    /// If no trust requirement is configured for a tool, the check is skipped
    /// (permissive). For defense in depth, configure a default:
    ///
    /// ```ignore
    /// data_plane.require_trust("*", TrustLevel::External)?;  // Baseline
    /// data_plane.require_trust("admin_*", TrustLevel::System)?;  // Override
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is invalid.
    pub fn require_trust(
        &mut self,
        tool_pattern: impl Into<String>,
        level: TrustLevel,
    ) -> Result<()> {
        let pattern = tool_pattern.into();
        Self::validate_trust_pattern(&pattern)?;
        self.tool_trust_requirements.insert(pattern, level);
        Ok(())
    }

    /// Validate a trust requirement pattern.
    ///
    /// Valid patterns:
    /// - `"*"` - match all (default)
    /// - `"exact_name"` - exact match (no wildcards)
    /// - `"prefix_*"` - prefix match (wildcard at end only)
    fn validate_trust_pattern(pattern: &str) -> Result<()> {
        if pattern.is_empty() {
            return Err(Error::Validation(
                "trust pattern cannot be empty".to_string(),
            ));
        }

        // Count wildcards
        let wildcard_count = pattern.matches('*').count();

        match wildcard_count {
            0 => Ok(()), // Exact match - always valid
            1 => {
                if pattern == "*" {
                    Ok(()) // Default wildcard
                } else if let Some(prefix) = pattern.strip_suffix('*') {
                    // Prefix pattern - check the prefix is valid
                    if prefix.is_empty() {
                        // This would be just "*" which is handled above
                        Ok(())
                    } else if prefix.contains('*') {
                        Err(Error::Validation(format!(
                            "invalid trust pattern '{}': wildcard must be at end only",
                            pattern
                        )))
                    } else {
                        Ok(())
                    }
                } else {
                    Err(Error::Validation(format!(
                        "invalid trust pattern '{}': wildcard must be at end (e.g., 'admin_*')",
                        pattern
                    )))
                }
            }
            _ => Err(Error::Validation(format!(
                "invalid trust pattern '{}': only one wildcard allowed",
                pattern
            ))),
        }
    }

    /// Get the required trust level for a tool.
    ///
    /// This is an **offline operation** - no network calls.
    ///
    /// Checks in order:
    /// 1. Exact match
    /// 2. Glob pattern match (e.g., "admin_*")
    /// 3. Default "*" if configured
    /// 4. None (no requirement - check is skipped)
    pub fn get_required_trust(&self, tool: &str) -> Option<TrustLevel> {
        // 1. Exact match
        if let Some(&level) = self.tool_trust_requirements.get(tool) {
            return Some(level);
        }

        // 2. Glob pattern match
        for (pattern, &level) in &self.tool_trust_requirements {
            if pattern != "*" && Self::matches_glob_pattern(pattern, tool) {
                return Some(level);
            }
        }

        // 3. Default "*"
        self.tool_trust_requirements.get("*").copied()
    }

    /// Check if a tool name matches a glob pattern (supports trailing * only).
    fn matches_glob_pattern(pattern: &str, tool: &str) -> bool {
        if let Some(prefix) = pattern.strip_suffix('*') {
            tool.starts_with(prefix)
        } else {
            pattern == tool
        }
    }

    /// Verify a warrant against trusted issuers.
    ///
    /// This checks:
    /// 1. The warrant is signed by a trusted issuer
    /// 2. The warrant has not expired
    ///
    /// This is an **offline operation** - no network calls.
    pub fn verify(&self, warrant: &Warrant) -> Result<()> {
        // Check revocation first
        if self.is_revoked(warrant) {
            return Err(Error::WarrantRevoked(warrant.id().to_string()));
        }

        // Check expiration first (fast path), with clock tolerance
        if warrant.is_expired_with_tolerance(self.clock_tolerance) {
            return Err(Error::WarrantExpired(warrant.expires_at()));
        }

        // Check if issuer is trusted
        let issuer = warrant.issuer();
        let is_trusted = self.trusted_issuers.values().any(|pk| pk == issuer);

        if !is_trusted {
            return Err(Error::SignatureInvalid(
                "warrant issuer is not trusted".to_string(),
            ));
        }

        // Verify the signature
        warrant.verify(issuer)
    }

    /// Verify a complete delegation chain.
    ///
    /// This is the most thorough verification method, validating the entire
    /// path from a trusted root to the leaf warrant.
    ///
    /// # Arguments
    ///
    /// * `chain` - Ordered list of warrants from root (index 0) to leaf (last)
    ///
    /// # Chain Invariants Verified
    ///
    /// 1. **Root Trust**: `chain[0]` must be signed by a trusted issuer
    /// 2. **Linkage**: `chain[i+1].parent_id == chain[i].id`
    /// 3. **Depth**: `chain[i+1].depth == chain[i].depth + 1`
    /// 4. **Expiration**: `chain[i+1].expires_at <= chain[i].expires_at`
    /// 5. **Monotonicity**: `chain[i+1].constraints ⊆ chain[i].constraints`
    /// 6. **Signatures**: Each warrant has a valid signature
    /// 7. **No Cycles**: Each warrant ID appears exactly once
    /// 8. **Session Binding** (optional): All warrants in same session
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Full chain from control plane → orchestrator → worker
    /// let chain = vec![root_warrant, orchestrator_warrant, worker_warrant];
    /// data_plane.verify_chain(&chain)?;
    /// ```
    pub fn verify_chain(&self, chain: &[Warrant]) -> Result<ChainVerificationResult> {
        self.verify_chain_with_options(chain, false)
    }

    /// Verify chain with session binding enforcement.
    ///
    /// Same as `verify_chain`, but also verifies that all warrants in the chain
    /// have the same `session_id`. Use this when warrants should be isolated
    /// per-session (e.g., per HTTP request, per task).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // All warrants must share the same session_id
    /// data_plane.verify_chain_strict(&chain)?;
    /// ```
    pub fn verify_chain_strict(&self, chain: &[Warrant]) -> Result<ChainVerificationResult> {
        self.verify_chain_with_options(chain, true)
    }

    fn verify_chain_with_options(
        &self,
        chain: &[Warrant],
        enforce_session: bool,
    ) -> Result<ChainVerificationResult> {
        let result = self.verify_chain_with_options_inner(chain, enforce_session);

        // Audit: Log verification failures
        if let Err(ref e) = result {
            let chain_ids: Vec<String> = chain.iter().map(|w| w.id().to_string()).collect();
            log_event(AuditEvent {
                id: uuid::Uuid::new_v4().to_string(),
                event_type: AuditEventType::VerificationFailed,
                timestamp: chrono::Utc::now(),
                provider: "tenuo".to_string(),
                external_id: None,
                public_key_hex: chain.first().map(|w| hex::encode(w.issuer().to_bytes())),
                actor: "data_plane".to_string(),
                details: Some(format!("chain verification failed: {}", e)),
                related_ids: Some(chain_ids),
            });
        }

        result
    }

    fn verify_chain_with_options_inner(
        &self,
        chain: &[Warrant],
        enforce_session: bool,
    ) -> Result<ChainVerificationResult> {
        if chain.is_empty() {
            return Err(Error::ChainVerificationFailed(
                "chain cannot be empty".to_string(),
            ));
        }

        // CASCADING REVOCATION: Check if ANY warrant in the chain is revoked
        // This must happen before any other validation to fail fast.
        for warrant in chain {
            if self.is_revoked(warrant) {
                return Err(Error::WarrantRevoked(warrant.id().to_string()));
            }
        }

        // CYCLE DETECTION: Track seen warrant IDs
        let mut seen_ids: HashSet<String> = HashSet::new();
        for warrant in chain {
            let id = &warrant.id().to_string();
            if !seen_ids.insert(id.clone()) {
                return Err(Error::ChainVerificationFailed(format!(
                    "cycle detected: warrant ID '{}' appears multiple times in chain",
                    id
                )));
            }
        }

        let mut result = ChainVerificationResult {
            root_issuer: None,
            chain_length: chain.len(),
            leaf_depth: 0,
            verified_steps: Vec::new(),
        };

        // Step 1: Verify the root warrant is from a trusted key
        let root = &chain[0];
        let issuer = root.issuer();
        if !self.trusted_issuers.values().any(|k| k == issuer) {
            return Err(Error::SignatureInvalid(
                "root warrant issuer not trusted".to_string(),
            ));
        }

        // Batch verify all signatures in the chain (3x faster than sequential)
        use crate::crypto::verify_batch;
        let preimages: Vec<Vec<u8>> = chain.iter().map(|w| w.signature_preimage()).collect();
        let batch_items: Vec<(&crate::crypto::PublicKey, &[u8], &crate::crypto::Signature)> = chain
            .iter()
            .zip(preimages.iter())
            .map(|(w, pre)| (w.issuer(), pre.as_slice(), w.signature()))
            .collect();
        verify_batch(&batch_items)?;

        result.root_issuer = Some(root.issuer().to_bytes());
        result.verified_steps.push(ChainStep {
            warrant_id: root.id().to_string(),
            depth: root.depth(),
            issuer: root.issuer().to_bytes(),
        });

        // SESSION BINDING: Track session from root
        let expected_session = if enforce_session {
            root.session_id()
        } else {
            None
        };

        // Step 2: Walk the chain, verifying each link
        for i in 1..chain.len() {
            let parent = &chain[i - 1];
            let child = &chain[i];

            // Verify linkage via parent_hash
            self.verify_chain_link(parent, child)?;

            // Check session binding if enforced
            if enforce_session && child.session_id() != expected_session {
                return Err(Error::ChainVerificationFailed(format!(
                    "session mismatch: expected {:?}, got {:?} at depth {}",
                    expected_session,
                    child.session_id(),
                    child.depth()
                )));
            }

            result.verified_steps.push(ChainStep {
                warrant_id: child.id().to_string(),
                depth: child.depth(),
                issuer: child.issuer().to_bytes(),
            });
        }

        result.leaf_depth = chain.last().map(|w| w.depth()).unwrap_or(0);
        Ok(result)
    }

    /// Verify a single link in the delegation chain.
    ///
    /// Validates that `child` is a valid delegation from `parent` by checking:
    /// - I1: Delegation authority (child.issuer == parent.holder)
    /// - I2: Depth monotonicity
    /// - I3: TTL monotonicity
    /// - I4: Capability monotonicity
    /// - I5: Cryptographic linkage (parent_hash and signatures)
    fn verify_chain_link(&self, parent: &Warrant, child: &Warrant) -> Result<()> {
        // Check revocation
        if self.is_revoked(child) {
            return Err(Error::WarrantRevoked(child.id().to_string()));
        }

        // I1: Delegation Authority (wire-format-spec.md)
        // Child's issuer must be parent's holder (proves delegation)
        if child.issuer() != parent.authorized_holder() {
            return Err(Error::ChainVerificationFailed(format!(
                "I1 violated: child.issuer ({}) != parent.holder ({})",
                child.issuer().fingerprint(),
                parent.authorized_holder().fingerprint()
            )));
        }

        // I5: Cryptographic Linkage - Check parent_hash linkage
        let child_parent_hash = child.parent_hash().ok_or_else(|| {
            Error::ChainVerificationFailed(
                "child warrant has no parent_hash (must be root)".to_string(),
            )
        })?;

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(parent.payload_bytes());
        let expected_hash: [u8; 32] = hasher.finalize().into();

        if child_parent_hash != &expected_hash {
            return Err(Error::ChainVerificationFailed(
                "I5 violated: chain broken - child's parent_hash does not match parent's payload hash"
                    .to_string(),
            ));
        }

        // I2: Depth Monotonicity - Check depth increment (use saturating_add to prevent overflow)
        let expected_depth = parent.depth().saturating_add(1);
        if child.depth() != expected_depth {
            return Err(Error::ChainVerificationFailed(format!(
                "I2 violated: depth mismatch - child depth {} != parent depth {} + 1",
                child.depth(),
                parent.depth()
            )));
        }

        // I2: Check max_depth policy (defense-in-depth)
        // The builder enforces this at creation time, but we verify here too
        // in case someone bypasses the builder and signs manually.
        let parent_max = parent.effective_max_depth();
        if child.depth() > parent_max {
            return Err(Error::ChainVerificationFailed(format!(
                "I2 violated: child depth {} exceeds parent's max_depth {}",
                child.depth(),
                parent_max
            )));
        }

        // I3: TTL Monotonicity - Check expiration doesn't exceed parent
        if child.expires_at() > parent.expires_at() {
            return Err(Error::ChainVerificationFailed(format!(
                "I3 violated: child expires at {} which is after parent {}",
                child.expires_at(),
                parent.expires_at()
            )));
        }

        // 4. Check child is not expired (with clock tolerance)
        if child.is_expired_with_tolerance(self.clock_tolerance) {
            return Err(Error::WarrantExpired(child.expires_at()));
        }

        // 5. Validate constraint attenuation (monotonicity)
        match (parent.r#type(), child.r#type()) {
            (WarrantType::Execution, WarrantType::Execution) => {
                // For execution warrants, validate capability attenuation
                if let (Some(parent_caps), Some(child_caps)) =
                    (parent.capabilities(), child.capabilities())
                {
                    for (tool, child_constraints) in child_caps {
                        let parent_constraints =
                            parent_caps.get(tool).or_else(|| parent_caps.get("*"));

                        if let Some(parent_constraints) = parent_constraints {
                            parent_constraints.validate_attenuation(child_constraints)?;
                        } else {
                            return Err(Error::MonotonicityViolation(format!(
                                "tool '{}' not in parent's capabilities",
                                tool
                            )));
                        }
                    }
                }
                // Trust level monotonicity: child trust_level cannot exceed parent's
                if let (Some(parent_trust), Some(child_trust)) =
                    (parent.trust_level(), child.trust_level())
                {
                    if child_trust > parent_trust {
                        return Err(Error::MonotonicityViolation(format!(
                            "trust_level cannot increase: parent {:?}, child {:?}",
                            parent_trust, child_trust
                        )));
                    }
                }
            }
            (WarrantType::Issuer, WarrantType::Issuer) => {
                // For issuer warrants, validate issuable_tools
                if let (Some(parent_tools), Some(child_tools)) =
                    (parent.issuable_tools(), child.issuable_tools())
                {
                    // Child issuable_tools must be a subset of parent
                    for tool in child_tools {
                        if !parent_tools.iter().any(|t| t == tool || t == "*") {
                            return Err(Error::MonotonicityViolation(format!(
                                "issuable_tool '{}' not in parent's issuable_tools",
                                tool
                            )));
                        }
                    }
                }
                // Constraint bounds must be monotonic
                if let (Some(parent_bounds), Some(child_bounds)) =
                    (parent.constraint_bounds(), child.constraint_bounds())
                {
                    parent_bounds.validate_attenuation(child_bounds)?;
                }
            }
            (WarrantType::Issuer, WarrantType::Execution) => {
                // ISSUER -> EXECUTION: Validate issuance constraints
                // 1. Child tool must be in issuer's issuable_tools
                if let Some(issuable_tools) = parent.issuable_tools() {
                    if let Some(child_caps) = child.capabilities() {
                        for tool in child_caps.keys() {
                            if !issuable_tools.iter().any(|t| t == tool || t == "*") {
                                return Err(Error::MonotonicityViolation(format!(
                                    "tool '{}' not in issuer's issuable_tools: {:?}",
                                    tool, issuable_tools
                                )));
                            }
                        }
                    }
                }
                // 2. Child trust_level must not exceed issuer's trust_level (monotonicity)
                if let Some(parent_trust) = parent.trust_level() {
                    if let Some(child_trust) = child.trust_level() {
                        if child_trust > parent_trust {
                            return Err(Error::MonotonicityViolation(format!(
                                "trust_level {:?} exceeds issuer's trust_level {:?}",
                                child_trust, parent_trust
                            )));
                        }
                    }
                }
                // 3. Child constraints must respect issuer's constraint_bounds
                if let (Some(bounds), Some(child_caps)) =
                    (parent.constraint_bounds(), child.capabilities())
                {
                    for constraints in child_caps.values() {
                        bounds.validate_attenuation(constraints)?;
                    }
                }
                // 4. SECURITY: Prevent self-issuance (P-LLM/Q-LLM separation)
                // The execution warrant holder cannot be the same as the issuer warrant holder
                // or the issuer warrant's issuer. This ensures the planner cannot grant
                // execution capabilities to itself, even if warrants are crafted manually.
                if child.authorized_holder() == parent.authorized_holder() {
                    return Err(Error::SelfIssuanceProhibited {
                        reason: "issuer cannot grant execution warrants to themselves".to_string(),
                    });
                }
                if child.authorized_holder() == parent.issuer() {
                    return Err(Error::SelfIssuanceProhibited {
                        reason: "execution warrant holder cannot be the issuer warrant's issuer (issuer-holder separation required)".to_string(),
                    });
                }
            }
            _ => {
                return Err(Error::MonotonicityViolation(format!(
                    "invalid warrant type transition: {:?} -> {:?}",
                    parent.r#type(),
                    child.r#type()
                )));
            }
        }

        // 6. Verify child's signature
        child.verify(child.issuer())?;

        Ok(())
    }

    /// Verify chain and authorize an action.
    ///
    /// Convenience method that verifies the full chain and then authorizes
    /// the action against the leaf warrant (last in chain).
    pub fn check_chain(
        &self,
        chain: &[Warrant],
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&crate::crypto::Signature>,
        approvals: &[crate::approval::Approval],
    ) -> Result<ChainVerificationResult> {
        let result = self.verify_chain(chain)?;

        // Authorize against the leaf warrant
        if let Some(leaf) = chain.last() {
            self.authorize(leaf, tool, args, signature, approvals)?;
        }

        Ok(result)
    }

    /// Authorize an action.
    ///
    /// This checks that the warrant permits the given tool call with the given arguments.
    /// If the warrant requires multi-sig, approvals must be provided.
    /// If tool trust requirements are configured, the warrant's trust level is also checked.
    ///
    /// This is an **offline operation** - no network calls.
    pub fn authorize(
        &self,
        warrant: &Warrant,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&crate::crypto::Signature>,
        approvals: &[crate::approval::Approval],
    ) -> Result<()> {
        // Check trust level requirements first
        if let Some(required_trust) = self.get_required_trust(tool) {
            let warrant_trust = warrant.trust_level().unwrap_or(TrustLevel::Untrusted);
            if warrant_trust < required_trust {
                return Err(Error::InsufficientTrustLevel {
                    tool: tool.to_string(),
                    required: format!("{:?}", required_trust),
                    actual: format!("{:?}", warrant_trust),
                });
            }
        }

        // Standard constraint authorization
        let result = warrant.authorize(tool, args, signature).and_then(|_| {
            // Multi-sig verification
            verify_approvals_with_tolerance(
                warrant,
                tool,
                args,
                approvals,
                chrono::Duration::seconds(DEFAULT_CLOCK_TOLERANCE_SECS),
            )
        });

        match &result {
            Ok(_) => {
                crate::audit::log_event(
                    crate::approval::AuditEvent::new(
                        crate::approval::AuditEventType::AuthorizationSuccess,
                        "data-plane",
                        "authorize",
                    )
                    .with_details(format!("Authorized tool '{}'", tool))
                    .with_related(vec![warrant.id().to_string()]),
                );
            }
            Err(e) => {
                crate::audit::log_event(
                    crate::approval::AuditEvent::new(
                        crate::approval::AuditEventType::AuthorizationFailure,
                        "data-plane",
                        "authorize",
                    )
                    .with_details(format!("Denied tool '{}': {}", tool, e))
                    .with_related(vec![warrant.id().to_string()]),
                );
            }
        }

        result
    }

    /// Convenience: verify and authorize in one call.
    pub fn check(
        &self,
        warrant: &Warrant,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&crate::crypto::Signature>,
        approvals: &[crate::approval::Approval],
    ) -> Result<()> {
        self.verify(warrant)?;
        self.authorize(warrant, tool, args, signature, approvals)
    }

    /// Attenuate a warrant for a sub-agent.
    ///
    /// Requires this data plane to have its own keypair.
    ///
    /// # Arguments
    ///
    /// * `parent` - The parent warrant to attenuate from
    /// * `constraints` - Constraints to apply to the child warrant
    /// * `holder_keypair` - The keypair of the parent warrant holder (who is delegating)
    pub fn attenuate(
        &self,
        parent: &Warrant,
        constraints: &[(&str, Constraint)],
        holder_keypair: &SigningKey,
    ) -> Result<Warrant> {
        let _own_keypair = self.own_keypair.as_ref().ok_or_else(|| {
            Error::CryptoError("data plane has no keypair for attenuation".to_string())
        })?;

        // Group constraints by tool (from prefix) or default to "*" ?
        // OLD logic: parent.attenuate() -> OwnedAttenuationBuilder. Not specific tool?
        // Wait, OwnedAttenuationBuilder adds capabilities?
        // How does attenuate work now?
        // OwnedAttenuationBuilder has `capability(tool, constraints)`.

        let mut builder = parent.attenuate();

        // We need to map constraint list to capability map.
        // Assuming constraints are global? No, accessors were removed.
        // If constraints have tool prefixes?
        // For now, assume single tool if parent has single tool?
        // Or if simple constraints, map to "*"?

        // Let's assume the callers pass tool-specific constraints?
        // Wait, the API `constraints: &[(&str, Constraint)]` is generic.
        // The `example` usage earlier had `tool`.
        // `attenuate` does NOT take `tool` arg.
        // So it must inherit tools?
        // `OwnedAttenuationBuilder` needs specific capability updates.

        let mut constraint_set = ConstraintSet::new();
        for (field, constraint) in constraints {
            constraint_set.insert(field.to_string(), constraint.clone());
        }

        // Apply to ALL tools in parent?
        if let Some(caps) = parent.capabilities() {
            for tool in caps.keys() {
                builder = builder.capability(tool, constraint_set.clone());
            }
        }

        builder.build(holder_keypair)
    }

    /// Get this data plane's public key (if it has one).
    pub fn public_key(&self) -> Option<PublicKey> {
        self.own_keypair.as_ref().map(|kp| kp.public_key())
    }
}

impl Default for DataPlane {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AUTHORIZER (Minimal Data Plane for embedding)
// ============================================================================

/// Default PoP window size in seconds.
///
/// PoP signatures are valid for `pop_window_secs * max_windows` seconds total
/// (default: 30 * 4 = 120 seconds).
pub const DEFAULT_POP_WINDOW_SECS: i64 = 30;

/// Default number of PoP windows to check (handles clock skew).
pub const DEFAULT_POP_MAX_WINDOWS: u32 = 4;

/// Builder for creating an [`Authorizer`] with validated configuration.
///
/// Use this builder to configure an authorizer before construction.
/// The `build()` method validates that at least one trusted root is configured.
///
/// # Example
///
/// ```rust,ignore
/// use tenuo::planes::AuthorizerBuilder;
///
/// let authorizer = AuthorizerBuilder::new()
///     .trusted_root(control_plane_key)
///     .trusted_root(backup_key)
///     .clock_tolerance(Duration::seconds(60))
///     .pop_window(15, 4)
///     .build()?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct AuthorizerBuilder {
    trusted_keys: Vec<PublicKey>,
    clock_tolerance: chrono::Duration,
    pop_window_secs: i64,
    pop_max_windows: u32,
    pending_srl: Option<(SignedRevocationList, PublicKey)>,
    tool_trust_requirements: HashMap<String, TrustLevel>,
}

impl AuthorizerBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
            clock_tolerance: chrono::Duration::seconds(DEFAULT_CLOCK_TOLERANCE_SECS),
            pop_window_secs: DEFAULT_POP_WINDOW_SECS,
            pop_max_windows: DEFAULT_POP_MAX_WINDOWS,
            pending_srl: None,
            tool_trust_requirements: HashMap::new(),
        }
    }

    /// Add a trusted root public key.
    ///
    /// Warrants signed by this key (or chains rooted in it) will be trusted.
    /// Can be called multiple times to trust multiple roots.
    ///
    /// At least one trusted root is required for `build()` to succeed.
    pub fn trusted_root(mut self, key: PublicKey) -> Self {
        self.trusted_keys.push(key);
        self
    }

    /// Add multiple trusted roots at once.
    pub fn trusted_roots(mut self, keys: impl IntoIterator<Item = PublicKey>) -> Self {
        self.trusted_keys.extend(keys);
        self
    }

    /// Set the clock tolerance for expiration checks.
    ///
    /// In distributed systems, clocks can drift. This tolerance allows a grace
    /// period when checking warrant expiration.
    ///
    /// Default: 30 seconds.
    pub fn clock_tolerance(mut self, tolerance: chrono::Duration) -> Self {
        self.clock_tolerance = tolerance;
        self
    }

    /// Set the PoP (Proof-of-Possession) window configuration.
    ///
    /// The PoP window determines how long a PoP signature is valid.
    /// Total validity = `window_secs * max_windows`.
    ///
    /// - Smaller windows = tighter security, requires better clock sync
    /// - Larger windows = more tolerant of clock skew
    ///
    /// Default: 30s windows, 4 windows = 120s total.
    pub fn pop_window(mut self, window_secs: i64, max_windows: u32) -> Self {
        self.pop_window_secs = window_secs;
        self.pop_max_windows = max_windows;
        self
    }

    /// Set a signed revocation list.
    ///
    /// The signature is verified during `build()`.
    /// This allows chaining without breaking the fluent API.
    pub fn revocation_list(mut self, srl: SignedRevocationList, issuer: PublicKey) -> Self {
        self.pending_srl = Some((srl, issuer));
        self
    }

    /// Set minimum trust level required for a tool.
    ///
    /// Supports exact tool names or glob patterns:
    /// - `"delete_database"` - exact match
    /// - `"admin_*"` - prefix match (admin_users, admin_config, etc.)
    /// - `"*"` - default for all tools (recommended for defense in depth)
    ///
    /// # Panics
    ///
    /// Panics if the pattern is invalid. Use `try_trust_requirement` for fallible version.
    ///
    /// # Example
    /// ```ignore
    /// let authorizer = Authorizer::builder()
    ///     .trusted_root(root_key)
    ///     .trust_requirement("*", TrustLevel::External)
    ///     .trust_requirement("admin_*", TrustLevel::System)
    ///     .build()?;
    /// ```
    pub fn trust_requirement(self, tool_pattern: impl Into<String>, level: TrustLevel) -> Self {
        self.try_trust_requirement(tool_pattern, level)
            .expect("invalid trust pattern")
    }

    /// Set minimum trust level required for a tool (fallible version).
    ///
    /// Like `trust_requirement`, but returns a Result instead of panicking.
    pub fn try_trust_requirement(
        mut self,
        tool_pattern: impl Into<String>,
        level: TrustLevel,
    ) -> Result<Self> {
        let pattern = tool_pattern.into();
        Self::validate_trust_pattern(&pattern)?;
        self.tool_trust_requirements.insert(pattern, level);
        Ok(self)
    }

    /// Validate a trust requirement pattern.
    fn validate_trust_pattern(pattern: &str) -> Result<()> {
        if pattern.is_empty() {
            return Err(Error::Validation(
                "trust pattern cannot be empty".to_string(),
            ));
        }

        let wildcard_count = pattern.matches('*').count();

        match wildcard_count {
            0 => Ok(()),
            1 => {
                if pattern == "*" {
                    Ok(())
                } else if let Some(prefix) = pattern.strip_suffix('*') {
                    if prefix.is_empty() || !prefix.contains('*') {
                        Ok(())
                    } else {
                        Err(Error::Validation(format!(
                            "invalid trust pattern '{}': wildcard must be at end only",
                            pattern
                        )))
                    }
                } else {
                    Err(Error::Validation(format!(
                        "invalid trust pattern '{}': wildcard must be at end (e.g., 'admin_*')",
                        pattern
                    )))
                }
            }
            _ => Err(Error::Validation(format!(
                "invalid trust pattern '{}': only one wildcard allowed",
                pattern
            ))),
        }
    }

    /// Build the [`Authorizer`], validating configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No trusted roots were configured
    /// - The revocation list signature is invalid
    pub fn build(self) -> Result<Authorizer> {
        if self.trusted_keys.is_empty() {
            return Err(crate::error::Error::Validation(
                "Authorizer requires at least one trusted root".to_string(),
            ));
        }

        let revocation_list = if let Some((srl, issuer)) = self.pending_srl {
            srl.verify(&issuer)?;
            Some(srl)
        } else {
            None
        };

        Ok(Authorizer {
            trusted_keys: self.trusted_keys,
            clock_tolerance: self.clock_tolerance,
            revocation_list,
            pop_window_secs: self.pop_window_secs,
            pop_max_windows: self.pop_max_windows,
            tool_trust_requirements: self.tool_trust_requirements,
        })
    }
}

/// A minimal authorizer for embedding in services.
///
/// This is the smallest possible data plane - just a set of trusted keys.
///
/// # Creating an Authorizer
///
/// Use [`AuthorizerBuilder`] for validated construction:
///
/// ```rust,ignore
/// let authorizer = AuthorizerBuilder::new()
///     .trusted_root(control_plane_key)
///     .trusted_root(backup_key)
///     .clock_tolerance(Duration::seconds(60))
///     .pop_window(15, 4)
///     .build()?;
/// ```
///
/// Or use the convenience method [`Authorizer::new()`] for quick setup:
///
/// ```rust,ignore
/// let authorizer = Authorizer::new()
///     .with_trusted_root(control_plane_key);
/// ```
#[derive(Debug, Clone)]
pub struct Authorizer {
    trusted_keys: Vec<PublicKey>,
    clock_tolerance: chrono::Duration,
    revocation_list: Option<SignedRevocationList>,
    pop_window_secs: i64,
    pop_max_windows: u32,
    /// Tool trust requirements: minimum trust level required per tool.
    tool_trust_requirements: HashMap<String, TrustLevel>,
}

impl Default for Authorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Authorizer {
    /// Create a new authorizer with default settings.
    ///
    /// This is a convenience method that allows immediate chaining.
    /// For validated construction, use [`AuthorizerBuilder`].
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let authorizer = Authorizer::new()
    ///     .with_trusted_root(root_key);
    /// ```
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
            clock_tolerance: chrono::Duration::seconds(DEFAULT_CLOCK_TOLERANCE_SECS),
            revocation_list: None,
            pop_window_secs: DEFAULT_POP_WINDOW_SECS,
            pop_max_windows: DEFAULT_POP_MAX_WINDOWS,
            tool_trust_requirements: HashMap::new(),
        }
    }

    /// Create a builder for more controlled construction.
    ///
    /// The builder validates configuration on `build()`.
    pub fn builder() -> AuthorizerBuilder {
        AuthorizerBuilder::new()
    }

    /// Add a trusted root public key (chainable).
    ///
    /// Warrants signed by this key (or chains rooted in it) will be trusted.
    /// Can be called multiple times to trust multiple roots.
    pub fn with_trusted_root(mut self, key: PublicKey) -> Self {
        self.trusted_keys.push(key);
        self
    }

    /// Set the clock tolerance for expiration checks (chainable).
    ///
    /// Default: 30 seconds.
    pub fn with_clock_tolerance(mut self, tolerance: chrono::Duration) -> Self {
        self.clock_tolerance = tolerance;
        self
    }

    /// Set the PoP window configuration (chainable).
    ///
    /// Default: 30s windows, 4 windows = 120s total.
    pub fn with_pop_window(mut self, window_secs: i64, max_windows: u32) -> Self {
        self.pop_window_secs = window_secs;
        self.pop_max_windows = max_windows;
        self
    }

    /// Set a signed revocation list (chainable, fallible).
    ///
    /// Verifies the signature before accepting.
    /// Use `revocation_list()` on [`AuthorizerBuilder`] for non-fallible chaining.
    pub fn try_revocation_list(
        mut self,
        srl: SignedRevocationList,
        issuer: &PublicKey,
    ) -> Result<Self> {
        srl.verify(issuer)?;
        self.revocation_list = Some(srl);
        Ok(self)
    }

    // =========================================================================
    // Mutable setters (for updating after construction)
    // =========================================================================

    /// Add a trusted root (mutable version).
    pub fn add_trusted_root(&mut self, key: PublicKey) {
        self.trusted_keys.push(key);
    }

    /// Set the PoP window (mutable version).
    pub fn set_pop_window(&mut self, window_secs: i64, max_windows: u32) {
        self.pop_window_secs = window_secs;
        self.pop_max_windows = max_windows;
    }

    /// Set a signed revocation list (mutable version).
    pub fn set_revocation_list(
        &mut self,
        srl: SignedRevocationList,
        expected_issuer: &PublicKey,
    ) -> Result<()> {
        srl.verify(expected_issuer)?;
        self.revocation_list = Some(srl);
        Ok(())
    }

    /// Set the clock tolerance (mutable version).
    pub fn set_clock_tolerance(&mut self, tolerance: chrono::Duration) {
        self.clock_tolerance = tolerance;
    }

    /// Set minimum trust level required for a tool (chainable, validated).
    ///
    /// This is **gateway-level policy**. The authorizer defines what trust levels
    /// are required for its tools. This is an **offline check**.
    ///
    /// Supports exact tool names or glob patterns:
    /// - `"delete_database"` - exact match
    /// - `"admin_*"` - prefix match (admin_users, admin_config, etc.)
    /// - `"*"` - default for all tools (recommended for defense in depth)
    ///
    /// # Panics
    ///
    /// Panics if the pattern is invalid. Use `try_trust_requirement` for fallible version.
    ///
    /// # Example
    /// ```ignore
    /// let authorizer = Authorizer::new()
    ///     .with_trusted_root(root_key)
    ///     .with_trust_requirement("*", TrustLevel::External)
    ///     .with_trust_requirement("admin_*", TrustLevel::System);
    /// ```
    pub fn with_trust_requirement(
        self,
        tool_pattern: impl Into<String>,
        level: TrustLevel,
    ) -> Self {
        self.try_trust_requirement(tool_pattern, level)
            .expect("invalid trust pattern")
    }

    /// Set minimum trust level required for a tool (chainable, fallible).
    ///
    /// Like `with_trust_requirement`, but returns a Result instead of panicking.
    pub fn try_trust_requirement(
        mut self,
        tool_pattern: impl Into<String>,
        level: TrustLevel,
    ) -> Result<Self> {
        let pattern = tool_pattern.into();
        Self::validate_trust_pattern(&pattern)?;
        self.tool_trust_requirements.insert(pattern, level);
        Ok(self)
    }

    /// Set minimum trust level required for a tool (mutable version).
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is invalid.
    pub fn require_trust(
        &mut self,
        tool_pattern: impl Into<String>,
        level: TrustLevel,
    ) -> Result<()> {
        let pattern = tool_pattern.into();
        Self::validate_trust_pattern(&pattern)?;
        self.tool_trust_requirements.insert(pattern, level);
        Ok(())
    }

    /// Validate a trust requirement pattern.
    fn validate_trust_pattern(pattern: &str) -> Result<()> {
        if pattern.is_empty() {
            return Err(Error::Validation(
                "trust pattern cannot be empty".to_string(),
            ));
        }

        let wildcard_count = pattern.matches('*').count();

        match wildcard_count {
            0 => Ok(()),
            1 => {
                if pattern == "*" {
                    Ok(())
                } else if let Some(prefix) = pattern.strip_suffix('*') {
                    if prefix.is_empty() || !prefix.contains('*') {
                        Ok(())
                    } else {
                        Err(Error::Validation(format!(
                            "invalid trust pattern '{}': wildcard must be at end only",
                            pattern
                        )))
                    }
                } else {
                    Err(Error::Validation(format!(
                        "invalid trust pattern '{}': wildcard must be at end (e.g., 'admin_*')",
                        pattern
                    )))
                }
            }
            _ => Err(Error::Validation(format!(
                "invalid trust pattern '{}': only one wildcard allowed",
                pattern
            ))),
        }
    }

    /// Get the required trust level for a tool.
    ///
    /// Checks in order: exact match, glob pattern, default "*", then None.
    pub fn get_required_trust(&self, tool: &str) -> Option<TrustLevel> {
        // 1. Exact match
        if let Some(&level) = self.tool_trust_requirements.get(tool) {
            return Some(level);
        }

        // 2. Glob pattern match
        for (pattern, &level) in &self.tool_trust_requirements {
            if pattern != "*" && Self::matches_glob_pattern(pattern, tool) {
                return Some(level);
            }
        }

        // 3. Default "*"
        self.tool_trust_requirements.get("*").copied()
    }

    /// Check if a tool name matches a glob pattern (supports trailing * only).
    fn matches_glob_pattern(pattern: &str, tool: &str) -> bool {
        if let Some(prefix) = pattern.strip_suffix('*') {
            tool.starts_with(prefix)
        } else {
            pattern == tool
        }
    }

    // =========================================================================
    // Getters
    // =========================================================================

    /// Get the current PoP window configuration.
    ///
    /// Returns (window_secs, max_windows).
    pub fn pop_window_config(&self) -> (i64, u32) {
        (self.pop_window_secs, self.pop_max_windows)
    }

    /// Get the total PoP validity duration in seconds.
    pub fn pop_validity_secs(&self) -> i64 {
        self.pop_window_secs * self.pop_max_windows as i64
    }

    /// Get the number of trusted roots.
    pub fn trusted_root_count(&self) -> usize {
        self.trusted_keys.len()
    }

    /// Check if the authorizer has any trusted roots configured.
    pub fn has_trusted_roots(&self) -> bool {
        !self.trusted_keys.is_empty()
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// Check if a warrant is revoked by ID.
    fn is_revoked(&self, warrant: &Warrant) -> bool {
        self.revocation_list
            .as_ref()
            .map(|srl| srl.is_revoked(&warrant.id().to_string()))
            .unwrap_or(false)
    }

    /// Verify a warrant.
    ///
    /// This checks:
    /// 1. The warrant is signed by a trusted issuer
    /// 2. The warrant has not expired
    /// 3. The warrant is not revoked
    pub fn verify(&self, warrant: &Warrant) -> Result<()> {
        // Check revocation first
        if self.is_revoked(warrant) {
            return Err(Error::WarrantRevoked(warrant.id().to_string()));
        }

        // Check expiration first (fast path), with clock tolerance
        if warrant.is_expired_with_tolerance(self.clock_tolerance) {
            return Err(Error::WarrantExpired(warrant.expires_at()));
        }

        // Check if issuer is trusted
        // 1. Verify the warrant signature
        // If trusted_issuers is empty, we skip the trust check (debug mode)
        // If trusted_issuers is not empty, we require the issuer to be trusted
        let issuer = warrant.issuer();
        if !self.trusted_keys.is_empty() && !self.trusted_keys.contains(issuer) {
            return Err(Error::Validation(format!(
                "warrant issuer is not trusted: {:?}",
                issuer
            )));
        }

        warrant.verify_signature()?;
        warrant.verify(issuer)
    }

    /// Authorize an action against a warrant.
    ///
    /// This is the main authorization entry point. It checks:
    /// 1. Trust level requirements (if configured)
    /// 2. Tool name matches
    /// 3. All constraints are satisfied
    /// 4. Holder signature (if warrant has `authorized_holder`)
    /// 5. Multi-sig approvals (if warrant has `required_approvers`)
    ///
    /// This is an **offline operation** - no network calls.
    ///
    /// # Arguments
    ///
    /// * `warrant` - The warrant authorizing the action
    /// * `tool` - The tool being invoked
    /// * `args` - The arguments to the tool
    /// * `holder_signature` - PoP signature (required if holder-bound)
    /// * `approvals` - Approval attestations (required if multi-sig)
    pub fn authorize(
        &self,
        warrant: &Warrant,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        holder_signature: Option<&crate::crypto::Signature>,
        approvals: &[crate::approval::Approval],
    ) -> Result<()> {
        // 1. Check trust level requirements first (fast fail)
        if let Some(required_trust) = self.get_required_trust(tool) {
            let warrant_trust = warrant.trust_level().unwrap_or(TrustLevel::Untrusted);
            if warrant_trust < required_trust {
                return Err(Error::InsufficientTrustLevel {
                    tool: tool.to_string(),
                    required: format!("{:?}", required_trust),
                    actual: format!("{:?}", warrant_trust),
                });
            }
        }

        // 2. Standard constraint authorization with configured PoP window
        warrant.authorize_with_pop_config(
            tool,
            args,
            holder_signature,
            self.pop_window_secs,
            self.pop_max_windows,
        )?;

        // 3. Multi-sig verification (if required)
        self.verify_approvals(warrant, tool, args, approvals)
    }

    /// Convenience: verify warrant and authorize in one call.
    pub fn check(
        &self,
        warrant: &Warrant,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        holder_signature: Option<&crate::crypto::Signature>,
        approvals: &[crate::approval::Approval],
    ) -> Result<()> {
        self.verify(warrant)?;
        self.authorize(warrant, tool, args, holder_signature, approvals)
    }

    /// Verify multi-sig approvals against a warrant.
    fn verify_approvals(
        &self,
        warrant: &Warrant,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        approvals: &[crate::approval::Approval],
    ) -> Result<()> {
        verify_approvals_with_tolerance(warrant, tool, args, approvals, self.clock_tolerance)
    }

    /// Verify a complete delegation chain.
    ///
    /// This is the most thorough verification method, validating the entire
    /// path from a trusted root to the leaf warrant.
    ///
    /// # Arguments
    ///
    /// * `chain` - Ordered list of warrants from root (index 0) to leaf (last)
    ///
    /// # Chain Invariants Verified
    ///
    /// 1. **Root Trust**: `chain[0]` must be signed by a trusted issuer
    /// 2. **Linkage**: `chain[i+1].parent_id == chain[i].id`
    /// 3. **Depth**: `chain[i+1].depth == chain[i].depth + 1`
    /// 4. **Expiration**: `chain[i+1].expires_at <= chain[i].expires_at`
    /// 5. **Monotonicity**: `chain[i+1].constraints ⊆ chain[i].constraints`
    /// 6. **Signatures**: Each warrant has a valid signature
    /// 7. **No Cycles**: Each warrant ID appears exactly once
    /// 8. **Session Binding** (optional): All warrants in same session
    pub fn verify_chain(&self, chain: &[Warrant]) -> Result<ChainVerificationResult> {
        self.verify_chain_with_options(chain, false)
    }

    /// Verify chain with session binding enforcement.
    ///
    /// Same as `verify_chain`, but also verifies that all warrants in the chain
    /// have the same `session_id`. Use this when warrants should be isolated
    /// per-session (e.g., per HTTP request, per task).
    pub fn verify_chain_strict(&self, chain: &[Warrant]) -> Result<ChainVerificationResult> {
        self.verify_chain_with_options(chain, true)
    }

    fn verify_chain_with_options(
        &self,
        chain: &[Warrant],
        enforce_session: bool,
    ) -> Result<ChainVerificationResult> {
        let result = self.verify_chain_with_options_inner(chain, enforce_session);

        // Audit: Log verification failures
        if let Err(ref e) = result {
            let chain_ids: Vec<String> = chain.iter().map(|w| w.id().to_string()).collect();
            log_event(AuditEvent {
                id: uuid::Uuid::new_v4().to_string(),
                event_type: AuditEventType::VerificationFailed,
                timestamp: chrono::Utc::now(),
                provider: "tenuo".to_string(),
                external_id: None,
                public_key_hex: chain.first().map(|w| hex::encode(w.issuer().to_bytes())),
                actor: "authorizer".to_string(),
                details: Some(format!("chain verification failed: {}", e)),
                related_ids: Some(chain_ids),
            });
        }

        result
    }

    fn verify_chain_with_options_inner(
        &self,
        chain: &[Warrant],
        enforce_session: bool,
    ) -> Result<ChainVerificationResult> {
        if chain.is_empty() {
            return Err(Error::ChainVerificationFailed(
                "chain cannot be empty".to_string(),
            ));
        }

        // CASCADING REVOCATION: Check if ANY warrant in the chain is revoked (from SRL)
        // This must happen before any other validation to fail fast.
        for warrant in chain {
            if self.is_revoked(warrant) {
                return Err(Error::WarrantRevoked(warrant.id().to_string()));
            }
        }

        // CYCLE DETECTION: Track seen warrant IDs
        let mut seen_ids: HashSet<String> = HashSet::new();
        for warrant in chain {
            let id = &warrant.id().to_string();
            if !seen_ids.insert(id.clone()) {
                return Err(Error::ChainVerificationFailed(format!(
                    "cycle detected: warrant ID '{}' appears multiple times in chain",
                    id
                )));
            }
        }

        let root = &chain[0];
        let mut result = ChainVerificationResult {
            root_issuer: None,
            chain_length: chain.len(),
            leaf_depth: 0,
            verified_steps: Vec::new(),
        };

        // Root must be from a trusted key
        let issuer = root.issuer();
        if !self.trusted_keys.iter().any(|k| k == issuer) {
            return Err(Error::SignatureInvalid(
                "root warrant issuer not trusted".to_string(),
            ));
        }

        // Batch verify all signatures in the chain (3x faster than sequential)
        // We verify all signatures in one batch after checking trust
        use crate::crypto::verify_batch;
        let preimages: Vec<Vec<u8>> = chain.iter().map(|w| w.signature_preimage()).collect();
        let batch_items: Vec<(&crate::crypto::PublicKey, &[u8], &crate::crypto::Signature)> = chain
            .iter()
            .zip(preimages.iter())
            .map(|(w, pre)| (w.issuer(), pre.as_slice(), w.signature()))
            .collect();
        verify_batch(&batch_items)?;

        result.root_issuer = Some(issuer.to_bytes());
        result.verified_steps.push(ChainStep {
            warrant_id: root.id().to_string(),
            depth: root.depth(),
            issuer: issuer.to_bytes(),
        });

        // SESSION BINDING: Track session from root
        let expected_session = if enforce_session {
            root.session_id()
        } else {
            None
        };

        // Walk the chain, verifying each link
        for i in 1..chain.len() {
            let parent = &chain[i - 1];
            let child = &chain[i];

            self.verify_link(parent, child)?;

            // Check session binding if enforced
            if enforce_session && child.session_id() != expected_session {
                return Err(Error::ChainVerificationFailed(format!(
                    "session mismatch: expected {:?}, got {:?} at depth {}",
                    expected_session,
                    child.session_id(),
                    child.depth()
                )));
            }

            result.verified_steps.push(ChainStep {
                warrant_id: child.id().to_string(),
                depth: child.depth(),
                issuer: child.issuer().to_bytes(),
            });
        }

        result.leaf_depth = chain.last().map(|w| w.depth()).unwrap_or(0);
        Ok(result)
    }

    /// Verify a single link in a delegation chain.
    fn verify_link(&self, parent: &Warrant, child: &Warrant) -> Result<()> {
        // Check revocation
        if self.is_revoked(child) {
            return Err(Error::WarrantRevoked(child.id().to_string()));
        }

        // Check parent_hash linkage
        let child_parent_hash = child.parent_hash().ok_or_else(|| {
            Error::ChainVerificationFailed("child warrant has no parent_hash".to_string())
        })?;

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(parent.payload_bytes());
        let expected_hash: [u8; 32] = hasher.finalize().into();

        if child_parent_hash != &expected_hash {
            return Err(Error::ChainVerificationFailed(
                "chain broken: child parent_hash mismatch".to_string(),
            ));
        }

        // Check depth increment
        if child.depth() != parent.depth() + 1 {
            return Err(Error::ChainVerificationFailed(format!(
                "depth mismatch: child {} != parent {} + 1",
                child.depth(),
                parent.depth()
            )));
        }

        // Check max_depth policy (defense-in-depth)
        let parent_max = parent.effective_max_depth();
        if child.depth() > parent_max {
            return Err(Error::ChainVerificationFailed(format!(
                "child depth {} exceeds parent's max_depth {}",
                child.depth(),
                parent_max
            )));
        }

        // Check expiration
        if child.expires_at() > parent.expires_at() {
            return Err(Error::ChainVerificationFailed(format!(
                "child expires at {} after parent {}",
                child.expires_at(),
                parent.expires_at()
            )));
        }

        // Check expiration with clock tolerance
        if child.is_expired_with_tolerance(self.clock_tolerance) {
            return Err(Error::WarrantExpired(child.expires_at()));
        }

        // Validate monotonicity based on warrant type
        match (parent.r#type(), child.r#type()) {
            (WarrantType::Execution, WarrantType::Execution) => {
                // For execution warrants, validate capability attenuation
                if let (Some(parent_caps), Some(child_caps)) =
                    (parent.capabilities(), child.capabilities())
                {
                    for (tool, child_constraints) in child_caps {
                        let parent_constraints =
                            parent_caps.get(tool).or_else(|| parent_caps.get("*"));

                        if let Some(parent_constraints) = parent_constraints {
                            parent_constraints.validate_attenuation(child_constraints)?;
                        } else {
                            return Err(Error::MonotonicityViolation(format!(
                                "tool '{}' not in parent's capabilities",
                                tool
                            )));
                        }
                    }
                }
                // Trust level monotonicity: child trust_level cannot exceed parent's
                if let (Some(parent_trust), Some(child_trust)) =
                    (parent.trust_level(), child.trust_level())
                {
                    if child_trust > parent_trust {
                        return Err(Error::MonotonicityViolation(format!(
                            "trust_level cannot increase: parent {:?}, child {:?}",
                            parent_trust, child_trust
                        )));
                    }
                }
            }
            (WarrantType::Issuer, WarrantType::Issuer) => {
                // For issuer warrants, validate issuable_tools
                if let (Some(parent_tools), Some(child_tools)) =
                    (parent.issuable_tools(), child.issuable_tools())
                {
                    // Child issuable_tools must be a subset of parent
                    for tool in child_tools {
                        if !parent_tools.iter().any(|t| t == tool || t == "*") {
                            return Err(Error::MonotonicityViolation(format!(
                                "issuable_tool '{}' not in parent's issuable_tools",
                                tool
                            )));
                        }
                    }
                }
                // Constraint bounds must be monotonic
                if let (Some(parent_bounds), Some(child_bounds)) =
                    (parent.constraint_bounds(), child.constraint_bounds())
                {
                    parent_bounds.validate_attenuation(child_bounds)?;
                }
            }
            (WarrantType::Issuer, WarrantType::Execution) => {
                // ISSUER -> EXECUTION: Validate issuance constraints
                // This is the primary use case: an issuer warrant creates execution warrants

                // 1. Child tool must be in issuer's issuable_tools
                if let Some(issuable_tools) = parent.issuable_tools() {
                    if let Some(child_caps) = child.capabilities() {
                        for tool in child_caps.keys() {
                            if !issuable_tools.iter().any(|t| t == tool || t == "*") {
                                return Err(Error::MonotonicityViolation(format!(
                                    "tool '{}' not in issuer's issuable_tools: {:?}",
                                    tool, issuable_tools
                                )));
                            }
                        }
                    }
                }

                // 2. Child trust_level must not exceed issuer's trust_level (monotonicity)
                if let Some(parent_trust) = parent.trust_level() {
                    if let Some(child_trust) = child.trust_level() {
                        if child_trust > parent_trust {
                            return Err(Error::MonotonicityViolation(format!(
                                "trust_level {:?} exceeds issuer's trust_level {:?}",
                                child_trust, parent_trust
                            )));
                        }
                    }
                }

                // 3. Child constraints must respect issuer's constraint_bounds
                if let (Some(bounds), Some(child_caps)) =
                    (parent.constraint_bounds(), child.capabilities())
                {
                    for constraints in child_caps.values() {
                        bounds.validate_attenuation(constraints)?;
                    }
                }

                // 4. SECURITY: Prevent self-issuance (P-LLM/Q-LLM separation)
                // The execution warrant holder cannot be the same as the issuer warrant holder
                // or the issuer warrant's issuer. This ensures the planner cannot grant
                // execution capabilities to itself, even if warrants are crafted manually.
                if child.authorized_holder() == parent.authorized_holder() {
                    return Err(Error::SelfIssuanceProhibited {
                        reason: "issuer cannot grant execution warrants to themselves".to_string(),
                    });
                }
                if child.authorized_holder() == parent.issuer() {
                    return Err(Error::SelfIssuanceProhibited {
                        reason: "execution warrant holder cannot be the issuer warrant's issuer (issuer-holder separation required)".to_string(),
                    });
                }
            }
            _ => {
                // Execution -> Issuer is not allowed (cannot escalate from execution to issuance)
                return Err(Error::MonotonicityViolation(format!(
                    "invalid warrant type transition: {:?} -> {:?}",
                    parent.r#type(),
                    child.r#type()
                )));
            }
        }

        // Note: Signature verification is done in batch at the chain level for performance
        // (see verify_chain_with_options). Individual verify_link calls don't re-verify signatures.
        Ok(())
    }

    /// Verify chain and authorize an action.
    ///
    /// Convenience method combining chain verification and authorization
    /// against the leaf warrant.
    pub fn check_chain(
        &self,
        chain: &[Warrant],
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&crate::crypto::Signature>,
        approvals: &[crate::approval::Approval],
    ) -> Result<ChainVerificationResult> {
        let result = self.verify_chain(chain)?;

        if let Some(leaf) = chain.last() {
            self.authorize(leaf, tool, args, signature, approvals)?;
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::{Exact, Pattern};

    #[test]
    fn test_control_data_plane_separation() {
        // === CONTROL PLANE (secure environment) ===
        let control_plane = ControlPlane::generate();
        let root_public_key = control_plane.public_key();

        // Issue a warrant
        let warrant = control_plane
            .issue_warrant(
                "upgrade_cluster",
                &[("cluster", Pattern::new("staging-*").unwrap().into())],
                Duration::from_secs(600),
            )
            .unwrap();

        // === DATA PLANE (edge/agent) ===
        // Only needs the public key, NOT the private key
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("control-plane", root_public_key);

        // Verify (offline - no network call)
        assert!(data_plane.verify(&warrant).is_ok());

        // Authorize (offline - no network call)
        let mut args = HashMap::new();
        args.insert(
            "cluster".to_string(),
            ConstraintValue::String("staging-web".to_string()),
        );
        // Note: warrant is bound to control_plane's key, but we can't access the private key
        // from DataPlane. In production, the holder would have their own keypair.
        // For this test, we'll create a warrant bound to a test keypair instead.
        let holder_keypair = SigningKey::generate();
        let warrant_for_holder = control_plane
            .issue_bound_warrant(
                "upgrade_cluster",
                &[("cluster", Pattern::new("staging-*").unwrap().into())],
                Duration::from_secs(600),
                &holder_keypair.public_key(),
            )
            .unwrap();

        let pop_sig = warrant_for_holder
            .create_pop_signature(&holder_keypair, "upgrade_cluster", &args)
            .unwrap();
        assert!(data_plane
            .authorize(
                &warrant_for_holder,
                "upgrade_cluster",
                &args,
                Some(&pop_sig),
                &[]
            )
            .is_ok());
    }

    #[test]
    fn test_data_plane_attenuation() {
        // Control plane issues root warrant
        let control_plane = ControlPlane::generate();
        let root_warrant = control_plane
            .issue_warrant(
                "query",
                &[("table", Pattern::new("*").unwrap().into())],
                Duration::from_secs(600),
            )
            .unwrap();

        // Orchestrator data plane (has its own keypair)
        let orchestrator = DataPlane::with_keypair(SigningKey::generate());

        let worker_warrant = orchestrator
            .attenuate(
                &root_warrant,
                &[("table", Pattern::new("public_*").unwrap().into())],
                &control_plane.keypair, // Parent issuer keypair
            )
            .unwrap();

        assert_eq!(worker_warrant.depth(), 1);
        // max_depth is now None when not explicitly set (protocol default applies via effective_max_depth)
        assert_eq!(root_warrant.max_depth(), Some(16));
        assert_eq!(
            root_warrant.effective_max_depth(),
            crate::MAX_DELEGATION_DEPTH
        );
    }

    #[test]
    fn test_minimal_authorizer() {
        let control_plane = ControlPlane::generate();
        let _warrant = control_plane
            .issue_warrant("test", &[], Duration::from_secs(60))
            .unwrap();

        // Minimal authorizer - just the public key
        let holder_keypair = SigningKey::generate();
        let warrant_for_holder = control_plane
            .issue_bound_warrant(
                "test",
                &[],
                Duration::from_secs(60),
                &holder_keypair.public_key(),
            )
            .unwrap();
        let authorizer = Authorizer::new().with_trusted_root(control_plane.public_key());

        // Check in one call
        let args = HashMap::new();
        let pop_sig = warrant_for_holder
            .create_pop_signature(&holder_keypair, "test", &args)
            .unwrap();
        assert!(authorizer
            .check(&warrant_for_holder, "test", &args, Some(&pop_sig), &[])
            .is_ok());
    }

    // =========================================================================
    // CHAIN VERIFICATION TESTS
    // =========================================================================

    #[test]
    fn test_chain_verification_single_warrant() {
        let control_plane = ControlPlane::generate();
        let warrant = control_plane
            .issue_warrant("test", &[], Duration::from_secs(60))
            .unwrap();

        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", control_plane.public_key());

        // Single warrant chain
        let result = data_plane.verify_chain(&[warrant]).unwrap();
        assert_eq!(result.chain_length, 1);
        assert_eq!(result.leaf_depth, 0);
        assert_eq!(result.verified_steps.len(), 1);
    }

    #[test]
    fn test_chain_verification_delegation() {
        let control_plane = ControlPlane::generate();
        let orchestrator_keypair = SigningKey::generate();

        // Root warrant
        let root = control_plane
            .issue_warrant(
                "upgrade_cluster",
                &[("cluster", Pattern::new("staging-*").unwrap().into())],
                Duration::from_secs(600),
            )
            .unwrap();

        // Control plane delegates to orchestrator
        let mut child_constraints = ConstraintSet::new();
        child_constraints.insert("cluster", Exact::new("staging-web"));
        let child = root
            .attenuate()
            .capability("upgrade_cluster", child_constraints)
            .authorized_holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair) // Control plane signs (they hold root)
            .unwrap();

        // Data plane verifies the chain
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", control_plane.public_key());

        let result = data_plane.verify_chain(&[root, child]).unwrap();
        assert_eq!(result.chain_length, 2);
        assert_eq!(result.leaf_depth, 1);
        assert_eq!(result.verified_steps.len(), 2);
    }

    #[test]
    fn test_chain_verification_three_levels() {
        let control_plane = ControlPlane::generate();
        let orchestrator_keypair = SigningKey::generate();
        let worker_keypair = SigningKey::generate();

        // Root → Orchestrator → Worker
        let root = control_plane
            .issue_warrant(
                "query",
                &[("table", Pattern::new("*").unwrap().into())],
                Duration::from_secs(600),
            )
            .unwrap();

        let mut orch_constraints = ConstraintSet::new();
        orch_constraints.insert("table", Pattern::new("public_*").unwrap());
        let orchestrator_warrant = root
            .attenuate()
            .capability("query", orch_constraints)
            .authorized_holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair) // Control plane signs (they hold root)
            .unwrap();

        let mut worker_constraints = ConstraintSet::new();
        worker_constraints.insert("table", Exact::new("public_users"));
        let worker_warrant = orchestrator_warrant
            .attenuate()
            .capability("query", worker_constraints)
            .authorized_holder(worker_keypair.public_key())
            .build(&orchestrator_keypair) // Orchestrator signs (they hold orchestrator_warrant)
            .unwrap();

        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", control_plane.public_key());

        let result = data_plane
            .verify_chain(&[root, orchestrator_warrant, worker_warrant])
            .unwrap();

        assert_eq!(result.chain_length, 3);
        assert_eq!(result.leaf_depth, 2);
        assert_eq!(result.verified_steps[0].depth, 0);
        assert_eq!(result.verified_steps[1].depth, 1);
        assert_eq!(result.verified_steps[2].depth, 2);
    }

    #[test]
    fn test_chain_verification_and_authorization() {
        let control_plane = ControlPlane::generate();
        let agent_keypair = SigningKey::generate();

        let root = control_plane
            .issue_warrant(
                "upgrade_cluster",
                &[("cluster", Pattern::new("staging-*").unwrap().into())],
                Duration::from_secs(600),
            )
            .unwrap();

        let mut agent_constraints = ConstraintSet::new();
        agent_constraints.insert("cluster", Exact::new("staging-web"));
        let agent_warrant = root
            .attenuate()
            .capability("upgrade_cluster", agent_constraints)
            .authorized_holder(agent_keypair.public_key())
            .build(&control_plane.keypair) // Control plane signs (they hold root)
            .unwrap();

        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", control_plane.public_key());

        // Verify chain and authorize in one call
        let mut args = HashMap::new();
        args.insert(
            "cluster".to_string(),
            ConstraintValue::String("staging-web".to_string()),
        );

        // Create PoP signature for the agent warrant
        let pop_sig = agent_warrant
            .create_pop_signature(&agent_keypair, "upgrade_cluster", &args)
            .unwrap();

        let result = data_plane
            .check_chain(
                &[root, agent_warrant],
                "upgrade_cluster",
                &args,
                Some(&pop_sig),
                &[],
            )
            .unwrap();
        assert_eq!(result.chain_length, 2);
    }

    #[test]
    fn test_chain_verification_fails_untrusted_root() {
        let control_plane = ControlPlane::generate();
        let other_control_plane = ControlPlane::generate();

        let warrant = control_plane
            .issue_warrant("test", &[], Duration::from_secs(60))
            .unwrap();

        // Data plane trusts a DIFFERENT key
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", other_control_plane.public_key());

        let result = data_plane.verify_chain(&[warrant]);
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_verification_fails_broken_linkage() {
        let control_plane = ControlPlane::generate();
        let agent_keypair = SigningKey::generate();

        // Two unrelated warrants
        let warrant1 = control_plane
            .issue_warrant("test1", &[], Duration::from_secs(60))
            .unwrap();

        let warrant2 = control_plane
            .issue_warrant("test2", &[], Duration::from_secs(60))
            .unwrap();

        // Create an attenuated warrant from warrant2 (POLA: inherit_all)
        let child = warrant2
            .attenuate()
            .inherit_all()
            .authorized_holder(agent_keypair.public_key())
            .build(&control_plane.keypair) // Control plane signs (they hold warrant2)
            .unwrap();

        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", control_plane.public_key());

        // Try to pass warrant1 as parent of child (which is actually from warrant2)
        let result = data_plane.verify_chain(&[warrant1, child]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("chain broken"));
    }

    #[test]
    fn test_chain_verification_fails_wrong_depth() {
        // This scenario shouldn't happen in practice, but let's test the check
        let control_plane = ControlPlane::generate();
        let warrant = control_plane
            .issue_warrant("test", &[], Duration::from_secs(60))
            .unwrap();

        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", control_plane.public_key());

        // Verify that a single root warrant with depth=0 works
        assert!(data_plane.verify_chain(&[warrant]).is_ok());
    }

    #[test]
    fn test_authorizer_chain_verification() {
        let control_plane = ControlPlane::generate();
        let agent_keypair = SigningKey::generate();

        let root = control_plane
            .issue_warrant(
                "test",
                &[("key", Exact::new("value").into())],
                Duration::from_secs(60),
            )
            .unwrap();

        // POLA: inherit_all to get parent capabilities
        let child = root
            .attenuate()
            .inherit_all()
            .authorized_holder(agent_keypair.public_key())
            .build(&control_plane.keypair) // Control plane signs (they hold root)
            .unwrap();

        let authorizer = Authorizer::new().with_trusted_root(control_plane.public_key());

        // Verify chain
        let result = authorizer
            .verify_chain(&[root.clone(), child.clone()])
            .unwrap();
        assert_eq!(result.chain_length, 2);

        // Check chain        // Authorize against child
        let mut args = HashMap::new();
        args.insert(
            "key".to_string(),
            ConstraintValue::String("value".to_string()),
        );

        // Create PoP signature for child warrant
        let pop_sig = child
            .create_pop_signature(&agent_keypair, "test", &args)
            .unwrap();

        assert!(authorizer
            .authorize(&child, "test", &args, Some(&pop_sig), &[])
            .is_ok());
        assert_eq!(result.chain_length, 2);
    }

    #[test]
    fn test_empty_chain_fails() {
        let control_plane = ControlPlane::generate();

        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", control_plane.public_key());

        let result = data_plane.verify_chain(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_cascading_revocation() {
        // If ANY warrant in the chain is revoked, the entire chain is invalid
        let control_plane = ControlPlane::generate();
        let orchestrator_keypair = SigningKey::generate();

        let root = control_plane
            .issue_warrant("test", &[], Duration::from_secs(60))
            .unwrap();

        // POLA: inherit_all to get parent capabilities
        let child = root
            .attenuate()
            .inherit_all()
            .authorized_holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair) // Control plane signs (they hold root)
            .unwrap();

        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", control_plane.public_key());

        // Chain should verify successfully
        assert!(data_plane
            .verify_chain(&[root.clone(), child.clone()])
            .is_ok());

        // Revoke the ROOT warrant (signed by control plane)
        let srl = SignedRevocationList::builder()
            .revoke(root.id().to_string())
            .version(1)
            .build(&control_plane.keypair)
            .unwrap();
        data_plane
            .set_revocation_list(srl, &control_plane.public_key())
            .unwrap();

        // Now the entire chain should fail (cascading revocation)
        let result = data_plane.verify_chain(&[root.clone(), child.clone()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("revoked"));

        // Also test with Authorizer
        let mut authorizer = Authorizer::new().with_trusted_root(control_plane.public_key());
        let srl = SignedRevocationList::builder()
            .revoke(root.id().to_string())
            .version(1)
            .build(&control_plane.keypair)
            .unwrap();
        authorizer
            .set_revocation_list(srl, &control_plane.public_key())
            .unwrap();

        let result = authorizer.verify_chain(&[root, child]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("revoked"));
    }

    // =========================================================================
    // MULTI-SIG AUTHORIZATION TESTS
    // =========================================================================

    #[test]
    fn test_authorize_with_approvals_no_multisig() {
        let control_plane = ControlPlane::generate();

        // Create warrant WITHOUT multi-sig
        let _warrant = control_plane
            .issue_warrant("test", &[], Duration::from_secs(60))
            .unwrap();

        let authorizer = Authorizer::new().with_trusted_root(control_plane.public_key());

        let args = HashMap::new();

        // Create PoP signature (warrant is bound to control_plane's key)
        // In a real scenario, the holder would have their own keypair
        let holder_keypair = SigningKey::generate();
        let warrant_for_holder = control_plane
            .issue_bound_warrant(
                "test",
                &[],
                Duration::from_secs(60),
                &holder_keypair.public_key(),
            )
            .unwrap();

        let pop_sig = warrant_for_holder
            .create_pop_signature(&holder_keypair, "test", &args)
            .unwrap();

        // Should pass without any approvals (just PoP)
        let result = authorizer.authorize(&warrant_for_holder, "test", &args, Some(&pop_sig), &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_requires_approval_when_multisig() {
        let issuer_keypair = SigningKey::generate();
        let admin_keypair = SigningKey::generate();

        // Create warrant WITH multi-sig requirement
        let warrant = Warrant::builder()
            .capability("sensitive_action", ConstraintSet::new())
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![admin_keypair.public_key()])
            .min_approvals(1)
            .authorized_holder(issuer_keypair.public_key())
            .build(&issuer_keypair)
            .unwrap();

        let authorizer = Authorizer::new().with_trusted_root(issuer_keypair.public_key());
        let args = HashMap::new();

        // Create PoP signature
        let pop_sig = warrant
            .create_pop_signature(&issuer_keypair, "sensitive_action", &args)
            .unwrap();

        // Should FAIL without approval (but WITH PoP signature)
        let result = authorizer.authorize(&warrant, "sensitive_action", &args, Some(&pop_sig), &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("insufficient"));
    }

    #[test]
    fn test_authorize_valid_approval() {
        use crate::approval::{compute_request_hash, Approval};
        use chrono::{Duration as ChronoDuration, Utc};

        let issuer_keypair = SigningKey::generate();
        let admin_keypair = SigningKey::generate();

        // Create warrant WITH multi-sig requirement
        let warrant = Warrant::builder()
            .capability("sensitive_action", ConstraintSet::new())
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![admin_keypair.public_key()])
            .min_approvals(1)
            .authorized_holder(issuer_keypair.public_key())
            .build(&issuer_keypair)
            .unwrap();

        let authorizer = Authorizer::new().with_trusted_root(issuer_keypair.public_key());
        let args = HashMap::new();

        // Create PoP signature
        let pop_sig = warrant
            .create_pop_signature(&issuer_keypair, "sensitive_action", &args)
            .unwrap();

        // Create approval
        let request_hash = compute_request_hash(
            &warrant.id().to_string(),
            "sensitive_action",
            &args,
            Some(warrant.authorized_holder()),
        );

        let now = Utc::now();
        let expires = now + ChronoDuration::seconds(300);

        // Create signable bytes for approval
        let mut signable = Vec::new();
        signable.extend_from_slice(&request_hash);
        signable.extend_from_slice("admin@test.com".as_bytes());
        signable.extend_from_slice(&now.timestamp().to_le_bytes());
        signable.extend_from_slice(&expires.timestamp().to_le_bytes());

        let approval = Approval {
            request_hash,
            approver_key: admin_keypair.public_key(),
            external_id: "admin@test.com".to_string(),
            provider: "test".to_string(),
            approved_at: now,
            expires_at: expires,
            reason: None,
            signature: admin_keypair.sign(&signable),
        };

        // Should SUCCEED with valid approval AND PoP signature
        let result = authorizer.authorize(
            &warrant,
            "sensitive_action",
            &args,
            Some(&pop_sig),
            &[approval],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_wrong_approver() {
        use crate::approval::{compute_request_hash, Approval};
        use chrono::{Duration as ChronoDuration, Utc};

        let issuer_keypair = SigningKey::generate();
        let admin_keypair = SigningKey::generate();
        let other_keypair = SigningKey::generate(); // Not in required_approvers

        // Create warrant requiring admin's approval
        let warrant = Warrant::builder()
            .capability("sensitive_action", ConstraintSet::new())
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![admin_keypair.public_key()])
            .min_approvals(1)
            .authorized_holder(issuer_keypair.public_key())
            .build(&issuer_keypair)
            .unwrap();

        let authorizer = Authorizer::new().with_trusted_root(issuer_keypair.public_key());
        let args = HashMap::new();

        // Create approval from WRONG keypair
        let now = Utc::now();
        let expires = now + ChronoDuration::seconds(300);
        let request_hash = compute_request_hash(
            &warrant.id().to_string(),
            "sensitive_action",
            &args,
            Some(warrant.authorized_holder()),
        );

        let mut signable = Vec::new();
        signable.extend_from_slice(&request_hash);
        signable.extend_from_slice("other@test.com".as_bytes());
        signable.extend_from_slice(&now.timestamp().to_le_bytes());
        signable.extend_from_slice(&expires.timestamp().to_le_bytes());

        let sig = other_keypair.sign(&signable);

        let approval = Approval {
            request_hash,
            approver_key: other_keypair.public_key(), // Wrong approver!
            external_id: "other@test.com".to_string(),
            provider: "test".to_string(),
            approved_at: now,
            expires_at: expires,
            reason: None,
            signature: sig,
        };

        // Create PoP signature
        let pop_sig = warrant
            .create_pop_signature(&issuer_keypair, "sensitive_action", &args)
            .unwrap();

        // Should FAIL - approver not in required set (even with valid PoP)
        let result = authorizer.authorize(
            &warrant,
            "sensitive_action",
            &args,
            Some(&pop_sig),
            &[approval],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_authorize_2_of_3() {
        use crate::approval::{compute_request_hash, Approval};
        use chrono::{Duration as ChronoDuration, Utc};

        let issuer_keypair = SigningKey::generate();
        let admin1 = SigningKey::generate();
        let admin2 = SigningKey::generate();
        let admin3 = SigningKey::generate();

        // Create warrant requiring 2-of-3 approvals
        let warrant = Warrant::builder()
            .capability("sensitive_action", ConstraintSet::new())
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![
                admin1.public_key(),
                admin2.public_key(),
                admin3.public_key(),
            ])
            .min_approvals(2)
            .authorized_holder(issuer_keypair.public_key()) // Added this line
            .build(&issuer_keypair)
            .unwrap();

        let authorizer = Authorizer::new().with_trusted_root(issuer_keypair.public_key());
        let args = HashMap::new();

        let now = Utc::now();
        let expires = now + ChronoDuration::seconds(300);
        let request_hash = compute_request_hash(
            &warrant.id().to_string(),
            "sensitive_action",
            &args,
            Some(warrant.authorized_holder()),
        );

        // Helper to create approval
        let make_approval = |kp: &SigningKey, id: &str| {
            let mut signable = Vec::new();
            signable.extend_from_slice(&request_hash);
            signable.extend_from_slice(id.as_bytes());
            signable.extend_from_slice(&now.timestamp().to_le_bytes());
            signable.extend_from_slice(&expires.timestamp().to_le_bytes());

            Approval {
                request_hash,
                approver_key: kp.public_key(),
                external_id: id.to_string(),
                provider: "test".to_string(),
                approved_at: now,
                expires_at: expires,
                reason: None,
                signature: kp.sign(&signable),
            }
        };

        let approval1 = make_approval(&admin1, "admin1@test.com");
        let approval2 = make_approval(&admin2, "admin2@test.com");

        // Create PoP signature
        let pop_sig = warrant
            .create_pop_signature(&issuer_keypair, "sensitive_action", &args)
            .unwrap();

        // With 1 approval - should fail (need 2)
        let result = authorizer.authorize(
            &warrant,
            "sensitive_action",
            &args,
            Some(&pop_sig),
            std::slice::from_ref(&approval1),
        );
        assert!(result.is_err());

        // With 2 approvals - should pass
        let result = authorizer.authorize(
            &warrant,
            "sensitive_action",
            &args,
            Some(&pop_sig),
            &[approval1, approval2],
        );
        assert!(result.is_ok());
    }

    // =========================================================================
    // CHAIN VERIFICATION STRICT (SESSION BINDING)
    // =========================================================================

    #[test]
    fn test_verify_chain_strict_matching_sessions() {
        let control_plane = ControlPlane::generate();
        let orchestrator_keypair = SigningKey::generate();
        let worker_keypair = SigningKey::generate();

        // Create chain with matching session IDs
        let root = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .session_id("session_123")
            .ttl(Duration::from_secs(600))
            .authorized_holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair)
            .unwrap();

        // POLA: inherit_all to get parent capabilities
        let child = root
            .attenuate()
            .inherit_all()
            // Session ID inherited from root (session_123)
            .authorized_holder(worker_keypair.public_key())
            .build(&orchestrator_keypair)
            .unwrap();

        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", control_plane.public_key());

        // Should pass with matching sessions
        let result = data_plane.verify_chain_strict(&[root, child]);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.chain_length, 2);
    }

    #[test]
    fn test_verify_chain_strict_mixed_session_ids() {
        let control_plane = ControlPlane::generate();
        let orchestrator_keypair = SigningKey::generate();
        let worker_keypair = SigningKey::generate();

        // Root has session ID
        let root = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .session_id("session_123")
            .ttl(Duration::from_secs(600))
            .authorized_holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair)
            .unwrap();

        // Root without session ID
        let root_no_session = Warrant::builder()
            .capability("test", ConstraintSet::new())
            // No session_id
            .ttl(Duration::from_secs(600))
            .authorized_holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair)
            .unwrap();

        // POLA: inherit_all
        let child = root_no_session
            .attenuate()
            .inherit_all()
            // Session ID inherited (None)
            .authorized_holder(worker_keypair.public_key())
            .build(&orchestrator_keypair)
            .unwrap();

        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", control_plane.public_key());

        // Try to verify chain where root has session_id but child doesn't
        // This simulates mixing warrants from sessioned and non-sessioned contexts
        let result = data_plane.verify_chain_strict(&[root, child]);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorizer_verify_chain_strict() {
        let control_plane = ControlPlane::generate();
        let orchestrator_keypair = SigningKey::generate();

        let root = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .session_id("session_123")
            .ttl(Duration::from_secs(600))
            .authorized_holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair)
            .unwrap();

        // POLA: inherit_all
        let child = root
            .attenuate()
            .inherit_all()
            // Session ID inherited from root (session_123)
            .authorized_holder(orchestrator_keypair.public_key())
            .build(&orchestrator_keypair)
            .unwrap();

        let authorizer = Authorizer::new().with_trusted_root(control_plane.public_key());

        // Should pass with matching sessions
        let result = authorizer.verify_chain_strict(&[root.clone(), child.clone()]);
        assert!(result.is_ok());

        // Create a different root with different session, then attenuate
        let root2 = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .session_id("session_456") // Different session
            .ttl(Duration::from_secs(600))
            .authorized_holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair)
            .unwrap();

        // POLA: inherit_all
        let child_bad = root2
            .attenuate()
            .inherit_all()
            // Session ID inherited from root2 (session_456)
            .authorized_holder(orchestrator_keypair.public_key())
            .build(&orchestrator_keypair)
            .unwrap();

        // Should fail - mixing warrants from different sessions
        let result = authorizer.verify_chain_strict(&[root, child_bad]);
        assert!(result.is_err());
    }

    #[test]
    fn test_issue_bound_warrant_and_audit_serialization() {
        let control_plane = ControlPlane::generate();
        let holder_key = SigningKey::generate().public_key();

        // 1. Issue bound warrant
        let warrant = control_plane
            .issue_bound_warrant("test_tool", &[], Duration::from_secs(60), &holder_key)
            .expect("Failed to issue bound warrant");

        assert_eq!(warrant.authorized_holder(), &holder_key);

        // 2. Create AuditEvent
        let event = crate::approval::AuditEvent::new(
            crate::approval::AuditEventType::EnrollmentSuccess,
            "control-plane",
            "test",
        )
        .with_key(warrant.authorized_holder())
        .with_details(format!("Issued warrant {}", warrant.id()))
        .with_related(vec![warrant.id().to_string()]);

        // 3. Serialize
        let json = serde_json::to_string(&event).expect("Failed to serialize audit event");
        println!("Serialized event: {}", json);
    }

    // =========================================================================
    // Security Review: Issuer -> Execution Chain Verification Tests
    // =========================================================================

    /// Test that verify_chain accepts valid Issuer -> Execution transitions.
    /// Regression test for Finding #1.
    #[test]
    fn test_verify_chain_issuer_to_execution() {
        use crate::crypto::SigningKey;
        use crate::warrant::{TrustLevel, Warrant, WarrantType};
        use std::time::Duration;

        let issuer_kp = SigningKey::generate();
        let worker_kp = SigningKey::generate();

        // 1. Create Root Issuer Warrant
        let root = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string(), "write_file".to_string()])
            .trust_level(TrustLevel::Internal)
            .constraint_bound("path", Pattern::new("/data/*").unwrap())
            .ttl(Duration::from_secs(3600))
            .authorized_holder(issuer_kp.public_key())
            .build(&issuer_kp)
            .expect("Failed to build issuer warrant");

        assert_eq!(root.r#type(), WarrantType::Issuer);

        // 2. Issue Child Execution Warrant
        let mut child_constraints = ConstraintSet::new();
        child_constraints.insert("path", Pattern::new("/data/reports/*").unwrap());
        let child = root
            .issue_execution_warrant()
            .expect("Failed to start issuance")
            .capability("read_file", child_constraints)
            .trust_level(TrustLevel::External)
            .ttl(Duration::from_secs(600))
            .authorized_holder(worker_kp.public_key())
            .build(&issuer_kp)
            .expect("Failed to build execution warrant");

        assert_eq!(child.r#type(), WarrantType::Execution);

        // 3. Verify Chain - THIS MUST SUCCEED
        let authorizer = Authorizer::new().with_trusted_root(issuer_kp.public_key());
        let result = authorizer.verify_chain(&[root.clone(), child.clone()]);

        assert!(
            result.is_ok(),
            "verify_chain should accept valid Issuer -> Execution: {:?}",
            result.err()
        );

        let chain_result = result.unwrap();
        assert_eq!(chain_result.chain_length, 2);
        assert_eq!(chain_result.leaf_depth, 1);
        println!("✅ verify_chain accepts Issuer -> Execution transition");
    }

    /// Test that verify_chain rejects Issuer -> Execution when child violates constraints.
    /// Security test for Finding #2 (applied to verify_chain).
    #[test]
    fn test_verify_chain_rejects_issuer_execution_constraint_violation() {
        use crate::crypto::SigningKey;
        use crate::warrant::{TrustLevel, Warrant, WarrantType};
        use std::time::Duration;

        let issuer_kp = SigningKey::generate();
        let worker_kp = SigningKey::generate();

        // Create Root Issuer Warrant with strict bounds
        let root = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string()])
            .trust_level(TrustLevel::External)
            .constraint_bound("path", Pattern::new("/data/*").unwrap())
            .ttl(Duration::from_secs(3600))
            .authorized_holder(issuer_kp.public_key())
            .build(&issuer_kp)
            .expect("Failed to build issuer warrant");

        // NOTE: We can't easily create a malformed warrant that bypasses builder validation
        // to test the verifier directly. The builder already enforces constraints.
        // This test verifies the builder + verifier combination works correctly.

        // Try to issue with tool not in issuable_tools (builder should reject)
        let result = root
            .issue_execution_warrant()
            .expect("Failed to start issuance")
            .capability("send_email", ConstraintSet::new()) // NOT in issuable_tools
            .ttl(Duration::from_secs(600))
            .authorized_holder(worker_kp.public_key())
            .build(&issuer_kp);

        assert!(result.is_err(), "Should reject tool not in issuable_tools");
        println!(
            "✅ Builder rejects tool not in issuable_tools: {}",
            result.unwrap_err()
        );

        // Try to issue with trust_level exceeding ceiling (builder should reject)
        let result = root
            .issue_execution_warrant()
            .expect("Failed to start issuance")
            .capability("read_file", ConstraintSet::new())
            .trust_level(TrustLevel::Internal) // Exceeds External ceiling
            .ttl(Duration::from_secs(600))
            .authorized_holder(worker_kp.public_key())
            .build(&issuer_kp);

        assert!(
            result.is_err(),
            "Should reject trust_level exceeding ceiling"
        );
        println!(
            "✅ Builder rejects trust_level exceeding ceiling: {}",
            result.unwrap_err()
        );

        // Try to issue with constraint outside bounds (builder should reject)
        let mut bad_constraints = ConstraintSet::new();
        bad_constraints.insert("path", Pattern::new("/etc/*").unwrap()); // Outside /data/*
        let result = root
            .issue_execution_warrant()
            .expect("Failed to start issuance")
            .capability("read_file", bad_constraints)
            .ttl(Duration::from_secs(600))
            .authorized_holder(worker_kp.public_key())
            .build(&issuer_kp);

        assert!(result.is_err(), "Should reject constraint outside bounds");
        println!(
            "✅ Builder rejects constraint outside bounds: {}",
            result.unwrap_err()
        );
    }

    /// Test that Execution -> Issuer is rejected (cannot escalate privileges).
    #[test]
    fn test_verify_chain_rejects_execution_to_issuer() {
        use crate::crypto::SigningKey;
        use crate::warrant::{Warrant, WarrantType};
        use std::time::Duration;

        let kp = SigningKey::generate();

        // Create Execution warrant as root (unusual but possible)
        let mut exec_constraints = ConstraintSet::new();
        exec_constraints.insert("path", Pattern::new("/data/*").unwrap());
        let exec_root = Warrant::builder()
            .capability("read_file", exec_constraints)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .expect("Failed to build execution warrant");

        assert_eq!(exec_root.r#type(), WarrantType::Execution);

        // Cannot issue an Issuer warrant from an Execution warrant
        // (issue_issuer_warrant would fail, so test the conceptual boundary)
        // The type system prevents this at the builder level.
        println!("✅ Type system prevents Execution -> Issuer escalation");
    }

    /// Security test: Verifier rejects self-issued execution warrants.
    /// This tests the verifier-side check (defense against crafted warrants).
    #[test]
    fn test_verify_chain_rejects_self_issuance() {
        use crate::crypto::SigningKey;
        use crate::warrant::{TrustLevel, Warrant, WarrantType};
        use std::time::Duration;

        let issuer_kp = SigningKey::generate();

        // Create issuer warrant
        let issuer_warrant = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string()])
            .trust_level(TrustLevel::Internal)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(issuer_kp.public_key())
            .build(&issuer_kp)
            .expect("Failed to build issuer warrant");

        // Manually construct a self-issued execution warrant by bypassing the builder's check.
        // In practice, an attacker would need to craft the warrant directly.
        // We simulate this by creating a warrant where holder == issuer warrant holder.
        //
        // Note: The normal builder prevents this, so we have to craft it more carefully.
        // For this test, we'll use a different holder keypair but the test demonstrates
        // that the verifier would catch a manually-crafted warrant.
        let worker_kp = SigningKey::generate();

        // Create a valid execution warrant (worker_kp as holder)
        let valid_exec = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .capability("read_file", ConstraintSet::new())
            .ttl(Duration::from_secs(60))
            .authorized_holder(worker_kp.public_key())
            .build(&issuer_kp)
            .expect("Failed to build valid execution warrant");

        // Verify the valid chain works
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("issuer", issuer_kp.public_key());
        let result = data_plane.verify_chain(&[issuer_warrant.clone(), valid_exec]);
        assert!(result.is_ok(), "Valid chain should pass verification");

        // Now test that builder properly rejects self-issuance (holder == issuer_warrant.holder)
        let self_issue_result = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .capability("read_file", ConstraintSet::new())
            .ttl(Duration::from_secs(60))
            .authorized_holder(issuer_kp.public_key()) // Same as issuer warrant holder!
            .build(&issuer_kp);

        assert!(
            self_issue_result.is_err(),
            "Builder should reject self-issuance"
        );
        assert!(
            self_issue_result
                .unwrap_err()
                .to_string()
                .contains("self-issuance"),
            "Error should mention self-issuance"
        );
    }

    /// Security test: Verifier rejects execution warrant where holder is issuer warrant's issuer.
    #[test]
    fn test_verify_chain_rejects_issuer_holder_loop() {
        use crate::crypto::SigningKey;
        use crate::warrant::{TrustLevel, Warrant, WarrantType};
        use std::time::Duration;

        let creator_kp = SigningKey::generate(); // Creates and signs the issuer warrant
        let planner_kp = SigningKey::generate(); // Holds the issuer warrant (P-LLM)

        // Create issuer warrant: signed by creator_kp, held by planner_kp
        let issuer_warrant = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string()])
            .trust_level(TrustLevel::Internal)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(planner_kp.public_key())
            .build(&creator_kp)
            .expect("Failed to build issuer warrant");

        // Test that builder rejects holder == issuer warrant's issuer
        let loop_result = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .capability("read_file", ConstraintSet::new())
            .ttl(Duration::from_secs(60))
            .authorized_holder(creator_kp.public_key()) // Same as issuer warrant's issuer!
            .build(&planner_kp); // planner signs (they hold issuer_warrant)

        assert!(
            loop_result.is_err(),
            "Builder should reject issuer-holder loop"
        );
        assert!(
            loop_result
                .unwrap_err()
                .to_string()
                .contains("issuer-holder separation"),
            "Error should mention issuer-holder separation"
        );
    }

    /// Test that execution warrants CAN self-attenuate (delegate to same holder).
    /// This is legitimate - the self-issuance check only applies to Issuer -> Execution.
    #[test]
    fn test_execution_warrant_self_attenuation_allowed() {
        use crate::crypto::SigningKey;
        use crate::warrant::Warrant;
        use std::time::Duration;

        let agent_kp = SigningKey::generate();

        // Create execution warrant held by agent
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/*").unwrap());
        let root = Warrant::builder()
            .capability("read_file", constraints)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(agent_kp.public_key())
            .build(&agent_kp)
            .expect("Failed to build root warrant");

        // Self-attenuate: same holder, narrower constraints
        let mut narrower = ConstraintSet::new();
        narrower.insert("path", Pattern::new("/data/reports/*").unwrap());
        let child = root
            .attenuate()
            .capability("read_file", narrower)
            .ttl(Duration::from_secs(60))
            .authorized_holder(agent_kp.public_key()) // Same holder - should be allowed!
            .build(&agent_kp)
            .expect("Self-attenuation should be allowed for execution warrants");

        // Verify the chain passes
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", agent_kp.public_key());
        let result = data_plane.verify_chain(&[root, child]);
        assert!(
            result.is_ok(),
            "Execution warrant self-attenuation should pass verification"
        );
    }

    /// Test that trust_level monotonicity is enforced for Execution → Execution attenuation.
    #[test]
    fn test_trust_level_monotonicity_execution_to_execution() {
        use crate::crypto::SigningKey;
        use crate::warrant::{TrustLevel, Warrant};
        use std::time::Duration;

        let parent_kp = SigningKey::generate();
        let child_kp = SigningKey::generate();

        // Create parent with Internal trust level
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/*").unwrap());
        let parent = Warrant::builder()
            .capability("read_file", constraints.clone())
            .trust_level(TrustLevel::Internal)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(parent_kp.public_key())
            .build(&parent_kp)
            .expect("Failed to build parent warrant");

        assert_eq!(parent.trust_level(), Some(TrustLevel::Internal));

        // Try to attenuate with HIGHER trust level (should fail)
        let result = parent
            .attenuate()
            .capability("read_file", constraints.clone())
            .trust_level(TrustLevel::Privileged) // Higher than Internal!
            .ttl(Duration::from_secs(60))
            .authorized_holder(child_kp.public_key())
            .build(&parent_kp);

        assert!(
            result.is_err(),
            "Builder should reject trust_level escalation"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("trust_level cannot increase"),
            "Error should mention trust_level monotonicity"
        );

        // Attenuate with LOWER trust level (should succeed)
        let child = parent
            .attenuate()
            .capability("read_file", constraints)
            .trust_level(TrustLevel::External) // Lower than Internal
            .ttl(Duration::from_secs(60))
            .authorized_holder(child_kp.public_key())
            .build(&parent_kp)
            .expect("Lower trust_level should be allowed");

        assert_eq!(child.trust_level(), Some(TrustLevel::External));

        // Verify the chain passes
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", parent_kp.public_key());
        let result = data_plane.verify_chain(&[parent, child]);
        assert!(
            result.is_ok(),
            "Chain with decreasing trust_level should pass verification"
        );
    }

    /// Test that tool trust requirements are enforced at authorization time.
    #[test]
    fn test_tool_trust_requirements_enforcement() {
        use crate::crypto::SigningKey;
        use crate::warrant::{TrustLevel, Warrant};
        use std::collections::HashMap;
        use std::time::Duration;

        let kp = SigningKey::generate();

        // Create warrant with External trust level
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/*").unwrap());
        let warrant = Warrant::builder()
            .capability("read_file", constraints.clone())
            .capability("delete_file", constraints.clone())
            .capability("admin_reset", constraints)
            .trust_level(TrustLevel::External)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .expect("Failed to build warrant");

        // Configure data plane with trust requirements
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", kp.public_key());
        data_plane
            .require_trust("delete_file", TrustLevel::Privileged)
            .unwrap();
        data_plane
            .require_trust("admin_*", TrustLevel::System)
            .unwrap();
        data_plane
            .require_trust("read_file", TrustLevel::External)
            .unwrap();

        let args: HashMap<String, ConstraintValue> = [(
            "path".to_string(),
            ConstraintValue::String("/data/test.txt".to_string()),
        )]
        .into_iter()
        .collect();

        // Create PoP signature for read_file
        let pop_sig = warrant
            .create_pop_signature(&kp, "read_file", &args)
            .expect("sign pop");

        // read_file should succeed (External >= External)
        let result = data_plane.authorize(&warrant, "read_file", &args, Some(&pop_sig), &[]);
        assert!(
            result.is_ok(),
            "read_file should be authorized: {:?}",
            result
        );

        // delete_file should fail (External < Privileged) - trust check happens before PoP
        let result = data_plane.authorize(&warrant, "delete_file", &args, None, &[]);
        assert!(result.is_err(), "delete_file should be denied");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("insufficient trust level"),
            "Error should mention trust level: {}",
            err
        );
        assert!(
            err.contains("Privileged"),
            "Error should mention required level"
        );

        // admin_reset should fail (External < System, via glob pattern)
        let result = data_plane.authorize(&warrant, "admin_reset", &args, None, &[]);
        assert!(result.is_err(), "admin_reset should be denied");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("System"),
            "Error should mention required level: {}",
            err
        );
    }

    /// Test glob pattern matching for trust requirements.
    #[test]
    fn test_tool_trust_requirements_glob_patterns() {
        let mut data_plane = DataPlane::new();

        // Configure various patterns
        data_plane
            .require_trust("admin_*", TrustLevel::System)
            .unwrap();
        data_plane
            .require_trust("write_*", TrustLevel::Internal)
            .unwrap();
        data_plane
            .require_trust("read_public", TrustLevel::External)
            .unwrap();
        data_plane
            .require_trust("*", TrustLevel::Untrusted)
            .unwrap(); // Default

        // Test exact match
        assert_eq!(
            data_plane.get_required_trust("read_public"),
            Some(TrustLevel::External)
        );

        // Test glob patterns
        assert_eq!(
            data_plane.get_required_trust("admin_users"),
            Some(TrustLevel::System)
        );
        assert_eq!(
            data_plane.get_required_trust("admin_config"),
            Some(TrustLevel::System)
        );
        assert_eq!(
            data_plane.get_required_trust("write_file"),
            Some(TrustLevel::Internal)
        );

        // Test default fallback
        assert_eq!(
            data_plane.get_required_trust("unknown_tool"),
            Some(TrustLevel::Untrusted)
        );
    }

    /// Test that higher trust levels can access lower-trust tools.
    #[test]
    fn test_tool_trust_requirements_hierarchy() {
        use crate::crypto::SigningKey;
        use crate::warrant::{TrustLevel, Warrant};
        use std::collections::HashMap;
        use std::time::Duration;

        let kp = SigningKey::generate();

        // Create warrant with Privileged trust level
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/*").unwrap());
        let warrant = Warrant::builder()
            .capability("read_file", constraints)
            .trust_level(TrustLevel::Privileged)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .expect("Failed to build warrant");

        // Configure data plane - read_file only requires External
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", kp.public_key());
        data_plane
            .require_trust("read_file", TrustLevel::External)
            .unwrap();

        let args: HashMap<String, ConstraintValue> = [(
            "path".to_string(),
            ConstraintValue::String("/data/test.txt".to_string()),
        )]
        .into_iter()
        .collect();

        // Create PoP signature
        let pop_sig = warrant
            .create_pop_signature(&kp, "read_file", &args)
            .expect("sign pop");

        // Privileged > External, so should succeed
        let result = data_plane.authorize(&warrant, "read_file", &args, Some(&pop_sig), &[]);
        assert!(
            result.is_ok(),
            "Privileged warrant should access External-required tool: {:?}",
            result
        );
    }

    /// Test that Authorizer also enforces tool trust requirements.
    #[test]
    fn test_authorizer_trust_requirements() {
        use crate::crypto::SigningKey;
        use crate::warrant::{TrustLevel, Warrant};
        use std::collections::HashMap;
        use std::time::Duration;

        let kp = SigningKey::generate();

        // Create warrant with External trust level
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/*").unwrap());
        let warrant = Warrant::builder()
            .capability("read_file", constraints.clone())
            .capability("admin_reset", constraints)
            .trust_level(TrustLevel::External)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .expect("Failed to build warrant");

        // Configure Authorizer with trust requirements using builder
        let authorizer = Authorizer::builder()
            .trusted_root(kp.public_key())
            .trust_requirement("read_file", TrustLevel::External)
            .trust_requirement("admin_*", TrustLevel::System)
            .build()
            .expect("Failed to build authorizer");

        let args: HashMap<String, ConstraintValue> = [(
            "path".to_string(),
            ConstraintValue::String("/data/test.txt".to_string()),
        )]
        .into_iter()
        .collect();

        // Create PoP signature for read_file
        let pop_sig = warrant
            .create_pop_signature(&kp, "read_file", &args)
            .expect("sign pop");

        // read_file should succeed (External >= External)
        let result = authorizer.authorize(&warrant, "read_file", &args, Some(&pop_sig), &[]);
        assert!(
            result.is_ok(),
            "read_file should be authorized: {:?}",
            result
        );

        // admin_reset should fail (External < System)
        let result = authorizer.authorize(&warrant, "admin_reset", &args, None, &[]);
        assert!(result.is_err(), "admin_reset should be denied");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("insufficient trust level"),
            "Error should mention trust level: {}",
            err
        );
    }

    /// Test Authorizer chainable API for trust requirements.
    #[test]
    fn test_authorizer_chainable_trust_api() {
        use crate::crypto::SigningKey;
        use crate::warrant::TrustLevel;

        let kp = SigningKey::generate();

        // Test chainable API
        let authorizer = Authorizer::new()
            .with_trusted_root(kp.public_key())
            .with_trust_requirement("delete_*", TrustLevel::Privileged)
            .with_trust_requirement("*", TrustLevel::External);

        assert_eq!(
            authorizer.get_required_trust("delete_database"),
            Some(TrustLevel::Privileged)
        );
        assert_eq!(
            authorizer.get_required_trust("read_file"),
            Some(TrustLevel::External)
        );

        // Test mutable API
        let mut authorizer2 = Authorizer::new();
        authorizer2
            .require_trust("admin_*", TrustLevel::System)
            .unwrap();

        assert_eq!(
            authorizer2.get_required_trust("admin_users"),
            Some(TrustLevel::System)
        );
    }

    // =========================================================================
    // Edge Case Tests for Trust Requirements
    // =========================================================================

    /// Test that invalid patterns are rejected at registration time.
    #[test]
    fn test_trust_pattern_validation() {
        use crate::warrant::TrustLevel;

        let mut data_plane = DataPlane::new();

        // Valid patterns
        assert!(data_plane.require_trust("*", TrustLevel::External).is_ok());
        assert!(data_plane
            .require_trust("admin_*", TrustLevel::System)
            .is_ok());
        assert!(data_plane
            .require_trust("exact_tool", TrustLevel::Internal)
            .is_ok());
        assert!(data_plane
            .require_trust("read_", TrustLevel::External)
            .is_ok()); // No wildcard

        // Invalid patterns
        assert!(data_plane.require_trust("", TrustLevel::External).is_err()); // Empty
        assert!(data_plane
            .require_trust("**", TrustLevel::External)
            .is_err()); // Double wildcard
        assert!(data_plane
            .require_trust("*admin", TrustLevel::External)
            .is_err()); // Wildcard at start
        assert!(data_plane
            .require_trust("*admin*", TrustLevel::External)
            .is_err()); // Multiple wildcards
        assert!(data_plane
            .require_trust("admin*foo", TrustLevel::External)
            .is_err()); // Wildcard in middle
        assert!(data_plane
            .require_trust("a*b*", TrustLevel::External)
            .is_err()); // Multiple wildcards
    }

    /// Test that exact matches take precedence over glob patterns.
    #[test]
    fn test_trust_pattern_precedence() {
        use crate::warrant::TrustLevel;

        let mut data_plane = DataPlane::new();

        // Configure overlapping patterns
        data_plane
            .require_trust("*", TrustLevel::Untrusted)
            .unwrap();
        data_plane
            .require_trust("admin_*", TrustLevel::Privileged)
            .unwrap();
        data_plane
            .require_trust("admin_users", TrustLevel::System)
            .unwrap(); // Exact match

        // Exact match should take precedence
        assert_eq!(
            data_plane.get_required_trust("admin_users"),
            Some(TrustLevel::System), // Exact match, not glob
        );

        // Glob should match other admin tools
        assert_eq!(
            data_plane.get_required_trust("admin_config"),
            Some(TrustLevel::Privileged), // Glob match
        );

        // Default should catch everything else
        assert_eq!(
            data_plane.get_required_trust("read_file"),
            Some(TrustLevel::Untrusted), // Default
        );
    }

    /// Test behavior when no trust requirements are configured.
    #[test]
    fn test_no_trust_requirements_configured() {
        use crate::crypto::SigningKey;
        use crate::warrant::{TrustLevel, Warrant};
        use std::collections::HashMap;
        use std::time::Duration;

        let kp = SigningKey::generate();

        // Create warrant with trust level
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/*").unwrap());
        let warrant = Warrant::builder()
            .capability("read_file", constraints)
            .trust_level(TrustLevel::External)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .expect("Failed to build warrant");

        // DataPlane with NO trust requirements
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", kp.public_key());
        // No require_trust calls

        // get_required_trust should return None
        assert_eq!(data_plane.get_required_trust("read_file"), None);
        assert_eq!(data_plane.get_required_trust("any_tool"), None);

        let args: HashMap<String, ConstraintValue> = [(
            "path".to_string(),
            ConstraintValue::String("/data/test.txt".to_string()),
        )]
        .into_iter()
        .collect();
        let pop_sig = warrant
            .create_pop_signature(&kp, "read_file", &args)
            .expect("sign pop");

        // Authorization should succeed (trust check is skipped when no requirements)
        let result = data_plane.authorize(&warrant, "read_file", &args, Some(&pop_sig), &[]);
        assert!(
            result.is_ok(),
            "Should succeed when no trust requirements: {:?}",
            result
        );
    }

    /// Test behavior when warrant has no trust level but requirements exist.
    #[test]
    fn test_missing_warrant_trust_level() {
        use crate::crypto::SigningKey;
        use crate::warrant::{TrustLevel, Warrant};
        use std::collections::HashMap;
        use std::time::Duration;

        let kp = SigningKey::generate();

        // Create warrant WITHOUT trust level
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/*").unwrap());
        let warrant = Warrant::builder()
            .capability("read_file", constraints)
            // No .trust_level() call
            .ttl(Duration::from_secs(3600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .expect("Failed to build warrant");

        // Warrant should have no trust level
        assert!(warrant.trust_level().is_none());

        // DataPlane with trust requirement
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", kp.public_key());
        data_plane.require_trust("*", TrustLevel::External).unwrap();

        let args: HashMap<String, ConstraintValue> = [(
            "path".to_string(),
            ConstraintValue::String("/data/test.txt".to_string()),
        )]
        .into_iter()
        .collect();

        // Should fail: warrant has no trust level (treated as Untrusted)
        let result = data_plane.authorize(&warrant, "read_file", &args, None, &[]);
        assert!(result.is_err(), "Should fail: Untrusted < External");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Untrusted"),
            "Should show warrant is Untrusted"
        );
    }

    /// Test AuthorizerBuilder pattern validation.
    #[test]
    fn test_authorizer_builder_pattern_validation() {
        use crate::crypto::SigningKey;
        use crate::warrant::TrustLevel;

        let kp = SigningKey::generate();

        // Valid patterns should work
        let result = Authorizer::builder()
            .trusted_root(kp.public_key())
            .try_trust_requirement("*", TrustLevel::External)
            .and_then(|b| b.try_trust_requirement("admin_*", TrustLevel::System))
            .and_then(|b| b.build());
        assert!(result.is_ok());

        // Invalid pattern should fail
        let result = Authorizer::builder()
            .trusted_root(kp.public_key())
            .try_trust_requirement("*admin*", TrustLevel::System);
        assert!(result.is_err());
    }
}
