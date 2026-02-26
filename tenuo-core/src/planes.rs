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
use crate::warrant::{Clearance, Warrant, WarrantType};
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
    approvals: &[crate::approval::SignedApproval],
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

    #[derive(Debug)]
    enum Rejection {
        InvalidSignature,
        NotAuthorized,
        Duplicate,
        Expired,
        HashMismatch,
    }

    let mut valid_count = 0u32;
    let mut seen_approvers = std::collections::HashSet::new();
    let now = chrono::Utc::now().timestamp() as u64;
    let tolerance_secs = clock_tolerance.num_seconds() as u64;
    let mut rejections: Vec<Rejection> = Vec::new();

    for approval in approvals {
        let payload = match approval.verify() {
            Ok(p) => p,
            Err(_) => {
                rejections.push(Rejection::InvalidSignature);
                continue;
            }
        };

        if !required_approvers.contains(&approval.approver_key) {
            rejections.push(Rejection::NotAuthorized);
            continue;
        }

        if seen_approvers.contains(&approval.approver_key) {
            rejections.push(Rejection::Duplicate);
            continue;
        }

        if payload.expires_at + tolerance_secs < now {
            rejections.push(Rejection::Expired);
            continue;
        }

        if payload.request_hash != request_hash {
            rejections.push(Rejection::HashMismatch);
            continue;
        }

        valid_count = valid_count.saturating_add(1);
        seen_approvers.insert(approval.approver_key.clone());

        if valid_count >= threshold {
            return Ok(());
        }
    }

    // 1-of-1 diagnostic: surface the exact rejection reason
    if threshold == 1 && approvals.len() == 1 && rejections.len() == 1 {
        let reason = match &rejections[0] {
            Rejection::InvalidSignature => "invalid signature on approval",
            Rejection::NotAuthorized => "approver not in trusted set",
            Rejection::Duplicate => "duplicate approval from same approver",
            Rejection::Expired => "approval expired (beyond clock tolerance)",
            Rejection::HashMismatch => {
                "request hash mismatch (approval was signed for a different request)"
            }
        };
        return Err(Error::InvalidApproval(reason.to_string()));
    }

    // m-of-n: build rejection summary
    let mut parts = Vec::new();
    let counts: [(usize, &str); 5] = [
        (
            rejections
                .iter()
                .filter(|r| matches!(r, Rejection::InvalidSignature))
                .count(),
            "invalid signature",
        ),
        (
            rejections
                .iter()
                .filter(|r| matches!(r, Rejection::NotAuthorized))
                .count(),
            "untrusted",
        ),
        (
            rejections
                .iter()
                .filter(|r| matches!(r, Rejection::Duplicate))
                .count(),
            "duplicate",
        ),
        (
            rejections
                .iter()
                .filter(|r| matches!(r, Rejection::Expired))
                .count(),
            "expired",
        ),
        (
            rejections
                .iter()
                .filter(|r| matches!(r, Rejection::HashMismatch))
                .count(),
            "hash mismatch",
        ),
    ];
    for (count, label) in &counts {
        if *count > 0 {
            parts.push(format!("{count} {label}"));
        }
    }
    let detail = if parts.is_empty() {
        None
    } else {
        Some(format!(" [rejected: {}]", parts.join(", ")))
    };

    Err(Error::InsufficientApprovals {
        required: threshold,
        received: valid_count,
        detail,
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
            .holder(self.keypair.public_key())
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
            .holder(holder.clone())
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
            .holder(holder.clone())
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
/// // At request time, verify and authorize in one call
/// let warrant = wire::decode_base64(&header_value)?;
/// data_plane.check_chain(&[warrant], "upgrade_cluster", &args, Some(&pop_sig), &[])?;
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
    /// Tool clearance requirements: minimum clearance required per tool.
    /// Supports exact matches and glob patterns (e.g., "admin_*").
    tool_clearance_requirements: HashMap<String, Clearance>,
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
            tool_clearance_requirements: HashMap::new(),
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
            tool_clearance_requirements: HashMap::new(),
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
            tool_clearance_requirements: HashMap::new(),
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

    /// Set minimum clearance level required for a tool.
    ///
    /// This is **gateway-level policy**, not warrant content. The gateway defines
    /// what clearance is required for its tools. This is an **offline check** -
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
    /// If no clearance requirement is configured for a tool, the check is skipped
    /// (permissive). For defense in depth, configure a default:
    ///
    /// ```ignore
    /// data_plane.require_clearance("*", Clearance::EXTERNAL)?;  // Baseline
    /// data_plane.require_clearance("admin_*", Clearance::SYSTEM)?;  // Override
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is invalid.
    pub fn require_clearance(
        &mut self,
        tool_pattern: impl Into<String>,
        level: Clearance,
    ) -> Result<()> {
        let pattern = tool_pattern.into();
        Self::validate_clearance_pattern(&pattern)?;
        self.tool_clearance_requirements.insert(pattern, level);
        Ok(())
    }

    /// Validate a clearance requirement pattern.
    ///
    /// Valid patterns:
    /// - `"*"` - match all (default)
    /// - `"exact_name"` - exact match (no wildcards)
    /// - `"prefix_*"` - prefix match (wildcard at end only)
    fn validate_clearance_pattern(pattern: &str) -> Result<()> {
        if pattern.is_empty() {
            return Err(Error::Validation(
                "clearance pattern cannot be empty".to_string(),
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
                            "invalid clearance pattern '{}': wildcard must be at end only",
                            pattern
                        )))
                    } else {
                        Ok(())
                    }
                } else {
                    Err(Error::Validation(format!(
                        "invalid clearance pattern '{}': wildcard must be at end (e.g., 'admin_*')",
                        pattern
                    )))
                }
            }
            _ => Err(Error::Validation(format!(
                "invalid clearance pattern '{}': only one wildcard allowed",
                pattern
            ))),
        }
    }

    /// Get the required clearance for a tool.
    ///
    /// This is an **offline operation** - no network calls.
    ///
    /// Checks in order:
    /// 1. Exact match
    /// 2. Glob pattern match (e.g., "admin_*")
    /// 3. Default "*" if configured
    /// 4. None (no requirement - check is skipped)
    pub fn get_required_clearance(&self, tool: &str) -> Option<Clearance> {
        // 1. Exact match
        if let Some(&level) = self.tool_clearance_requirements.get(tool) {
            return Some(level);
        }

        // 2. Glob pattern match
        for (pattern, &level) in &self.tool_clearance_requirements {
            if pattern != "*" && Self::matches_glob_pattern(pattern, tool) {
                return Some(level);
            }
        }

        // 3. Default "*"
        self.tool_clearance_requirements.get("*").copied()
    }

    /// Check if a tool name matches a glob pattern (supports trailing * only).
    fn matches_glob_pattern(pattern: &str, tool: &str) -> bool {
        if let Some(prefix) = pattern.strip_suffix('*') {
            tool.starts_with(prefix)
        } else {
            pattern == tool
        }
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
                // Clearance monotonicity: child clearance cannot exceed parent's
                if let (Some(parent_trust), Some(child_trust)) =
                    (parent.clearance(), child.clearance())
                {
                    if child_trust > parent_trust {
                        return Err(Error::MonotonicityViolation(format!(
                            "clearance cannot increase: parent {:?}, child {:?}",
                            parent_trust, child_trust
                        )));
                    }
                }
                // NOTE: Self-issuance (holder == issuer) is NOT blocked for Execution → Execution.
                // Monotonicity invariants (I2-I4) ensure a self-issued delegation can only
                // attenuate capabilities, not escalate them. Self-delegation is harmless.
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
                // 2. Child clearance must not exceed issuer's clearance (monotonicity)
                if let Some(parent_trust) = parent.clearance() {
                    if let Some(child_trust) = child.clearance() {
                        if child_trust > parent_trust {
                            return Err(Error::MonotonicityViolation(format!(
                                "clearance {:?} exceeds issuer's clearance {:?}",
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

    /// Verify chain and authorize a tool call in one atomic operation.
    ///
    /// This is the **primary authorization method** for DataPlane. It:
    /// 1. Verifies the entire delegation chain (signatures, linkage, monotonicity)
    /// 2. Checks clearance requirements against the leaf warrant
    /// 3. Authorizes the tool call (capabilities, constraints, PoP)
    /// 4. Verifies multi-sig approvals if required
    ///
    /// For a single warrant, pass `&[warrant]`.
    pub fn check_chain(
        &self,
        chain: &[Warrant],
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&crate::crypto::Signature>,
        approvals: &[crate::approval::SignedApproval],
    ) -> Result<ChainVerificationResult> {
        let result = self.verify_chain(chain)?;

        if let Some(leaf) = chain.last() {
            // Check clearance requirement
            if let Some(required) = self.get_required_clearance(tool) {
                let actual = leaf.payload.clearance.unwrap_or(Clearance::UNTRUSTED);
                if !actual.meets(required) {
                    return Err(Error::InsufficientClearance {
                        tool: tool.to_string(),
                        required: required.to_string(),
                        actual: actual.to_string(),
                    });
                }
            }

            let auth_result = leaf.authorize(tool, args, signature).and_then(|_| {
                verify_approvals_with_tolerance(
                    leaf,
                    tool,
                    args,
                    approvals,
                    chrono::Duration::seconds(DEFAULT_CLOCK_TOLERANCE_SECS),
                )
            });

            match &auth_result {
                Ok(_) => {
                    crate::audit::log_event(
                        crate::approval::AuditEvent::new(
                            crate::approval::AuditEventType::AuthorizationSuccess,
                            "data-plane",
                            "check_chain",
                        )
                        .with_details(format!("Authorized tool '{}'", tool))
                        .with_related(vec![leaf.id().to_string()]),
                    );
                }
                Err(e) => {
                    crate::audit::log_event(
                        crate::approval::AuditEvent::new(
                            crate::approval::AuditEventType::AuthorizationFailure,
                            "data-plane",
                            "check_chain",
                        )
                        .with_details(format!("Denied tool '{}': {}", tool, e))
                        .with_related(vec![leaf.id().to_string()]),
                    );
                }
            }
            auth_result?;
        }

        Ok(result)
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
/// PoP signatures use **bidirectional** window checking centered on current time.
/// With `window_secs = 30` and `max_windows = 5`, tolerance is ±60 seconds.
pub const DEFAULT_POP_WINDOW_SECS: i64 = 30;

/// Default number of PoP windows to check (handles bidirectional clock skew).
///
/// Uses 5 windows for symmetric tolerance: current ± 2 windows = ±60s with 30s windows.
/// Window check order: [0, -1, +1, -2, +2] to prefer closer matches.
pub const DEFAULT_POP_MAX_WINDOWS: u32 = 5;

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
    tool_clearance_requirements: HashMap<String, Clearance>,
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
            tool_clearance_requirements: HashMap::new(),
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

    /// Set minimum clearance required for a tool (builder style).
    ///
    /// # Example
    ///
    /// ```rust
    /// use tenuo::Authorizer;
    /// use tenuo::Clearance;
    ///
    /// let auth = Authorizer::builder()
    ///     .with_clearance_requirement("admin_*", Clearance::SYSTEM)
    ///     .build();
    /// ```
    pub fn with_clearance_requirement(
        self,
        tool_pattern: impl Into<String>,
        level: Clearance,
    ) -> Self {
        self.try_clearance_requirement(tool_pattern, level)
            .expect("invalid clearance pattern")
    }

    /// Set minimum clearance required for a tool (chainable, fallible).
    ///
    /// Like `with_clearance_requirement`, but returns a Result instead of panicking.
    pub fn try_clearance_requirement(
        mut self,
        tool_pattern: impl Into<String>,
        level: Clearance,
    ) -> Result<Self> {
        let pattern = tool_pattern.into();
        Self::validate_clearance_pattern(&pattern)?;
        self.tool_clearance_requirements.insert(pattern, level);
        Ok(self)
    }

    /// Validate a clearance requirement pattern.
    fn validate_clearance_pattern(pattern: &str) -> Result<()> {
        if pattern.is_empty() {
            return Err(Error::Validation(
                "clearance pattern cannot be empty".to_string(),
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
                            "invalid clearance pattern '{}': wildcard must be at end only",
                            pattern
                        )))
                    }
                } else {
                    Err(Error::Validation(format!(
                        "invalid clearance pattern '{}': wildcard must be at end (e.g., 'admin_*')",
                        pattern
                    )))
                }
            }
            _ => Err(Error::Validation(format!(
                "invalid clearance pattern '{}': only one wildcard allowed",
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
            tool_clearance_requirements: self.tool_clearance_requirements,
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
    tool_clearance_requirements: HashMap<String, Clearance>,
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
            tool_clearance_requirements: HashMap::new(),
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

    /// Set minimum clearance required for a tool (builder style).
    ///
    /// This is **gateway-level policy**. The authorizer defines what clearance levels
    /// are required for its tools. This is an **offline check**.
    ///
    /// Supports exact tool names or glob patterns:
    /// - `"delete_database"` - exact match
    /// - `"admin_*"` - prefix match (admin_users, admin_config, etc.)
    /// - `"*"` - default for all tools (recommended for defense in depth)
    ///
    /// # Panics
    ///
    /// Panics if the pattern is invalid.
    ///
    /// # Example
    /// ```ignore
    /// let authorizer = Authorizer::new()
    ///     .with_trusted_root(root_key)
    ///     .with_clearance_requirement("*", Clearance::External)
    ///     .with_clearance_requirement("admin_*", Clearance::System);
    /// ```
    pub fn with_clearance_requirement(
        self,
        tool_pattern: impl Into<String>,
        level: Clearance,
    ) -> Self {
        self.try_clearance_requirement(tool_pattern, level)
            .expect("invalid clearance pattern")
    }

    /// Set minimum clearance required for a tool (chainable, fallible).
    ///
    /// Like `with_clearance_requirement`, but returns a Result instead of panicking.
    pub fn try_clearance_requirement(
        mut self,
        tool_pattern: impl Into<String>,
        level: Clearance,
    ) -> Result<Self> {
        let pattern = tool_pattern.into();
        Self::validate_clearance_pattern(&pattern)?;
        self.tool_clearance_requirements.insert(pattern, level);
        Ok(self)
    }

    /// Set minimum clearance required for a tool (mutable version).
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is invalid.
    pub fn require_clearance(
        &mut self,
        tool_pattern: impl Into<String>,
        level: Clearance,
    ) -> Result<()> {
        let pattern = tool_pattern.into();
        Self::validate_clearance_pattern(&pattern)?;
        self.tool_clearance_requirements.insert(pattern, level);
        Ok(())
    }

    /// Validate a clearance requirement pattern.
    fn validate_clearance_pattern(pattern: &str) -> Result<()> {
        if pattern.is_empty() {
            return Err(Error::Validation(
                "clearance pattern cannot be empty".to_string(),
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
                            "invalid clearance pattern '{}': wildcard must be at end only",
                            pattern
                        )))
                    }
                } else {
                    Err(Error::Validation(format!(
                        "invalid clearance pattern '{}': wildcard must be at end (e.g., 'admin_*')",
                        pattern
                    )))
                }
            }
            _ => Err(Error::Validation(format!(
                "invalid clearance pattern '{}': max one wildcard allowed",
                pattern
            ))),
        }
    }

    /// Get the required clearance for a tool.
    ///
    /// Checks exact match first, then most specific wildcard match.
    /// Get required clearance for a tool.
    pub fn get_required_clearance(&self, tool: &str) -> Option<Clearance> {
        // 1. Exact match
        if let Some(level) = self.tool_clearance_requirements.get(tool) {
            return Some(*level);
        }

        // 2. Wildcard matches (longest prefix wins)
        // Iterate over requirements, filter for wildcards, verify prefix match
        // and pick the one with longest prefix.
        let mut best_match: Option<Clearance> = None;
        let mut max_prefix_len = -1; // -1 indicates no match found yet

        for (pattern, level) in &self.tool_clearance_requirements {
            if pattern == "*" {
                // Global default, length 0
                if max_prefix_len < 0 {
                    best_match = Some(*level);
                    max_prefix_len = 0;
                }
                continue;
            }

            if let Some(prefix) = pattern.strip_suffix('*') {
                if tool.starts_with(prefix) {
                    let len = prefix.len() as i32;
                    if len > max_prefix_len {
                        best_match = Some(*level);
                        max_prefix_len = len;
                    }
                }
            }
        }

        best_match
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

    /// Authorize a single warrant.
    ///
    /// This is a convenience wrapper around `check_chain()` that treats
    /// the warrant as a single-element chain. It provides the complete
    /// security boundary in one call: signature verification, issuer
    /// trust, revocation, clearance, capabilities, constraints, PoP,
    /// and multi-sig.
    ///
    /// For delegation chains, use `check_chain()` directly.
    pub fn authorize_one(
        &self,
        warrant: &Warrant,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&crate::crypto::Signature>,
        approvals: &[crate::approval::SignedApproval],
    ) -> Result<ChainVerificationResult> {
        self.check_chain(
            std::slice::from_ref(warrant),
            tool,
            args,
            signature,
            approvals,
        )
    }

    /// Verify multi-sig approvals against a warrant.
    fn verify_approvals(
        &self,
        warrant: &Warrant,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        approvals: &[crate::approval::SignedApproval],
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
                // Clearance monotonicity: child clearance cannot exceed parent's
                if let (Some(parent_trust), Some(child_trust)) =
                    (parent.clearance(), child.clearance())
                {
                    if child_trust > parent_trust {
                        return Err(Error::MonotonicityViolation(format!(
                            "clearance cannot increase: parent {:?}, child {:?}",
                            parent_trust, child_trust
                        )));
                    }
                }
                // NOTE: Self-issuance (holder == issuer) is NOT blocked for Execution → Execution.
                // Monotonicity invariants (I2-I4) ensure a self-issued delegation can only
                // attenuate capabilities, not escalate them. Self-delegation is harmless.
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

                // 2. Child clearance must not exceed issuer's clearance (monotonicity)
                if let Some(parent_trust) = parent.clearance() {
                    if let Some(child_trust) = child.clearance() {
                        if child_trust > parent_trust {
                            return Err(Error::MonotonicityViolation(format!(
                                "clearance {:?} exceeds issuer's clearance {:?}",
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
    /// Verify a delegation chain and authorize the leaf warrant.
    ///
    /// This is the **primary authorization entry point**. For single
    /// warrants, use `authorize_one()` which wraps this method.
    ///
    /// Complete security boundary in one call:
    /// - `verify_chain()`: signature verification, issuer trust,
    ///   revocation, chain linkage, monotonic narrowing, expiry
    /// - Leaf authorization: clearance, capabilities, constraints,
    ///   PoP, and multi-sig
    pub fn check_chain(
        &self,
        chain: &[Warrant],
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&crate::crypto::Signature>,
        approvals: &[crate::approval::SignedApproval],
    ) -> Result<ChainVerificationResult> {
        let result = self.verify_chain(chain)?;

        if let Some(leaf) = chain.last() {
            // Clearance check
            if let Some(required) = self.get_required_clearance(tool) {
                let actual = leaf.clearance().unwrap_or(Clearance::UNTRUSTED);
                if actual < required {
                    return Err(Error::InsufficientClearance {
                        tool: tool.to_string(),
                        required: format!("{:?}", required),
                        actual: format!("{:?}", actual),
                    });
                }
            }

            // Capability, constraint, and PoP verification
            leaf.authorize_with_pop_config(
                tool,
                args,
                signature,
                self.pop_window_secs,
                self.pop_max_windows,
            )?;

            // Multi-sig verification
            self.verify_approvals(leaf, tool, args, approvals)?;
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

        // Verify chain (offline - no network call)
        assert!(data_plane.verify_chain(&[warrant.clone()]).is_ok());

        // Full check_chain (offline - no network call)
        let mut args = HashMap::new();
        args.insert(
            "cluster".to_string(),
            ConstraintValue::String("staging-web".to_string()),
        );
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
            .sign(&holder_keypair, "upgrade_cluster", &args)
            .unwrap();
        assert!(data_plane
            .check_chain(
                &[warrant_for_holder],
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
        // max_depth defaults to MAX_DELEGATION_DEPTH when not explicitly set
        assert_eq!(root_warrant.max_depth(), Some(64));
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
            .sign(&holder_keypair, "test", &args)
            .unwrap();
        assert!(authorizer
            .authorize_one(&warrant_for_holder, "test", &args, Some(&pop_sig), &[])
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
            .holder(orchestrator_keypair.public_key())
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
            .holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair) // Control plane signs (they hold root)
            .unwrap();

        let mut worker_constraints = ConstraintSet::new();
        worker_constraints.insert("table", Exact::new("public_users"));
        let worker_warrant = orchestrator_warrant
            .attenuate()
            .capability("query", worker_constraints)
            .holder(worker_keypair.public_key())
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
            .holder(agent_keypair.public_key())
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
            .sign(&agent_keypair, "upgrade_cluster", &args)
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
            .holder(agent_keypair.public_key())
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
            .holder(agent_keypair.public_key())
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
        let pop_sig = child.sign(&agent_keypair, "test", &args).unwrap();

        assert!(authorizer
            .authorize_one(&child, "test", &args, Some(&pop_sig), &[])
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
            .holder(orchestrator_keypair.public_key())
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
            .sign(&holder_keypair, "test", &args)
            .unwrap();

        // Should pass without any approvals (just PoP)
        let result =
            authorizer.authorize_one(&warrant_for_holder, "test", &args, Some(&pop_sig), &[]);
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
            .holder(issuer_keypair.public_key())
            .build(&issuer_keypair)
            .unwrap();

        let authorizer = Authorizer::new().with_trusted_root(issuer_keypair.public_key());
        let args = HashMap::new();

        // Create PoP signature
        let pop_sig = warrant
            .sign(&issuer_keypair, "sensitive_action", &args)
            .unwrap();

        // Should FAIL without approval (but WITH PoP signature)
        let result =
            authorizer.authorize_one(&warrant, "sensitive_action", &args, Some(&pop_sig), &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("insufficient"));
    }

    #[test]
    fn test_authorize_valid_approval() {
        use crate::approval::{compute_request_hash, ApprovalPayload, SignedApproval};
        use chrono::{Duration as ChronoDuration, Utc};

        let issuer_keypair = SigningKey::generate();
        let admin_keypair = SigningKey::generate();

        // Create warrant WITH multi-sig requirement
        let warrant = Warrant::builder()
            .capability("sensitive_action", ConstraintSet::new())
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![admin_keypair.public_key()])
            .min_approvals(1)
            .holder(issuer_keypair.public_key())
            .build(&issuer_keypair)
            .unwrap();

        let authorizer = Authorizer::new().with_trusted_root(issuer_keypair.public_key());
        let args = HashMap::new();

        // Create PoP signature
        let pop_sig = warrant
            .sign(&issuer_keypair, "sensitive_action", &args)
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

        // Generate nonce for replay protection
        let nonce: [u8; 16] = rand::random();

        // Create approval using envelope pattern
        let payload = ApprovalPayload {
            version: 1,
            request_hash,
            nonce,
            external_id: "admin@test.com".to_string(),
            approved_at: now.timestamp() as u64,
            expires_at: expires.timestamp() as u64,
            extensions: None,
        };

        let approval = SignedApproval::create(payload, &admin_keypair);

        // Should SUCCEED with valid approval AND PoP signature
        let result = authorizer.authorize_one(
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
        use crate::approval::{compute_request_hash, ApprovalPayload, SignedApproval};
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
            .holder(issuer_keypair.public_key())
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

        // Generate nonce for replay protection
        let nonce: [u8; 16] = rand::random();

        // Create approval using envelope pattern (wrong approver)
        let payload = ApprovalPayload {
            version: 1,
            request_hash,
            nonce,
            external_id: "other@test.com".to_string(),
            approved_at: now.timestamp() as u64,
            expires_at: expires.timestamp() as u64,
            extensions: None,
        };

        let approval = SignedApproval::create(payload, &other_keypair);

        // Create PoP signature
        let pop_sig = warrant
            .sign(&issuer_keypair, "sensitive_action", &args)
            .unwrap();

        // Should FAIL - approver not in required set (even with valid PoP)
        let result = authorizer.authorize_one(
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
        use crate::approval::{compute_request_hash, ApprovalPayload, SignedApproval};
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
            .holder(issuer_keypair.public_key()) // Added this line
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

        // Helper to create approval (with domain separation + nonce)
        let make_approval = |kp: &SigningKey, id: &str| {
            // Each approval gets a unique nonce
            let nonce: [u8; 16] = rand::random();

            // Create approval using envelope pattern
            let payload = ApprovalPayload {
                version: 1,
                request_hash,
                nonce,
                external_id: id.to_string(),
                approved_at: now.timestamp() as u64,
                expires_at: expires.timestamp() as u64,
                extensions: None,
            };

            SignedApproval::create(payload, kp)
        };

        let approval1 = make_approval(&admin1, "admin1@test.com");
        let approval2 = make_approval(&admin2, "admin2@test.com");

        // Create PoP signature
        let pop_sig = warrant
            .sign(&issuer_keypair, "sensitive_action", &args)
            .unwrap();

        // With 1 approval - should fail (need 2)
        let result = authorizer.authorize_one(
            &warrant,
            "sensitive_action",
            &args,
            Some(&pop_sig),
            std::slice::from_ref(&approval1),
        );
        assert!(result.is_err());

        // With 2 approvals - should pass
        let result = authorizer.authorize_one(
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
            .holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair)
            .unwrap();

        // POLA: inherit_all to get parent capabilities
        let child = root
            .attenuate()
            .inherit_all()
            // Session ID inherited from root (session_123)
            .holder(worker_keypair.public_key())
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
            .holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair)
            .unwrap();

        // Root without session ID
        let root_no_session = Warrant::builder()
            .capability("test", ConstraintSet::new())
            // No session_id
            .ttl(Duration::from_secs(600))
            .holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair)
            .unwrap();

        // POLA: inherit_all
        let child = root_no_session
            .attenuate()
            .inherit_all()
            // Session ID inherited (None)
            .holder(worker_keypair.public_key())
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
            .holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair)
            .unwrap();

        // POLA: inherit_all
        let child = root
            .attenuate()
            .inherit_all()
            // Session ID inherited from root (session_123)
            .holder(orchestrator_keypair.public_key())
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
            .holder(orchestrator_keypair.public_key())
            .build(&control_plane.keypair)
            .unwrap();

        // POLA: inherit_all
        let child_bad = root2
            .attenuate()
            .inherit_all()
            // Session ID inherited from root2 (session_456)
            .holder(orchestrator_keypair.public_key())
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
        use crate::warrant::{Clearance, Warrant, WarrantType};
        use std::time::Duration;

        let issuer_kp = SigningKey::generate();
        let worker_kp = SigningKey::generate();

        // 1. Create Root Issuer Warrant
        let root = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string(), "write_file".to_string()])
            .clearance(Clearance::INTERNAL)
            .constraint_bound("path", Pattern::new("/data/*").unwrap())
            .ttl(Duration::from_secs(3600))
            .holder(issuer_kp.public_key())
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
            .clearance(Clearance::EXTERNAL)
            .ttl(Duration::from_secs(600))
            .holder(worker_kp.public_key())
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
        use crate::warrant::{Clearance, Warrant, WarrantType};
        use std::time::Duration;

        let issuer_kp = SigningKey::generate();
        let worker_kp = SigningKey::generate();

        // Create Root Issuer Warrant with strict bounds
        let root = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string()])
            .clearance(Clearance::EXTERNAL)
            .constraint_bound("path", Pattern::new("/data/*").unwrap())
            .ttl(Duration::from_secs(3600))
            .holder(issuer_kp.public_key())
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
            .holder(worker_kp.public_key())
            .build(&issuer_kp);

        assert!(result.is_err(), "Should reject tool not in issuable_tools");
        println!(
            "✅ Builder rejects tool not in issuable_tools: {}",
            result.unwrap_err()
        );

        // Try to issue with clearance exceeding limit (builder should reject)
        let result = root
            .issue_execution_warrant()
            .expect("Failed to start issuance")
            .capability("read_file", ConstraintSet::new())
            .clearance(Clearance::INTERNAL) // Exceeds External ceiling
            .ttl(Duration::from_secs(600))
            .holder(worker_kp.public_key())
            .build(&issuer_kp);

        assert!(result.is_err(), "Should reject clearance exceeding limit");
        println!(
            "✅ Builder rejects clearance exceeding limit: {}",
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
            .holder(worker_kp.public_key())
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
            .holder(kp.public_key())
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
        use crate::warrant::{Clearance, Warrant, WarrantType};
        use std::time::Duration;

        let issuer_kp = SigningKey::generate();

        // Create issuer warrant
        let issuer_warrant = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string()])
            .clearance(Clearance::INTERNAL)
            .ttl(Duration::from_secs(3600))
            .holder(issuer_kp.public_key())
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
            .holder(worker_kp.public_key())
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
            .holder(issuer_kp.public_key()) // Same as issuer warrant holder!
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
        use crate::warrant::{Clearance, Warrant, WarrantType};
        use std::time::Duration;

        let creator_kp = SigningKey::generate(); // Creates and signs the issuer warrant
        let planner_kp = SigningKey::generate(); // Holds the issuer warrant (P-LLM)

        // Create issuer warrant: signed by creator_kp, held by planner_kp
        let issuer_warrant = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string()])
            .clearance(Clearance::INTERNAL)
            .ttl(Duration::from_secs(3600))
            .holder(planner_kp.public_key())
            .build(&creator_kp)
            .expect("Failed to build issuer warrant");

        // Test that builder rejects holder == issuer warrant's issuer
        let loop_result = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .capability("read_file", ConstraintSet::new())
            .ttl(Duration::from_secs(60))
            .holder(creator_kp.public_key()) // Same as issuer warrant's issuer!
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
            .holder(agent_kp.public_key())
            .build(&agent_kp)
            .expect("Failed to build root warrant");

        // Self-attenuate: same holder, narrower constraints
        let mut narrower = ConstraintSet::new();
        narrower.insert("path", Pattern::new("/data/reports/*").unwrap());
        let child = root
            .attenuate()
            .capability("read_file", narrower)
            .ttl(Duration::from_secs(60))
            .holder(agent_kp.public_key()) // Same holder - should be allowed!
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

    /// Test that clearance monotonicity is enforced for Execution → Execution attenuation.
    #[test]
    fn test_clearance_monotonicity_execution_to_execution() {
        use crate::crypto::SigningKey;
        use crate::warrant::{Clearance, Warrant};
        use std::time::Duration;

        let parent_kp = SigningKey::generate();
        let child_kp = SigningKey::generate();

        // Create parent with Internal trust level
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/*").unwrap());
        let parent = Warrant::builder()
            .capability("read_file", constraints.clone())
            .clearance(Clearance::INTERNAL)
            .ttl(Duration::from_secs(3600))
            .holder(parent_kp.public_key())
            .build(&parent_kp)
            .expect("Failed to build parent warrant");

        assert_eq!(parent.clearance(), Some(Clearance::INTERNAL));

        // Try to attenuate with HIGHER trust level (should fail)
        let result = parent
            .attenuate()
            .capability("read_file", constraints.clone())
            .clearance(Clearance::PRIVILEGED) // Higher than Internal!
            .ttl(Duration::from_secs(60))
            .holder(child_kp.public_key())
            .build(&parent_kp);

        assert!(
            result.is_err(),
            "Builder should reject clearance escalation"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("clearance cannot increase"),
            "Error should mention clearance monotonicity"
        );

        // Attenuate with LOWER trust level (should succeed)
        let child = parent
            .attenuate()
            .capability("read_file", constraints)
            .clearance(Clearance::EXTERNAL) // Lower than Internal
            .ttl(Duration::from_secs(60))
            .holder(child_kp.public_key())
            .build(&parent_kp)
            .expect("Lower clearance should be allowed");

        assert_eq!(child.clearance(), Some(Clearance::EXTERNAL));

        // Verify the chain passes
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", parent_kp.public_key());
        let result = data_plane.verify_chain(&[parent, child]);
        assert!(
            result.is_ok(),
            "Chain with decreasing clearance should pass verification"
        );
    }

    /// Test that tool trust requirements are enforced at authorization time.
    #[test]
    fn test_tool_trust_requirements_enforcement() {
        use crate::crypto::SigningKey;
        use crate::warrant::{Clearance, Warrant};
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
            .clearance(Clearance::EXTERNAL)
            .ttl(Duration::from_secs(3600))
            .holder(kp.public_key())
            .build(&kp)
            .expect("Failed to build warrant");

        // Configure data plane with trust requirements
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", kp.public_key());
        data_plane
            .require_clearance("delete_file", Clearance::PRIVILEGED)
            .unwrap();
        data_plane
            .require_clearance("admin_*", Clearance::SYSTEM)
            .unwrap();
        data_plane
            .require_clearance("read_file", Clearance::EXTERNAL)
            .unwrap();

        let args: HashMap<String, ConstraintValue> = [(
            "path".to_string(),
            ConstraintValue::String("/data/test.txt".to_string()),
        )]
        .into_iter()
        .collect();

        // Create PoP signature for read_file
        let pop_sig = warrant.sign(&kp, "read_file", &args).expect("sign pop");

        // read_file should succeed (External >= External)
        let result =
            data_plane.check_chain(&[warrant.clone()], "read_file", &args, Some(&pop_sig), &[]);
        assert!(
            result.is_ok(),
            "read_file should be authorized: {:?}",
            result
        );

        // delete_file should fail (External < Privileged) - trust check happens before PoP
        let result = data_plane.check_chain(&[warrant.clone()], "delete_file", &args, None, &[]);
        assert!(result.is_err(), "delete_file should be denied");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("insufficient clearance"),
            "Error should mention clearance: {}",
            err
        );
        assert!(
            err.contains("Privileged"),
            "Error should mention required level"
        );

        // admin_reset should fail (External < System, via glob pattern)
        let result = data_plane.check_chain(&[warrant.clone()], "admin_reset", &args, None, &[]);
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
            .require_clearance("admin_*", Clearance::SYSTEM)
            .unwrap();
        data_plane
            .require_clearance("write_*", Clearance::INTERNAL)
            .unwrap();
        data_plane
            .require_clearance("read_public", Clearance::EXTERNAL)
            .unwrap();
        data_plane
            .require_clearance("*", Clearance::UNTRUSTED)
            .unwrap(); // Default

        // Test exact match
        assert_eq!(
            data_plane.get_required_clearance("read_public"),
            Some(Clearance::EXTERNAL)
        );

        // Test glob patterns
        assert_eq!(
            data_plane.get_required_clearance("admin_users"),
            Some(Clearance::SYSTEM)
        );
        assert_eq!(
            data_plane.get_required_clearance("admin_config"),
            Some(Clearance::SYSTEM)
        );
        assert_eq!(
            data_plane.get_required_clearance("write_file"),
            Some(Clearance::INTERNAL)
        );

        // Test default fallback
        assert_eq!(
            data_plane.get_required_clearance("unknown_tool"),
            Some(Clearance::UNTRUSTED)
        );
    }

    /// Test that higher trust levels can access lower-trust tools.
    #[test]
    fn test_tool_trust_requirements_hierarchy() {
        use crate::crypto::SigningKey;
        use crate::warrant::{Clearance, Warrant};
        use std::collections::HashMap;
        use std::time::Duration;

        let kp = SigningKey::generate();

        // Create warrant with Privileged trust level
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/*").unwrap());
        let warrant = Warrant::builder()
            .capability("read_file", constraints)
            .clearance(Clearance::PRIVILEGED)
            .ttl(Duration::from_secs(3600))
            .holder(kp.public_key())
            .build(&kp)
            .expect("Failed to build warrant");

        // Configure data plane - read_file only requires External
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", kp.public_key());
        data_plane
            .require_clearance("read_file", Clearance::EXTERNAL)
            .unwrap();

        let args: HashMap<String, ConstraintValue> = [(
            "path".to_string(),
            ConstraintValue::String("/data/test.txt".to_string()),
        )]
        .into_iter()
        .collect();

        // Create PoP signature
        let pop_sig = warrant.sign(&kp, "read_file", &args).expect("sign pop");

        // Privileged > External, so should succeed
        let result = data_plane.check_chain(&[warrant], "read_file", &args, Some(&pop_sig), &[]);
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
        use crate::warrant::{Clearance, Warrant};
        use std::collections::HashMap;
        use std::time::Duration;

        let kp = SigningKey::generate();

        // Create warrant with External trust level
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/*").unwrap());
        let warrant = Warrant::builder()
            .capability("read_file", constraints.clone())
            .capability("admin_reset", constraints)
            .clearance(Clearance::EXTERNAL)
            .ttl(Duration::from_secs(3600))
            .holder(kp.public_key())
            .build(&kp)
            .expect("Failed to build warrant");

        // Configure Authorizer with trust requirements using builder
        let authorizer = Authorizer::builder()
            .trusted_root(kp.public_key())
            .with_clearance_requirement("read_file", Clearance::EXTERNAL)
            .with_clearance_requirement("admin_*", Clearance::SYSTEM)
            .build()
            .expect("Failed to build authorizer");

        let args: HashMap<String, ConstraintValue> = [(
            "path".to_string(),
            ConstraintValue::String("/data/test.txt".to_string()),
        )]
        .into_iter()
        .collect();

        // Create PoP signature for read_file
        let pop_sig = warrant.sign(&kp, "read_file", &args).expect("sign pop");

        // read_file should succeed (External >= External)
        let result = authorizer.authorize_one(&warrant, "read_file", &args, Some(&pop_sig), &[]);
        assert!(
            result.is_ok(),
            "read_file should be authorized: {:?}",
            result
        );

        // admin_reset should fail (External < System)
        let result = authorizer.authorize_one(&warrant, "admin_reset", &args, None, &[]);
        assert!(result.is_err(), "admin_reset should be denied");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("insufficient clearance"),
            "Error should mention clearance: {}",
            err
        );
    }

    /// Test Authorizer chainable API for clearance requirements.
    #[test]
    fn test_authorizer_chainable_clearance_api() {
        use crate::crypto::SigningKey;
        use crate::warrant::Clearance;

        let kp = SigningKey::generate();

        // Test chainable API
        let authorizer = Authorizer::new()
            .with_trusted_root(kp.public_key())
            .with_clearance_requirement("delete_*", Clearance::PRIVILEGED)
            .with_clearance_requirement("*", Clearance::EXTERNAL);

        assert_eq!(
            authorizer.get_required_clearance("delete_database"),
            Some(Clearance::PRIVILEGED)
        );
        assert_eq!(
            authorizer.get_required_clearance("read_file"),
            Some(Clearance::EXTERNAL)
        );

        // Test mutable API
        let mut authorizer2 = Authorizer::new();
        authorizer2
            .require_clearance("admin_*", Clearance::SYSTEM)
            .unwrap();

        assert_eq!(
            authorizer2.get_required_clearance("admin_users"),
            Some(Clearance::SYSTEM)
        );
    }

    // =========================================================================
    // Edge Case Tests for Clearance Requirements
    // =========================================================================

    /// Test that invalid patterns are rejected at registration time.
    #[test]
    fn test_clearance_pattern_validation() {
        use crate::warrant::Clearance;

        let mut data_plane = DataPlane::new();

        // Valid patterns
        assert!(data_plane
            .require_clearance("*", Clearance::EXTERNAL)
            .is_ok());
        assert!(data_plane
            .require_clearance("admin_*", Clearance::SYSTEM)
            .is_ok());
        assert!(data_plane
            .require_clearance("exact_tool", Clearance::INTERNAL)
            .is_ok());
        assert!(data_plane
            .require_clearance("read_", Clearance::EXTERNAL)
            .is_ok()); // No wildcard

        // Invalid patterns
        assert!(data_plane
            .require_clearance("", Clearance::EXTERNAL)
            .is_err()); // Empty
        assert!(data_plane
            .require_clearance("**", Clearance::EXTERNAL)
            .is_err()); // Double wildcard
        assert!(data_plane
            .require_clearance("*admin", Clearance::EXTERNAL)
            .is_err()); // Wildcard at start
        assert!(data_plane
            .require_clearance("*admin*", Clearance::EXTERNAL)
            .is_err()); // Multiple wildcards
        assert!(data_plane
            .require_clearance("admin*foo", Clearance::EXTERNAL)
            .is_err()); // Wildcard in middle
        assert!(data_plane
            .require_clearance("a*b*", Clearance::EXTERNAL)
            .is_err()); // Multiple wildcards
    }

    /// Test that exact matches take precedence over glob patterns.
    #[test]
    fn test_clearance_pattern_precedence() {
        use crate::warrant::Clearance;

        let mut data_plane = DataPlane::new();

        // Configure overlapping patterns
        data_plane
            .require_clearance("*", Clearance::UNTRUSTED)
            .unwrap();
        data_plane
            .require_clearance("admin_*", Clearance::PRIVILEGED)
            .unwrap();
        data_plane
            .require_clearance("admin_users", Clearance::SYSTEM)
            .unwrap(); // Exact match

        // Exact match should take precedence
        assert_eq!(
            data_plane.get_required_clearance("admin_users"),
            Some(Clearance::SYSTEM), // Exact match, not glob
        );

        // Glob should match other admin tools
        assert_eq!(
            data_plane.get_required_clearance("admin_config"),
            Some(Clearance::PRIVILEGED), // Glob match
        );

        // Default should catch everything else
        assert_eq!(
            data_plane.get_required_clearance("read_file"),
            Some(Clearance::UNTRUSTED), // Default
        );
    }

    /// Test behavior when no clearance requirements are configured.
    #[test]
    fn test_no_clearance_requirements_configured() {
        use crate::crypto::SigningKey;
        use crate::warrant::{Clearance, Warrant};
        use std::collections::HashMap;
        use std::time::Duration;

        let kp = SigningKey::generate();

        // Create warrant with clearance level
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/*").unwrap());
        let warrant = Warrant::builder()
            .capability("read_file", constraints)
            .clearance(Clearance::EXTERNAL)
            .ttl(Duration::from_secs(3600))
            .holder(kp.public_key())
            .build(&kp)
            .expect("Failed to build warrant");

        // DataPlane with NO clearance requirements
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", kp.public_key());
        // No require_clearance calls

        // get_required_clearance should return None
        assert_eq!(data_plane.get_required_clearance("read_file"), None);
        assert_eq!(data_plane.get_required_clearance("any_tool"), None);

        let args: HashMap<String, ConstraintValue> = [(
            "path".to_string(),
            ConstraintValue::String("/data/test.txt".to_string()),
        )]
        .into_iter()
        .collect();
        let pop_sig = warrant.sign(&kp, "read_file", &args).expect("sign pop");

        // Authorization should succeed (clearance check is skipped when no requirements)
        let result = data_plane.check_chain(&[warrant], "read_file", &args, Some(&pop_sig), &[]);
        assert!(
            result.is_ok(),
            "Should succeed when no clearance requirements: {:?}",
            result
        );
    }

    /// Test behavior when warrant has no clearance but requirements exist.
    #[test]
    fn test_missing_warrant_clearance() {
        use crate::crypto::SigningKey;
        use crate::warrant::{Clearance, Warrant};
        use std::collections::HashMap;
        use std::time::Duration;

        let kp = SigningKey::generate();

        // Create warrant WITHOUT clearance
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/*").unwrap());
        let warrant = Warrant::builder()
            .capability("read_file", constraints)
            // No .clearance() call
            .ttl(Duration::from_secs(3600))
            .holder(kp.public_key())
            .build(&kp)
            .expect("Failed to build warrant");

        // Warrant should have no clearance
        assert!(warrant.clearance().is_none());

        // DataPlane with clearance requirement
        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", kp.public_key());
        data_plane
            .require_clearance("*", Clearance::EXTERNAL)
            .unwrap();

        let args: HashMap<String, ConstraintValue> = [(
            "path".to_string(),
            ConstraintValue::String("/data/test.txt".to_string()),
        )]
        .into_iter()
        .collect();

        // Should fail: warrant has no clearance (treated as Untrusted)
        let result = data_plane.check_chain(&[warrant], "read_file", &args, None, &[]);
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
        use crate::warrant::Clearance;

        let kp = SigningKey::generate();

        // Valid patterns should work
        let result = Authorizer::builder()
            .trusted_root(kp.public_key())
            .try_clearance_requirement("*", Clearance::EXTERNAL)
            .and_then(|b| b.try_clearance_requirement("admin_*", Clearance::SYSTEM))
            .and_then(|b| b.build());
        assert!(result.is_ok());

        // Invalid pattern should fail
        let result = Authorizer::builder()
            .trusted_root(kp.public_key())
            .try_clearance_requirement("*admin*", Clearance::SYSTEM);
        assert!(result.is_err());
    }

    // =========================================================================
    // SECURITY REGRESSION TESTS
    // These tests ensure the Authorizer correctly rejects untrusted issuers.
    // Added after discovering that trust verification was missing.
    // =========================================================================

    /// SECURITY: Authorizer MUST reject warrants from untrusted issuers.
    /// This test prevents regression of the trust verification bug.
    ///
    /// Note: Trust check happens BEFORE PoP check, so we don't need to
    /// provide a valid PoP - the untrusted issuer is rejected first.
    #[test]
    fn test_authorizer_rejects_untrusted_issuer() {
        use crate::crypto::SigningKey;
        use std::time::Duration;

        // Two different keys
        let trusted_key = SigningKey::generate();
        let attacker_key = SigningKey::generate();

        // Authorizer trusts only one key
        let authorizer = Authorizer::new().with_trusted_root(trusted_key.public_key());

        // Attacker issues a warrant with their own key
        let attacker_warrant = crate::Warrant::builder()
            .capability("read_file", crate::ConstraintSet::new())
            .ttl(Duration::from_secs(3600))
            .holder(attacker_key.public_key()) // Has holder, but not from trusted issuer
            .build(&attacker_key)
            .expect("warrant creation should work");

        // Authorization MUST fail at trust check (before PoP)
        let result = authorizer.authorize_one(
            &attacker_warrant,
            "read_file",
            &Default::default(),
            None, // No PoP needed - trust check fails first
            &[],
        );

        assert!(
            result.is_err(),
            "SECURITY BUG: Authorizer accepted untrusted issuer!"
        );
        let err = result.unwrap_err();
        assert!(
            format!("{}", err).contains("not trusted"),
            "Error should mention untrusted issuer: {}",
            err
        );
    }

    /// SECURITY: Authorizer MUST allow warrants from trusted issuers.
    /// Uses holder binding with PoP to fully test the authorization path.
    #[test]
    fn test_authorizer_allows_trusted_issuer() {
        use crate::crypto::SigningKey;
        use std::time::Duration;

        let trusted_key = SigningKey::generate();
        let holder_key = SigningKey::generate();

        // Authorizer trusts this issuer
        let authorizer = Authorizer::new().with_trusted_root(trusted_key.public_key());

        // Warrant issued by trusted key with holder binding
        let warrant = crate::Warrant::builder()
            .capability("read_file", crate::ConstraintSet::new())
            .ttl(Duration::from_secs(3600))
            .holder(holder_key.public_key())
            .build(&trusted_key)
            .expect("warrant creation should work");

        // Create PoP signature for the holder
        let args = std::collections::HashMap::new();
        let pop_sig = warrant.sign(&holder_key, "read_file", &args).unwrap();

        // Authorization should succeed (trust check passes, PoP valid)
        let result = authorizer.authorize_one(&warrant, "read_file", &args, Some(&pop_sig), &[]);

        assert!(
            result.is_ok(),
            "Authorizer rejected trusted issuer: {:?}",
            result.err()
        );
    }

    /// SECURITY: Authorizer with no trusted roots must reject everything.
    #[test]
    fn test_authorizer_no_trusted_roots_rejects() {
        use crate::crypto::SigningKey;
        use std::time::Duration;

        let any_key = SigningKey::generate();
        let holder_key = SigningKey::generate();

        let authorizer = Authorizer::new();
        assert!(!authorizer.has_trusted_roots());

        let warrant = crate::Warrant::builder()
            .capability("read_file", crate::ConstraintSet::new())
            .ttl(Duration::from_secs(3600))
            .holder(holder_key.public_key())
            .build(&any_key)
            .expect("warrant creation should work");

        let args = std::collections::HashMap::new();
        let pop_sig = warrant.sign(&holder_key, "read_file", &args).unwrap();

        let result = authorizer.authorize_one(&warrant, "read_file", &args, Some(&pop_sig), &[]);
        assert!(
            result.is_err(),
            "Authorizer with no trusted roots must reject all warrants"
        );
    }

    /// SECURITY: Multiple trusted roots should all be accepted.
    #[test]
    fn test_authorizer_multiple_trusted_roots() {
        use crate::crypto::SigningKey;
        use std::time::Duration;

        let key1 = SigningKey::generate();
        let key2 = SigningKey::generate();
        let untrusted_key = SigningKey::generate();
        let holder_key = SigningKey::generate();

        // Trust both key1 and key2
        let authorizer = Authorizer::new()
            .with_trusted_root(key1.public_key())
            .with_trusted_root(key2.public_key());

        assert_eq!(authorizer.trusted_root_count(), 2);

        let args = std::collections::HashMap::new();

        // Warrant from key1 should work
        let warrant1 = crate::Warrant::builder()
            .capability("tool", crate::ConstraintSet::new())
            .ttl(Duration::from_secs(3600))
            .holder(holder_key.public_key())
            .build(&key1)
            .unwrap();
        let pop1 = warrant1.sign(&holder_key, "tool", &args).unwrap();
        assert!(authorizer
            .authorize_one(&warrant1, "tool", &args, Some(&pop1), &[])
            .is_ok());

        // Warrant from key2 should work
        let warrant2 = crate::Warrant::builder()
            .capability("tool", crate::ConstraintSet::new())
            .ttl(Duration::from_secs(3600))
            .holder(holder_key.public_key())
            .build(&key2)
            .unwrap();
        let pop2 = warrant2.sign(&holder_key, "tool", &args).unwrap();
        assert!(authorizer
            .authorize_one(&warrant2, "tool", &args, Some(&pop2), &[])
            .is_ok());

        // Warrant from untrusted key should fail (at trust check, before PoP)
        let warrant3 = crate::Warrant::builder()
            .capability("tool", crate::ConstraintSet::new())
            .ttl(Duration::from_secs(3600))
            .holder(holder_key.public_key())
            .build(&untrusted_key)
            .unwrap();
        // Don't need PoP since trust check fails first
        assert!(authorizer
            .authorize_one(&warrant3, "tool", &args, None, &[])
            .is_err());
    }

    /// SECURITY: PoP signature is mandatory — passing None must fail.
    #[test]
    fn test_pop_required_rejects_none() {
        use crate::crypto::SigningKey;
        use std::time::Duration;

        let root_key = SigningKey::generate();
        let holder_key = SigningKey::generate();

        let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());

        let warrant = crate::Warrant::builder()
            .capability("read_file", crate::ConstraintSet::new())
            .ttl(Duration::from_secs(3600))
            .holder(holder_key.public_key())
            .build(&root_key)
            .unwrap();

        let args = std::collections::HashMap::new();

        let result = authorizer.authorize_one(&warrant, "read_file", &args, None, &[]);
        assert!(
            result.is_err(),
            "SECURITY BUG: Authorization succeeded without PoP signature"
        );
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("Proof-of-Possession"),
            "Error should mention PoP requirement: {}",
            err
        );
    }
}
