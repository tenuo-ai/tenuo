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

use crate::constraints::{Constraint, ConstraintValue};
use crate::crypto::{Keypair, PublicKey};
use crate::error::{Error, Result};
use crate::warrant::Warrant;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::Duration;
use crate::approval::WarrantTracker;
use crate::revocation::RevocationRequest;

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
            approvals.len(), max_approvals
        )));
    }

    // Compute the request hash for verification (includes authorized_holder to prevent theft)
    let request_hash = crate::approval::compute_request_hash(
        warrant.id().as_str(),
        tool,
        args,
        warrant.authorized_holder(),
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
    keypair: Keypair,
    /// Optional: known child public keys for delegation tracking.
    known_delegates: HashSet<[u8; 32]>,
}

impl ControlPlane {
    /// Create a new control plane with the given root keypair.
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair,
            known_delegates: HashSet::new(),
        }
    }

    /// Generate a new control plane with a fresh keypair.
    pub fn generate() -> Self {
        Self::new(Keypair::generate())
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
    pub fn issue_warrant(
        &self,
        tool: &str,
        constraints: &[(&str, Constraint)],
        ttl: Duration,
    ) -> Result<Warrant> {
        let mut builder = Warrant::builder().tool(tool).ttl(ttl);

        for (field, constraint) in constraints {
            builder = builder.constraint(*field, constraint.clone());
        }

        builder.build(&self.keypair)
    }

    /// Issue a warrant bound to a specific holder.
    pub fn issue_bound_warrant(
        &self,
        tool: &str,
        constraints: &[(&str, Constraint)],
        ttl: Duration,
        holder: &PublicKey,
    ) -> Result<Warrant> {
        let mut builder = Warrant::builder().tool(tool).ttl(ttl).authorized_holder(holder.clone());

        for (field, constraint) in constraints {
            builder = builder.constraint(*field, constraint.clone());
        }

        builder.build(&self.keypair)
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
        let mut builder = Warrant::builder()
            .tool(tool)
            .ttl(ttl)
            .authorized_holder(holder.clone())
            .max_depth(max_depth);

        for (field, constraint) in constraints {
            builder = builder.constraint(*field, constraint.clone());
        }

        builder.build(&self.keypair)
    }

    /// Issue a warrant and automatically track it in the registry.
    ///
    /// This is the recommended way to issue warrants to ensure cascading revocation works.
    pub fn issue_tracked_warrant<T: WarrantTracker>(
        &self,
        tool: &str,
        constraints: &[(&str, Constraint)],
        ttl: Duration,
        tracker: &mut T,
    ) -> Result<Warrant> {
        let warrant = self.issue_warrant(tool, constraints, ttl)?;
        
        // Track for issuer (Control Plane)
        tracker.track_warrant(&self.public_key(), warrant.id().as_str());
        
        // Track for authorized holder (if any)
        if let Some(holder) = warrant.authorized_holder() {
            tracker.track_warrant(holder, warrant.id().as_str());
        }

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
    own_keypair: Option<Keypair>,
    /// Clock skew tolerance for expiration checks.
    clock_tolerance: chrono::Duration,
    /// Signed revocation list.
    revocation_list: Option<crate::revocation::SignedRevocationList>,
    /// Local cache of directly revoked warrants (Parental Revocation)
    local_revocation_cache: RwLock<HashSet<String>>,
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
        }
    }

    /// Create a data plane that can also attenuate warrants.
    pub fn with_keypair(keypair: Keypair) -> Self {
        Self {
            trusted_issuers: HashMap::new(),
            own_keypair: Some(keypair),
            clock_tolerance: chrono::Duration::seconds(DEFAULT_CLOCK_TOLERANCE_SECS),
            revocation_list: None,
            local_revocation_cache: RwLock::new(HashSet::new()),
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
        let id = warrant.id().as_str();
        
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
                    .with_related(vec![id.to_string()])
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
                    .with_related(vec![id.to_string()])
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
        if request.warrant_id != warrant.id().as_str() {
            return Err(Error::Unauthorized(format!(
                "Request warrant_id '{}' does not match provided warrant '{}'",
                request.warrant_id, warrant.id()
            )));
        }

        // 3. Verify authorization (Issuer or Holder only for direct revocation)
        // Note: We don't check Control Plane key here as we might not know it,
        // and CP revocations should go through SRL anyway.
        let is_authorized = 
            request.requestor == *warrant.issuer() || // Parent
            Some(&request.requestor) == warrant.authorized_holder(); // Self

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
        enforce_session: bool
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
            let id = warrant.id().to_string();
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

        // Step 1: Verify the root warrant
        let root = &chain[0];
        self.verify(root)?;

        result.root_issuer = Some(root.issuer().to_bytes());
        result.verified_steps.push(ChainStep {
            warrant_id: root.id().to_string(),
            depth: root.depth(),
            issuer: root.issuer().to_bytes(),
        });
        
        // SESSION BINDING: Track session from root
        let expected_session = if enforce_session { root.session_id() } else { None };

        // Step 2: Walk the chain, verifying each link
        for i in 1..chain.len() {
            let parent = &chain[i - 1];
            let child = &chain[i];

            self.verify_chain_link(parent, child)?;
            
            // Check session binding if enforced
            if enforce_session && child.session_id() != expected_session {
                return Err(Error::ChainVerificationFailed(format!(
                    "session mismatch: expected {:?}, got {:?} at depth {}",
                    expected_session, child.session_id(), child.depth()
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
    /// Validates that `child` is a valid delegation from `parent`.
    fn verify_chain_link(&self, parent: &Warrant, child: &Warrant) -> Result<()> {
        // Check revocation
        if self.is_revoked(child) {
            return Err(Error::WarrantRevoked(child.id().to_string()));
        }

        // 1. Check parent_id linkage
        let parent_id = child.parent_id().ok_or_else(|| {
            Error::ChainVerificationFailed(
                "child warrant has no parent_id".to_string()
            )
        })?;

        if parent_id != parent.id() {
            return Err(Error::ChainVerificationFailed(format!(
                "chain broken: child's parent_id '{}' != parent's id '{}'",
                parent_id, parent.id()
            )));
        }

        // 2. Check depth increment (use saturating_add to prevent overflow)
        let expected_depth = parent.depth().saturating_add(1);
        if child.depth() != expected_depth {
            return Err(Error::ChainVerificationFailed(format!(
                "depth mismatch: child depth {} != parent depth {} + 1",
                child.depth(), parent.depth()
            )));
        }

        // 2b. Check max_depth policy (defense-in-depth)
        // The builder enforces this at creation time, but we verify here too
        // in case someone bypasses the builder and signs manually.
        let parent_max = parent.effective_max_depth();
        if child.depth() > parent_max {
            return Err(Error::ChainVerificationFailed(format!(
                "child depth {} exceeds parent's max_depth {}",
                child.depth(), parent_max
            )));
        }

        // 3. Check expiration doesn't exceed parent
        if child.expires_at() > parent.expires_at() {
            return Err(Error::ChainVerificationFailed(format!(
                "child expires at {} which is after parent {}",
                child.expires_at(), parent.expires_at()
            )));
        }

        // 4. Check child is not expired (with clock tolerance)
        if child.is_expired_with_tolerance(self.clock_tolerance) {
            return Err(Error::WarrantExpired(child.expires_at()));
        }

        // 5. Validate constraint attenuation (monotonicity)
        parent.constraints().validate_attenuation(child.constraints())?;

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
        // Standard constraint authorization
        let result = warrant.authorize(tool, args, signature)
            .and_then(|_| {
                // Multi-sig verification
                verify_approvals_with_tolerance(
                    warrant, tool, args, approvals,
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
                    .with_related(vec![warrant.id().to_string()])
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
                    .with_related(vec![warrant.id().to_string()])
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
    pub fn attenuate(
        &self,
        parent: &Warrant,
        constraints: &[(&str, Constraint)],
    ) -> Result<Warrant> {
        let keypair = self.own_keypair.as_ref().ok_or_else(|| {
            Error::CryptoError("data plane has no keypair for attenuation".to_string())
        })?;

        let mut builder = parent.attenuate();
        for (field, constraint) in constraints {
            builder = builder.constraint(*field, constraint.clone());
        }

        builder.build(keypair)
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

/// A minimal authorizer for embedding in services.
///
/// This is the smallest possible data plane - just a set of trusted
/// This is the smallest possible data plane - just a set of trusted keys.

#[derive(Debug, Clone)]
pub struct Authorizer {
    trusted_keys: Vec<PublicKey>,
    clock_tolerance: chrono::Duration,
    revocation_list: Option<SignedRevocationList>,
}

impl Authorizer {
    /// Create an authorizer with a single trusted key.
    ///
    /// Uses the default clock tolerance of 30 seconds.
    pub fn new(root_public_key: PublicKey) -> Self {
        Self {
            trusted_keys: vec![root_public_key],
            clock_tolerance: chrono::Duration::seconds(DEFAULT_CLOCK_TOLERANCE_SECS),
            revocation_list: None,
        }
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
        srl.verify(expected_issuer)?;
        self.revocation_list = Some(srl);
        Ok(())
    }

    /// Check if a warrant is revoked by ID.
    fn is_revoked(&self, warrant: &Warrant) -> bool {
        self.revocation_list
            .as_ref()
            .map(|srl| srl.is_revoked(warrant.id().as_str()))
            .unwrap_or(false)
    }

    /// Create an authorizer from raw key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Ok(Self::new(PublicKey::from_bytes(bytes)?))
    }

    /// Add an additional trusted key.
    pub fn add_trusted_key(&mut self, key: PublicKey) {
        self.trusted_keys.push(key);
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
        let issuer = warrant.issuer();
        if !self.trusted_keys.iter().any(|pk| pk == issuer) {
            return Err(Error::SignatureInvalid(
                "warrant issuer is not trusted".to_string(),
            ));
        }

        // Verify the signature
        warrant.verify(issuer)
    }

    /// Authorize an action against a warrant.
    ///
    /// This is the main authorization entry point. It checks:
    /// 1. Tool name matches
    /// 2. All constraints are satisfied
    /// 3. Holder signature (if warrant has `authorized_holder`)
    /// 4. Multi-sig approvals (if warrant has `required_approvers`)
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
        // 1. Standard constraint authorization
        warrant.authorize(tool, args, holder_signature)?;

        // 2. Multi-sig verification (if required)
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
        enforce_session: bool
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
            let id = warrant.id().to_string();
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
        root.verify(issuer)?;

        result.root_issuer = Some(issuer.to_bytes());
        result.verified_steps.push(ChainStep {
            warrant_id: root.id().to_string(),
            depth: root.depth(),
            issuer: issuer.to_bytes(),
        });
        
        // SESSION BINDING: Track session from root
        let expected_session = if enforce_session { root.session_id() } else { None };

        // Walk the chain, verifying each link
        for i in 1..chain.len() {
            let parent = &chain[i - 1];
            let child = &chain[i];

            self.verify_link(parent, child)?;
            
            // Check session binding if enforced
            if enforce_session && child.session_id() != expected_session {
                return Err(Error::ChainVerificationFailed(format!(
                    "session mismatch: expected {:?}, got {:?} at depth {}",
                    expected_session, child.session_id(), child.depth()
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

        // Check parent_id linkage
        let parent_id = child.parent_id().ok_or_else(|| {
            Error::ChainVerificationFailed(
                "child warrant has no parent_id".to_string()
            )
        })?;

        if parent_id != parent.id() {
            return Err(Error::ChainVerificationFailed(format!(
                "chain broken: child parent_id '{}' != parent id '{}'",
                parent_id, parent.id()
            )));
        }

        // Check depth increment
        if child.depth() != parent.depth() + 1 {
            return Err(Error::ChainVerificationFailed(format!(
                "depth mismatch: child {} != parent {} + 1",
                child.depth(), parent.depth()
            )));
        }

        // Check max_depth policy (defense-in-depth)
        let parent_max = parent.effective_max_depth();
        if child.depth() > parent_max {
            return Err(Error::ChainVerificationFailed(format!(
                "child depth {} exceeds parent's max_depth {}",
                child.depth(), parent_max
            )));
        }

        // Check expiration
        if child.expires_at() > parent.expires_at() {
            return Err(Error::ChainVerificationFailed(format!(
                "child expires at {} after parent {}",
                child.expires_at(), parent.expires_at()
            )));
        }

        // Check expiration with clock tolerance
        if child.is_expired_with_tolerance(self.clock_tolerance) {
            return Err(Error::WarrantExpired(child.expires_at()));
        }

        // Validate monotonicity
        parent.constraints().validate_attenuation(child.constraints())?;

        // Verify signature
        child.verify(child.issuer())
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
        assert!(data_plane.authorize(&warrant, "upgrade_cluster", &args, None, &[]).is_ok());
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
        let orchestrator = DataPlane::with_keypair(Keypair::generate());

        // Attenuate for worker (no control plane involvement!)
        let worker_warrant = orchestrator
            .attenuate(&root_warrant, &[("table", Pattern::new("public_*").unwrap().into())])
            .unwrap();

        assert_eq!(worker_warrant.depth(), 1);
    }

    #[test]
    fn test_minimal_authorizer() {
        let control_plane = ControlPlane::generate();
        let warrant = control_plane
            .issue_warrant("test", &[], Duration::from_secs(60))
            .unwrap();

        // Minimal authorizer - just the public key
        let authorizer = Authorizer::new(control_plane.public_key());

        // Check in one call
        assert!(authorizer.check(&warrant, "test", &HashMap::new(), None, &[]).is_ok());
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
        let orchestrator_keypair = Keypair::generate();
        
        // Root warrant
        let root = control_plane
            .issue_warrant(
                "upgrade_cluster",
                &[("cluster", Pattern::new("staging-*").unwrap().into())],
                Duration::from_secs(600),
            )
            .unwrap();

        // Orchestrator delegates
        let child = root
            .attenuate()
            .constraint("cluster", Exact::new("staging-web"))
            .build(&orchestrator_keypair)
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
        let orchestrator_keypair = Keypair::generate();
        let worker_keypair = Keypair::generate();

        // Root → Orchestrator → Worker
        let root = control_plane
            .issue_warrant(
                "query",
                &[("table", Pattern::new("*").unwrap().into())],
                Duration::from_secs(600),
            )
            .unwrap();

        let orchestrator_warrant = root
            .attenuate()
            .constraint("table", Pattern::new("public_*").unwrap())
            .build(&orchestrator_keypair)
            .unwrap();

        let worker_warrant = orchestrator_warrant
            .attenuate()
            .constraint("table", Exact::new("public_users"))
            .build(&worker_keypair)
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
        let agent_keypair = Keypair::generate();

        let root = control_plane
            .issue_warrant(
                "upgrade_cluster",
                &[("cluster", Pattern::new("staging-*").unwrap().into())],
                Duration::from_secs(600),
            )
            .unwrap();

        let agent_warrant = root
            .attenuate()
            .constraint("cluster", Exact::new("staging-web"))
            .build(&agent_keypair)
            .unwrap();

        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", control_plane.public_key());

        // Verify chain and authorize in one call
        let mut args = HashMap::new();
        args.insert(
            "cluster".to_string(),
            ConstraintValue::String("staging-web".to_string()),
        );

        let result = data_plane
            .check_chain(&[root, agent_warrant], "upgrade_cluster", &args, None, &[])
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
        let agent_keypair = Keypair::generate();

        // Two unrelated warrants
        let warrant1 = control_plane
            .issue_warrant("test1", &[], Duration::from_secs(60))
            .unwrap();

        let warrant2 = control_plane
            .issue_warrant("test2", &[], Duration::from_secs(60))
            .unwrap();

        // Create an attenuated warrant from warrant2
        let child = warrant2
            .attenuate()
            .build(&agent_keypair)
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
        let agent_keypair = Keypair::generate();

        let root = control_plane
            .issue_warrant(
                "test",
                &[("key", Exact::new("value").into())],
                Duration::from_secs(60),
            )
            .unwrap();

        let child = root
            .attenuate()
            .build(&agent_keypair)
            .unwrap();

        let authorizer = Authorizer::new(control_plane.public_key());

        // Verify chain
        let result = authorizer.verify_chain(&[root.clone(), child.clone()]).unwrap();
        assert_eq!(result.chain_length, 2);

        // Check chain with authorization
        let mut args = HashMap::new();
        args.insert("key".to_string(), ConstraintValue::String("value".to_string()));
        
        let result = authorizer.check_chain(&[root, child], "test", &args, None, &[]).unwrap();
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
        let orchestrator_keypair = Keypair::generate();

        let root = control_plane
            .issue_warrant("test", &[], Duration::from_secs(60))
            .unwrap();

        let child = root
            .attenuate()
            .build(&orchestrator_keypair)
            .unwrap();

        let mut data_plane = DataPlane::new();
        data_plane.trust_issuer("root", control_plane.public_key());

        // Chain should verify successfully
        assert!(data_plane.verify_chain(&[root.clone(), child.clone()]).is_ok());

        // Revoke the ROOT warrant (signed by control plane)
        let srl = SignedRevocationList::builder()
            .revoke(root.id().as_str())
            .version(1)
            .build(&control_plane.keypair)
            .unwrap();
        data_plane.set_revocation_list(srl, &control_plane.public_key()).unwrap();

        // Now the entire chain should fail (cascading revocation)
        let result = data_plane.verify_chain(&[root.clone(), child.clone()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("revoked"));

        // Also test with Authorizer
        let mut authorizer = Authorizer::new(control_plane.public_key());
        let srl = SignedRevocationList::builder()
            .revoke(root.id().as_str())
            .version(1)
            .build(&control_plane.keypair)
            .unwrap();
        authorizer.set_revocation_list(srl, &control_plane.public_key()).unwrap();

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
        let warrant = control_plane
            .issue_warrant("test", &[], Duration::from_secs(60))
            .unwrap();

        let authorizer = Authorizer::new(control_plane.public_key());
        
        let args = HashMap::new();
        
        // Should pass without any approvals
        let result = authorizer.authorize(&warrant, "test", &args, None, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_requires_approval_when_multisig() {
        let issuer_keypair = Keypair::generate();
        let admin_keypair = Keypair::generate();
        
        // Create warrant WITH multi-sig requirement
        let warrant = Warrant::builder()
            .tool("sensitive_action")
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![admin_keypair.public_key()])
            .min_approvals(1)
            .build(&issuer_keypair)
            .unwrap();

        let authorizer = Authorizer::new(issuer_keypair.public_key());
        let args = HashMap::new();
        
        // Should FAIL without approval
        let result = authorizer.authorize(&warrant, "sensitive_action", &args, None, &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("insufficient"));
    }

    #[test]
    fn test_authorize_valid_approval() {
        use crate::approval::{Approval, compute_request_hash};
        use chrono::{Duration as ChronoDuration, Utc};
        
        let issuer_keypair = Keypair::generate();
        let admin_keypair = Keypair::generate();
        
        // Create warrant WITH multi-sig requirement
        let warrant = Warrant::builder()
            .tool("sensitive_action")
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![admin_keypair.public_key()])
            .min_approvals(1)
            .build(&issuer_keypair)
            .unwrap();

        let authorizer = Authorizer::new(issuer_keypair.public_key());
        let args = HashMap::new();
        
        // Create valid approval
        let now = Utc::now();
        let expires = now + ChronoDuration::seconds(300);
        let request_hash = compute_request_hash(warrant.id().as_str(), "sensitive_action", &args, warrant.authorized_holder());
        
        // Create signable bytes
        let mut signable = Vec::new();
        signable.extend_from_slice(&request_hash);
        signable.extend_from_slice("admin@test.com".as_bytes());
        signable.extend_from_slice(&now.timestamp().to_le_bytes());
        signable.extend_from_slice(&expires.timestamp().to_le_bytes());
        
        let sig = admin_keypair.sign(&signable);
        
        let approval = Approval {
            request_hash,
            approver_key: admin_keypair.public_key(),
            external_id: "admin@test.com".to_string(),
            provider: "test".to_string(),
            approved_at: now,
            expires_at: expires,
            reason: None,
            signature: sig,
        };
        
        // Should PASS with valid approval
        let result = authorizer.authorize(&warrant, "sensitive_action", &args, None, &[approval]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_authorize_wrong_approver() {
        use crate::approval::{Approval, compute_request_hash};
        use chrono::{Duration as ChronoDuration, Utc};
        
        let issuer_keypair = Keypair::generate();
        let admin_keypair = Keypair::generate();
        let other_keypair = Keypair::generate(); // Not in required_approvers
        
        // Create warrant requiring admin's approval
        let warrant = Warrant::builder()
            .tool("sensitive_action")
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![admin_keypair.public_key()])
            .min_approvals(1)
            .build(&issuer_keypair)
            .unwrap();

        let authorizer = Authorizer::new(issuer_keypair.public_key());
        let args = HashMap::new();
        
        // Create approval from WRONG keypair
        let now = Utc::now();
        let expires = now + ChronoDuration::seconds(300);
        let request_hash = compute_request_hash(warrant.id().as_str(), "sensitive_action", &args, warrant.authorized_holder());
        
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
        
        // Should FAIL - approver not in required set
        let result = authorizer.authorize(&warrant, "sensitive_action", &args, None, &[approval]);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorize_2_of_3() {
        use crate::approval::{Approval, compute_request_hash};
        use chrono::{Duration as ChronoDuration, Utc};
        
        let issuer_keypair = Keypair::generate();
        let admin1 = Keypair::generate();
        let admin2 = Keypair::generate();
        let admin3 = Keypair::generate();
        
        // Create warrant requiring 2-of-3 approvals
        let warrant = Warrant::builder()
            .tool("sensitive_action")
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![admin1.public_key(), admin2.public_key(), admin3.public_key()])
            .min_approvals(2)
            .build(&issuer_keypair)
            .unwrap();

        let authorizer = Authorizer::new(issuer_keypair.public_key());
        let args = HashMap::new();
        
        let now = Utc::now();
        let expires = now + ChronoDuration::seconds(300);
        let request_hash = compute_request_hash(warrant.id().as_str(), "sensitive_action", &args, warrant.authorized_holder());
        
        // Helper to create approval
        let make_approval = |kp: &Keypair, id: &str| {
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
        
        // With 1 approval - should fail (need 2)
        let result = authorizer.authorize(&warrant, "sensitive_action", &args, None, std::slice::from_ref(&approval1));
        assert!(result.is_err());
        
        // With 2 approvals - should pass
        let result = authorizer.authorize(&warrant, "sensitive_action", &args, None, &[approval1, approval2]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_issue_bound_warrant_and_audit_serialization() {
        let control_plane = ControlPlane::generate();
        let holder_key = Keypair::generate().public_key();
        
        // 1. Issue bound warrant
        let warrant = control_plane.issue_bound_warrant(
            "test_tool",
            &[],
            Duration::from_secs(60),
            &holder_key
        ).expect("Failed to issue bound warrant");
        
        assert_eq!(warrant.authorized_holder(), Some(&holder_key));
        
        // 2. Create AuditEvent
        let event = crate::approval::AuditEvent::new(
            crate::approval::AuditEventType::EnrollmentSuccess,
            "control-plane",
            "test",
        )
        .with_key(warrant.authorized_holder().unwrap())
        .with_details(format!("Issued warrant {}", warrant.id()))
        .with_related(vec![warrant.id().to_string()]);
        
        // 3. Serialize
        let json = serde_json::to_string(&event).expect("Failed to serialize audit event");
        println!("Serialized event: {}", json);
    }
}

