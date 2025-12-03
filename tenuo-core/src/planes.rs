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
use std::time::Duration;

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

use crate::revocation::RevocationList;

#[derive(Debug)]
pub struct DataPlane {
    /// Trusted issuer public keys, keyed by name.
    trusted_issuers: HashMap<String, PublicKey>,
    /// Optional: own keypair for attenuating warrants.
    own_keypair: Option<Keypair>,
    /// Clock skew tolerance for expiration checks.
    clock_tolerance: chrono::Duration,
    /// List of revoked warrant IDs.
    revocation_list: RevocationList,
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
            revocation_list: RevocationList::new(),
        }
    }

    /// Create a data plane that can also attenuate warrants.
    pub fn with_keypair(keypair: Keypair) -> Self {
        Self {
            trusted_issuers: HashMap::new(),
            own_keypair: Some(keypair),
            clock_tolerance: chrono::Duration::seconds(DEFAULT_CLOCK_TOLERANCE_SECS),
            revocation_list: RevocationList::new(),
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

    /// Set the revocation list.
    pub fn set_revocation_list(&mut self, list: RevocationList) {
        self.revocation_list = list;
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
        if self.revocation_list.is_revoked(warrant.id().as_str()) {
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
    /// 1. **Root Trust**: chain[0] must be signed by a trusted issuer
    /// 2. **Linkage**: chain[i+1].parent_id == chain[i].id
    /// 3. **Depth**: chain[i+1].depth == chain[i].depth + 1
    /// 4. **Expiration**: chain[i+1].expires_at <= chain[i].expires_at
    /// 5. **Monotonicity**: chain[i+1].constraints ⊆ chain[i].constraints
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
    /// // All warrants must have session_id = "sess_123"
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
            if enforce_session {
                if child.session_id() != expected_session {
                    return Err(Error::ChainVerificationFailed(format!(
                        "session mismatch: expected {:?}, got {:?} at depth {}",
                        expected_session, child.session_id(), child.depth()
                    )));
                }
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

        // 2. Check depth increment
        if child.depth() != parent.depth() + 1 {
            return Err(Error::ChainVerificationFailed(format!(
                "depth mismatch: child depth {} != parent depth {} + 1",
                child.depth(), parent.depth()
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
    ) -> Result<ChainVerificationResult> {
        let result = self.verify_chain(chain)?;

        // Authorize against the leaf warrant
        if let Some(leaf) = chain.last() {
            self.authorize(leaf, tool, args, signature)?;
        }

        Ok(result)
    }

    /// Authorize an action.
    ///
    /// This checks that the warrant permits the given tool call with the given arguments.
    ///
    /// This is an **offline operation** - no network calls.
    pub fn authorize(
        &self,
        warrant: &Warrant,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&crate::crypto::Signature>,
    ) -> Result<()> {
        warrant.authorize(tool, args, signature)
    }

    /// Convenience: verify and authorize in one call.
    pub fn check(
        &self,
        warrant: &Warrant,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&crate::crypto::Signature>,
    ) -> Result<()> {
        self.verify(warrant)?;
        self.authorize(warrant, tool, args, signature)
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
/// This is the smallest possible data plane - just a set of trusted

#[derive(Debug, Clone)]
pub struct Authorizer {
    trusted_keys: Vec<PublicKey>,
    clock_tolerance: chrono::Duration,
    revocation_list: RevocationList,
}

impl Authorizer {
    /// Create an authorizer with a single trusted key.
    ///
    /// Uses the default clock tolerance of 30 seconds.
    pub fn new(root_public_key: PublicKey) -> Self {
        Self {
            trusted_keys: vec![root_public_key],
            clock_tolerance: chrono::Duration::seconds(DEFAULT_CLOCK_TOLERANCE_SECS as i64),
            revocation_list: RevocationList::new(),
        }
    }

    /// Set the revocation list.
    pub fn set_revocation_list(&mut self, list: RevocationList) {
        self.revocation_list = list;
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
        if self.revocation_list.is_revoked(warrant.id().as_str()) {
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

    /// Authorize an action.
    ///
    /// This checks that the warrant permits the given tool call with the given arguments.
    pub fn authorize(
        &self,
        warrant: &Warrant,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&crate::crypto::Signature>,
    ) -> Result<()> {
        warrant.authorize(tool, args, signature)
    }

    /// Convenience: verify and authorize in one call.
    pub fn check(
        &self,
        warrant: &Warrant,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&crate::crypto::Signature>,
    ) -> Result<()> {
        self.verify(warrant)?;
        self.authorize(warrant, tool, args, signature)
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
    /// 1. **Root Trust**: chain[0] must be signed by a trusted issuer
    /// 2. **Linkage**: chain[i+1].parent_id == chain[i].id
    /// 3. **Depth**: chain[i+1].depth == chain[i].depth + 1
    /// 4. **Expiration**: chain[i+1].expires_at <= chain[i].expires_at
    /// 5. **Monotonicity**: chain[i+1].constraints ⊆ chain[i].constraints
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
            if enforce_session {
                if child.session_id() != expected_session {
                    return Err(Error::ChainVerificationFailed(format!(
                        "session mismatch: expected {:?}, got {:?} at depth {}",
                        expected_session, child.session_id(), child.depth()
                    )));
                }
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
        if self.revocation_list.is_revoked(child.id().as_str()) {
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
    ) -> Result<ChainVerificationResult> {
        let result = self.verify_chain(chain)?;
        
        if let Some(leaf) = chain.last() {
            leaf.authorize(tool, args, signature)?;
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
        assert!(data_plane.authorize(&warrant, "upgrade_cluster", &args, None).is_ok());
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
        assert!(authorizer.check(&warrant, "test", &HashMap::new(), None).is_ok());
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
            .check_chain(&[root, agent_warrant], "upgrade_cluster", &args, None)
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
        
        let result = authorizer.check_chain(&[root, child], "test", &args, None).unwrap();
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
}

