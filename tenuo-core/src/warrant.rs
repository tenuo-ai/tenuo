//! Warrant type - the core primitive of Tenuo.
//!
//! A warrant is a transferable token of authority containing:
//! - A tool name (what action is authorized)
//! - Constraints on arguments (how arguments must be restricted)
//! - A time-to-live (when the warrant expires)
//! - A signature proving provenance (who issued it)
//!
//! Crucially, capabilities can only shrink when warrants are delegated, never expand.

use crate::constraints::{Constraint, ConstraintSet, ConstraintValue};
use crate::crypto::{Keypair, PublicKey, Signature};
use crate::error::{Error, Result};
use crate::MAX_DELEGATION_DEPTH;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

/// The required prefix for all warrant IDs.
pub const WARRANT_ID_PREFIX: &str = "tnu_wrt_";

/// Size of the timestamp window for PoP signatures in seconds.
///
/// The verifier accepts signatures from 4 consecutive windows (current ± 2),
/// giving approximately 2 minutes of tolerance for clock skew.
///
/// **Security trade-off**: Larger windows tolerate more clock skew but increase
/// the replay window. Smaller windows reduce replay risk but may cause false
/// rejections in distributed systems.
pub const POP_TIMESTAMP_WINDOW_SECS: i64 = 30;

/// A unique identifier for a warrant.
/// 
/// Uses UUIDv7 (time-ordered) which provides:
/// - 48 bits of millisecond timestamp
/// - 74 bits of random data
/// - Monotonically increasing within the same millisecond
/// - Collision probability: 1 in 2^74 per millisecond (effectively zero)
/// 
/// **Validation**: IDs must start with `tnu_wrt_` prefix. This is enforced
/// during both construction (`from_string`) and deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct WarrantId(String);

impl<'de> Deserialize<'de> for WarrantId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if !s.starts_with(WARRANT_ID_PREFIX) {
            return Err(serde::de::Error::custom(format!(
                "warrant ID must start with '{}', got: {}",
                WARRANT_ID_PREFIX,
                if s.len() > 20 { &s[..20] } else { &s }
            )));
        }
        Ok(WarrantId(s))
    }
}

impl WarrantId {
    /// Generate a new time-ordered warrant ID (UUIDv7).
    /// 
    /// UUIDv7 provides both uniqueness and chronological ordering,
    /// making it ideal for debugging and audit trails.
    pub fn new() -> Self {
        Self(format!("tnu_wrt_{}", Uuid::now_v7().simple()))
    }
    
    /// Generate a random warrant ID (UUIDv4).
    /// 
    /// Use this when you don't want IDs to reveal timing information.
    pub fn new_random() -> Self {
        Self(format!("tnu_wrt_{}", Uuid::new_v4().simple()))
    }

    /// Create a warrant ID from a string.
    /// 
    /// Returns `InvalidWarrantId` if the string doesn't start with `tnu_wrt_`.
    pub fn from_string(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if !s.starts_with(WARRANT_ID_PREFIX) {
            return Err(Error::InvalidWarrantId(format!(
                "warrant ID must start with '{}', got: {}",
                WARRANT_ID_PREFIX,
                if s.len() > 20 { &s[..20] } else { &s }
            )));
        }
        Ok(Self(s))
    }

    /// Get the ID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for WarrantId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for WarrantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The payload of a warrant (unsigned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarrantPayload {
    /// Unique identifier for this warrant.
    pub id: WarrantId,
    /// The tool this warrant authorizes.
    pub tool: String,
    /// Constraints on tool arguments.
    pub constraints: ConstraintSet,
    /// When this warrant expires.
    pub expires_at: DateTime<Utc>,
    /// Delegation depth (0 for root warrants).
    pub depth: u32,
    /// Maximum delegation depth allowed from this warrant chain.
    /// 
    /// If set, child warrants cannot exceed this depth. This is a policy limit
    /// that can be set by the Control Plane or any delegator. The value can only
    /// shrink during attenuation (monotonicity).
    /// 
    /// If `None`, the protocol-level `MAX_DELEGATION_DEPTH` applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
    /// Parent warrant ID (None for root warrants).
    pub parent_id: Option<WarrantId>,
    /// Session ID for session binding.
    pub session_id: Option<String>,
    /// Agent ID for traceability (e.g., UUID of the agent software/instance).
    pub agent_id: Option<String>,
    /// Public key of the issuer (who signed this warrant).
    pub issuer: PublicKey,
    /// Public key of the authorized holder (Proof-of-Possession).
    /// 
    /// If set, the holder must prove they control this key when using the warrant.
    /// This prevents stolen warrants from being used by attackers.
    /// 
    /// When `None`, the warrant is a bearer token (anyone with it can use it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_holder: Option<PublicKey>,

    /// Public keys of required approvers for multi-sig workflows.
    /// 
    /// If set, actions require signatures from approvers in this list.
    /// Use with `min_approvals` for M-of-N schemes (e.g., 2-of-3).
    /// 
    /// When `None`, no additional approvals are required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_approvers: Option<Vec<PublicKey>>,

    /// Minimum number of approvals required (for M-of-N multi-sig).
    /// 
    /// If `None` but `required_approvers` is set, ALL approvers must sign.
    /// Must be <= len(required_approvers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_approvals: Option<u32>,
}

/// A signed warrant - the complete token of authority.
/// 
/// **Security**: Custom deserialization validates constraint depth to prevent
/// stack overflow attacks from maliciously nested constraints.
#[derive(Debug, Clone, Serialize)]
pub struct Warrant {
    /// The warrant payload.
    payload: WarrantPayload,
    /// Signature over the payload.
    signature: Signature,
    /// Original serialized payload bytes (for deterministic verification).
    /// This ensures signature verification works even when HashMap serialization
    /// order varies between serialize/deserialize cycles.
    #[serde(with = "serde_bytes")]
    payload_bytes: Vec<u8>,
}

// Custom Deserialize to enforce constraint depth validation
impl<'de> Deserialize<'de> for Warrant {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Helper struct for raw deserialization
        #[derive(Deserialize)]
        struct WarrantRaw {
            payload: WarrantPayload,
            signature: Signature,
            #[serde(with = "serde_bytes")]
            payload_bytes: Vec<u8>,
        }

        let raw = WarrantRaw::deserialize(deserializer)?;
        
        // Validate constraint depth before returning
        raw.payload.constraints.validate_depth()
            .map_err(serde::de::Error::custom)?;
        
        Ok(Warrant {
            payload: raw.payload,
            signature: raw.signature,
            payload_bytes: raw.payload_bytes,
        })
    }
}

impl Warrant {
    /// Create a new warrant builder.
    pub fn builder() -> WarrantBuilder {
        WarrantBuilder::new()
    }

    /// Get the warrant ID.
    pub fn id(&self) -> &WarrantId {
        &self.payload.id
    }

    /// Get the tool name.
    pub fn tool(&self) -> &str {
        &self.payload.tool
    }

    /// Get the constraints.
    pub fn constraints(&self) -> &ConstraintSet {
        &self.payload.constraints
    }
    
    /// Validate that constraint nesting depths are within limits.
    /// 
    /// Call this after deserializing warrants from untrusted sources
    /// to prevent stack overflow attacks from deeply nested constraints.
    pub fn validate_constraint_depth(&self) -> Result<()> {
        self.payload.constraints.validate_depth()
    }

    /// Get the expiration time.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.payload.expires_at
    }

    /// Get the delegation depth.
    pub fn depth(&self) -> u32 {
        self.payload.depth
    }

    /// Get the maximum delegation depth allowed for this warrant chain.
    /// 
    /// Returns `None` if no limit was set (protocol default applies).
    pub fn max_depth(&self) -> Option<u32> {
        self.payload.max_depth
    }

    /// Get the effective maximum depth (considering protocol cap).
    pub fn effective_max_depth(&self) -> u32 {
        self.payload.max_depth.unwrap_or(MAX_DELEGATION_DEPTH)
    }

    /// Get the parent warrant ID.
    pub fn parent_id(&self) -> Option<&WarrantId> {
        self.payload.parent_id.as_ref()
    }

    /// Get the session ID.
    pub fn session_id(&self) -> Option<&str> {
        self.payload.session_id.as_deref()
    }

    /// Get the agent ID.
    pub fn agent_id(&self) -> Option<&str> {
        self.payload.agent_id.as_deref()
    }

    /// Get the issuer's public key.
    pub fn issuer(&self) -> &PublicKey {
        &self.payload.issuer
    }

    /// Get the authorized holder's public key (if set).
    /// 
    /// When set, the holder must prove possession of the corresponding
    /// private key to use this warrant (Proof-of-Possession).
    pub fn authorized_holder(&self) -> Option<&PublicKey> {
        self.payload.authorized_holder.as_ref()
    }

    /// Check if this warrant requires Proof-of-Possession.
    pub fn requires_pop(&self) -> bool {
        self.payload.authorized_holder.is_some()
    }

    /// Get the required approvers for multi-sig workflows.
    pub fn required_approvers(&self) -> Option<&Vec<PublicKey>> {
        self.payload.required_approvers.as_ref()
    }

    /// Get the minimum number of approvals required.
    pub fn min_approvals(&self) -> Option<u32> {
        self.payload.min_approvals
    }

    /// Check if this warrant requires multi-sig approval.
    pub fn requires_multisig(&self) -> bool {
        self.payload.required_approvers.is_some()
    }

    /// Get the effective approval threshold.
    /// 
    /// Returns the number of approvals needed:
    /// - If `min_approvals` is set, returns that value
    /// - If `required_approvers` is set but `min_approvals` is not, returns the count (all must sign)
    /// - Otherwise returns 0 (no approvals needed)
    pub fn approval_threshold(&self) -> u32 {
        match (&self.payload.required_approvers, self.payload.min_approvals) {
            (Some(approvers), Some(min)) => min.min(approvers.len() as u32),
            (Some(approvers), None) => approvers.len() as u32, // All must sign
            (None, _) => 0, // No multi-sig required
        }
    }

    /// Verify that a holder signature proves possession.
    /// 
    /// The holder must sign a challenge (typically the action being performed)
    /// to prove they control the `authorized_holder` key.
    /// 
    /// # Arguments
    /// * `challenge` - The data that was signed (e.g., action + timestamp + nonce)
    /// * `signature` - The holder's signature over the challenge
    /// 
    /// # Returns
    /// * `Ok(())` if no PoP required OR signature is valid
    /// * `Err` if PoP required but signature invalid or missing holder
    pub fn verify_holder(&self, challenge: &[u8], signature: &Signature) -> Result<()> {
        match &self.payload.authorized_holder {
            None => Ok(()), // Bearer token, no PoP required
            Some(holder_key) => {
                holder_key.verify(challenge, signature)
                    .map_err(|_| Error::SignatureInvalid(
                        "holder proof-of-possession failed".to_string()
                    ))
            }
        }
    }

    /// Check if the warrant has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.payload.expires_at
    }

    /// Check if the warrant has expired, with clock skew tolerance.
    ///
    /// In distributed systems, clocks can drift. This method allows a grace period
    /// so that a warrant issued by a machine with a slightly fast clock doesn't
    /// appear expired prematurely on a machine with a slower clock.
    ///
    /// # Arguments
    /// * `tolerance` - Grace period to add to expiration time (e.g., 30 seconds)
    pub fn is_expired_with_tolerance(&self, tolerance: chrono::Duration) -> bool {
        Utc::now() > self.payload.expires_at + tolerance
    }

    /// Verify the warrant signature.
    pub fn verify(&self, expected_issuer: &PublicKey) -> Result<()> {
        if &self.payload.issuer != expected_issuer {
            return Err(Error::SignatureInvalid(
                "issuer public key does not match".to_string(),
            ));
        }

        // Use the stored payload bytes for verification (ensures determinism)
        self.payload.issuer.verify(&self.payload_bytes, &self.signature)
    }

    /// Authorize an action against this warrant.
    ///
    /// Checks:
    /// 1. Warrant is not expired
    /// 2. Tool name matches
    /// 3. All constraints are satisfied
    /// 4. Proof-of-Possession (if authorized_holder is set)
    pub fn authorize(
        &self,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&Signature>,
    ) -> Result<()> {
        // Check expiration
        if self.is_expired() {
            return Err(Error::WarrantExpired(self.payload.expires_at));
        }

        // Check tool name
        if self.payload.tool != "*" {
            let allowed_tools: Vec<&str> = self.payload.tool.split(',').map(|s| s.trim()).collect();
            if !allowed_tools.contains(&tool) {
                return Err(Error::ConstraintNotSatisfied {
                    field: "tool".to_string(),
                    reason: format!(
                        "warrant is for tools '{:?}', not '{}'",
                        allowed_tools, tool
                    ),
                });
            }
        }

        // Check constraints
        self.payload.constraints.matches(args)?;

        // Check Proof-of-Possession
        if let Some(holder_key) = &self.payload.authorized_holder {
            let signature = signature.ok_or_else(|| {
                Error::MissingSignature("Proof-of-Possession required".to_string())
            })?;

            // PoP signature covers (warrant_id, tool, sorted_args, timestamp_window)
            // We verify against multiple recent windows to handle clock skew.
            // 
            // Security: This creates a ~2 minute replay window. Mitigate with:
            // - Short-lived warrants (TTL < 2 min)
            // - Application-layer request deduplication
            let now = Utc::now().timestamp();
            let max_windows = 4; // Accept signatures from last ~2 minutes
            
            let mut sorted_args: Vec<(&String, &ConstraintValue)> = args.iter().collect();
            sorted_args.sort_by_key(|(k, _)| *k);

            let mut verified = false;
            for i in 0..max_windows {
                // Try current and recent time windows
                let window_ts = (now / POP_TIMESTAMP_WINDOW_SECS - i) * POP_TIMESTAMP_WINDOW_SECS;
                let challenge_data = (self.payload.id.as_str(), tool, &sorted_args, window_ts);
                let mut challenge_bytes = Vec::new();
                if ciborium::ser::into_writer(&challenge_data, &mut challenge_bytes).is_err() {
                    continue;
                }
                if holder_key.verify(&challenge_bytes, signature).is_ok() {
                    verified = true;
                    break;
                }
            }
            
            if !verified {
                return Err(Error::SignatureInvalid("Proof-of-Possession failed or expired".to_string()));
            }
        }

        Ok(())
    }

    /// Create a Proof-of-Possession signature for a request.
    ///
    /// This generates a time-bounded signature that proves you hold the private key
    /// corresponding to the warrant's `authorized_holder`. The signature is valid
    /// for approximately 2 minutes (to handle clock skew in distributed systems).
    ///
    /// The challenge includes: `(warrant_id, tool, sorted_args, timestamp_window)`
    ///
    /// # Security Note
    ///
    /// **Residual replay risk**: Within the ~2 minute window, a captured PoP signature
    /// can be replayed. This is an intentional trade-off to handle clock skew.
    ///
    /// **Mitigations**:
    /// - Use short-lived warrants (TTL < 2 min) for high-security operations
    /// - Implement request deduplication at the application layer using
    ///   `(warrant_id, tool, args)` as a cache key with 2-minute TTL
    pub fn create_pop_signature(
        &self,
        keypair: &Keypair,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
    ) -> Result<Signature> {
        // Create challenge: (warrant_id, tool, sorted_args, timestamp_window)
        let mut sorted_args: Vec<(&String, &ConstraintValue)> = args.iter().collect();
        sorted_args.sort_by_key(|(k, _)| *k);

        // Time-bound the signature to a window for replay protection
        let now = Utc::now().timestamp();
        let window_ts = (now / POP_TIMESTAMP_WINDOW_SECS) * POP_TIMESTAMP_WINDOW_SECS;

        let challenge_data = (self.payload.id.as_str(), tool, sorted_args, window_ts);
        let mut challenge_bytes = Vec::new();
        ciborium::ser::into_writer(&challenge_data, &mut challenge_bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

        Ok(keypair.sign(&challenge_bytes))
    }

    /// Create a builder for attenuating this warrant.
    pub fn attenuate(&self) -> AttenuationBuilder<'_> {
        AttenuationBuilder::new(self)
    }
}

/// Builder for creating root warrants.
#[derive(Debug)]
pub struct WarrantBuilder {
    tool: Option<String>,
    constraints: ConstraintSet,
    ttl: Option<Duration>,
    max_depth: Option<u32>,
    session_id: Option<String>,
    agent_id: Option<String>,
    authorized_holder: Option<PublicKey>,
    required_approvers: Option<Vec<PublicKey>>,
    min_approvals: Option<u32>,
}

impl WarrantBuilder {
    /// Create a new warrant builder.
    pub fn new() -> Self {
        Self {
            tool: None,
            constraints: ConstraintSet::new(),
            ttl: None,
            max_depth: None,
            session_id: None,
            agent_id: None,
            authorized_holder: None,
            required_approvers: None,
            min_approvals: None,
        }
    }

    /// Set the tool name.
    pub fn tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = Some(tool.into());
        self
    }

    /// Add a constraint.
    pub fn constraint(mut self, field: impl Into<String>, constraint: impl Into<Constraint>) -> Self {
        self.constraints.insert(field, constraint);
        self
    }

    /// Set the time-to-live.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the maximum delegation depth for this warrant chain.
    /// 
    /// This is a policy limit that restricts how deep the delegation chain
    /// can grow. Child warrants can only shrink this value, never expand it.
    /// 
    /// If not set, the protocol-level `MAX_DELEGATION_DEPTH` (64) applies.
    pub fn max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = Some(max_depth);
        self
    }

    /// Set the session ID.
    pub fn session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Set the agent ID.
    pub fn agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Set the authorized holder (Proof-of-Possession).
    pub fn authorized_holder(mut self, public_key: PublicKey) -> Self {
        self.authorized_holder = Some(public_key);
        self
    }

    /// Set required approvers for multi-sig workflows.
    /// 
    /// Actions will require signatures from these approvers.
    /// Use with `min_approvals()` for M-of-N schemes.
    pub fn required_approvers(mut self, approvers: Vec<PublicKey>) -> Self {
        self.required_approvers = Some(approvers);
        self
    }

    /// Set the minimum number of approvals required (M-of-N).
    /// 
    /// If not set but `required_approvers` is set, ALL approvers must sign.
    pub fn min_approvals(mut self, min: u32) -> Self {
        self.min_approvals = Some(min);
        self
    }

    /// Build and sign the warrant.
    pub fn build(self, keypair: &Keypair) -> Result<Warrant> {
        let tool = self.tool.ok_or(Error::MissingField("tool".to_string()))?;
        let ttl = self.ttl.ok_or(Error::MissingField("ttl".to_string()))?;

        // Validate max_depth doesn't exceed protocol cap
        if let Some(max) = self.max_depth {
            if max > MAX_DELEGATION_DEPTH {
                return Err(Error::DepthExceeded(max, MAX_DELEGATION_DEPTH));
            }
        }

        let chrono_ttl = ChronoDuration::from_std(ttl)
            .map_err(|_| Error::InvalidTtl("TTL too large".to_string()))?;
        let expires_at = Utc::now() + chrono_ttl;

        // Validate min_approvals if set
        if let (Some(approvers), Some(min)) = (&self.required_approvers, self.min_approvals) {
            if min as usize > approvers.len() {
                return Err(Error::MonotonicityViolation(format!(
                    "min_approvals ({}) cannot exceed required_approvers count ({})",
                    min, approvers.len()
                )));
            }
        }

        let payload = WarrantPayload {
            id: WarrantId::new(),
            tool,
            constraints: self.constraints,
            expires_at,
            depth: 0,
            max_depth: self.max_depth,
            parent_id: None,
            session_id: self.session_id,
            agent_id: self.agent_id,
            issuer: keypair.public_key(),
            authorized_holder: self.authorized_holder,
            required_approvers: self.required_approvers,
            min_approvals: self.min_approvals,
        };

        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)?;
        let signature = keypair.sign(&payload_bytes);

        let warrant = Warrant { payload, signature, payload_bytes };

        // Audit log: Warrant created
        crate::audit::log_event(
            crate::approval::AuditEvent::new(
                crate::approval::AuditEventType::WarrantIssued,
                "tenuo-core",
                "warrant-builder",
            )
            .with_warrant_id(warrant.id().as_str())
            .with_tool(warrant.tool())
            .with_action("created")
            .with_key(&keypair.public_key())
            .with_details(format!(
                "Root warrant created: tool={}, ttl={}s, max_depth={:?}",
                warrant.tool(),
                self.ttl.map(|t| t.as_secs()).unwrap_or(0),
                warrant.effective_max_depth()
            ))
        );

        Ok(warrant)
    }
}

impl Default for WarrantBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for attenuating existing warrants.
#[derive(Debug)]
pub struct AttenuationBuilder<'a> {
    parent: &'a Warrant,
    tool: Option<String>,
    constraints: ConstraintSet,
    ttl: Option<Duration>,
    max_depth: Option<u32>,
    session_id: Option<String>,
    agent_id: Option<String>,
    authorized_holder: Option<PublicKey>,
    required_approvers: Option<Vec<PublicKey>>,
    min_approvals: Option<u32>,
}

impl<'a> AttenuationBuilder<'a> {
    /// Create a new attenuation builder.
    fn new(parent: &'a Warrant) -> Self {
        Self {
            parent,
            tool: None,
            constraints: parent.payload.constraints.clone(),
            ttl: None,
            max_depth: None, // Will inherit from parent if not set
            session_id: parent.payload.session_id.clone(),
            agent_id: parent.payload.agent_id.clone(),
            authorized_holder: parent.payload.authorized_holder.clone(),
            // Multi-sig: inherit from parent (can only add MORE approvers or raise threshold)
            required_approvers: parent.payload.required_approvers.clone(),
            min_approvals: parent.payload.min_approvals,
        }
    }

    /// Set the tool name.
    /// 
    /// This is only allowed if the parent warrant is for the wildcard tool "*".
    /// If parent is for a specific tool, changing it is a monotonicity violation.
    pub fn tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = Some(tool.into());
        self
    }

    /// Override a constraint with a narrower one.
    pub fn constraint(mut self, field: impl Into<String>, constraint: impl Into<Constraint>) -> Self {
        self.constraints.insert(field, constraint);
        self
    }

    /// Set a shorter TTL.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set a lower maximum delegation depth.
    /// 
    /// This can only shrink the parent's `max_depth`, never expand it.
    /// An error will be returned at build time if monotonicity is violated.
    pub fn max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = Some(max_depth);
        self
    }

    // NOTE: session_id is inherited from parent and immutable during attenuation.
    // This follows the monotonicity principle - sessions cannot be changed mid-chain.

    /// Set or change the agent ID.
    pub fn agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Set or change the authorized holder (Proof-of-Possession).
    pub fn authorized_holder(mut self, public_key: PublicKey) -> Self {
        self.authorized_holder = Some(public_key);
        self
    }

    /// Add required approvers (can only add more, not remove).
    /// 
    /// Multi-sig is monotonic: you can add approvers but not remove them.
    /// The new approvers are merged with any inherited from the parent.
    pub fn add_approvers(mut self, approvers: Vec<PublicKey>) -> Self {
        let mut current = self.required_approvers.unwrap_or_default();
        for approver in approvers {
            if !current.contains(&approver) {
                current.push(approver);
            }
        }
        self.required_approvers = Some(current);
        self
    }

    /// Increase the minimum approvals required (can only increase).
    /// 
    /// Multi-sig threshold is monotonic: you can raise it but not lower it.
    pub fn raise_min_approvals(mut self, min: u32) -> Self {
        let current = self.min_approvals.unwrap_or(0);
        self.min_approvals = Some(min.max(current));
        self
    }

    /// Validate multi-sig monotonicity (cannot remove approvers or lower threshold).
    fn validate_multisig_monotonicity(&self) -> Result<()> {
        // 1. Cannot remove approvers (child must include all parent approvers)
        if let Some(parent_approvers) = &self.parent.payload.required_approvers {
            if let Some(child_approvers) = &self.required_approvers {
                for parent_key in parent_approvers {
                    if !child_approvers.contains(parent_key) {
                        return Err(Error::MonotonicityViolation(format!(
                            "cannot remove approver {} from multi-sig set",
                            hex::encode(parent_key.to_bytes())
                        )));
                    }
                }
            } else {
                // Child doesn't have approvers but parent does - violation
                return Err(Error::MonotonicityViolation(
                    "cannot remove multi-sig requirement from parent".to_string()
                ));
            }
        }

        // 2. Cannot lower min_approvals
        if let Some(parent_min) = self.parent.payload.min_approvals {
            if let Some(child_min) = self.min_approvals {
                if child_min < parent_min {
                    return Err(Error::MonotonicityViolation(format!(
                        "cannot lower min_approvals from {} to {}",
                        parent_min, child_min
                    )));
                }
            }
            // If parent has min_approvals but child doesn't set it, inherit (ok)
        }

        // 3. Validate min_approvals doesn't exceed approvers count
        if let (Some(approvers), Some(min)) = (&self.required_approvers, self.min_approvals) {
            if min as usize > approvers.len() {
                return Err(Error::MonotonicityViolation(format!(
                    "min_approvals ({}) cannot exceed required_approvers count ({})",
                    min, approvers.len()
                )));
            }
        }

        Ok(())
    }

    /// Build and sign the attenuated warrant.
    pub fn build(self, keypair: &Keypair) -> Result<Warrant> {
        // Use checked arithmetic to prevent overflow
        let new_depth = self.parent.payload.depth
            .checked_add(1)
            .ok_or(Error::DepthExceeded(u32::MAX, MAX_DELEGATION_DEPTH))?;
        
        // Calculate effective max_depth (monotonic: can only shrink)
        let effective_max = match (self.parent.payload.max_depth, self.max_depth) {
            // Both set: take the minimum (can only shrink)
            (Some(parent_max), Some(child_max)) => {
                if child_max > parent_max {
                    return Err(Error::MonotonicityViolation(format!(
                        "max_depth {} exceeds parent's max_depth {}",
                        child_max, parent_max
                    )));
                }
                Some(child_max)
            }
            // Parent set, child not: inherit parent's limit
            (Some(parent_max), None) => Some(parent_max),
            // Child set, parent not: use child's limit (capped by protocol)
            (None, Some(child_max)) => {
                if child_max > MAX_DELEGATION_DEPTH {
                    return Err(Error::DepthExceeded(child_max, MAX_DELEGATION_DEPTH));
                }
                Some(child_max)
            }
            // Neither set: no limit (protocol default applies)
            (None, None) => None,
        };

        // Check depth against effective limit
        let depth_limit = effective_max.unwrap_or(MAX_DELEGATION_DEPTH);
        if new_depth > depth_limit {
            return Err(Error::DepthExceeded(new_depth, depth_limit));
        }

        // Also enforce protocol hard cap
        if new_depth > MAX_DELEGATION_DEPTH {
            return Err(Error::DepthExceeded(new_depth, MAX_DELEGATION_DEPTH));
        }

        // Check parent is not expired
        if self.parent.is_expired() {
            return Err(Error::WarrantExpired(self.parent.payload.expires_at));
        }

        // Validate attenuation monotonicity for constraints
        self.parent.payload.constraints.validate_attenuation(&self.constraints)?;

        // Validate multi-sig monotonicity
        self.validate_multisig_monotonicity()?;
        
        // Calculate expiration
        let parent_expires = self.parent.payload.expires_at;
        let expires_at = if let Some(ttl) = self.ttl {
            let chrono_ttl = ChronoDuration::from_std(ttl)
                .map_err(|_| Error::InvalidTtl("TTL too large".to_string()))?;
            let proposed = Utc::now() + chrono_ttl;
            if proposed > parent_expires {
                parent_expires // Cap at parent expiry
            } else {
                proposed
            }
        } else {
            parent_expires
        };

        // Calculate depth
        let depth = self.parent.payload.depth
            .checked_add(1)
            .ok_or(Error::DepthExceeded(u32::MAX, MAX_DELEGATION_DEPTH))?;
        
        // Determine tool
        let tool = match self.tool {
            Some(t) => {
                // Monotonicity check
                if self.parent.payload.tool == "*" {
                    // Allowed to narrow to anything
                } else {
                    // Parent has specific tools. Child must be a subset.
                    let parent_tools: Vec<&str> = self.parent.payload.tool.split(',').map(|s| s.trim()).collect();
                    let child_tools: Vec<&str> = t.split(',').map(|s| s.trim()).collect();
                    
                    for child_tool in child_tools {
                        if !parent_tools.contains(&child_tool) {
                            return Err(Error::MonotonicityViolation(format!(
                                "cannot expand tools from '{:?}' to include '{}'",
                                parent_tools, child_tool
                            )));
                        }
                    }
                }
                t
            },
            None => self.parent.payload.tool.clone(),
        };
        // Calculate max_depth
        let max_depth = match (self.max_depth, self.parent.payload.max_depth) {
            (Some(child_max), Some(parent_max)) => {
                if child_max > parent_max {
                    return Err(Error::MonotonicityViolation(format!(
                        "cannot expand max_depth from {} to {}",
                        parent_max, child_max
                    )));
                }
                Some(child_max)
            },
            (Some(child_max), None) => {
                if child_max > MAX_DELEGATION_DEPTH {
                    return Err(Error::DepthExceeded(child_max, MAX_DELEGATION_DEPTH));
                }
                Some(child_max)
            },
            (None, Some(parent_max)) => Some(parent_max),
            (None, None) => None,
        };

        // Check depth limit
        let effective_max = max_depth.unwrap_or(MAX_DELEGATION_DEPTH);
        if depth > effective_max {
            return Err(Error::DepthExceeded(depth, effective_max));
        }

        // Also enforce protocol hard cap
        if depth > MAX_DELEGATION_DEPTH {
            return Err(Error::DepthExceeded(depth, MAX_DELEGATION_DEPTH));
        }

        // Determine effective min_approvals (inherit if not set)
        let effective_min = self.min_approvals.or(self.parent.payload.min_approvals);

        let payload = WarrantPayload {
            id: WarrantId::new(),
            tool,
            constraints: self.constraints,
            expires_at,
            depth,
            max_depth,
            parent_id: Some(self.parent.payload.id.clone()),
            session_id: self.session_id,
            agent_id: self.agent_id,
            issuer: keypair.public_key(),
            authorized_holder: self.authorized_holder,
            required_approvers: self.required_approvers,
            min_approvals: effective_min,
        };

        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)?;
        let signature = keypair.sign(&payload_bytes);

        let warrant = Warrant { payload, signature, payload_bytes };

        // Audit log: Warrant attenuated
        crate::audit::log_event(
            crate::approval::AuditEvent::new(
                crate::approval::AuditEventType::WarrantAttenuated,
                "tenuo-core",
                "attenuation-builder",
            )
            .with_warrant_id(warrant.id().as_str())
            .with_tool(warrant.tool())
            .with_action("attenuated")
            .with_key(&keypair.public_key())
            .with_related(vec![self.parent.id().to_string()])
            .with_details(format!(
                "Warrant attenuated: parent={}, depth={}/{}, holder={}",
                self.parent.id().as_str(),
                warrant.depth(),
                warrant.effective_max_depth(),
                warrant.authorized_holder()
                    .map(|k| format!("{}...", &hex::encode(k.to_bytes())[..16]))
                    .unwrap_or_else(|| "none".to_string())
            ))
        );

        Ok(warrant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::{Exact, Pattern, Range};

    fn create_test_keypair() -> Keypair {
        Keypair::generate()
    }

    #[test]
    fn test_warrant_creation() {
        let keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .tool("upgrade_cluster")
            .constraint("cluster", Pattern::new("staging-*").unwrap())
            .ttl(Duration::from_secs(600))
            .build(&keypair)
            .unwrap();

        assert_eq!(warrant.tool(), "upgrade_cluster");
        assert_eq!(warrant.depth(), 0);
        assert!(warrant.parent_id().is_none());
        assert!(!warrant.is_expired());
    }

    #[test]
    fn test_warrant_verification() {
        let keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(60))
            .build(&keypair)
            .unwrap();

        assert!(warrant.verify(&keypair.public_key()).is_ok());

        let other_keypair = create_test_keypair();
        assert!(warrant.verify(&other_keypair.public_key()).is_err());
    }

    #[test]
    fn test_warrant_authorization() {
        let keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .tool("upgrade_cluster")
            .constraint("cluster", Pattern::new("staging-*").unwrap())
            .constraint("version", Pattern::new("1.28.*").unwrap())
            .ttl(Duration::from_secs(600))
            .build(&keypair)
            .unwrap();

        let mut args = HashMap::new();
        args.insert("cluster".to_string(), ConstraintValue::String("staging-web".to_string()));
        args.insert("version".to_string(), ConstraintValue::String("1.28.5".to_string()));

        args.insert("version".to_string(), ConstraintValue::String("1.28.5".to_string()));

        assert!(warrant.authorize("upgrade_cluster", &args, None).is_ok());

        // Wrong tool
        assert!(warrant.authorize("delete_cluster", &args, None).is_err());

        // Wrong cluster
        args.insert("cluster".to_string(), ConstraintValue::String("prod-web".to_string()));
        assert!(warrant.authorize("upgrade_cluster", &args, None).is_err());
    }

    #[test]
    fn test_attenuation_basic() {
        let parent_keypair = create_test_keypair();
        let child_keypair = create_test_keypair();

        let parent = Warrant::builder()
            .tool("upgrade_cluster")
            .constraint("cluster", Pattern::new("staging-*").unwrap())
            .ttl(Duration::from_secs(600))
            .build(&parent_keypair)
            .unwrap();

        let child = parent
            .attenuate()
            .constraint("cluster", Exact::new("staging-web"))
            .build(&child_keypair)
            .unwrap();

        assert_eq!(child.depth(), 1);
        assert_eq!(child.parent_id(), Some(parent.id()));
        assert!(child.expires_at() <= parent.expires_at());
    }

    #[test]
    fn test_attenuation_monotonicity_enforced() {
        let parent_keypair = create_test_keypair();
        let child_keypair = create_test_keypair();

        let parent = Warrant::builder()
            .tool("upgrade_cluster")
            .constraint("cluster", Pattern::new("staging-*").unwrap())
            .ttl(Duration::from_secs(600))
            .build(&parent_keypair)
            .unwrap();

        // Attempt to widen scope - should fail
        let result = parent
            .attenuate()
            .constraint("cluster", Pattern::new("*").unwrap())
            .build(&child_keypair);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::PatternExpanded { parent, child } => {
                assert_eq!(parent, "staging-*");
                assert_eq!(child, "*");
            }
            e => panic!("Expected PatternExpanded, got {:?}", e),
        }
    }

    #[test]
    fn test_attenuation_ttl_cannot_exceed_parent() {
        let parent_keypair = create_test_keypair();
        let child_keypair = create_test_keypair();

        let parent = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(60))
            .build(&parent_keypair)
            .unwrap();

        // Request longer TTL - should be capped to parent
        let child = parent
            .attenuate()
            .ttl(Duration::from_secs(3600))
            .build(&child_keypair)
            .unwrap();

        assert!(child.expires_at() <= parent.expires_at());
    }

    #[test]
    fn test_attenuation_depth_limit() {
        let keypair = create_test_keypair();

        let mut warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(3600))
            .build(&keypair)
            .unwrap();

        // Delegate up to max depth
        for _ in 0..MAX_DELEGATION_DEPTH {
            warrant = warrant.attenuate().build(&keypair).unwrap();
        }

        // Next delegation should fail
        let result = warrant.attenuate().build(&keypair);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::DepthExceeded(_, _) => {}
            e => panic!("Expected DepthExceeded, got {:?}", e),
        }
    }

    #[test]
    fn test_range_constraint_attenuation() {
        let parent_keypair = create_test_keypair();
        let child_keypair = create_test_keypair();

        let parent = Warrant::builder()
            .tool("transfer_funds")
            .constraint("amount", Range::max(10000.0))
            .ttl(Duration::from_secs(600))
            .build(&parent_keypair)
            .unwrap();

        // Valid: narrower range
        let child = parent
            .attenuate()
            .constraint("amount", Range::max(5000.0))
            .build(&child_keypair);
        assert!(child.is_ok());

        // Invalid: wider range
        let invalid = parent
            .attenuate()
            .constraint("amount", Range::max(20000.0))
            .build(&child_keypair);
        assert!(invalid.is_err());
    }

    #[test]
    fn test_session_binding() {
        let keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(60))
            .session_id("session_123")
            .build(&keypair)
            .unwrap();

        assert_eq!(warrant.session_id(), Some("session_123"));

        // Session ID is preserved through attenuation
        let child = warrant.attenuate().build(&keypair).unwrap();
        assert_eq!(child.session_id(), Some("session_123"));
    }

    #[test]
    fn test_warrant_id_format() {
        let id = WarrantId::new();
        assert!(id.as_str().starts_with("tnu_wrt_"));

        let parsed = WarrantId::from_string(id.as_str()).unwrap();
        assert_eq!(parsed, id);

        let invalid = WarrantId::from_string("invalid_id");
        assert!(invalid.is_err());
    }

    #[test]
    fn test_max_depth_policy_limit() {
        let keypair = create_test_keypair();

        // Create warrant with policy limit of 3
        let root = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(3600))
            .max_depth(3)
            .build(&keypair)
            .unwrap();

        assert_eq!(root.max_depth(), Some(3));
        assert_eq!(root.effective_max_depth(), 3);

        // Can delegate up to depth 3
        let level1 = root.attenuate().build(&keypair).unwrap();
        assert_eq!(level1.depth(), 1);
        assert_eq!(level1.max_depth(), Some(3)); // Inherited

        let level2 = level1.attenuate().build(&keypair).unwrap();
        assert_eq!(level2.depth(), 2);

        let level3 = level2.attenuate().build(&keypair).unwrap();
        assert_eq!(level3.depth(), 3);

        // Depth 4 should fail (exceeds policy limit)
        let result = level3.attenuate().build(&keypair);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::DepthExceeded(4, 3) => {}
            e => panic!("Expected DepthExceeded(4, 3), got {:?}", e),
        }
    }

    #[test]
    fn test_max_depth_monotonicity() {
        let keypair = create_test_keypair();

        let root = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(3600))
            .max_depth(5)
            .build(&keypair)
            .unwrap();

        // Can shrink max_depth
        let child = root.attenuate().max_depth(3).build(&keypair).unwrap();
        assert_eq!(child.max_depth(), Some(3));

        // Cannot expand max_depth
        let result = child.attenuate().max_depth(10).build(&keypair);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::MonotonicityViolation(_) => {}
            e => panic!("Expected MonotonicityViolation, got {:?}", e),
        }
    }

    #[test]
    fn test_max_depth_protocol_cap() {
        let keypair = create_test_keypair();

        // Cannot set max_depth above protocol cap
        let result = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(60))
            .max_depth(100) // Above MAX_DELEGATION_DEPTH (64)
            .build(&keypair);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::DepthExceeded(100, 64) => {}
            e => panic!("Expected DepthExceeded(100, 64), got {:?}", e),
        }
    }

    #[test]
    fn test_no_max_depth_uses_protocol_default() {
        let keypair = create_test_keypair();

        let root = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(3600))
            .build(&keypair)
            .unwrap();

        assert_eq!(root.max_depth(), None);
        assert_eq!(root.effective_max_depth(), MAX_DELEGATION_DEPTH);
    }

    // =========================================================================
    // MULTI-SIG TESTS
    // =========================================================================

    #[test]
    fn test_multisig_root_warrant() {
        let issuer = create_test_keypair();
        let approver1 = create_test_keypair();
        let approver2 = create_test_keypair();

        let warrant = Warrant::builder()
            .tool("sensitive_action")
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![approver1.public_key(), approver2.public_key()])
            .min_approvals(2)
            .build(&issuer)
            .unwrap();

        assert!(warrant.requires_multisig());
        assert_eq!(warrant.approval_threshold(), 2);
        assert_eq!(warrant.required_approvers().unwrap().len(), 2);
    }

    #[test]
    fn test_multisig_default_all_must_sign() {
        let issuer = create_test_keypair();
        let approver1 = create_test_keypair();
        let approver2 = create_test_keypair();

        // Set approvers but NOT min_approvals - should require all
        let warrant = Warrant::builder()
            .tool("sensitive_action")
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![approver1.public_key(), approver2.public_key()])
            // min_approvals NOT set
            .build(&issuer)
            .unwrap();

        assert!(warrant.requires_multisig());
        assert_eq!(warrant.approval_threshold(), 2); // All must sign
    }

    #[test]
    fn test_multisig_min_approvals_exceeds_approvers() {
        let issuer = create_test_keypair();
        let approver1 = create_test_keypair();

        // Try to require 3 approvals with only 1 approver
        let result = Warrant::builder()
            .tool("sensitive_action")
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![approver1.public_key()])
            .min_approvals(3)
            .build(&issuer);

        assert!(result.is_err());
    }

    #[test]
    fn test_multisig_attenuation_add_approvers() {
        let issuer = create_test_keypair();
        let delegator = create_test_keypair();
        let approver1 = create_test_keypair();
        let approver2 = create_test_keypair();

        // Root with 1 approver
        let root = Warrant::builder()
            .tool("sensitive_action")
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![approver1.public_key()])
            .min_approvals(1)
            .build(&issuer)
            .unwrap();

        // Attenuate and ADD another approver (valid: more restrictive)
        let child = root.attenuate()
            .add_approvers(vec![approver2.public_key()])
            .raise_min_approvals(2)
            .build(&delegator)
            .unwrap();

        assert_eq!(child.required_approvers().unwrap().len(), 2);
        assert_eq!(child.approval_threshold(), 2);
    }

    #[test]
    fn test_multisig_attenuation_cannot_remove_approvers() {
        let issuer = create_test_keypair();
        let delegator = create_test_keypair();
        let approver1 = create_test_keypair();
        let approver2 = create_test_keypair();

        // Root with 2 approvers
        let root = Warrant::builder()
            .tool("sensitive_action")
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![approver1.public_key(), approver2.public_key()])
            .min_approvals(1)
            .build(&issuer)
            .unwrap();

        // Create attenuation builder and clear approvers (simulating removal)
        // The builder inherits from parent, so we can't directly remove.
        // But if the internal field is manipulated, the build should fail.
        // For now, verify that inherited approvers are preserved.
        let child = root.attenuate()
            .build(&delegator)
            .unwrap();

        // All parent approvers should be preserved
        assert_eq!(child.required_approvers().unwrap().len(), 2);
    }

    #[test]
    fn test_multisig_attenuation_cannot_lower_threshold() {
        let issuer = create_test_keypair();
        let delegator = create_test_keypair();
        let approver1 = create_test_keypair();
        let approver2 = create_test_keypair();

        // Root with threshold of 2
        let root = Warrant::builder()
            .tool("sensitive_action")
            .ttl(Duration::from_secs(300))
            .required_approvers(vec![approver1.public_key(), approver2.public_key()])
            .min_approvals(2)
            .build(&issuer)
            .unwrap();

        // Try to lower threshold using raise_min_approvals (should be ignored)
        // raise_min_approvals uses max() so it cannot lower
        let child = root.attenuate()
            .raise_min_approvals(1) // Tries to set 1, but max(current, 1) = 2
            .build(&delegator)
            .unwrap();

        // Threshold should still be 2 (inherited, max applied)
        assert_eq!(child.approval_threshold(), 2);
    }

    #[test]
    fn test_no_multisig_by_default() {
        let keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .tool("regular_action")
            .ttl(Duration::from_secs(300))
            .build(&keypair)
            .unwrap();

        assert!(!warrant.requires_multisig());
        assert_eq!(warrant.approval_threshold(), 0);
        assert!(warrant.required_approvers().is_none());
    }
}

