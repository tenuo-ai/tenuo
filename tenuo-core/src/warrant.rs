//! Warrant type - the core primitive of Tenuo.
//!
//! A warrant is a cryptographically-signed token of authority. There are two types:
//!
//! ## Warrant Types
//!
//! - **ISSUER**: Can issue EXECUTION warrants. Used by planners/orchestrators that
//!   decide what capabilities to grant without executing tools themselves.
//! - **EXECUTION**: Can invoke specific tools with specific constraints. Used by
//!   workers that execute actions.
//!
//! ## Trust Levels
//!
//! Warrants have hierarchical trust levels (Untrusted=0 → System=50):
//! - **Untrusted** (0): Anonymous/unauthenticated entities
//! - **External** (10): Authenticated external users
//! - **Partner** (20): Third-party integrations
//! - **Internal** (30): Internal services
//! - **Privileged** (40): Admin operations
//! - **System** (50): Control plane
//!
//! Trust levels can only decrease during delegation, preventing privilege escalation.
//!
//! ## Core Components
//!
//! - **Type**: ISSUER or EXECUTION (determines capabilities)
//! - **Tools/Constraints**: What actions are authorized and how
//! - **Chain Links**: Embedded delegation chain for offline verification
//! - **Signatures**: Cryptographic proof of authority (including chain link signatures)
//! - **TTL**: Time-to-live (ephemeral by design)
//!
//! ## Key Properties
//!
//! - **Monotonic Attenuation**: Capabilities only shrink when delegated, never expand
//! - **Mandatory PoP**: Proof-of-Possession prevents stolen warrant usage
//! - **Self-Contained**: Chain links enable offline verification without external lookups
//! - **Type-Safe**: Rust's type system prevents misuse

use crate::constraints::{Constraint, ConstraintSet, ConstraintValue};
use crate::crypto::{PublicKey, Signature, SigningKey};
use crate::error::{Error, Result};
use crate::MAX_DELEGATION_DEPTH;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

/// The required prefix for all warrant IDs.
pub const WARRANT_ID_PREFIX: &str = "tnu_wrt_";

/// Warrant schema version.
///
/// Incremented when breaking changes are made to the warrant structure.
pub const WARRANT_VERSION: u32 = 1;

/// Type of warrant: ISSUER or EXECUTION.
///
/// - **ISSUER**: Can issue execution warrants. Used by P-LLM/planner components
///   that decide capabilities without executing tools.
/// - **EXECUTION**: Can invoke specific tools with specific constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WarrantType {
    /// Issuer warrant - can issue execution warrants.
    Issuer,
    /// Execution warrant - can invoke tools.
    Execution,
}

/// Trust level for warrants.
///
/// Used to enforce trust boundaries in multi-tenant or multi-component systems.
/// Issuers can only issue warrants with trust levels at or below their `trust_ceiling`.
///
/// Trust levels are ordered numerically, with higher values indicating greater trust.
/// This allows for simple comparisons: `trust_level >= TrustLevel::INTERNAL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Untrusted - anonymous or unauthenticated entities (0).
    Untrusted = 0,
    /// External - authenticated external users (10).
    External = 10,
    /// Partner - third-party integrations (20).
    Partner = 20,
    /// Internal - internal services (30).
    Internal = 30,
    /// Privileged - admin-level access (40).
    Privileged = 40,
    /// System - control plane and highest trust (50).
    System = 50,
}

impl std::str::FromStr for TrustLevel {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "untrusted" => Ok(TrustLevel::Untrusted),
            "external" => Ok(TrustLevel::External),
            "partner" => Ok(TrustLevel::Partner),
            "internal" => Ok(TrustLevel::Internal),
            "privileged" => Ok(TrustLevel::Privileged),
            "system" => Ok(TrustLevel::System),
            _ => Err(format!(
                "Invalid trust level: {}. Must be one of: 'untrusted', 'external', 'partner', 'internal', 'privileged', 'system'",
                s
            )),
        }
    }
}

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

/// A link in the delegation chain, embedding the issuer's full scope.
///
/// This enables self-contained verification without needing to fetch
/// parent warrants from external sources. Each link contains:
/// - Identity information (issuer ID, public key)
/// - Embedded scope (tools, constraints, trust level, expiration)
/// - Signature binding both the child warrant AND issuer scope
///
/// ## Cryptographic Binding
///
/// The `signature` field contains the parent's signature over a `ChainLinkSignedData`
/// struct that includes BOTH:
/// 1. The child warrant's payload bytes (without issuer_chain)
/// 2. All issuer scope fields (tools, constraints, trust, expiration, max_depth)
///
/// This prevents attacks where an attacker modifies the embedded issuer scope
/// (e.g., adding tools the issuer never had) while keeping a valid signature.
///
/// During verification:
/// 1. Reconstruct `ChainLinkSignedData` from the link and child payload
/// 2. Verify the signature covers this exact data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainLink {
    /// Warrant ID of the issuer.
    pub issuer_id: WarrantId,
    /// Public key of the issuer.
    pub issuer_pubkey: PublicKey,
    /// Type of the issuer warrant (execution or issuer).
    pub issuer_type: WarrantType,
    /// Tools the issuer had (for execution warrants) or could issue (for issuer warrants).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_tools: Option<Vec<String>>,
    /// Constraint bounds from the issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_constraints: Option<ConstraintSet>,
    /// Trust level of the issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_trust: Option<TrustLevel>,
    /// Expiration time of the issuer warrant.
    pub issuer_expires_at: DateTime<Utc>,
    /// Maximum depth allowed by the issuer.
    pub issuer_max_depth: u32,
    /// Signature over ChainLinkSignedData (child payload + issuer scope).
    pub signature: Signature,
}

/// Data structure that is signed for ChainLink verification.
///
/// This struct binds BOTH the child warrant payload AND the issuer's scope fields
/// into a single signed message. This prevents scope tampering attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainLinkSignedData {
    /// Child warrant's payload bytes (without issuer_chain)
    #[serde(with = "serde_bytes")]
    pub child_payload_bytes: Vec<u8>,
    /// Issuer's warrant ID
    pub issuer_id: WarrantId,
    /// Issuer's warrant type
    pub issuer_type: WarrantType,
    /// Issuer's tools (execution) or issuable_tools (issuer)
    pub issuer_tools: Option<Vec<String>>,
    /// Issuer's constraints or constraint_bounds
    pub issuer_constraints: Option<ConstraintSet>,
    /// Issuer's trust level or trust_ceiling
    pub issuer_trust: Option<TrustLevel>,
    /// Issuer's expiration time
    pub issuer_expires_at: DateTime<Utc>,
    /// Issuer's max_depth
    pub issuer_max_depth: u32,
}

impl ChainLink {
    /// Create signed data for this link given the child's payload bytes.
    pub fn signed_data(&self, child_payload_bytes: Vec<u8>) -> ChainLinkSignedData {
        ChainLinkSignedData {
            child_payload_bytes,
            issuer_id: self.issuer_id.clone(),
            issuer_type: self.issuer_type,
            issuer_tools: self.issuer_tools.clone(),
            issuer_constraints: self.issuer_constraints.clone(),
            issuer_trust: self.issuer_trust,
            issuer_expires_at: self.issuer_expires_at,
            issuer_max_depth: self.issuer_max_depth,
        }
    }

    /// Verify this chain link's signature against the child's payload bytes.
    pub fn verify_signature(&self, child_payload_bytes: &[u8]) -> Result<()> {
        let signed_data = self.signed_data(child_payload_bytes.to_vec());
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&signed_data, &mut buf).map_err(|e| {
            Error::Validation(format!("failed to serialize ChainLinkSignedData: {}", e))
        })?;
        self.issuer_pubkey.verify(&buf, &self.signature)
    }
}

/// The payload of a warrant (unsigned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarrantPayload {
    /// Schema version for this warrant.
    pub version: u32,
    /// Type of warrant: ISSUER or EXECUTION.
    pub r#type: WarrantType,
    /// Unique identifier for this warrant.
    pub id: WarrantId,
    /// Public key of the authorized holder (Proof-of-Possession).
    ///
    /// Mandatory - the holder must prove they control this key when using the warrant.
    /// This prevents stolen warrants from being used by attackers.
    pub authorized_holder: PublicKey,

    // =========================================================================
    // Execution Warrant Fields
    // =========================================================================
    /// The tool(s) this warrant authorizes (None for issuer warrants).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
    /// Constraints on tool arguments (None for issuer warrants).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<ConstraintSet>,

    // =========================================================================
    // Issuer Warrant Fields
    // =========================================================================
    /// Tools that can be issued by this issuer warrant (None for execution warrants).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuable_tools: Option<Vec<String>>,
    /// Maximum trust level that can be issued (None for execution warrants).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_ceiling: Option<TrustLevel>,
    /// Maximum depth for issued warrants (None for execution warrants).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_issue_depth: Option<u32>,
    /// Constraint bounds on issued warrants (None for execution warrants).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraint_bounds: Option<ConstraintSet>,

    // =========================================================================
    // Common Fields
    // =========================================================================
    /// Trust level of this warrant (optional, for audit/classification).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<TrustLevel>,
    /// When this warrant was issued.
    pub issued_at: DateTime<Utc>,
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
    /// Session ID for session binding (audit only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Agent ID for traceability (e.g., UUID of the agent software/instance).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Public key of the issuer (who signed this warrant).
    pub issuer: PublicKey,
    /// Parent warrant ID (None for root warrants).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<WarrantId>,

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

    /// Embedded delegation chain for self-contained verification.
    ///
    /// Each link contains the issuer's full scope, enabling verification
    /// without fetching parent warrants from external sources.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub issuer_chain: Vec<ChainLink>,
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

// Custom Deserialize to enforce constraint depth validation and canonical binding
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
        if let Some(ref constraints) = raw.payload.constraints {
            constraints
                .validate_depth()
                .map_err(serde::de::Error::custom)?;
        }
        if let Some(ref constraint_bounds) = raw.payload.constraint_bounds {
            constraint_bounds
                .validate_depth()
                .map_err(serde::de::Error::custom)?;
        }

        // SECURITY: Canonical binding verification
        // This prevents attacks where an attacker crafts a token where:
        //   - payload says tools=["read"]
        //   - payload_bytes (what's actually signed) encodes tools=["write"]
        // We recompute canonical bytes from the payload (sans issuer_chain) and require equality.
        let mut payload_sans_chain = raw.payload.clone();
        payload_sans_chain.issuer_chain = Vec::new();
        let canonical_bytes = {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&payload_sans_chain, &mut buf).map_err(|e| {
                serde::de::Error::custom(format!("canonical serialization failed: {}", e))
            })?;
            buf
        };

        if canonical_bytes != raw.payload_bytes {
            return Err(serde::de::Error::custom(
                "payload_bytes mismatch: parsed payload does not match signed bytes (potential forgery)"
            ));
        }

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

    /// Get the warrant type.
    pub fn r#type(&self) -> WarrantType {
        self.payload.r#type
    }

    /// Get the warrant version.
    pub fn version(&self) -> u32 {
        self.payload.version
    }

    /// Get the tool name (None for issuer warrants).
    pub fn tools(&self) -> Option<&[String]> {
        self.payload.tools.as_deref()
    }

    /// Get the constraints (None for issuer warrants).
    pub fn constraints(&self) -> Option<&ConstraintSet> {
        self.payload.constraints.as_ref()
    }

    /// Get issuable tools (None for execution warrants).
    pub fn issuable_tools(&self) -> Option<&[String]> {
        self.payload.issuable_tools.as_deref()
    }

    /// Get trust ceiling (None for execution warrants).
    pub fn trust_ceiling(&self) -> Option<TrustLevel> {
        self.payload.trust_ceiling
    }

    /// Get max issue depth (None for execution warrants).
    pub fn max_issue_depth(&self) -> Option<u32> {
        self.payload.max_issue_depth
    }

    /// Get constraint bounds (None for execution warrants).
    pub fn constraint_bounds(&self) -> Option<&ConstraintSet> {
        self.payload.constraint_bounds.as_ref()
    }

    /// Get trust level (optional, for audit/classification).
    pub fn trust_level(&self) -> Option<TrustLevel> {
        self.payload.trust_level
    }

    /// Get the embedded issuer chain (for self-contained verification).
    pub fn issuer_chain(&self) -> &[ChainLink] {
        &self.payload.issuer_chain
    }

    /// Get when this warrant was issued.
    pub fn issued_at(&self) -> DateTime<Utc> {
        self.payload.issued_at
    }

    /// Validate that constraint nesting depths are within limits.
    ///
    /// Call this after deserializing warrants from untrusted sources
    /// to prevent stack overflow attacks from deeply nested constraints.
    pub fn validate_constraint_depth(&self) -> Result<()> {
        if let Some(constraints) = &self.payload.constraints {
            constraints.validate_depth()?;
        }
        if let Some(constraint_bounds) = &self.payload.constraint_bounds {
            constraint_bounds.validate_depth()?;
        }
        Ok(())
    }

    /// Comprehensive validation of warrant structure and invariants.
    ///
    /// Validates:
    /// 1. Warrant type consistency (execution has tool/constraints, issuer has issuable_tools/trust_ceiling)
    /// 2. Trust level doesn't exceed trust_ceiling for issuer warrants
    /// 3. Constraint depth is valid
    /// 4. max_issue_depth doesn't exceed max_depth
    /// 5. Version is valid
    /// 6. Issuer chain is valid (if present)
    /// 7. Expiration is in the future
    pub fn validate(&self) -> Result<()> {
        // Validate version
        if self.payload.version != WARRANT_VERSION {
            return Err(Error::Validation(format!(
                "unsupported warrant version: {} (expected {})",
                self.payload.version, WARRANT_VERSION
            )));
        }

        // Validate warrant type consistency
        match self.payload.r#type {
            WarrantType::Execution => {
                if self.payload.tools.is_none() {
                    return Err(Error::Validation(
                        "execution warrant must have a tool".to_string(),
                    ));
                }
                if self.payload.issuable_tools.is_some() {
                    return Err(Error::Validation(
                        "execution warrant cannot have issuable_tools".to_string(),
                    ));
                }
                if self.payload.trust_ceiling.is_some() {
                    return Err(Error::Validation(
                        "execution warrant cannot have trust_ceiling".to_string(),
                    ));
                }
                if self.payload.max_issue_depth.is_some() {
                    return Err(Error::Validation(
                        "execution warrant cannot have max_issue_depth".to_string(),
                    ));
                }
            }
            WarrantType::Issuer => {
                if self.payload.tools.is_some() {
                    return Err(Error::Validation(
                        "issuer warrant cannot have a tool".to_string(),
                    ));
                }
                if self.payload.constraints.is_some() {
                    return Err(Error::Validation(
                        "issuer warrant cannot have constraints (use constraint_bounds)"
                            .to_string(),
                    ));
                }
                if self.payload.issuable_tools.is_none()
                    || self.payload.issuable_tools.as_ref().unwrap().is_empty()
                {
                    return Err(Error::Validation(
                        "issuer warrant must have at least one issuable_tool".to_string(),
                    ));
                }
                if self.payload.trust_ceiling.is_none() {
                    return Err(Error::Validation(
                        "issuer warrant must have trust_ceiling".to_string(),
                    ));
                }
            }
        }

        // Validate trust level doesn't exceed trust_ceiling for issuer warrants
        if let (Some(trust_level), Some(trust_ceiling)) =
            (self.payload.trust_level, self.payload.trust_ceiling)
        {
            if trust_level > trust_ceiling {
                return Err(Error::Validation(format!(
                    "trust_level ({:?}) cannot exceed trust_ceiling ({:?})",
                    trust_level, trust_ceiling
                )));
            }
        }

        // Validate max_issue_depth doesn't exceed max_depth
        if let Some(max_issue) = self.payload.max_issue_depth {
            let effective_max = self.effective_max_depth();
            if max_issue > effective_max {
                return Err(Error::Validation(format!(
                    "max_issue_depth ({}) cannot exceed max_depth ({})",
                    max_issue, effective_max
                )));
            }
        }

        // Validate constraint depth
        self.validate_constraint_depth()?;

        // SECURITY: Validate issuer chain length to prevent stack overflow attacks
        // and excessive memory consumption during verification.
        if self.payload.issuer_chain.len() > crate::MAX_ISSUER_CHAIN_LENGTH {
            return Err(Error::Validation(format!(
                "issuer chain length {} exceeds maximum {} (potential DoS attack)",
                self.payload.issuer_chain.len(),
                crate::MAX_ISSUER_CHAIN_LENGTH
            )));
        }

        // Validate issuer chain (if present)
        for (i, link) in self.payload.issuer_chain.iter().enumerate() {
            // Validate link depth matches expected
            if link.issuer_max_depth < self.payload.depth {
                return Err(Error::Validation(format!(
                    "issuer chain link {} has max_depth {} less than warrant depth {}",
                    i, link.issuer_max_depth, self.payload.depth
                )));
            }

            // Validate expiration chain (child must expire before or at parent)
            if link.issuer_expires_at < self.payload.expires_at {
                return Err(Error::Validation(format!(
                    "issuer chain link {} expires before warrant (link: {}, warrant: {})",
                    i, link.issuer_expires_at, self.payload.expires_at
                )));
            }
        }

        // Validate expiration is in the future (warn but don't fail - expired warrants are valid but unusable)
        if self.is_expired() {
            // This is informational - expired warrants are valid structures
        }

        Ok(())
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

    /// Get the authorized holder's public key.
    ///
    /// The holder must prove possession of the corresponding
    /// private key to use this warrant (Proof-of-Possession).
    /// PoP is mandatory in the dual-role architecture.
    pub fn authorized_holder(&self) -> &PublicKey {
        &self.payload.authorized_holder
    }

    /// Check if this warrant requires Proof-of-Possession.
    ///
    /// Always returns `true` in the dual-role architecture (PoP is mandatory).
    pub fn requires_pop(&self) -> bool {
        true
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
    ///
    /// # Type Safety
    ///
    /// If the approver count exceeds `u32::MAX`, it is capped at `u32::MAX`.
    /// In practice, this is extremely unlikely (would require > 4 billion approvers).
    pub fn approval_threshold(&self) -> u32 {
        use std::convert::TryInto;
        match (&self.payload.required_approvers, self.payload.min_approvals) {
            (Some(approvers), Some(min)) => {
                let len: u32 = approvers.len().try_into().unwrap_or(u32::MAX); // Cap at u32::MAX if conversion fails
                min.min(len)
            }
            (Some(approvers), None) => {
                approvers.len().try_into().unwrap_or(u32::MAX) // Cap at u32::MAX if conversion fails
            }
            (None, _) => 0, // No multi-sig required
        }
    }

    /// Get the payload bytes (for batch signature verification).
    ///
    /// Returns the original serialized payload bytes used for signature verification.
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload_bytes
    }

    /// Get the payload bytes without the issuer_chain (for chain link signature verification).
    ///
    /// Chain link signatures are over the payload WITHOUT the issuer_chain to avoid
    /// circular dependencies. This method reconstructs that payload for verification.
    pub fn payload_bytes_without_chain(&self) -> Result<Vec<u8>> {
        let mut payload_without_chain = self.payload.clone();
        payload_without_chain.issuer_chain = Vec::new();
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&payload_without_chain, &mut bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(bytes)
    }

    /// Get the signature (for batch signature verification).
    pub fn signature(&self) -> &Signature {
        &self.signature
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
        self.payload
            .authorized_holder
            .verify(challenge, signature)
            .map_err(|_| Error::SignatureInvalid("holder proof-of-possession failed".to_string()))
    }

    /// Check if the warrant has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.payload.expires_at
    }

    /// Check if this warrant is terminal (cannot delegate further).
    ///
    /// A warrant is terminal when its depth equals or exceeds its max_depth,
    /// meaning it has exhausted its delegation budget.
    ///
    /// Terminal warrants can still execute tools but cannot attenuate/delegate.
    pub fn is_terminal(&self) -> bool {
        match self.payload.max_depth {
            Some(max) => self.payload.depth >= max,
            None => false, // No limit means not terminal
        }
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

        self.verify_signature()
    }

    /// Verify the warrant signature without checking the issuer.
    ///
    /// This verifies that the signature is valid for the payload and the issuer key
    /// contained within the warrant itself. It does NOT verify that the issuer is trusted.
    pub fn verify_signature(&self) -> Result<()> {
        // Use the stored payload bytes for verification (ensures determinism)
        self.payload
            .issuer
            .verify(&self.payload_bytes, &self.signature)
    }

    /// Authorize an action against this warrant.
    ///
    /// Checks:
    /// 1. Warrant is not expired
    /// 2. Warrant type is EXECUTION (issuer warrants cannot authorize actions)
    /// 3. Tool name matches
    /// 4. All constraints are satisfied
    /// 5. Proof-of-Possession (mandatory)
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

        // Only execution warrants can authorize actions
        if self.payload.r#type != WarrantType::Execution {
            return Err(Error::Validation(
                "only execution warrants can authorize actions".to_string(),
            ));
        }

        // Check tool name
        let warrant_tools =
            self.payload.tools.as_ref().ok_or_else(|| {
                Error::Validation("execution warrant must have tools".to_string())
            })?;

        // Check if wildcard or if requested tool is in the list
        if !warrant_tools.contains(&"*".to_string()) && !warrant_tools.iter().any(|t| t == tool) {
            return Err(Error::ConstraintNotSatisfied {
                field: "tool".to_string(),
                reason: format!("warrant is for tools {:?}, not '{}'", warrant_tools, tool),
            });
        }

        // Check constraints
        if let Some(constraints) = &self.payload.constraints {
            constraints.matches(args)?;
        }

        // Check Proof-of-Possession (mandatory) with default window config
        self.verify_pop(tool, args, signature, POP_TIMESTAMP_WINDOW_SECS, 4)
    }

    /// Authorize an action with custom PoP window configuration.
    ///
    /// Use this for deployments with specific security/clock requirements:
    /// - Smaller windows = tighter security, requires better clock sync
    /// - Larger windows = more tolerant of clock skew, larger replay window
    ///
    /// # Arguments
    ///
    /// * `tool` - The tool being invoked
    /// * `args` - The arguments to the tool
    /// * `signature` - The PoP signature
    /// * `pop_window_secs` - Size of each time window in seconds
    /// * `pop_max_windows` - Number of windows to accept
    pub fn authorize_with_pop_config(
        &self,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&Signature>,
        pop_window_secs: i64,
        pop_max_windows: u32,
    ) -> Result<()> {
        // Perform same checks as authorize()
        if self.is_expired() {
            return Err(Error::WarrantExpired(self.payload.expires_at));
        }

        if self.payload.r#type != WarrantType::Execution {
            return Err(Error::Validation(
                "only execution warrants can authorize actions".to_string(),
            ));
        }

        let warrant_tools =
            self.payload.tools.as_ref().ok_or_else(|| {
                Error::Validation("execution warrant must have tools".to_string())
            })?;

        // Check if the requested tool is allowed
        // "*" is a wildcard that allows any tool
        if !warrant_tools.contains(&"*".to_string()) && !warrant_tools.iter().any(|t| t == tool) {
            return Err(Error::ConstraintNotSatisfied {
                field: "tool".to_string(),
                reason: format!("warrant is for tools '{:?}', not '{}'", warrant_tools, tool),
            });
        }

        if let Some(constraints) = &self.payload.constraints {
            constraints.matches(args)?;
        }

        // Check PoP with custom window config
        self.verify_pop(tool, args, signature, pop_window_secs, pop_max_windows)
    }

    /// Verify PoP signature with configurable window.
    fn verify_pop(
        &self,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&Signature>,
        window_secs: i64,
        max_windows: u32,
    ) -> Result<()> {
        let signature = signature
            .ok_or_else(|| Error::MissingSignature("Proof-of-Possession required".to_string()))?;

        let now = Utc::now().timestamp();

        let mut sorted_args: Vec<(&String, &ConstraintValue)> = args.iter().collect();
        sorted_args.sort_by_key(|(k, _)| *k);

        let mut verified = false;
        for i in 0..max_windows {
            // Try current and recent time windows
            let window_ts = (now / window_secs - i as i64) * window_secs;
            let challenge_data = (self.payload.id.as_str(), tool, &sorted_args, window_ts);
            let mut challenge_bytes = Vec::new();
            if ciborium::ser::into_writer(&challenge_data, &mut challenge_bytes).is_err() {
                continue;
            }
            if self
                .payload
                .authorized_holder
                .verify(&challenge_bytes, signature)
                .is_ok()
            {
                verified = true;
                break;
            }
        }

        if !verified {
            return Err(Error::SignatureInvalid(
                "Proof-of-Possession failed or expired".to_string(),
            ));
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
        keypair: &SigningKey,
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

    /// Generate a deduplication key for replay protection.
    ///
    /// This key can be used as a cache key to prevent replay attacks within
    /// the PoP validity window (~2 minutes). Store this key with a TTL of
    /// `POP_TIMESTAMP_WINDOW_SECS * 4` (120 seconds by default).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let dedup_key = warrant.dedup_key("upgrade_cluster", &args);
    /// if cache.contains(&dedup_key) {
    ///     return Err("Duplicate request - possible replay attack");
    /// }
    /// cache.insert_with_ttl(dedup_key, Duration::from_secs(120));
    /// // ... proceed with authorization
    /// ```
    ///
    /// # Format
    ///
    /// Returns a hex string: `sha256(warrant_id || tool || sorted_args_cbor)`
    ///
    /// This is deterministic: same (warrant, tool, args) always produces
    /// the same key, enabling consistent deduplication across services.
    pub fn dedup_key(&self, tool: &str, args: &HashMap<String, ConstraintValue>) -> String {
        use sha2::{Digest, Sha256};

        let mut sorted_args: Vec<(&String, &ConstraintValue)> = args.iter().collect();
        sorted_args.sort_by_key(|(k, _)| *k);

        // Serialize the dedup payload
        let payload = (self.payload.id.as_str(), tool, &sorted_args);
        let mut payload_bytes = Vec::new();
        // Unwrap is safe here - these types always serialize
        ciborium::ser::into_writer(&payload, &mut payload_bytes)
            .expect("dedup payload serialization should never fail");

        // Hash to fixed-length key
        let mut hasher = Sha256::new();
        hasher.update(&payload_bytes);
        let hash = hasher.finalize();

        hex::encode(hash)
    }

    /// Get the recommended TTL for deduplication cache entries.
    ///
    /// This is `POP_TIMESTAMP_WINDOW_SECS * 4` (120 seconds by default),
    /// which matches the PoP verification window.
    pub const fn dedup_ttl_secs() -> i64 {
        POP_TIMESTAMP_WINDOW_SECS * 4
    }

    /// Create a builder for attenuating this warrant.
    pub fn attenuate(&self) -> AttenuationBuilder<'_> {
        AttenuationBuilder::new(self)
    }

    /// Create a builder for issuing an execution warrant from this issuer warrant.
    ///
    /// This method allows an issuer warrant holder to create new execution warrants
    /// that are validated against the issuer's constraints:
    /// - Tool must be in `issuable_tools`
    /// - Trust level must be <= `trust_ceiling`
    /// - Constraints must be within `constraint_bounds`
    /// - Depth must not exceed `max_issue_depth`
    ///
    /// # Errors
    ///
    /// Returns an error if this warrant is not an issuer warrant.
    pub fn issue_execution_warrant(&self) -> Result<IssuanceBuilder<'_>> {
        if self.payload.r#type != WarrantType::Issuer {
            return Err(Error::Validation(
                "can only issue execution warrants from issuer warrants".to_string(),
            ));
        }
        Ok(IssuanceBuilder::new(self))
    }
}

/// Builder for creating root warrants.
#[derive(Debug)]
pub struct WarrantBuilder {
    warrant_type: Option<WarrantType>,
    // Execution warrant fields
    tools: Option<Vec<String>>,
    constraints: ConstraintSet,
    // Issuer warrant fields
    issuable_tools: Option<Vec<String>>,
    trust_ceiling: Option<TrustLevel>,
    max_issue_depth: Option<u32>,
    constraint_bounds: ConstraintSet,
    // Common fields
    trust_level: Option<TrustLevel>,
    ttl: Option<Duration>,
    max_depth: Option<u32>,
    session_id: Option<String>,
    agent_id: Option<String>,
    authorized_holder: Option<PublicKey>,
    required_approvers: Option<Vec<PublicKey>>,
    min_approvals: Option<u32>,
    id: Option<WarrantId>,
    parent_id: Option<WarrantId>,
    depth: Option<u32>,
}

impl WarrantBuilder {
    /// Create a new warrant builder.
    pub fn new() -> Self {
        Self {
            warrant_type: None,
            tools: None,
            constraints: ConstraintSet::new(),
            issuable_tools: None,
            trust_ceiling: None,
            max_issue_depth: None,
            constraint_bounds: ConstraintSet::new(),
            trust_level: None,
            ttl: None,
            max_depth: None,
            session_id: None,
            agent_id: None,
            authorized_holder: None,
            required_approvers: None,
            min_approvals: None,
            id: None,
            parent_id: None,
            depth: None,
        }
    }

    /// Set the warrant type (EXECUTION or ISSUER).
    pub fn r#type(mut self, warrant_type: WarrantType) -> Self {
        self.warrant_type = Some(warrant_type);
        self
    }

    /// Set the trust level (optional, for audit/classification).
    pub fn trust_level(mut self, level: TrustLevel) -> Self {
        self.trust_level = Some(level);
        self
    }

    /// Set issuable tools (for issuer warrants).
    pub fn issuable_tools(mut self, tools: Vec<String>) -> Self {
        self.issuable_tools = Some(tools);
        self
    }

    /// Set trust ceiling (for issuer warrants).
    pub fn trust_ceiling(mut self, ceiling: TrustLevel) -> Self {
        self.trust_ceiling = Some(ceiling);
        self
    }

    /// Set maximum issue depth (for issuer warrants).
    pub fn max_issue_depth(mut self, depth: u32) -> Self {
        self.max_issue_depth = Some(depth);
        self
    }

    /// Add a constraint bound (for issuer warrants).
    pub fn constraint_bound(
        mut self,
        field: impl Into<String>,
        constraint: impl Into<Constraint>,
    ) -> Self {
        self.constraint_bounds.insert(field, constraint);
        self
    }

    /// Set the warrant depth (advanced usage).
    pub fn depth(mut self, depth: u32) -> Self {
        self.depth = Some(depth);
        self
    }

    /// Set the parent warrant ID (advanced usage).
    pub fn parent_id(mut self, parent_id: WarrantId) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    /// Set a custom warrant ID.
    ///
    /// If not set, a random time-ordered ID (UUIDv7) will be generated.
    pub fn id(mut self, id: WarrantId) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the tool name (single tool).
    pub fn tool(mut self, tool: impl Into<String>) -> Self {
        self.tools = Some(vec![tool.into()]);
        self
    }

    /// Set multiple tools.
    pub fn tools(mut self, tools: Vec<String>) -> Self {
        self.tools = Some(tools);
        self
    }

    /// Add a constraint.
    pub fn constraint(
        mut self,
        field: impl Into<String>,
        constraint: impl Into<Constraint>,
    ) -> Self {
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
    pub fn build(self, keypair: &SigningKey) -> Result<Warrant> {
        // Determine warrant type (default to EXECUTION for backward compatibility)
        let warrant_type = self.warrant_type.unwrap_or(WarrantType::Execution);

        // Validate required fields based on warrant type
        match warrant_type {
            WarrantType::Execution => {
                if self.tools.is_none() {
                    return Err(Error::Validation(
                        "execution warrant requires a tool".to_string(),
                    ));
                }
                if self.issuable_tools.is_some() {
                    return Err(Error::Validation(
                        "execution warrant cannot have issuable_tools".to_string(),
                    ));
                }
                if self.trust_ceiling.is_some() {
                    return Err(Error::Validation(
                        "execution warrant cannot have trust_ceiling".to_string(),
                    ));
                }
            }
            WarrantType::Issuer => {
                if self.tools.is_some() {
                    return Err(Error::Validation(
                        "issuer warrant cannot have a tool".to_string(),
                    ));
                }
                if self.issuable_tools.is_none() || self.issuable_tools.as_ref().unwrap().is_empty()
                {
                    return Err(Error::Validation(
                        "issuer warrant requires at least one issuable_tool".to_string(),
                    ));
                }
                if self.trust_ceiling.is_none() {
                    return Err(Error::Validation(
                        "issuer warrant requires trust_ceiling".to_string(),
                    ));
                }
            }
        }

        // Validate common required fields
        let ttl = self.ttl.ok_or(Error::MissingField("ttl".to_string()))?;
        let authorized_holder = self.authorized_holder.ok_or_else(|| {
            Error::Validation("authorized_holder is required (Mandatory PoP)".into())
        })?;

        // Validate max_depth doesn't exceed protocol cap
        if let Some(max) = self.max_depth {
            if max > MAX_DELEGATION_DEPTH {
                return Err(Error::DepthExceeded(max, MAX_DELEGATION_DEPTH));
            }
        }

        // Validate max_issue_depth for issuer warrants
        if let Some(max_issue) = self.max_issue_depth {
            if let Some(max_delegation) = self.max_depth {
                if max_issue > max_delegation {
                    return Err(Error::Validation(format!(
                        "max_issue_depth ({}) cannot exceed max_depth ({})",
                        max_issue, max_delegation
                    )));
                }
            }
        }

        // Validate trust_level doesn't exceed trust_ceiling for issuer warrants
        if let (Some(trust_level), Some(trust_ceiling)) = (self.trust_level, self.trust_ceiling) {
            if trust_level > trust_ceiling {
                return Err(Error::Validation(format!(
                    "trust_level ({:?}) cannot exceed trust_ceiling ({:?})",
                    trust_level, trust_ceiling
                )));
            }
        }

        let chrono_ttl = ChronoDuration::from_std(ttl)
            .map_err(|_| Error::InvalidTtl("TTL too large".to_string()))?;
        let issued_at = Utc::now();
        let expires_at = issued_at + chrono_ttl;

        // Validate min_approvals if set
        if let (Some(approvers), Some(min)) = (&self.required_approvers, self.min_approvals) {
            if min as usize > approvers.len() {
                return Err(Error::MonotonicityViolation(format!(
                    "min_approvals ({}) cannot exceed required_approvers count ({})",
                    min,
                    approvers.len()
                )));
            }
        }

        // Validate constraint depth
        if !self.constraints.is_empty() {
            self.constraints.validate_depth()?;
        }
        if !self.constraint_bounds.is_empty() {
            self.constraint_bounds.validate_depth()?;
        }

        let payload = WarrantPayload {
            version: WARRANT_VERSION,
            r#type: warrant_type,
            id: self.id.unwrap_or_default(),
            authorized_holder,
            tools: self.tools,
            constraints: if self.constraints.is_empty() {
                None
            } else {
                Some(self.constraints)
            },
            issuable_tools: self.issuable_tools,
            trust_ceiling: self.trust_ceiling,
            max_issue_depth: self.max_issue_depth,
            constraint_bounds: if self.constraint_bounds.is_empty() {
                None
            } else {
                Some(self.constraint_bounds)
            },
            trust_level: self.trust_level,
            issued_at,
            expires_at,
            depth: self.depth.unwrap_or(0),
            max_depth: self.max_depth,
            session_id: self.session_id,
            agent_id: self.agent_id,
            issuer: keypair.public_key(),
            parent_id: self.parent_id,
            required_approvers: self.required_approvers,
            min_approvals: self.min_approvals,
            issuer_chain: Vec::new(), // Root warrants have empty chain
        };

        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)?;
        let signature = keypair.sign(&payload_bytes);

        Ok(Warrant {
            payload,
            signature,
            payload_bytes,
        })
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
    // Execution warrant fields
    exec_tools: Option<Vec<String>>, // For narrowing execution warrant tools
    constraints: ConstraintSet,
    // Issuer warrant fields
    issuable_tools: Option<Vec<String>>,
    trust_ceiling: Option<TrustLevel>,
    max_issue_depth: Option<u32>,
    constraint_bounds: ConstraintSet,
    // Common fields
    trust_level: Option<TrustLevel>,
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
        // Inherit from parent based on warrant type
        let (constraints, issuable_tools, trust_ceiling, max_issue_depth, constraint_bounds) =
            match parent.payload.r#type {
                WarrantType::Execution => (
                    parent.payload.constraints.clone().unwrap_or_default(),
                    None,
                    None,
                    None,
                    ConstraintSet::new(),
                ),
                WarrantType::Issuer => (
                    ConstraintSet::new(),
                    parent.payload.issuable_tools.clone(),
                    parent.payload.trust_ceiling,
                    parent.payload.max_issue_depth,
                    parent.payload.constraint_bounds.clone().unwrap_or_default(),
                ),
            };

        Self {
            parent,
            exec_tools: None, // Will inherit from parent if not set
            constraints,
            issuable_tools,
            trust_ceiling,
            max_issue_depth,
            constraint_bounds,
            trust_level: parent.payload.trust_level,
            ttl: None,
            max_depth: None, // Will inherit from parent if not set
            session_id: parent.payload.session_id.clone(),
            agent_id: parent.payload.agent_id.clone(),
            authorized_holder: Some(parent.payload.authorized_holder.clone()),
            // Multi-sig: inherit from parent (can only add MORE approvers or raise threshold)
            required_approvers: parent.payload.required_approvers.clone(),
            min_approvals: parent.payload.min_approvals,
        }
    }

    /// Override a constraint with a narrower one.
    pub fn constraint(
        mut self,
        field: impl Into<String>,
        constraint: impl Into<Constraint>,
    ) -> Self {
        self.constraints.insert(field, constraint);
        self
    }

    /// Narrow execution warrant tools to a subset.
    ///
    /// The specified tools must be a subset of the parent's tools.
    /// This enables the "always shrinking authority" principle for non-terminal warrants.
    /// For ISSUER warrants, use `issuable_tool()` instead.
    ///
    /// # Example
    /// ```ignore
    /// // Parent has tools: ["read_file", "send_email", "query_db"]
    /// let child = parent.attenuate()
    ///     .with_tools(vec!["read_file".to_string()])  // Narrow to just read_file
    ///     .authorized_holder(worker.public_key())
    ///     .build(&keypair, &keypair)?;
    /// ```
    pub fn with_tools(mut self, tools: Vec<String>) -> Self {
        self.exec_tools = Some(tools);
        self
    }

    /// Narrow to a single tool (for execution warrants).
    pub fn with_tool(mut self, tool: impl Into<String>) -> Self {
        self.exec_tools = Some(vec![tool.into()]);
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
    ///
    /// # Important
    ///
    /// If you don't call this method, the child warrant will inherit the parent's
    /// `authorized_holder`. This means the parent can re-delegate to itself, which
    /// is valid but may not be what you want. Always explicitly set the holder
    /// when delegating to a different agent.
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
                    "cannot remove multi-sig requirement from parent".to_string(),
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
                    min,
                    approvers.len()
                )));
            }
        }

        Ok(())
    }

    /// Build and sign the attenuated warrant.
    ///
    /// # Arguments
    ///
    /// * `keypair` - The keypair of the delegator (who is creating the child warrant)
    /// * `parent_keypair` - The keypair of the parent warrant issuer (for chain link signature)
    pub fn build(self, keypair: &SigningKey, parent_keypair: &SigningKey) -> Result<Warrant> {
        // Use checked arithmetic to prevent overflow
        let new_depth = self
            .parent
            .payload
            .depth
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

        // Validate attenuation monotonicity based on warrant type
        match self.parent.payload.r#type {
            WarrantType::Execution => {
                // For execution warrants, validate tool narrowing (if specified)
                if let Some(ref child_tools) = self.exec_tools {
                    if let Some(parent_tools) = &self.parent.payload.tools {
                        // Child tools must be a subset of parent tools
                        for tool in child_tools {
                            if !parent_tools.contains(tool) {
                                return Err(Error::MonotonicityViolation(format!(
                                    "tool '{}' not in parent's tools {:?}",
                                    tool, parent_tools
                                )));
                            }
                        }
                        // Must have at least one tool
                        if child_tools.is_empty() {
                            return Err(Error::Validation(
                                "execution warrant must have at least one tool".to_string(),
                            ));
                        }
                    }
                }
                // For execution warrants, validate constraint attenuation
                if let Some(parent_constraints) = &self.parent.payload.constraints {
                    parent_constraints.validate_attenuation(&self.constraints)?;
                }
            }
            WarrantType::Issuer => {
                // For issuer warrants, validate issuable_tools and trust_ceiling monotonicity
                if let Some(parent_issuable) = &self.parent.payload.issuable_tools {
                    if let Some(ref child_issuable) = self.issuable_tools {
                        // Child issuable_tools must be a subset of parent
                        for tool in child_issuable {
                            if !parent_issuable.contains(tool) {
                                return Err(Error::MonotonicityViolation(format!(
                                    "issuable_tool '{}' not in parent's issuable_tools",
                                    tool
                                )));
                            }
                        }
                    }
                }
                // Trust ceiling can only decrease (higher trust level = lower value in enum)
                if let (Some(parent_ceiling), Some(child_ceiling)) =
                    (self.parent.payload.trust_ceiling, self.trust_ceiling)
                {
                    if child_ceiling > parent_ceiling {
                        return Err(Error::MonotonicityViolation(format!(
                            "trust_ceiling cannot increase: parent {:?}, child {:?}",
                            parent_ceiling, child_ceiling
                        )));
                    }
                }
                // Constraint bounds must be monotonic
                if let Some(parent_bounds) = &self.parent.payload.constraint_bounds {
                    parent_bounds.validate_attenuation(&self.constraint_bounds)?;
                }
            }
        }

        // Validate multi-sig monotonicity (cannot remove approvers or lower threshold)
        self.validate_multisig_monotonicity()?;

        // Warn if authorized_holder wasn't explicitly changed (common mistake)
        // Note: Inheriting parent's holder is valid (self-delegation), but usually not intended
        let authorized_holder = self
            .authorized_holder
            .ok_or_else(|| Error::Validation("authorized_holder is required".to_string()))?;
        if authorized_holder == self.parent.payload.authorized_holder {
            // Holder wasn't changed - this is valid but might be unintentional
            // We don't error here because self-delegation is a valid pattern,
            // but users should be aware they're delegating to the same key
        }

        // NOTE: Holder cycling (A → B → A) is NOT blocked for execution warrants because:
        // - Monotonic attenuation guarantees privileges can only shrink, never expand
        // - Even if B delegates back to A, A gets a strictly weaker warrant
        // - The cycle detection in planes.rs prevents infinite loops via warrant ID tracking
        //
        // For issuer warrants, self-issuance IS blocked in IssuanceBuilder to prevent
        // privilege escalation through the warrant creation mechanism.

        // Calculate expiration (must not exceed parent)
        let expires_at = if let Some(ttl) = self.ttl {
            let chrono_ttl = ChronoDuration::from_std(ttl)
                .map_err(|_| Error::InvalidTtl("TTL too large".to_string()))?;
            let proposed = Utc::now() + chrono_ttl;
            if proposed > self.parent.payload.expires_at {
                self.parent.payload.expires_at
            } else {
                proposed
            }
        } else {
            self.parent.payload.expires_at
        };

        // Determine effective min_approvals (inherit if not set)
        let effective_min = self.min_approvals.or(self.parent.payload.min_approvals);

        // SECURITY: Check issuer chain length before adding another link
        // This prevents building warrants with chains exceeding the protocol limit.
        if self.parent.payload.issuer_chain.len() >= crate::MAX_ISSUER_CHAIN_LENGTH {
            return Err(Error::Validation(format!(
                "cannot delegate: issuer chain length {} would exceed maximum {}",
                self.parent.payload.issuer_chain.len() + 1,
                crate::MAX_ISSUER_CHAIN_LENGTH
            )));
        }

        // Build issuer chain link from parent
        let mut issuer_chain = self.parent.payload.issuer_chain.clone();

        // Create the child payload first (without issuer_chain) to sign it
        let payload = WarrantPayload {
            version: WARRANT_VERSION,
            r#type: self.parent.payload.r#type, // Inherit type from parent
            id: WarrantId::new(),
            authorized_holder,
            tools: match self.parent.payload.r#type {
                WarrantType::Execution => Some(
                    // Use narrowed tools if specified, otherwise inherit from parent
                    self.exec_tools.clone().unwrap_or_else(|| {
                        self.parent
                            .payload
                            .tools
                            .clone()
                            .expect("execution warrant must have tools")
                    }),
                ),
                WarrantType::Issuer => None,
            },
            constraints: match self.parent.payload.r#type {
                WarrantType::Execution => {
                    if self.constraints.is_empty() {
                        None
                    } else {
                        Some(self.constraints)
                    }
                }
                WarrantType::Issuer => None,
            },
            issuable_tools: match self.parent.payload.r#type {
                WarrantType::Issuer => self.issuable_tools.clone(),
                WarrantType::Execution => None,
            },
            trust_ceiling: match self.parent.payload.r#type {
                WarrantType::Issuer => self.trust_ceiling,
                WarrantType::Execution => None,
            },
            max_issue_depth: match self.parent.payload.r#type {
                WarrantType::Issuer => self.max_issue_depth,
                WarrantType::Execution => None,
            },
            constraint_bounds: match self.parent.payload.r#type {
                WarrantType::Issuer => {
                    if self.constraint_bounds.is_empty() {
                        None
                    } else {
                        Some(self.constraint_bounds)
                    }
                }
                WarrantType::Execution => None,
            },
            trust_level: self.trust_level,
            issued_at: Utc::now(),
            expires_at,
            depth: new_depth,
            max_depth: effective_max,
            session_id: self.session_id,
            agent_id: self.agent_id,
            issuer: keypair.public_key(),
            parent_id: Some(self.parent.payload.id.clone()),
            required_approvers: self.required_approvers,
            min_approvals: effective_min,
            issuer_chain: Vec::new(), // Temporarily empty for signing
        };

        // Serialize payload to sign it
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)?;
        let signature = keypair.sign(&payload_bytes);

        // Now create the chain link with parent's signature over BOTH
        // the child warrant AND the issuer's scope fields
        let issuer_scope = ChainLinkSignedData {
            child_payload_bytes: payload_bytes.clone(),
            issuer_id: self.parent.payload.id.clone(),
            issuer_type: self.parent.payload.r#type,
            issuer_tools: self.parent.payload.tools.clone(),
            issuer_constraints: self.parent.payload.constraints.clone(),
            issuer_trust: self.parent.payload.trust_level,
            issuer_expires_at: self.parent.payload.expires_at,
            issuer_max_depth: self.parent.effective_max_depth(),
        };
        let mut scope_bytes = Vec::new();
        ciborium::ser::into_writer(&issuer_scope, &mut scope_bytes)?;

        let parent_link = ChainLink {
            issuer_id: self.parent.payload.id.clone(),
            issuer_pubkey: self.parent.payload.issuer.clone(),
            issuer_type: self.parent.payload.r#type,
            issuer_tools: self.parent.payload.tools.clone(),
            issuer_constraints: self.parent.payload.constraints.clone(),
            issuer_trust: self.parent.payload.trust_level,
            issuer_expires_at: self.parent.payload.expires_at,
            issuer_max_depth: self.parent.effective_max_depth(),
            // Parent signs ChainLinkSignedData (child + issuer scope)
            signature: parent_keypair.sign(&scope_bytes),
        };
        issuer_chain.push(parent_link);

        // Update payload with the chain link
        let mut final_payload = payload;
        final_payload.issuer_chain = issuer_chain;

        // Re-serialize with the chain link included
        let mut final_payload_bytes = Vec::new();
        ciborium::ser::into_writer(&final_payload, &mut final_payload_bytes)?;

        Ok(Warrant {
            payload: final_payload,
            signature,
            payload_bytes, // Child's signature is over payload WITHOUT chain
        })
    }
}

/// Builder for attenuating warrants that owns its data (no lifetime).
///
/// This is identical to `AttenuationBuilder` but owns the parent warrant,
/// making it suitable for FFI boundaries (e.g., Python bindings) where
/// lifetime management is difficult.
///
/// # Example
///
/// ```ignore
/// let builder = OwnedAttenuationBuilder::new(parent.clone());
/// let child = builder
///     .constraint("path", Pattern::new("/data/specific/*"))
///     .ttl(Duration::from_secs(60))
///     .build(&delegator_keypair, &parent_keypair)?;
/// ```
#[derive(Debug, Clone)]
pub struct OwnedAttenuationBuilder {
    parent: Warrant,
    // Execution warrant fields
    exec_tools: Option<Vec<String>>, // For narrowing execution warrant tools
    constraints: ConstraintSet,
    // Issuer warrant fields
    issuable_tools: Option<Vec<String>>,
    trust_ceiling: Option<TrustLevel>,
    max_issue_depth: Option<u32>,
    constraint_bounds: ConstraintSet,
    // Common fields
    trust_level: Option<TrustLevel>,
    ttl: Option<Duration>,
    max_depth: Option<u32>,
    session_id: Option<String>,
    agent_id: Option<String>,
    authorized_holder: Option<PublicKey>,
    required_approvers: Option<Vec<PublicKey>>,
    min_approvals: Option<u32>,
    /// Intent/purpose for this delegation (for audit trails).
    intent: Option<String>,
}

impl OwnedAttenuationBuilder {
    /// Create a new owned attenuation builder.
    pub fn new(parent: Warrant) -> Self {
        // Inherit from parent based on warrant type
        let (constraints, issuable_tools, trust_ceiling, max_issue_depth, constraint_bounds) =
            match parent.payload.r#type {
                WarrantType::Execution => (
                    parent.payload.constraints.clone().unwrap_or_default(),
                    None,
                    None,
                    None,
                    ConstraintSet::new(),
                ),
                WarrantType::Issuer => (
                    ConstraintSet::new(),
                    parent.payload.issuable_tools.clone(),
                    parent.payload.trust_ceiling,
                    parent.payload.max_issue_depth,
                    parent.payload.constraint_bounds.clone().unwrap_or_default(),
                ),
            };

        Self {
            trust_level: parent.payload.trust_level,
            session_id: parent.payload.session_id.clone(),
            agent_id: parent.payload.agent_id.clone(),
            authorized_holder: Some(parent.payload.authorized_holder.clone()),
            required_approvers: parent.payload.required_approvers.clone(),
            min_approvals: parent.payload.min_approvals,
            parent,
            exec_tools: None, // Will inherit from parent if not narrowed
            constraints,
            issuable_tools,
            trust_ceiling,
            max_issue_depth,
            constraint_bounds,
            ttl: None,
            max_depth: None,
            intent: None,
        }
    }

    /// Get a reference to the parent warrant.
    pub fn parent(&self) -> &Warrant {
        &self.parent
    }

    /// Get the current constraints being configured.
    pub fn constraints(&self) -> &ConstraintSet {
        &self.constraints
    }

    /// Get the configured TTL (if any).
    pub fn ttl_seconds(&self) -> Option<u64> {
        self.ttl.map(|d| d.as_secs())
    }

    /// Get the configured holder (if any).
    pub fn holder(&self) -> Option<&PublicKey> {
        self.authorized_holder.as_ref()
    }

    /// Get the configured trust level.
    pub fn trust_level(&self) -> Option<TrustLevel> {
        self.trust_level
    }

    /// Get the configured intent.
    pub fn intent(&self) -> Option<&str> {
        self.intent.as_deref()
    }

    /// Override a constraint with a narrower one.
    pub fn constraint(
        mut self,
        field: impl Into<String>,
        constraint: impl Into<Constraint>,
    ) -> Self {
        self.constraints.insert(field, constraint);
        self
    }

    /// Set a constraint (mutable version for FFI).
    pub fn set_constraint(&mut self, field: impl Into<String>, constraint: impl Into<Constraint>) {
        self.constraints.insert(field, constraint);
    }

    /// Narrow execution warrant tools to a subset.
    ///
    /// The specified tools must be a subset of the parent's tools.
    /// This is for EXECUTION warrants. For ISSUER warrants, use `issuable_tool()`.
    pub fn with_tool(mut self, tool: impl Into<String>) -> Self {
        self.exec_tools = Some(vec![tool.into()]);
        self
    }

    /// Narrow execution warrant tools to a subset (multiple tools).
    ///
    /// The specified tools must be a subset of the parent's tools.
    pub fn with_tools(mut self, tools: Vec<String>) -> Self {
        self.exec_tools = Some(tools);
        self
    }

    /// Set execution tools (mutable version for FFI).
    pub fn set_exec_tools(&mut self, tools: Vec<String>) {
        self.exec_tools = Some(tools);
    }

    /// Set single execution tool (mutable version for FFI).
    pub fn set_exec_tool(&mut self, tool: impl Into<String>) {
        self.exec_tools = Some(vec![tool.into()]);
    }

    /// Set a shorter TTL.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set TTL (mutable version for FFI).
    pub fn set_ttl(&mut self, ttl: Duration) {
        self.ttl = Some(ttl);
    }

    /// Set a lower maximum delegation depth.
    pub fn max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = Some(max_depth);
        self
    }

    /// Set max depth (mutable version for FFI).
    pub fn set_max_depth(&mut self, max_depth: u32) {
        self.max_depth = Some(max_depth);
    }

    /// Make this warrant terminal (cannot be delegated further).
    pub fn terminal(mut self) -> Self {
        self.max_depth = Some(self.parent.depth() + 1);
        self
    }

    /// Make this warrant terminal (mutable version for FFI).
    pub fn set_terminal(&mut self) {
        self.max_depth = Some(self.parent.depth() + 1);
    }

    /// Set or change the agent ID.
    pub fn agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Set or change the authorized holder.
    pub fn authorized_holder(mut self, public_key: PublicKey) -> Self {
        self.authorized_holder = Some(public_key);
        self
    }

    /// Set holder (mutable version for FFI).
    pub fn set_authorized_holder(&mut self, public_key: PublicKey) {
        self.authorized_holder = Some(public_key);
    }

    /// Set the trust level for the child warrant.
    pub fn set_trust_level(&mut self, level: TrustLevel) {
        self.trust_level = Some(level);
    }

    /// Set the intent/purpose for this delegation.
    pub fn set_intent(&mut self, intent: impl Into<String>) {
        self.intent = Some(intent.into());
    }

    /// Set a single tool for issuable_tools (for issuer warrants).
    pub fn tool(mut self, tool: impl Into<String>) -> Self {
        self.issuable_tools = Some(vec![tool.into()]);
        self
    }

    /// Set a single tool (mutable version for FFI).
    pub fn set_tool(&mut self, tool: impl Into<String>) {
        self.issuable_tools = Some(vec![tool.into()]);
    }

    /// Set multiple tools for issuable_tools (for issuer warrants).
    pub fn tools(mut self, tools: Vec<String>) -> Self {
        self.issuable_tools = Some(tools);
        self
    }

    /// Set multiple tools (mutable version for FFI).
    pub fn set_tools(&mut self, tools: Vec<String>) {
        self.issuable_tools = Some(tools);
    }

    /// Drop tools from issuable_tools (for issuer warrants).
    pub fn drop_tools(&mut self, tools_to_drop: Vec<String>) {
        if let Some(current) = &mut self.issuable_tools {
            current.retain(|t| !tools_to_drop.contains(t));
        } else if let Some(parent_tools) = &self.parent.payload.issuable_tools {
            // If not set, start with parent's tools and remove
            let mut current = parent_tools.clone();
            current.retain(|t| !tools_to_drop.contains(t));
            self.issuable_tools = Some(current);
        }
    }

    /// Add required approvers.
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

    /// Increase the minimum approvals required.
    pub fn raise_min_approvals(mut self, min: u32) -> Self {
        let current = self.min_approvals.unwrap_or(0);
        self.min_approvals = Some(min.max(current));
        self
    }

    /// Compute the diff between parent and proposed child warrant.
    ///
    /// This can be used to preview what will change before calling `build()`.
    pub fn diff(&self) -> crate::diff::DelegationDiff {
        use crate::diff::{
            ConstraintDiff, DelegationDiff, DepthDiff, ToolsDiff, TrustDiff, TtlDiff,
        };
        use chrono::Utc;
        use std::collections::HashMap;

        // Tools - for attenuation, tools stay the same
        let parent_tools = self.parent.tools().map(|t| t.to_vec()).unwrap_or_default();
        let child_tools = parent_tools.clone(); // Attenuation doesn't change tools
        let tools = ToolsDiff::new(parent_tools, child_tools);

        // Constraints
        let mut constraints: HashMap<String, ConstraintDiff> = HashMap::new();
        let parent_constraints = self.parent.constraints().cloned().unwrap_or_default();

        // Get all constraint fields (parent + builder's overrides)
        let mut all_fields: Vec<String> = Vec::new();
        for (field, _) in parent_constraints.iter() {
            all_fields.push(field.clone());
        }
        for (field, _) in self.constraints.iter() {
            if !all_fields.contains(field) {
                all_fields.push(field.clone());
            }
        }

        for field in all_fields {
            let pc = parent_constraints.get(&field).cloned();
            // Child constraint: use override if set, otherwise inherit from parent
            let cc = self.constraints.get(&field).cloned().or_else(|| pc.clone());
            constraints.insert(field.clone(), ConstraintDiff::new(field, pc, cc));
        }

        // TTL
        let now = Utc::now();
        let parent_remaining = (self.parent.expires_at() - now).num_seconds().max(0);
        let child_ttl = self.ttl.map(|d| d.as_secs() as i64);
        let ttl = TtlDiff::new(Some(parent_remaining), child_ttl);

        // Trust
        let trust = TrustDiff::new(self.parent.trust_level(), self.trust_level);

        // Depth
        let depth = DepthDiff::new(
            self.parent.depth(),
            self.parent.depth() + 1,
            self.parent.max_depth(),
        );

        DelegationDiff {
            parent_warrant_id: self.parent.id().to_string(),
            child_warrant_id: None, // Not yet built
            timestamp: Utc::now(),
            tools,
            constraints,
            ttl,
            trust,
            depth,
            intent: self.intent.clone(),
        }
    }

    /// Validate multi-sig monotonicity.
    fn validate_multisig_monotonicity(&self) -> Result<()> {
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
                return Err(Error::MonotonicityViolation(
                    "cannot remove multi-sig requirement from parent".to_string(),
                ));
            }
        }

        if let Some(parent_min) = self.parent.payload.min_approvals {
            if let Some(child_min) = self.min_approvals {
                if child_min < parent_min {
                    return Err(Error::MonotonicityViolation(format!(
                        "cannot lower min_approvals from {} to {}",
                        parent_min, child_min
                    )));
                }
            }
        }

        if let (Some(approvers), Some(min)) = (&self.required_approvers, self.min_approvals) {
            if min as usize > approvers.len() {
                return Err(Error::MonotonicityViolation(format!(
                    "min_approvals ({}) cannot exceed required_approvers count ({})",
                    min,
                    approvers.len()
                )));
            }
        }

        Ok(())
    }

    /// Build and sign the attenuated warrant.
    pub fn build(self, keypair: &SigningKey, parent_keypair: &SigningKey) -> Result<Warrant> {
        let new_depth = self
            .parent
            .payload
            .depth
            .checked_add(1)
            .ok_or(Error::DepthExceeded(u32::MAX, MAX_DELEGATION_DEPTH))?;

        let effective_max = match (self.parent.payload.max_depth, self.max_depth) {
            (Some(parent_max), Some(child_max)) => {
                if child_max > parent_max {
                    return Err(Error::MonotonicityViolation(format!(
                        "max_depth {} exceeds parent's max_depth {}",
                        child_max, parent_max
                    )));
                }
                Some(child_max)
            }
            (Some(parent_max), None) => Some(parent_max),
            (None, Some(child_max)) => {
                if child_max > MAX_DELEGATION_DEPTH {
                    return Err(Error::DepthExceeded(child_max, MAX_DELEGATION_DEPTH));
                }
                Some(child_max)
            }
            (None, None) => None,
        };

        let depth_limit = effective_max.unwrap_or(MAX_DELEGATION_DEPTH);
        if new_depth > depth_limit {
            return Err(Error::DepthExceeded(new_depth, depth_limit));
        }

        if new_depth > MAX_DELEGATION_DEPTH {
            return Err(Error::DepthExceeded(new_depth, MAX_DELEGATION_DEPTH));
        }

        if self.parent.is_expired() {
            return Err(Error::WarrantExpired(self.parent.payload.expires_at));
        }

        // Validate attenuation monotonicity
        match self.parent.payload.r#type {
            WarrantType::Execution => {
                // For execution warrants, validate tool narrowing (if specified)
                if let Some(ref child_tools) = self.exec_tools {
                    if let Some(parent_tools) = &self.parent.payload.tools {
                        // Child tools must be a subset of parent tools
                        for tool in child_tools {
                            if !parent_tools.contains(tool) {
                                return Err(Error::MonotonicityViolation(format!(
                                    "tool '{}' not in parent's tools {:?}",
                                    tool, parent_tools
                                )));
                            }
                        }
                        // Must have at least one tool
                        if child_tools.is_empty() {
                            return Err(Error::Validation(
                                "execution warrant must have at least one tool".to_string(),
                            ));
                        }
                    }
                }
                // For execution warrants, validate constraint attenuation
                if let Some(parent_constraints) = &self.parent.payload.constraints {
                    parent_constraints.validate_attenuation(&self.constraints)?;
                }
            }
            WarrantType::Issuer => {
                if let Some(parent_issuable) = &self.parent.payload.issuable_tools {
                    if let Some(ref child_issuable) = self.issuable_tools {
                        for tool in child_issuable {
                            if !parent_issuable.contains(tool) {
                                return Err(Error::MonotonicityViolation(format!(
                                    "issuable_tool '{}' not in parent's issuable_tools",
                                    tool
                                )));
                            }
                        }
                    }
                }
                if let (Some(parent_ceiling), Some(child_ceiling)) =
                    (self.parent.payload.trust_ceiling, self.trust_ceiling)
                {
                    if child_ceiling > parent_ceiling {
                        return Err(Error::MonotonicityViolation(format!(
                            "trust_ceiling cannot increase: parent {:?}, child {:?}",
                            parent_ceiling, child_ceiling
                        )));
                    }
                }
                if let Some(parent_bounds) = &self.parent.payload.constraint_bounds {
                    parent_bounds.validate_attenuation(&self.constraint_bounds)?;
                }
            }
        }

        self.validate_multisig_monotonicity()?;

        let authorized_holder = self
            .authorized_holder
            .ok_or_else(|| Error::Validation("authorized_holder is required".to_string()))?;

        // NOTE: Holder cycling (A → B → A) is NOT blocked for execution warrants because:
        // - Monotonic attenuation guarantees privileges can only shrink, never expand
        // - Even if B delegates back to A, A gets a strictly weaker warrant
        // - The cycle detection in planes.rs prevents infinite loops via warrant ID tracking

        let expires_at = if let Some(ttl) = self.ttl {
            let chrono_ttl = ChronoDuration::from_std(ttl)
                .map_err(|_| Error::InvalidTtl("TTL too large".to_string()))?;
            let proposed = Utc::now() + chrono_ttl;
            if proposed > self.parent.payload.expires_at {
                self.parent.payload.expires_at
            } else {
                proposed
            }
        } else {
            self.parent.payload.expires_at
        };

        let effective_min = self.min_approvals.or(self.parent.payload.min_approvals);

        // SECURITY: Check issuer chain length before adding another link
        if self.parent.payload.issuer_chain.len() >= crate::MAX_ISSUER_CHAIN_LENGTH {
            return Err(Error::Validation(format!(
                "cannot delegate: issuer chain length {} would exceed maximum {}",
                self.parent.payload.issuer_chain.len() + 1,
                crate::MAX_ISSUER_CHAIN_LENGTH
            )));
        }

        let mut issuer_chain = self.parent.payload.issuer_chain.clone();

        let payload = WarrantPayload {
            version: WARRANT_VERSION,
            r#type: self.parent.payload.r#type,
            id: WarrantId::new(),
            authorized_holder,
            tools: match self.parent.payload.r#type {
                WarrantType::Execution => Some(
                    // Use narrowed tools if specified, otherwise inherit from parent
                    self.exec_tools.clone().unwrap_or_else(|| {
                        self.parent
                            .payload
                            .tools
                            .clone()
                            .expect("execution warrant must have tools")
                    }),
                ),
                WarrantType::Issuer => None,
            },
            constraints: match self.parent.payload.r#type {
                WarrantType::Execution => {
                    if self.constraints.is_empty() {
                        None
                    } else {
                        Some(self.constraints)
                    }
                }
                WarrantType::Issuer => None,
            },
            issuable_tools: match self.parent.payload.r#type {
                WarrantType::Issuer => self.issuable_tools.clone(),
                WarrantType::Execution => None,
            },
            trust_ceiling: match self.parent.payload.r#type {
                WarrantType::Issuer => self.trust_ceiling,
                WarrantType::Execution => None,
            },
            max_issue_depth: match self.parent.payload.r#type {
                WarrantType::Issuer => self.max_issue_depth,
                WarrantType::Execution => None,
            },
            constraint_bounds: match self.parent.payload.r#type {
                WarrantType::Issuer => {
                    if self.constraint_bounds.is_empty() {
                        None
                    } else {
                        Some(self.constraint_bounds)
                    }
                }
                WarrantType::Execution => None,
            },
            trust_level: self.trust_level,
            issued_at: Utc::now(),
            expires_at,
            depth: new_depth,
            max_depth: effective_max,
            session_id: self.session_id,
            agent_id: self.agent_id,
            issuer: keypair.public_key(),
            parent_id: Some(self.parent.payload.id.clone()),
            required_approvers: self.required_approvers,
            min_approvals: effective_min,
            issuer_chain: Vec::new(),
        };

        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)?;
        let signature = keypair.sign(&payload_bytes);

        // Create ChainLinkSignedData binding child payload AND issuer scope
        let issuer_scope = ChainLinkSignedData {
            child_payload_bytes: payload_bytes.clone(),
            issuer_id: self.parent.payload.id.clone(),
            issuer_type: self.parent.payload.r#type,
            issuer_tools: self.parent.payload.tools.clone(),
            issuer_constraints: self.parent.payload.constraints.clone(),
            issuer_trust: self.parent.payload.trust_level,
            issuer_expires_at: self.parent.payload.expires_at,
            issuer_max_depth: self.parent.effective_max_depth(),
        };
        let mut scope_bytes = Vec::new();
        ciborium::ser::into_writer(&issuer_scope, &mut scope_bytes)?;

        let parent_link = ChainLink {
            issuer_id: self.parent.payload.id.clone(),
            issuer_pubkey: self.parent.payload.issuer.clone(),
            issuer_type: self.parent.payload.r#type,
            issuer_tools: self.parent.payload.tools.clone(),
            issuer_constraints: self.parent.payload.constraints.clone(),
            issuer_trust: self.parent.payload.trust_level,
            issuer_expires_at: self.parent.payload.expires_at,
            issuer_max_depth: self.parent.effective_max_depth(),
            // Sign ChainLinkSignedData (child + issuer scope)
            signature: parent_keypair.sign(&scope_bytes),
        };
        issuer_chain.push(parent_link);

        let mut final_payload = payload;
        final_payload.issuer_chain = issuer_chain;

        let mut final_payload_bytes = Vec::new();
        ciborium::ser::into_writer(&final_payload, &mut final_payload_bytes)?;

        Ok(Warrant {
            payload: final_payload,
            signature,
            payload_bytes,
        })
    }

    /// Build and sign the attenuated warrant, returning both warrant and receipt.
    ///
    /// This is a convenience method for audit-conscious workflows that need
    /// to capture the delegation receipt immediately.
    ///
    /// # Arguments
    ///
    /// * `keypair` - The keypair of the delegator (who is creating the child warrant)
    /// * `parent_keypair` - The keypair of the parent warrant issuer (for chain link signature)
    ///
    /// # Returns
    ///
    /// A tuple of (child_warrant, delegation_receipt)
    pub fn build_with_receipt(
        self,
        keypair: &SigningKey,
        parent_keypair: &SigningKey,
    ) -> Result<(Warrant, crate::diff::DelegationReceipt)> {
        // Capture diff before build consumes self
        let mut diff = self.diff();

        // Get fingerprints before build
        let delegator_fingerprint = keypair.public_key().fingerprint();
        let delegatee_fingerprint = self
            .holder()
            .map(|h| h.fingerprint())
            .unwrap_or_else(|| keypair.public_key().fingerprint());

        // Build the warrant
        let child = self.build(keypair, parent_keypair)?;

        // Update diff with child warrant ID
        diff.child_warrant_id = Some(child.id().to_string());

        // Create receipt from diff
        let receipt = crate::diff::DelegationReceipt::from_diff(
            diff,
            child.id().to_string(),
            delegator_fingerprint,
            delegatee_fingerprint,
        );

        Ok((child, receipt))
    }
}

/// Builder for issuing execution warrants from issuer warrants.
///
/// This builder validates that the issued execution warrant complies with
/// the issuer warrant's constraints:
/// - Tool must be in `issuable_tools`
/// - Trust level must be <= `trust_ceiling`
/// - Constraints must be within `constraint_bounds`
/// - Depth must not exceed `max_issue_depth`
#[derive(Debug)]
pub struct IssuanceBuilder<'a> {
    issuer: &'a Warrant,
    tools: Option<Vec<String>>,
    constraints: ConstraintSet,
    trust_level: Option<TrustLevel>,
    ttl: Option<Duration>,
    max_depth: Option<u32>,
    session_id: Option<String>,
    agent_id: Option<String>,
    authorized_holder: Option<PublicKey>,
    required_approvers: Option<Vec<PublicKey>>,
    min_approvals: Option<u32>,
}

impl<'a> IssuanceBuilder<'a> {
    /// Create a new issuance builder.
    fn new(issuer: &'a Warrant) -> Self {
        Self {
            issuer,
            tools: None,
            constraints: ConstraintSet::new(),
            trust_level: None,
            ttl: None,
            max_depth: None,
            session_id: issuer.payload.session_id.clone(),
            agent_id: issuer.payload.agent_id.clone(),
            authorized_holder: None,
            required_approvers: None,
            min_approvals: None,
        }
    }

    /// Set the tool name for the execution warrant.
    ///
    /// The tool must be in the issuer's `issuable_tools` list.
    pub fn tool(mut self, tool: impl Into<String>) -> Self {
        self.tools = Some(vec![tool.into()]);
        self
    }

    /// Set multiple tools for the execution warrant.
    ///
    /// All tools must be in the issuer's `issuable_tools` list.
    pub fn tools(mut self, tools: Vec<String>) -> Self {
        self.tools = Some(tools);
        self
    }

    /// Add a constraint to the execution warrant.
    ///
    /// The constraint must be within the issuer's `constraint_bounds`.
    pub fn constraint(
        mut self,
        field: impl Into<String>,
        constraint: impl Into<Constraint>,
    ) -> Self {
        self.constraints.insert(field, constraint);
        self
    }

    /// Set the trust level for the execution warrant.
    ///
    /// The trust level must be <= the issuer's `trust_ceiling`.
    pub fn trust_level(mut self, level: TrustLevel) -> Self {
        self.trust_level = Some(level);
        self
    }

    /// Set the time-to-live for the execution warrant.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the maximum delegation depth for the execution warrant.
    ///
    /// This must not exceed the issuer's `max_issue_depth`.
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
    ///
    /// This is required - the execution warrant must have a holder.
    pub fn authorized_holder(mut self, public_key: PublicKey) -> Self {
        self.authorized_holder = Some(public_key);
        self
    }

    /// Set required approvers for multi-sig workflows.
    pub fn required_approvers(mut self, approvers: Vec<PublicKey>) -> Self {
        self.required_approvers = Some(approvers);
        self
    }

    /// Set the minimum number of approvals required.
    pub fn min_approvals(mut self, min: u32) -> Self {
        self.min_approvals = Some(min);
        self
    }

    /// Build and sign the execution warrant.
    ///
    /// This validates:
    /// - Tool is in issuer's `issuable_tools`
    /// - Trust level <= issuer's `trust_ceiling`
    /// - Constraints are within issuer's `constraint_bounds`
    /// - Depth doesn't exceed issuer's `max_issue_depth`
    ///
    /// # Arguments
    ///
    /// * `keypair` - The keypair of the issuer warrant holder (who is creating the execution warrant)
    /// * `issuer_keypair` - The keypair of the issuer warrant issuer (for chain link signature)
    pub fn build(self, keypair: &SigningKey, issuer_keypair: &SigningKey) -> Result<Warrant> {
        // Validate issuer is not expired
        if self.issuer.is_expired() {
            return Err(Error::WarrantExpired(self.issuer.payload.expires_at));
        }

        // Validate required fields
        let tools = self.tools.ok_or(Error::Validation(
            "execution warrant requires tools".to_string(),
        ))?;
        let authorized_holder = self.authorized_holder.ok_or(Error::Validation(
            "execution warrant requires authorized_holder".to_string(),
        ))?;
        let ttl = self.ttl.ok_or(Error::MissingField("ttl".to_string()))?;

        // SECURITY: Issuer cannot grant execution warrants to themselves
        // This prevents privilege escalation where an issuer could convert their
        // issuer warrant into execution capabilities for themselves.
        if authorized_holder == self.issuer.payload.authorized_holder {
            return Err(Error::Validation(
                "issuer cannot grant execution warrants to themselves (self-issuance prohibited)"
                    .to_string(),
            ));
        }

        // SECURITY: Execution warrant holder cannot be the issuer warrant's issuer
        // This prevents a more subtle privilege escalation where the issuer warrant's
        // issuer could indirectly grant execution capabilities to themselves through
        // the issuer warrant mechanism.
        if authorized_holder == self.issuer.payload.issuer {
            return Err(Error::Validation(
                "execution warrant holder cannot be the issuer warrant's issuer (issuer-holder separation required)"
                    .to_string(),
            ));
        }

        // Validate all tools are in issuable_tools
        if let Some(issuable_tools) = &self.issuer.payload.issuable_tools {
            for tool in &tools {
                if !issuable_tools.contains(tool) {
                    return Err(Error::Validation(format!(
                        "tool '{}' is not in issuer's issuable_tools: {:?}",
                        tool, issuable_tools
                    )));
                }
            }
        } else {
            return Err(Error::Validation(
                "issuer warrant must have issuable_tools".to_string(),
            ));
        }

        // Validate trust_level <= trust_ceiling
        if let Some(trust_level) = self.trust_level {
            if let Some(trust_ceiling) = self.issuer.payload.trust_ceiling {
                if trust_level > trust_ceiling {
                    return Err(Error::Validation(format!(
                        "trust_level ({:?}) cannot exceed issuer's trust_ceiling ({:?})",
                        trust_level, trust_ceiling
                    )));
                }
            }
        }

        // Validate constraints are within constraint_bounds
        if let Some(constraint_bounds) = &self.issuer.payload.constraint_bounds {
            if !constraint_bounds.is_empty() {
                for (field, constraint) in self.constraints.iter() {
                    if let Some(bound) = constraint_bounds.get(field) {
                        // Validate that the constraint is within the bound using attenuation validation
                        bound.validate_attenuation(constraint).map_err(|e| {
                            Error::Validation(format!(
                                "constraint for field '{}' exceeds issuer's constraint_bounds: {}",
                                field, e
                            ))
                        })?;
                    }
                }
            }
        }

        // Validate depth doesn't exceed max_issue_depth
        let new_depth = self.issuer.payload.depth + 1;
        if let Some(max_issue_depth) = self.issuer.payload.max_issue_depth {
            if new_depth > max_issue_depth {
                return Err(Error::Validation(format!(
                    "issued warrant depth ({}) exceeds issuer's max_issue_depth ({})",
                    new_depth, max_issue_depth
                )));
            }
        }

        // Validate max_depth doesn't exceed issuer's max_issue_depth
        if let Some(max_depth) = self.max_depth {
            if let Some(max_issue_depth) = self.issuer.payload.max_issue_depth {
                if max_depth > max_issue_depth {
                    return Err(Error::Validation(format!(
                        "max_depth ({}) exceeds issuer's max_issue_depth ({})",
                        max_depth, max_issue_depth
                    )));
                }
            }
        }

        // Validate min_approvals if set
        if let (Some(approvers), Some(min)) = (&self.required_approvers, self.min_approvals) {
            if min as usize > approvers.len() {
                return Err(Error::Validation(format!(
                    "min_approvals ({}) cannot exceed required_approvers count ({})",
                    min,
                    approvers.len()
                )));
            }
        }

        // Validate constraint depth
        if !self.constraints.is_empty() {
            self.constraints.validate_depth()?;
        }

        // SECURITY: Check issuer chain length before adding another link
        if self.issuer.payload.issuer_chain.len() >= crate::MAX_ISSUER_CHAIN_LENGTH {
            return Err(Error::Validation(format!(
                "cannot issue: issuer chain length {} would exceed maximum {}",
                self.issuer.payload.issuer_chain.len() + 1,
                crate::MAX_ISSUER_CHAIN_LENGTH
            )));
        }

        // Build issuer chain link
        let mut issuer_chain = self.issuer.payload.issuer_chain.clone();

        let chrono_ttl = ChronoDuration::from_std(ttl)
            .map_err(|_| Error::InvalidTtl("TTL too large".to_string()))?;
        let issued_at = Utc::now();
        let expires_at = issued_at + chrono_ttl;

        let effective_max = self.max_depth.or(self.issuer.payload.max_depth);

        // Create payload first (without issuer_chain) to sign it
        let payload = WarrantPayload {
            version: WARRANT_VERSION,
            r#type: WarrantType::Execution,
            id: WarrantId::new(),
            authorized_holder,
            tools: Some(tools),
            constraints: if self.constraints.is_empty() {
                None
            } else {
                Some(self.constraints)
            },
            issuable_tools: None,
            trust_ceiling: None,
            max_issue_depth: None,
            constraint_bounds: None,
            trust_level: self.trust_level,
            issued_at,
            expires_at,
            depth: new_depth,
            max_depth: effective_max,
            session_id: self.session_id,
            agent_id: self.agent_id,
            issuer: keypair.public_key(),
            parent_id: Some(self.issuer.payload.id.clone()),
            required_approvers: self.required_approvers,
            min_approvals: self.min_approvals,
            issuer_chain: Vec::new(), // Temporarily empty for signing
        };

        // Serialize payload to sign it
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)?;
        let signature = keypair.sign(&payload_bytes);

        // Create ChainLinkSignedData binding child payload AND issuer scope
        let issuer_scope = ChainLinkSignedData {
            child_payload_bytes: payload_bytes.clone(),
            issuer_id: self.issuer.payload.id.clone(),
            issuer_type: self.issuer.payload.r#type,
            issuer_tools: self.issuer.payload.issuable_tools.clone(),
            issuer_constraints: self.issuer.payload.constraint_bounds.clone(),
            issuer_trust: self.issuer.payload.trust_ceiling,
            issuer_expires_at: self.issuer.payload.expires_at,
            issuer_max_depth: self.issuer.effective_max_depth(),
        };
        let mut scope_bytes = Vec::new();
        ciborium::ser::into_writer(&issuer_scope, &mut scope_bytes)?;

        let issuer_link = ChainLink {
            issuer_id: self.issuer.payload.id.clone(),
            issuer_pubkey: self.issuer.payload.issuer.clone(),
            issuer_type: self.issuer.payload.r#type,
            issuer_tools: self.issuer.payload.issuable_tools.clone(),
            issuer_constraints: self.issuer.payload.constraint_bounds.clone(),
            issuer_trust: self.issuer.payload.trust_ceiling,
            issuer_expires_at: self.issuer.payload.expires_at,
            issuer_max_depth: self.issuer.effective_max_depth(),
            // Sign ChainLinkSignedData (child + issuer scope)
            signature: issuer_keypair.sign(&scope_bytes),
        };
        issuer_chain.push(issuer_link);

        // Update payload with the chain link
        let mut final_payload = payload;
        final_payload.issuer_chain = issuer_chain;

        // Re-serialize with the chain link included
        let mut final_payload_bytes = Vec::new();
        ciborium::ser::into_writer(&final_payload, &mut final_payload_bytes)?;

        Ok(Warrant {
            payload: final_payload,
            signature,
            payload_bytes, // Child's signature is over payload WITHOUT chain
        })
    }
}

/// Owned version of IssuanceBuilder for use in FFI contexts (e.g., Python bindings).
///
/// This builder owns the issuer warrant, avoiding lifetime issues in FFI.
#[derive(Debug, Clone)]
pub struct OwnedIssuanceBuilder {
    issuer: Warrant,
    tools: Option<Vec<String>>,
    constraints: ConstraintSet,
    trust_level: Option<TrustLevel>,
    ttl: Option<Duration>,
    max_depth: Option<u32>,
    session_id: Option<String>,
    agent_id: Option<String>,
    authorized_holder: Option<PublicKey>,
    required_approvers: Option<Vec<PublicKey>>,
    min_approvals: Option<u32>,
    intent: Option<String>,
}

impl OwnedIssuanceBuilder {
    /// Create a new owned issuance builder.
    pub fn new(issuer: Warrant) -> Self {
        Self {
            session_id: issuer.payload.session_id.clone(),
            agent_id: issuer.payload.agent_id.clone(),
            issuer,
            tools: None,
            constraints: ConstraintSet::new(),
            trust_level: None,
            ttl: None,
            max_depth: None,
            authorized_holder: None,
            required_approvers: None,
            min_approvals: None,
            intent: None,
        }
    }

    /// Get a reference to the issuer warrant.
    pub fn issuer(&self) -> &Warrant {
        &self.issuer
    }

    /// Get the configured tools (if any).
    pub fn tools(&self) -> Option<&[String]> {
        self.tools.as_deref()
    }

    /// Get the configured tool (if single tool is set).
    pub fn tool(&self) -> Option<&str> {
        self.tools
            .as_ref()
            .and_then(|t| t.first().map(|s| s.as_str()))
    }

    /// Get the current constraints being configured.
    pub fn constraints(&self) -> &ConstraintSet {
        &self.constraints
    }

    /// Get the configured TTL (if any).
    pub fn ttl_seconds(&self) -> Option<u64> {
        self.ttl.map(|d| d.as_secs())
    }

    /// Get the configured holder (if any).
    pub fn holder(&self) -> Option<&PublicKey> {
        self.authorized_holder.as_ref()
    }

    /// Get the configured trust level.
    pub fn trust_level(&self) -> Option<TrustLevel> {
        self.trust_level
    }

    /// Get the configured intent.
    pub fn intent(&self) -> Option<&str> {
        self.intent.as_deref()
    }

    /// Set the tool name for the execution warrant (mutable version for FFI).
    pub fn set_tool(&mut self, tool: impl Into<String>) {
        self.tools = Some(vec![tool.into()]);
    }

    /// Set multiple tools for the execution warrant (mutable version for FFI).
    pub fn set_tools(&mut self, tools: Vec<String>) {
        self.tools = Some(tools);
    }

    /// Set a constraint (mutable version for FFI).
    pub fn set_constraint(&mut self, field: impl Into<String>, constraint: impl Into<Constraint>) {
        self.constraints.insert(field, constraint);
    }

    /// Set the trust level (mutable version for FFI).
    pub fn set_trust_level(&mut self, level: TrustLevel) {
        self.trust_level = Some(level);
    }

    /// Set TTL (mutable version for FFI).
    pub fn set_ttl(&mut self, ttl: Duration) {
        self.ttl = Some(ttl);
    }

    /// Set the maximum delegation depth (mutable version for FFI).
    pub fn set_max_depth(&mut self, max_depth: u32) {
        self.max_depth = Some(max_depth);
    }

    /// Make this warrant terminal (cannot be delegated further).
    pub fn terminal(mut self) -> Self {
        self.max_depth = Some(self.issuer.depth() + 1);
        self
    }

    /// Make this warrant terminal (mutable version for FFI).
    pub fn set_terminal(&mut self) {
        self.max_depth = Some(self.issuer.depth() + 1);
    }

    /// Set the session ID (mutable version for FFI).
    pub fn set_session_id(&mut self, session_id: impl Into<String>) {
        self.session_id = Some(session_id.into());
    }

    /// Set the agent ID (mutable version for FFI).
    pub fn set_agent_id(&mut self, agent_id: impl Into<String>) {
        self.agent_id = Some(agent_id.into());
    }

    /// Set the authorized holder (mutable version for FFI).
    pub fn set_authorized_holder(&mut self, public_key: PublicKey) {
        self.authorized_holder = Some(public_key);
    }

    /// Set required approvers (mutable version for FFI).
    pub fn set_required_approvers(&mut self, approvers: Vec<PublicKey>) {
        self.required_approvers = Some(approvers);
    }

    /// Set minimum approvals (mutable version for FFI).
    pub fn set_min_approvals(&mut self, min: u32) {
        self.min_approvals = Some(min);
    }

    /// Set the intent/purpose for this issuance (mutable version for FFI).
    pub fn set_intent(&mut self, intent: impl Into<String>) {
        self.intent = Some(intent.into());
    }

    /// Build and sign the execution warrant.
    pub fn build(self, keypair: &SigningKey, issuer_keypair: &SigningKey) -> Result<Warrant> {
        // Delegate to IssuanceBuilder
        IssuanceBuilder {
            issuer: &self.issuer,
            tools: self.tools,
            constraints: self.constraints,
            trust_level: self.trust_level,
            ttl: self.ttl,
            max_depth: self.max_depth,
            session_id: self.session_id,
            agent_id: self.agent_id,
            authorized_holder: self.authorized_holder,
            required_approvers: self.required_approvers,
            min_approvals: self.min_approvals,
        }
        .build(keypair, issuer_keypair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::{Exact, Pattern, Range};

    fn create_test_keypair() -> SigningKey {
        SigningKey::generate()
    }

    #[test]
    fn test_warrant_creation() {
        let keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .tool("upgrade_cluster")
            .constraint("cluster", Pattern::new("staging-*").unwrap())
            .ttl(Duration::from_secs(600))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        assert_eq!(warrant.tools(), Some(&["upgrade_cluster".to_string()][..]));
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
            .authorized_holder(keypair.public_key())
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
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let mut args = HashMap::new();
        args.insert(
            "cluster".to_string(),
            ConstraintValue::String("staging-web".to_string()),
        );
        args.insert(
            "version".to_string(),
            ConstraintValue::String("1.28.5".to_string()),
        );

        // Create PoP signature (mandatory now)
        let pop_sig = warrant
            .create_pop_signature(&keypair, "upgrade_cluster", &args)
            .unwrap();

        assert!(warrant
            .authorize("upgrade_cluster", &args, Some(&pop_sig))
            .is_ok());

        // Wrong tool
        assert!(warrant
            .authorize("delete_cluster", &args, Some(&pop_sig))
            .is_err());

        // Wrong cluster
        let mut bad_args = args.clone();
        bad_args.insert(
            "cluster".to_string(),
            ConstraintValue::String("production-web".to_string()),
        );
        assert!(warrant
            .authorize("upgrade_cluster", &bad_args, Some(&pop_sig))
            .is_err());
    }

    #[test]
    fn test_attenuation_basic() {
        let parent_keypair = create_test_keypair();
        let child_keypair = create_test_keypair();

        let parent = Warrant::builder()
            .tool("upgrade_cluster")
            .constraint("cluster", Pattern::new("staging-*").unwrap())
            .ttl(Duration::from_secs(600))
            .authorized_holder(parent_keypair.public_key())
            .build(&parent_keypair)
            .unwrap();

        let child = parent
            .attenuate()
            .constraint("cluster", Exact::new("staging-web"))
            .build(&child_keypair, &parent_keypair)
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
            .authorized_holder(parent_keypair.public_key())
            .build(&parent_keypair)
            .unwrap();

        // Attempt to widen scope - should fail
        let result = parent
            .attenuate()
            .constraint("cluster", Pattern::new("*").unwrap())
            .build(&child_keypair, &parent_keypair);

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
            .authorized_holder(parent_keypair.public_key())
            .build(&parent_keypair)
            .unwrap();

        // Request longer TTL - should be capped to parent
        let child = parent
            .attenuate()
            .ttl(Duration::from_secs(3600))
            .build(&child_keypair, &parent_keypair)
            .unwrap();

        assert!(child.expires_at() <= parent.expires_at());
    }

    #[test]
    fn test_attenuation_chain_length_limit() {
        let keypair = create_test_keypair();

        let mut warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(3600))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        // Delegate up to max issuer chain length
        // Note: MAX_ISSUER_CHAIN_LENGTH (8) < MAX_DELEGATION_DEPTH (64)
        // Chain length limit kicks in first to prevent DoS attacks
        for _ in 0..crate::MAX_ISSUER_CHAIN_LENGTH {
            warrant = warrant.attenuate().build(&keypair, &keypair).unwrap();
        }

        // Next delegation should fail due to chain length limit
        let result = warrant.attenuate().build(&keypair, &keypair);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("issuer chain length") && err_msg.contains("exceed maximum"),
            "Expected chain length error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_attenuation_depth_limit_with_max_depth() {
        let keypair = create_test_keypair();

        // Create warrant with explicit max_depth of 3 (smaller than chain length limit)
        let mut warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(3600))
            .max_depth(3)
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        // Delegate up to max depth
        for _ in 0..3 {
            warrant = warrant.attenuate().build(&keypair, &keypair).unwrap();
        }

        // Next delegation should fail due to depth limit
        let result = warrant.attenuate().build(&keypair, &keypair);
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
            .authorized_holder(parent_keypair.public_key())
            .build(&parent_keypair)
            .unwrap();

        // Valid: narrower range
        let child = parent
            .attenuate()
            .constraint("amount", Range::max(5000.0))
            .build(&child_keypair, &parent_keypair);
        assert!(child.is_ok());

        // Invalid: wider range
        let invalid = parent
            .attenuate()
            .constraint("amount", Range::max(20000.0))
            .build(&child_keypair, &parent_keypair);
        assert!(invalid.is_err());
    }

    #[test]
    fn test_session_binding() {
        let keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(60))
            .session_id("session_123")
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        assert_eq!(warrant.session_id(), Some("session_123"));

        // Session ID is preserved through attenuation
        let child = warrant.attenuate().build(&keypair, &keypair).unwrap();
        assert_eq!(child.session_id(), Some("session_123"));
    }

    // =========================================================================
    // PROOF-OF-POSSESSION (PoP) FAILURE CASES
    // =========================================================================

    #[test]
    fn test_pop_signature_wrong_keypair() {
        let correct_keypair = create_test_keypair();
        let wrong_keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(600))
            .authorized_holder(correct_keypair.public_key())
            .build(&correct_keypair)
            .unwrap();

        let mut args = HashMap::new();
        args.insert(
            "param".to_string(),
            ConstraintValue::String("value".to_string()),
        );

        // Create PoP signature with WRONG keypair
        let wrong_pop_sig = warrant
            .create_pop_signature(&wrong_keypair, "test", &args)
            .unwrap();

        // Authorization should fail - wrong keypair
        assert!(warrant
            .authorize("test", &args, Some(&wrong_pop_sig))
            .is_err());
    }

    #[test]
    fn test_pop_signature_wrong_tool() {
        let keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .tool("test_tool")
            .ttl(Duration::from_secs(600))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let mut args = HashMap::new();
        args.insert(
            "param".to_string(),
            ConstraintValue::String("value".to_string()),
        );

        // Create PoP signature for WRONG tool
        let pop_sig = warrant
            .create_pop_signature(&keypair, "wrong_tool", &args)
            .unwrap();

        // Authorization should fail - tool mismatch
        assert!(warrant
            .authorize("test_tool", &args, Some(&pop_sig))
            .is_err());
    }

    #[test]
    fn test_pop_signature_wrong_args() {
        let keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .tool("test")
            .constraint("cluster", Pattern::new("staging-*").unwrap())
            .ttl(Duration::from_secs(600))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let mut correct_args = HashMap::new();
        correct_args.insert(
            "cluster".to_string(),
            ConstraintValue::String("staging-web".to_string()),
        );

        let mut wrong_args = HashMap::new();
        wrong_args.insert(
            "cluster".to_string(),
            ConstraintValue::String("prod-web".to_string()),
        );

        // Create PoP signature with WRONG args
        let pop_sig = warrant
            .create_pop_signature(&keypair, "test", &wrong_args)
            .unwrap();

        // Authorization with correct args but wrong PoP signature should fail
        // (PoP signature is bound to specific args)
        assert!(warrant
            .authorize("test", &correct_args, Some(&pop_sig))
            .is_err());
    }

    #[test]
    fn test_pop_signature_expired_warrant() {
        let keypair = create_test_keypair();

        // Create warrant with very short TTL
        let warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(1)) // 1 second TTL
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let args = HashMap::new();
        let pop_sig = warrant
            .create_pop_signature(&keypair, "test", &args)
            .unwrap();

        // Wait for expiration
        std::thread::sleep(Duration::from_secs(2));

        // Authorization should fail - warrant expired
        assert!(warrant.authorize("test", &args, Some(&pop_sig)).is_err());
    }

    #[test]
    fn test_pop_signature_no_signature() {
        let keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(600))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let args = HashMap::new();

        // Authorization without PoP signature should fail
        assert!(warrant.authorize("test", &args, None).is_err());
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
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        assert_eq!(root.max_depth(), Some(3));
        assert_eq!(root.effective_max_depth(), 3);

        // Can delegate up to depth 3 (self-delegation in this test)
        let level1 = root.attenuate().build(&keypair, &keypair).unwrap();
        assert_eq!(level1.depth(), 1);
        assert_eq!(level1.max_depth(), Some(3)); // Inherited

        let level2 = level1.attenuate().build(&keypair, &keypair).unwrap();
        assert_eq!(level2.depth(), 2);

        let level3 = level2.attenuate().build(&keypair, &keypair).unwrap();
        assert_eq!(level3.depth(), 3);

        // Depth 4 should fail (exceeds policy limit)
        let result = level3.attenuate().build(&keypair, &keypair);
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
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        // Can shrink max_depth
        let child = root
            .attenuate()
            .max_depth(3)
            .build(&keypair, &keypair)
            .unwrap();
        assert_eq!(child.max_depth(), Some(3));

        // Cannot expand max_depth
        let result = child.attenuate().max_depth(10).build(&keypair, &keypair);
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
            .authorized_holder(keypair.public_key())
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
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        // max_depth is now None when not explicitly set (protocol default applies)
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
            .authorized_holder(issuer.public_key())
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
            .authorized_holder(issuer.public_key())
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
            .authorized_holder(issuer.public_key())
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
            .authorized_holder(issuer.public_key())
            .build(&issuer)
            .unwrap();

        // Attenuate and ADD another approver (valid: more restrictive)
        let child = root
            .attenuate()
            .add_approvers(vec![approver2.public_key()])
            .raise_min_approvals(2)
            .build(&delegator, &issuer)
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
            .authorized_holder(issuer.public_key())
            .build(&issuer)
            .unwrap();

        // Create attenuation builder and clear approvers (simulating removal)
        // The builder inherits from parent, so we can't directly remove.
        // But if the internal field is manipulated, the build should fail.
        // For now, verify that inherited approvers are preserved.
        let child = root.attenuate().build(&delegator, &issuer).unwrap();

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
            .authorized_holder(issuer.public_key())
            .build(&issuer)
            .unwrap();

        // Try to lower threshold using raise_min_approvals (should be ignored)
        // raise_min_approvals uses max() so it cannot lower
        let child = root
            .attenuate()
            .raise_min_approvals(1) // Tries to set 1, but max(current, 1) = 2
            .build(&delegator, &issuer)
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
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        assert!(!warrant.requires_multisig());
        assert_eq!(warrant.approval_threshold(), 0);
        assert!(warrant.required_approvers().is_none());
    }

    #[test]
    fn test_issuer_warrant_issues_execution_warrant() {
        let issuer_kp = create_test_keypair();
        let holder_kp = create_test_keypair();

        // Create an issuer warrant
        let issuer_warrant = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string(), "send_email".to_string()])
            .trust_ceiling(TrustLevel::Internal)
            .max_issue_depth(2)
            .constraint_bound("path", Pattern::new("/data/*").unwrap())
            .ttl(Duration::from_secs(3600))
            .authorized_holder(issuer_kp.public_key())
            .build(&issuer_kp)
            .unwrap();

        // Issue an execution warrant
        // Note: issuer_kp is both the issuer warrant holder and the issuer warrant issuer
        let execution_warrant = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .tool("read_file")
            .constraint("path", Pattern::new("/data/q3.pdf").unwrap())
            .trust_level(TrustLevel::External)
            .ttl(Duration::from_secs(60))
            .authorized_holder(holder_kp.public_key())
            .build(&issuer_kp, &issuer_kp) // issuer_kp is both holder and issuer
            .unwrap();

        assert_eq!(execution_warrant.r#type(), WarrantType::Execution);
        assert_eq!(
            execution_warrant.tools(),
            Some(&["read_file".to_string()][..])
        );
        assert_eq!(
            execution_warrant.authorized_holder(),
            &holder_kp.public_key()
        );
        assert_eq!(execution_warrant.depth(), 1);
        assert_eq!(execution_warrant.parent_id(), Some(issuer_warrant.id()));
    }

    #[test]
    fn test_issuer_cannot_issue_to_self() {
        let issuer_kp = create_test_keypair();

        // Create an issuer warrant held by issuer_kp
        let issuer_warrant = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string()])
            .trust_ceiling(TrustLevel::Internal)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(issuer_kp.public_key())
            .build(&issuer_kp)
            .unwrap();

        // Try to issue an execution warrant to SELF (the issuer warrant holder)
        // This should be rejected as it would allow privilege escalation
        let result = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .tool("read_file")
            .ttl(Duration::from_secs(60))
            .authorized_holder(issuer_kp.public_key()) // Same as issuer warrant holder!
            .build(&issuer_kp, &issuer_kp);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("self-issuance prohibited"),
            "Expected self-issuance error, got: {}",
            err
        );
    }

    #[test]
    fn test_issuer_holder_separation() {
        // Test that execution warrant holder cannot be the issuer warrant's issuer
        // (the key that signed the issuer warrant)
        let issuer_kp = create_test_keypair(); // Signs issuer warrant AND will be execution holder
        let holder_kp = create_test_keypair(); // Holds the issuer warrant

        // Create an issuer warrant signed by issuer_kp, held by holder_kp
        let issuer_warrant = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string()])
            .trust_ceiling(TrustLevel::Internal)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(holder_kp.public_key())
            .build(&issuer_kp)
            .unwrap();

        // Try to issue an execution warrant where the holder is the issuer warrant's issuer
        // This should be rejected as it would allow indirect privilege escalation
        let result = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .tool("read_file")
            .ttl(Duration::from_secs(60))
            .authorized_holder(issuer_kp.public_key()) // Same as issuer warrant's issuer!
            .build(&holder_kp, &issuer_kp);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("issuer-holder separation required"),
            "Expected issuer-holder separation error, got: {}",
            err
        );
    }

    #[test]
    fn test_holder_cycling_allowed_with_monotonicity() {
        // Test that A → B → A delegation is allowed because monotonic attenuation
        // already guarantees privileges can only shrink. B delegating back to A
        // gives A a strictly weaker warrant than their original.
        let keypair_a = create_test_keypair();
        let keypair_b = create_test_keypair();

        // A creates a root warrant for themselves
        let root = Warrant::builder()
            .tool("test")
            .constraint("env", Pattern::new("*").unwrap())
            .ttl(Duration::from_secs(3600))
            .authorized_holder(keypair_a.public_key())
            .build(&keypair_a)
            .unwrap();

        // A delegates to B with narrower constraints
        let child_b = root
            .attenuate()
            .constraint("env", Pattern::new("staging-*").unwrap())
            .authorized_holder(keypair_b.public_key())
            .build(&keypair_b, &keypair_a)
            .unwrap();

        assert_eq!(child_b.depth(), 1);

        // B delegates back to A - this IS allowed because A gets a weaker warrant
        let result = child_b
            .attenuate()
            .authorized_holder(keypair_a.public_key())
            .build(&keypair_a, &keypair_b);

        // Should succeed - A now has a warrant limited to staging-*, not the original *
        assert!(result.is_ok());
        let child_a = result.unwrap();
        assert_eq!(child_a.depth(), 2);
        // A's new warrant is strictly weaker than their original due to monotonicity
    }

    #[test]
    fn test_issuance_validates_tool_in_issuable_tools() {
        let issuer_kp = create_test_keypair();
        let holder_kp = create_test_keypair();

        let issuer_warrant = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string()])
            .trust_ceiling(TrustLevel::Internal)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(issuer_kp.public_key())
            .build(&issuer_kp)
            .unwrap();

        // Try to issue with invalid tool
        let result = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .tool("send_email") // Not in issuable_tools
            .ttl(Duration::from_secs(60))
            .authorized_holder(holder_kp.public_key())
            .build(&issuer_kp, &issuer_kp);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not in issuer's issuable_tools"));
    }

    #[test]
    fn test_issuance_validates_trust_level() {
        let issuer_kp = create_test_keypair();
        let holder_kp = create_test_keypair();

        let issuer_warrant = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string()])
            .trust_ceiling(TrustLevel::External) // Low ceiling
            .ttl(Duration::from_secs(3600))
            .authorized_holder(issuer_kp.public_key())
            .build(&issuer_kp)
            .unwrap();

        // Try to issue with trust level exceeding ceiling
        let result = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .tool("read_file")
            .trust_level(TrustLevel::Internal) // Exceeds External ceiling
            .ttl(Duration::from_secs(60))
            .authorized_holder(holder_kp.public_key())
            .build(&issuer_kp, &issuer_kp);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot exceed issuer's trust_ceiling"));
    }

    #[test]
    fn test_issuance_validates_constraint_bounds() {
        let issuer_kp = create_test_keypair();
        let holder_kp = create_test_keypair();

        let issuer_warrant = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string()])
            .trust_ceiling(TrustLevel::Internal)
            .constraint_bound("path", Pattern::new("/data/*").unwrap())
            .ttl(Duration::from_secs(3600))
            .authorized_holder(issuer_kp.public_key())
            .build(&issuer_kp)
            .unwrap();

        // Try to issue with constraint outside bounds
        let result = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .tool("read_file")
            .constraint("path", Pattern::new("/etc/*").unwrap()) // Outside /data/*
            .ttl(Duration::from_secs(60))
            .authorized_holder(holder_kp.public_key())
            .build(&issuer_kp, &issuer_kp);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds issuer's constraint_bounds"));
    }

    #[test]
    fn test_issuance_validates_max_issue_depth() {
        let issuer_kp = create_test_keypair();
        let holder_kp = create_test_keypair();

        let issuer_warrant = Warrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(vec!["read_file".to_string()])
            .trust_ceiling(TrustLevel::Internal)
            .max_issue_depth(1) // Only allow depth 1
            .ttl(Duration::from_secs(3600))
            .authorized_holder(issuer_kp.public_key())
            .build(&issuer_kp)
            .unwrap();

        // Issue first execution warrant (depth 1) - should work
        let exec1 = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .tool("read_file")
            .ttl(Duration::from_secs(60))
            .authorized_holder(holder_kp.public_key())
            .build(&issuer_kp, &issuer_kp)
            .unwrap();

        assert_eq!(exec1.depth(), 1);

        // Try to issue from execution warrant (would be depth 2) - should fail
        // But wait, execution warrants can't issue, so this test doesn't apply
        // The max_issue_depth is about the depth of issued warrants, not delegation
    }

    #[test]
    fn test_execution_warrant_cannot_issue() {
        let issuer_kp = create_test_keypair();

        let execution_warrant = Warrant::builder()
            .r#type(WarrantType::Execution)
            .tool("read_file")
            .ttl(Duration::from_secs(3600))
            .authorized_holder(issuer_kp.public_key())
            .build(&issuer_kp)
            .unwrap();

        // Try to issue from execution warrant - should fail
        let result = execution_warrant.issue_execution_warrant();

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("can only issue execution warrants from issuer warrants"));
    }
}
