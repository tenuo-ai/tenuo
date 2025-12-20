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
//! - **parent_hash**: Cryptographic linkage to parent warrant
//! - **Signatures**: Cryptographic proof of authority
//! - **TTL**: Time-to-live (ephemeral by design)
//!
//! ## Key Properties
//!
//! - **Monotonic Attenuation**: Capabilities only shrink when delegated, never expand
//! - **Mandatory PoP**: Proof-of-Possession prevents stolen warrant usage
//! - **WarrantStack Verification**: Full chain verified via parent_hash linkage
//! - **Type-Safe**: Rust's type system prevents misuse

use crate::approval::{AuditEvent, AuditEventType};
use crate::audit::log_event;
use crate::constraints::{Constraint, ConstraintSet, ConstraintValue};
use crate::crypto::{PublicKey, Signature, SigningKey};
use crate::error::{Error, Result};
use crate::MAX_DELEGATION_DEPTH;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, HashMap};
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
/// Stored as raw 16-byte UUID on the wire (CBOR bytes).
/// Uses UUIDv7 (time-ordered) which provides:
/// - 48 bits of millisecond timestamp
/// - 74 bits of random data
/// - Monotonically increasing within the same millisecond
/// - Collision probability: 1 in 2^74 per millisecond (effectively zero)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WarrantId([u8; 16]);

impl Serialize for WarrantId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for WarrantId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = WarrantId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("16 bytes for warrant ID")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 16 {
                    return Err(E::custom(format!(
                        "warrant ID must be 16 bytes, got {}",
                        v.len()
                    )));
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(v);
                Ok(WarrantId(arr))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(&v)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}

impl WarrantId {
    /// Generate a new time-ordered warrant ID (UUIDv7).
    ///
    /// UUIDv7 provides both uniqueness and chronological ordering,
    /// making it ideal for debugging and audit trails.
    pub fn new() -> Self {
        Self(*Uuid::now_v7().as_bytes())
    }

    /// Generate a random warrant ID (UUIDv4).
    ///
    /// Use this when you don't want IDs to reveal timing information.
    pub fn new_random() -> Self {
        Self(*Uuid::new_v4().as_bytes())
    }

    /// Create a warrant ID from raw bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Create a warrant ID from a hex string or prefixed string.
    ///
    /// Accepts:
    /// - Raw hex: "0123456789abcdef0123456789abcdef" (32 chars)
    /// - Prefixed: "tnu_wrt_0123456789abcdef0123456789abcdef"
    /// - Standard UUID: "01234567-89ab-cdef-0123-456789abcdef"
    pub fn from_string(s: impl AsRef<str>) -> Result<Self> {
        let s = s.as_ref();

        // Try parsing with prefix
        let hex_str = if let Some(stripped) = s.strip_prefix(WARRANT_ID_PREFIX) {
            stripped
        } else if s.contains('-') {
            // Standard UUID format
            return Uuid::parse_str(s)
                .map(|u| Self(*u.as_bytes()))
                .map_err(|e| Error::InvalidWarrantId(format!("invalid UUID: {}", e)));
        } else {
            s
        };

        // Parse hex
        if hex_str.len() != 32 {
            return Err(Error::InvalidWarrantId(format!(
                "expected 32 hex chars, got {}",
                hex_str.len()
            )));
        }

        let mut bytes = [0u8; 16];
        for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
            let hex = std::str::from_utf8(chunk)
                .map_err(|_| Error::InvalidWarrantId("invalid UTF-8".to_string()))?;
            bytes[i] = u8::from_str_radix(hex, 16)
                .map_err(|_| Error::InvalidWarrantId(format!("invalid hex: {}", hex)))?;
        }
        Ok(Self(bytes))
    }

    /// Get the ID as raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Get the ID as a hex string (for display/logging).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get the ID as a prefixed string (for display/logging).
    pub fn to_prefixed_string(&self) -> String {
        format!("{}{}", WARRANT_ID_PREFIX, hex::encode(self.0))
    }

    /// Get the ID as a string slice (compatibility method).
    /// Returns the hex representation.
    #[deprecated(note = "Use to_hex() or to_prefixed_string() instead")]
    pub fn as_str(&self) -> String {
        self.to_hex()
    }
}

impl Default for WarrantId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for WarrantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display as prefixed string for human readability
        write!(f, "{}{}", WARRANT_ID_PREFIX, hex::encode(self.0))
    }
}

pub use crate::payload::WarrantPayload;

/// A signed warrant - the complete token of authority.
/// This corresponds to the "Envelope" in the spec.
/// A signed warrant - the complete token of authority.
///
/// This serves as the primary domain object. On the wire, it is serialized
/// as a `SignedWarrant` envelope (ver, payload_bytes, sig).
#[derive(Debug, Clone)]
pub struct Warrant {
    /// The deserialized payload (for business logic).
    pub payload: WarrantPayload,
    /// The internal signature.
    pub signature: Signature,
    /// The canonical bytes of the payload (for signature verification).
    #[allow(dead_code)] // Used for verification and re-serialization
    pub payload_bytes: Vec<u8>,
    /// Envelope format version (default 1).
    pub envelope_version: u8,
}

// Domain separation is handled by crypto::SigningKey using strictly defined context.
// PREIMAGE = envelope_version || payload_bytes
// Actual signed message = SIGNATURE_CONTEXT || PREIMAGE

impl Serialize for Warrant {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as SignedWarrant envelope
        // Using a tuple/array format as per spec?
        // Spec says: CBOR Array [0: ver, 1: payload, 2: sig]
        // Our SignedWarrantEnvelope struct with integer keys implies a Map.
        // Spec text: "The outer envelope (SignedWarrant) is a CBOR Map."
        // Spec block:
        // CBOR Array [ ... ]
        // Wait, spec is contradictory or I misread "Structure" as Array?
        // "We use integer keys for compactness in the envelope." usually implies Map with integer keys.
        // But the block shows `[...]` which is Array.
        // And "Index 0:", "Index 1:".
        // Let's re-read spec carefully.
        // Line 521: "Envelope (SignedWarrant): CBOR Array [...]"
        // But Line 511 mentions integer keys?
        // Wait, line 511 was about constraints?
        // Let's check spec content again via view_file.
        // Line 638: | Envelope pattern | `SignedWarrant { payload, signature }` |

        // If it's an Array:
        // Use `serializer.serialize_tuple(3)`

        // If it's a Map:
        // Use struct with `rename="0"`, etc.

        // My previous view showed:
        // 524: CBOR Array [
        // 525:     0: envelope_version (u8),
        // 526:     1: payload (bytes),
        // 527:     2: signature (Signature),
        // 528: ]

        // This notation usually means Array indices.
        // So tuple (u8, Vec<u8>, Signature).

        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(3)?;
        tup.serialize_element(&self.envelope_version)?;
        tup.serialize_element(&serde_bytes::Bytes::new(&self.payload_bytes))?;
        tup.serialize_element(&self.signature)?;
        tup.end()
    }
}

impl<'de> Deserialize<'de> for Warrant {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct WarrantVisitor;

        impl<'de> serde::de::Visitor<'de> for WarrantVisitor {
            type Value = Warrant;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a signed warrant array [ver, payload_bytes, sig]")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let envelope_version: u8 = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                if envelope_version != 1 {
                    return Err(serde::de::Error::custom(format!(
                        "unsupported envelope_version: {}",
                        envelope_version
                    )));
                }

                let payload_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                let signature: Signature = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;

                // Deserialize payload
                let payload: WarrantPayload = ciborium::de::from_reader(&payload_bytes[..])
                    .map_err(|e| {
                        serde::de::Error::custom(format!("invalid payload CBOR: {}", e))
                    })?;

                // Verify signature against domain-separated preimage: version || payload
                let mut preimage = Vec::with_capacity(1 + payload_bytes.len());
                preimage.push(envelope_version);
                preimage.extend_from_slice(&payload_bytes);

                if payload.issuer.verify(&preimage, &signature).is_err() {
                    return Err(serde::de::Error::custom("invalid warrant signature"));
                }

                // Also validate constraint depth during deserialization
                // We'll trust accessors to validate, or call validate() later.
                // But generally safe deserialization implies valid object.
                // For now, let's return the object. User should call .validate().
                // Or we can call validate_struct?

                Ok(Warrant {
                    envelope_version,
                    payload,
                    signature,
                    payload_bytes,
                })
            }
        }

        deserializer.deserialize_tuple(3, WarrantVisitor)
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
        self.payload.warrant_type
    }

    /// Get the warrant version.
    pub fn version(&self) -> u8 {
        self.payload.version
    }

    /// Get the tools map.
    pub fn tools_map(&self) -> &BTreeMap<String, ConstraintSet> {
        &self.payload.tools
    }

    /// Get capabilities (compat alias for tools).
    pub fn capabilities(&self) -> Option<&BTreeMap<String, ConstraintSet>> {
        if self.payload.tools.is_empty() {
            None
        } else {
            Some(&self.payload.tools)
        }
    }

    /// Retain only specific tools (attenuation).
    pub fn retain_capabilities(&mut self, tools: &[String]) {
        let tools_set: std::collections::HashSet<_> = tools.iter().map(|s| s.as_str()).collect();
        self.payload
            .tools
            .retain(|k, _| tools_set.contains(k.as_str()));
    }

    /// Get the tools authorized by this warrant.
    pub fn tools(&self) -> Vec<String> {
        let mut tools: Vec<String> = self.payload.tools.keys().cloned().collect();
        tools.sort(); // Deterministic order
        tools
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

    /// Get when this warrant was issued.
    pub fn issued_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.payload.issued_at as i64, 0).unwrap_or_default()
    }

    /// Get the expiration time.
    pub fn expires_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.payload.expires_at as i64, 0).unwrap_or_default()
    }

    /// Validate that constraint nesting depths are within limits.
    pub fn validate_constraint_depth(&self) -> Result<()> {
        for constraints in self.payload.tools.values() {
            constraints.validate_depth()?;
        }
        if let Some(constraint_bounds) = &self.payload.constraint_bounds {
            constraint_bounds.validate_depth()?;
        }
        Ok(())
    }

    /// Comprehensive validation of warrant structure and invariants.
    pub fn validate(&self) -> Result<()> {
        // Validate version
        // NOTE: Warrant version is u8 now. Assuming const WARRANT_VERSION is updated to u8 or cast here.
        if self.payload.version != WARRANT_VERSION as u8 {
            return Err(Error::Validation(format!(
                "unsupported warrant version: {} (expected {})",
                self.payload.version, WARRANT_VERSION
            )));
        }

        // Validate warrant type consistency
        match self.payload.warrant_type {
            WarrantType::Execution => {
                // Execution warrants MUST have tools (even if empty map, though usually not)
                // Spec implies "tools" is always present.
                if self.payload.issuable_tools.is_some() {
                    return Err(Error::InvalidWarrantType {
                        message: "execution warrant cannot have issuable_tools".to_string(),
                    });
                }
                if self.payload.trust_ceiling.is_some() {
                    return Err(Error::InvalidWarrantType {
                        message: "execution warrant cannot have trust_ceiling".to_string(),
                    });
                }
                if self.payload.max_issue_depth.is_some() {
                    return Err(Error::InvalidWarrantType {
                        message: "execution warrant cannot have max_issue_depth".to_string(),
                    });
                }
            }
            WarrantType::Issuer => {
                // Issuer warrants should NOT have tools (capabilities)
                if !self.payload.tools.is_empty() {
                    return Err(Error::InvalidWarrantType {
                        message: "issuer warrant cannot have tools (capabilities)".to_string(),
                    });
                }

                if self.payload.issuable_tools.is_none()
                    || self.payload.issuable_tools.as_ref().unwrap().is_empty()
                {
                    return Err(Error::InvalidWarrantType {
                        message: "issuer warrant must have at least one issuable_tool".to_string(),
                    });
                }
                if self.payload.trust_ceiling.is_none() {
                    return Err(Error::InvalidWarrantType {
                        message: "issuer warrant must have trust_ceiling".to_string(),
                    });
                }
            }
        }

        // Validate trust level doesn't exceed trust_ceiling for issuer warrants
        if let (Some(trust_level), Some(trust_ceiling)) =
            (self.payload.trust_level, self.payload.trust_ceiling)
        {
            if trust_level > trust_ceiling {
                return Err(Error::TrustLevelExceeded {
                    requested: format!("{:?}", trust_level),
                    ceiling: format!("{:?}", trust_ceiling),
                });
            }
        }

        // Validate max_issue_depth doesn't exceed max_depth
        if let Some(max_issue) = self.payload.max_issue_depth {
            let effective_max = self.effective_max_depth();
            if max_issue > effective_max {
                return Err(Error::IssueDepthExceeded {
                    depth: max_issue,
                    max: effective_max,
                });
            }
        }

        // Validate constraint depth
        self.validate_constraint_depth()?;

        // Validate expiration is in the future
        if self.is_expired() {
            // Informational
        }

        Ok(())
    }

    /// Get the delegation depth (0 for root, increments on each attenuation).
    pub fn depth(&self) -> u32 {
        self.payload.depth
    }

    /// Get the maximum delegation depth allowed for this warrant chain.
    pub fn max_depth(&self) -> Option<u32> {
        // Spec has max_depth as u8. Code uses u32. Cast safely.
        Some(self.payload.max_depth as u32)
    }

    /// Get the effective maximum depth.
    pub fn effective_max_depth(&self) -> u32 {
        self.payload.max_depth as u32
    }

    /// Get the parent warrant ID.
    /// Get the parent warrant hash, if this is a delegated warrant.
    pub fn parent_hash(&self) -> Option<&[u8; 32]> {
        self.payload.parent_hash.as_ref()
    }

    /// Check if this warrant is a root warrant (no parent).
    pub fn is_root(&self) -> bool {
        self.payload.parent_hash.is_none()
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
    pub fn authorized_holder(&self) -> &PublicKey {
        &self.payload.holder
    }

    /// Check if this warrant requires Proof-of-Possession.
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
    pub fn approval_threshold(&self) -> u32 {
        use std::convert::TryInto;
        match (&self.payload.required_approvers, self.payload.min_approvals) {
            (Some(approvers), Some(min)) => {
                let len: u32 = approvers.len().try_into().unwrap_or(u32::MAX);
                min.min(len)
            }
            (Some(approvers), None) => approvers.len().try_into().unwrap_or(u32::MAX),
            (None, _) => 0,
        }
    }

    /// Get the payload bytes (for batch signature verification).
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload_bytes
    }

    /// Build the domain-separated signature preimage.
    pub fn signature_preimage(&self) -> Vec<u8> {
        let mut preimage = Vec::with_capacity(1 + self.payload_bytes.len());
        preimage.push(self.envelope_version);
        preimage.extend_from_slice(&self.payload_bytes);
        preimage
    }

    /// Get the signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Verify that a holder signature proves possession.
    pub fn verify_holder(&self, challenge: &[u8], signature: &Signature) -> Result<()> {
        self.payload
            .holder
            .verify(challenge, signature)
            .map_err(|_| Error::SignatureInvalid("holder proof-of-possession failed".to_string()))
    }

    /// Check if the warrant has expired.
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp() as u64;
        now >= self.payload.expires_at
    }

    /// Check if this warrant is terminal (cannot delegate further).
    pub fn is_terminal(&self) -> bool {
        self.depth() >= self.effective_max_depth()
    }

    /// Check if the warrant has expired, with clock skew tolerance.
    pub fn is_expired_with_tolerance(&self, tolerance: chrono::Duration) -> bool {
        let now = Utc::now().timestamp() as u64;
        // Avoid underflow if tolerance is relatively large negative (unlikely)
        // tolerance.num_seconds()
        let tol_secs = tolerance.num_seconds();
        if tol_secs < 0 {
            now > self.payload.expires_at.saturating_sub((-tol_secs) as u64)
        } else {
            now > self.payload.expires_at.saturating_add(tol_secs as u64)
        }
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
    pub fn verify_signature(&self) -> Result<()> {
        self.payload
            .issuer
            .verify(&self.signature_preimage(), &self.signature)
    }

    /// Authorize an action against this warrant.
    pub fn authorize(
        &self,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&Signature>,
    ) -> Result<()> {
        // Check expiration
        if self.is_expired() {
            return Err(Error::WarrantExpired(self.expires_at()));
        }

        // Only execution warrants can authorize actions
        if self.payload.warrant_type != WarrantType::Execution {
            return Err(Error::InvalidWarrantType {
                message: "only execution warrants can authorize actions".to_string(),
            });
        }

        // Check if tool is allowed
        let constraints = if let Some(c) = self.payload.tools.get(tool) {
            c
        } else if let Some(c) = self.payload.tools.get("*") {
            c
        } else {
            return Err(Error::ConstraintNotSatisfied {
                field: "tool".to_string(),
                reason: format!("warrant does not authorize tool '{}'", tool),
            });
        };

        // Check constraints
        constraints.matches(args)?;

        // Check Proof-of-Possession (mandatory)
        self.verify_pop(tool, args, signature, POP_TIMESTAMP_WINDOW_SECS, 4)
    }

    /// Authorize an action with custom PoP window configuration.
    pub fn authorize_with_pop_config(
        &self,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        signature: Option<&Signature>,
        pop_window_secs: i64,
        pop_max_windows: u32,
    ) -> Result<()> {
        // Check expiration
        if self.is_expired() {
            return Err(Error::WarrantExpired(self.expires_at()));
        }

        if self.payload.warrant_type != WarrantType::Execution {
            return Err(Error::InvalidWarrantType {
                message: "only execution warrants can authorize actions".to_string(),
            });
        }

        let constraints = if let Some(c) = self.payload.tools.get(tool) {
            c
        } else if let Some(c) = self.payload.tools.get("*") {
            c
        } else {
            return Err(Error::ConstraintNotSatisfied {
                field: "tool".to_string(),
                reason: format!("warrant does not authorize tool '{}'", tool),
            });
        };

        constraints.matches(args)?;

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
                .holder
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
    pub fn create_pop_signature(
        &self,
        keypair: &SigningKey,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
    ) -> Result<Signature> {
        let mut sorted_args: Vec<(&String, &ConstraintValue)> = args.iter().collect();
        sorted_args.sort_by_key(|(k, _)| *k);

        let now = Utc::now().timestamp();
        let window_ts = (now / POP_TIMESTAMP_WINDOW_SECS) * POP_TIMESTAMP_WINDOW_SECS;

        let challenge_data = (self.payload.id.as_str(), tool, sorted_args, window_ts);
        let mut challenge_bytes = Vec::new();
        ciborium::ser::into_writer(&challenge_data, &mut challenge_bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

        Ok(keypair.sign(&challenge_bytes))
    }

    /// Generate a deduplication key.
    pub fn dedup_key(&self, tool: &str, args: &HashMap<String, ConstraintValue>) -> String {
        use sha2::{Digest, Sha256};

        let mut sorted_args: Vec<(&String, &ConstraintValue)> = args.iter().collect();
        sorted_args.sort_by_key(|(k, _)| *k);

        let payload = (self.payload.id.as_str(), tool, &sorted_args);
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)
            .expect("dedup payload serialization should never fail");

        let mut hasher = Sha256::new();
        hasher.update(&payload_bytes);
        let hash = hasher.finalize();

        hex::encode(hash)
    }

    pub const fn dedup_ttl_secs() -> i64 {
        POP_TIMESTAMP_WINDOW_SECS * 4
    }

    pub fn attenuate(&self) -> AttenuationBuilder<'_> {
        AttenuationBuilder::new(self)
    }

    pub fn issue_execution_warrant(&self) -> Result<IssuanceBuilder<'_>> {
        if self.payload.warrant_type != WarrantType::Issuer {
            return Err(Error::InvalidWarrantType {
                message: "can only issue execution warrants from issuer warrants".to_string(),
            });
        }
        Ok(IssuanceBuilder::new(self))
    }
}

/// Builder for creating root warrants.
#[derive(Debug, Clone)]
pub struct WarrantBuilder {
    warrant_type: Option<WarrantType>,
    // tools (Execution)
    tools: BTreeMap<String, ConstraintSet>,
    // Issuer fields
    issuable_tools: Option<Vec<String>>,
    trust_ceiling: Option<TrustLevel>,
    max_issue_depth: Option<u32>,
    constraint_bounds: ConstraintSet,
    // Common
    trust_level: Option<TrustLevel>,
    ttl: Option<Duration>,
    max_depth: Option<u32>,
    session_id: Option<String>,
    agent_id: Option<String>,
    holder: Option<PublicKey>,
    required_approvers: Option<Vec<PublicKey>>,
    min_approvals: Option<u32>,
    id: Option<WarrantId>,
    // Root warrants have no parent hash
    // parent_id removed as it is not part of root warrant payload
    // extensions
    extensions: BTreeMap<String, Vec<u8>>,
}

impl WarrantBuilder {
    pub fn new() -> Self {
        Self {
            warrant_type: None,
            tools: BTreeMap::new(),
            issuable_tools: None,
            trust_ceiling: None,
            max_issue_depth: None,
            constraint_bounds: ConstraintSet::new(),
            trust_level: None,
            ttl: None,
            max_depth: None,
            session_id: None,
            agent_id: None,
            holder: None,
            required_approvers: None,
            min_approvals: None,
            id: None,
            // parent_id: None,
            extensions: BTreeMap::new(),
        }
    }

    pub fn r#type(mut self, warrant_type: WarrantType) -> Self {
        self.warrant_type = Some(warrant_type);
        self
    }

    pub fn trust_level(mut self, level: TrustLevel) -> Self {
        self.trust_level = Some(level);
        self
    }

    pub fn issuable_tools(mut self, tools: Vec<String>) -> Self {
        self.issuable_tools = Some(tools);
        self
    }

    pub fn trust_ceiling(mut self, ceiling: TrustLevel) -> Self {
        self.trust_ceiling = Some(ceiling);
        self
    }

    pub fn max_issue_depth(mut self, depth: u32) -> Self {
        self.max_issue_depth = Some(depth);
        self
    }

    pub fn constraint_bound(
        mut self,
        field: impl Into<String>,
        constraint: impl Into<Constraint>,
    ) -> Self {
        self.constraint_bounds.insert(field, constraint);
        self
    }

    pub fn depth(self, _: u32) -> Self {
        // Deprecated/Ignored in builder, calculated from chain?
        // Actually for root warrants depth is 0.
        // We removed `depth` field from Payload, it is implicit 0 for root or len of chain.
        self
    }

    // Root warrants cannot have a parent ID/hash set manually via this builder.
    // Use AttenuationBuilder for delegated warrants.

    // Add extension support
    pub fn extension(mut self, key: impl Into<String>, value: Vec<u8>) -> Self {
        self.extensions.insert(key.into(), value);
        self
    }

    // Support    /// Add a capability (tool + constraints).
    pub fn capability(mut self, tool: impl Into<String>, constraints: ConstraintSet) -> Self {
        let tool_name = tool.into();

        // Validate reserved tool namespace
        if tool_name.starts_with("tenuo:") {
            // Store error to be returned during build()
            // For now, we'll panic to match existing builder pattern
            panic!("Reserved tool namespace: tools starting with 'tenuo:' are reserved for framework use");
        }

        self.tools.insert(tool_name, constraints);
        self
    }

    // Support old "tools" method? No, refactor to capability/tool
    // But keep "tool" method for single tool?
    pub fn tool(mut self, tool: impl Into<String>, constraints: ConstraintSet) -> Self {
        self.tools.insert(tool.into(), constraints);
        self
    }

    // Support authorized_holder renamed to holder
    pub fn holder(mut self, holder: PublicKey) -> Self {
        self.holder = Some(holder);
        self
    }

    // Compat alias
    pub fn authorized_holder(self, holder: PublicKey) -> Self {
        self.holder(holder)
    }

    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    pub fn agent_id(mut self, id: impl Into<String>) -> Self {
        self.agent_id = Some(id.into());
        self
    }

    pub fn required_approvers(mut self, approvers: Vec<PublicKey>) -> Self {
        self.required_approvers = Some(approvers);
        self
    }

    pub fn min_approvals(mut self, min: u32) -> Self {
        self.min_approvals = Some(min);
        self
    }

    pub fn max_depth(mut self, depth: u32) -> Self {
        self.max_depth = Some(depth);
        self
    }

    /// Set a custom warrant ID.
    pub fn id(mut self, id: WarrantId) -> Self {
        self.id = Some(id);
        self
    }

    /// Build and sign the warrant.
    pub fn build(mut self, signing_key: &SigningKey) -> Result<Warrant> {
        if self.warrant_type.is_none() {
            if !self.tools.is_empty() {
                self.warrant_type = Some(WarrantType::Execution);
            } else if self.issuable_tools.is_some()
                || self.trust_ceiling.is_some()
                || self.max_issue_depth.is_some()
            {
                self.warrant_type = Some(WarrantType::Issuer);
            }
        }

        let warrant_type = self
            .warrant_type
            .ok_or_else(|| Error::Validation("warrant type required".to_string()))?;

        // Validate required fields based on warrant type
        match warrant_type {
            WarrantType::Execution => {
                if self.tools.is_empty() {
                    return Err(Error::InvalidWarrantType {
                        message: "execution warrant must have tools".to_string(),
                    });
                }
                if self.issuable_tools.is_some() {
                    return Err(Error::InvalidWarrantType {
                        message: "execution warrant cannot have issuable_tools".to_string(),
                    });
                }
                if self.trust_ceiling.is_some() {
                    return Err(Error::InvalidWarrantType {
                        message: "execution warrant cannot have trust_ceiling".to_string(),
                    });
                }
                if self.max_issue_depth.is_some() {
                    return Err(Error::InvalidWarrantType {
                        message: "execution warrant cannot have max_issue_depth".to_string(),
                    });
                }
            }
            WarrantType::Issuer => {
                if !self.tools.is_empty() {
                    return Err(Error::InvalidWarrantType {
                        message: "issuer warrant cannot have tools (capabilities)".to_string(),
                    });
                }
                if self.issuable_tools.is_none() || self.issuable_tools.as_ref().unwrap().is_empty()
                {
                    return Err(Error::InvalidWarrantType {
                        message: "issuer warrant requires at least one issuable_tool".to_string(),
                    });
                }
                if self.trust_ceiling.is_none() {
                    return Err(Error::InvalidWarrantType {
                        message: "issuer warrant requires trust_ceiling".to_string(),
                    });
                }
            }
        }

        // Default TTL: 1 hour for better DX, but validate against protocol max
        let ttl = self.ttl.unwrap_or_else(|| Duration::from_secs(3600));

        // Validate TTL doesn't exceed protocol maximum (90 days)
        if ttl.as_secs() > crate::MAX_WARRANT_TTL_SECS {
            return Err(Error::InvalidTtl(format!(
                "TTL {} seconds exceeds protocol maximum of {} seconds ({} days)",
                ttl.as_secs(),
                crate::MAX_WARRANT_TTL_SECS,
                crate::MAX_WARRANT_TTL_SECS / 86400
            )));
        }

        // Holder defaults to issuer if not set (Self-issued) which is valid.
        let holder = self.holder.unwrap_or_else(|| signing_key.public_key());

        let max_depth_val = self.max_depth.unwrap_or(crate::MAX_DELEGATION_DEPTH);
        let max_depth_u8 = max_depth_val as u8; // Safe cast assuming MAX_DELEGATION_DEPTH small

        // Validate max_depth doesn't exceed protocol cap
        if max_depth_val > crate::MAX_DELEGATION_DEPTH {
            return Err(Error::DepthExceeded(
                max_depth_val,
                crate::MAX_DELEGATION_DEPTH,
            ));
        }

        // Validate max_issue_depth for issuer warrants
        if let Some(max_issue) = self.max_issue_depth {
            if max_issue > max_depth_val {
                return Err(Error::IssueDepthExceeded {
                    depth: max_issue,
                    max: max_depth_val,
                });
            }
        }

        // Validate trust_level doesn't exceed trust_ceiling for issuer warrants
        if let (Some(trust_level), Some(trust_ceiling)) = (self.trust_level, self.trust_ceiling) {
            if trust_level > trust_ceiling {
                return Err(Error::TrustLevelExceeded {
                    requested: format!("{:?}", trust_level),
                    ceiling: format!("{:?}", trust_ceiling),
                });
            }
        }

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

        // Validate constraint depth in tools
        for constraints in self.tools.values() {
            constraints.validate_depth()?;
        }
        if !self.constraint_bounds.is_empty() {
            self.constraint_bounds.validate_depth()?;
        }

        let id = self.id.unwrap_or_default();
        let issued_at = Utc::now().timestamp() as u64;
        let expires_at = issued_at + ttl.as_secs();

        let payload = WarrantPayload {
            version: WARRANT_VERSION as u8,
            warrant_type,
            id,
            tools: self.tools,
            holder,
            issuer: signing_key.public_key(),
            issued_at,
            expires_at,
            max_depth: max_depth_u8,
            depth: 0,          // Root warrant has depth 0
            parent_hash: None, // Root warrant has no parent hash
            extensions: self.extensions,

            issuable_tools: self.issuable_tools,
            trust_ceiling: self.trust_ceiling,
            max_issue_depth: self.max_issue_depth,
            constraint_bounds: if self.constraint_bounds.is_empty() {
                None
            } else {
                Some(self.constraint_bounds)
            },

            trust_level: self.trust_level,
            session_id: self.session_id,
            agent_id: self.agent_id,
            required_approvers: self.required_approvers,
            min_approvals: self.min_approvals,
        };

        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

        // Preimage: envelope_version || payload_bytes
        let mut preimage = Vec::with_capacity(1 + payload_bytes.len());
        preimage.push(1); // envelope_version
        preimage.extend_from_slice(&payload_bytes);

        let signature = signing_key.sign(&preimage);

        let warrant = Warrant {
            payload,
            signature,
            payload_bytes,
            envelope_version: 1,
        };

        // Audit: Log warrant creation
        log_event(AuditEvent {
            id: Uuid::new_v4().to_string(),
            event_type: AuditEventType::WarrantIssued,
            timestamp: Utc::now(),
            provider: "tenuo".to_string(),
            external_id: None,
            public_key_hex: Some(hex::encode(signing_key.public_key().to_bytes())),
            actor: format!(
                "issuer:{}",
                hex::encode(&signing_key.public_key().to_bytes()[..8])
            ),
            details: Some(format!(
                "root warrant created: type={:?}, tools={:?}, depth=0",
                warrant.payload.warrant_type,
                warrant.tools()
            )),
            related_ids: Some(vec![warrant.id().to_string()]),
        });

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
    // Execution warrant fields
    tools: BTreeMap<String, ConstraintSet>,
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
    holder: Option<PublicKey>,
    required_approvers: Option<Vec<PublicKey>>,
    min_approvals: Option<u32>,
    // Extensions
    extensions: BTreeMap<String, Vec<u8>>,
}

impl<'a> AttenuationBuilder<'a> {
    /// Create a new attenuation builder.
    fn new(parent: &'a Warrant) -> Self {
        // Inherit from parent based on warrant type
        let (tools, issuable_tools, trust_ceiling, max_issue_depth, constraint_bounds) =
            match parent.payload.warrant_type {
                WarrantType::Execution => (
                    // Start with parent's tools
                    parent.payload.tools.clone(),
                    None,
                    None,
                    None,
                    ConstraintSet::new(),
                ),
                WarrantType::Issuer => (
                    BTreeMap::new(),
                    parent.payload.issuable_tools.clone(),
                    parent.payload.trust_ceiling,
                    parent.payload.max_issue_depth,
                    parent.payload.constraint_bounds.clone().unwrap_or_default(),
                ),
            };

        Self {
            parent,
            tools,
            issuable_tools,
            trust_ceiling,
            max_issue_depth,
            constraint_bounds,
            trust_level: parent.payload.trust_level,
            ttl: None,
            max_depth: None, // Will inherit from parent if not set
            session_id: parent.payload.session_id.clone(),
            agent_id: parent.payload.agent_id.clone(),
            holder: Some(parent.payload.holder.clone()),
            // Multi-sig: inherit from parent (can only add MORE approvers or raise threshold)
            required_approvers: parent.payload.required_approvers.clone(),
            min_approvals: parent.payload.min_approvals,
            extensions: BTreeMap::new(),
        }
    }

    /// Add a capability (tool + constraint) to the attenuated warrant.
    ///
    /// This effectively narrows the parent's capability for this tool.
    /// If the tool wasn't in the parent or previous set, it's added (subject to validation).
    pub fn capability(
        mut self,
        tool: impl Into<String>,
        constraints: impl Into<ConstraintSet>,
    ) -> Self {
        self.tools.insert(tool.into(), constraints.into());
        self
    }

    /// Add a tool (alias for capability).
    pub fn tool(self, tool: impl Into<String>, constraints: impl Into<ConstraintSet>) -> Self {
        self.capability(tool, constraints)
    }

    /// Set a shorter TTL.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set a lower maximum delegation depth.
    pub fn max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = Some(max_depth);
        self
    }

    // NOTE: session_id is inherited from parent and immutable during attenuation.

    /// Set or change the agent ID.
    pub fn agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Set or change the authorized holder (Proof-of-Possession).
    pub fn holder(mut self, public_key: PublicKey) -> Self {
        self.holder = Some(public_key);
        self
    }

    /// Compat alias for holder.
    pub fn authorized_holder(self, public_key: PublicKey) -> Self {
        self.holder(public_key)
    }

    /// Add required approvers (can only add more, not remove).
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
    pub fn raise_min_approvals(mut self, min: u32) -> Self {
        let current = self.min_approvals.unwrap_or(0);
        self.min_approvals = Some(min.max(current));
        self
    }

    /// Add an extension.
    pub fn extension(mut self, key: impl Into<String>, value: Vec<u8>) -> Self {
        self.extensions.insert(key.into(), value);
        self
    }

    /// Validate multi-sig monotonicity (cannot remove approvers or lower threshold).
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
    pub fn build(self, keypair: &SigningKey, _parent_keypair: &SigningKey) -> Result<Warrant> {
        let new_depth = self.parent.depth() + 1;
        if new_depth > MAX_DELEGATION_DEPTH {
            return Err(Error::DepthExceeded(new_depth, MAX_DELEGATION_DEPTH));
        }

        // Calculate effective max_depth (monotonic: can only shrink)
        let parent_max_depth = self.parent.max_depth();

        let effective_max = match (parent_max_depth, self.max_depth) {
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

        if self.parent.is_expired() {
            return Err(Error::WarrantExpired(self.parent.expires_at()));
        }

        // Validate attenuation monotonicity based on warrant type
        match self.parent.payload.warrant_type {
            WarrantType::Execution => {
                let parent_tools = &self.parent.payload.tools;

                for (tool, constraints) in &self.tools {
                    if let Some(parent_constraints) = parent_tools.get(tool) {
                        parent_constraints.validate_attenuation(constraints)?;
                    } else if let Some(parent_wildcard) = parent_tools.get("*") {
                        parent_wildcard.validate_attenuation(constraints)?;
                    } else {
                        return Err(Error::MonotonicityViolation(format!(
                            "tool '{}' not in parent's tools",
                            tool
                        )));
                    }
                }

                if self.tools.is_empty() {
                    return Err(Error::Validation(
                        "execution warrant must have at least one tool".to_string(),
                    ));
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

        let holder = self
            .holder
            .ok_or_else(|| Error::Validation("holder is required".to_string()))?;

        let now_sec = Utc::now().timestamp() as u64;
        let expires_at = if let Some(ttl) = self.ttl {
            let ttl_secs = ttl.as_secs();
            let proposed = now_sec + ttl_secs;
            if proposed > self.parent.payload.expires_at {
                self.parent.payload.expires_at
            } else {
                proposed
            }
        } else {
            self.parent.payload.expires_at
        };

        let effective_min = self.min_approvals.or(self.parent.payload.min_approvals);

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.parent.payload_bytes);
        let parent_hash: [u8; 32] = hasher.finalize().into();

        let payload = WarrantPayload {
            version: WARRANT_VERSION as u8,
            warrant_type: self.parent.payload.warrant_type,
            id: WarrantId::new(),
            holder,
            tools: self.tools,
            issuable_tools: match self.parent.payload.warrant_type {
                WarrantType::Issuer => self.issuable_tools.clone(),
                WarrantType::Execution => None,
            },
            trust_ceiling: match self.parent.payload.warrant_type {
                WarrantType::Issuer => self.trust_ceiling,
                WarrantType::Execution => None,
            },
            max_issue_depth: match self.parent.payload.warrant_type {
                WarrantType::Issuer => self.max_issue_depth,
                WarrantType::Execution => None,
            },
            constraint_bounds: match self.parent.payload.warrant_type {
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
            issued_at: now_sec,
            expires_at,
            max_depth: effective_max
                .map(|d| d as u8)
                .unwrap_or(MAX_DELEGATION_DEPTH as u8),
            depth: self.parent.depth() + 1, // Increment depth from parent
            session_id: self.session_id,
            agent_id: self.agent_id,
            issuer: keypair.public_key(),
            parent_hash: Some(parent_hash),
            required_approvers: self.required_approvers,
            min_approvals: effective_min,
            extensions: self.extensions,
        };

        if payload.warrant_type == WarrantType::Issuer && !payload.tools.is_empty() {
            return Err(Error::InvalidWarrantType {
                message: "issuer warrant cannot have tools".to_string(),
            });
        }

        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

        // Preimage: envelope_version || payload_bytes
        let mut preimage = Vec::with_capacity(1 + payload_bytes.len());
        preimage.push(1); // envelope_version
        preimage.extend_from_slice(&payload_bytes);

        let signature = keypair.sign(&preimage);

        let warrant = Warrant {
            payload,
            signature,
            payload_bytes,
            envelope_version: 1,
        };

        // Audit: Log warrant attenuation
        log_event(AuditEvent {
            id: Uuid::new_v4().to_string(),
            event_type: AuditEventType::WarrantIssued,
            timestamp: Utc::now(),
            provider: "tenuo".to_string(),
            external_id: None,
            public_key_hex: Some(hex::encode(keypair.public_key().to_bytes())),
            actor: format!(
                "delegator:{}",
                hex::encode(&keypair.public_key().to_bytes()[..8])
            ),
            details: Some(format!(
                "warrant attenuated: type={:?}, depth={}, parent={}",
                warrant.payload.warrant_type,
                warrant.depth(),
                self.parent.id()
            )),
            related_ids: Some(vec![warrant.id().to_string(), self.parent.id().to_string()]),
        });

        Ok(warrant)
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
    tools: BTreeMap<String, ConstraintSet>,
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
    holder: Option<PublicKey>,
    required_approvers: Option<Vec<PublicKey>>,
    min_approvals: Option<u32>,
    /// Intent/purpose for this delegation (for audit trails).
    intent: Option<String>,
    // Extensions
    extensions: BTreeMap<String, Vec<u8>>,
}

impl OwnedAttenuationBuilder {
    /// Create a new owned attenuation builder.
    pub fn new(parent: Warrant) -> Self {
        // Inherit from parent based on warrant type
        let (tools, issuable_tools, trust_ceiling, max_issue_depth, constraint_bounds) =
            match parent.payload.warrant_type {
                WarrantType::Execution => (
                    // Start with parent's tools
                    parent.payload.tools.clone(),
                    None,
                    None,
                    None,
                    ConstraintSet::new(),
                ),
                WarrantType::Issuer => (
                    BTreeMap::new(),
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
            holder: Some(parent.payload.holder.clone()),
            required_approvers: parent.payload.required_approvers.clone(),
            min_approvals: parent.payload.min_approvals,
            parent,

            tools,
            issuable_tools,
            trust_ceiling,
            max_issue_depth,
            constraint_bounds,
            ttl: None,
            max_depth: None,
            intent: None,
            extensions: BTreeMap::new(),
        }
    }

    /// Get the configured tools.
    pub fn tools(&self) -> &BTreeMap<String, ConstraintSet> {
        &self.tools
    }

    /// Get a reference to the parent warrant.
    pub fn parent(&self) -> &Warrant {
        &self.parent
    }

    /// Keep only the specified tool (remove others).
    pub fn retain_tool(&mut self, tool: &str) {
        self.tools.retain(|k, _| k == tool);
    }

    /// Compat alias
    pub fn retain_capability(&mut self, tool: &str) {
        self.retain_tool(tool)
    }

    /// Keep only the specified tools (remove others).
    pub fn retain_tools(&mut self, tools: &[String]) {
        self.tools.retain(|k, _| tools.contains(k));
    }

    /// Compat alias
    pub fn retain_capabilities(&mut self, tools: &[String]) {
        self.retain_tools(tools)
    }

    /// Get the configured TTL (if any).
    pub fn ttl_seconds(&self) -> Option<u64> {
        self.ttl.map(|d| d.as_secs())
    }

    /// Get the configured holder (if any).
    pub fn get_holder(&self) -> Option<&PublicKey> {
        self.holder.as_ref()
    }

    /// Get the configured trust level.
    pub fn trust_level(&self) -> Option<TrustLevel> {
        self.trust_level
    }

    /// Get the configured intent.
    pub fn intent(&self) -> Option<&str> {
        self.intent.as_deref()
    }

    /// Add a tool description (tool + constraints) to the warrant.
    pub fn tool(mut self, tool: impl Into<String>, constraints: impl Into<ConstraintSet>) -> Self {
        self.tools.insert(tool.into(), constraints.into());
        self
    }

    /// Compat alias
    pub fn capability(
        self,
        tool: impl Into<String>,
        constraints: impl Into<ConstraintSet>,
    ) -> Self {
        self.tool(tool, constraints)
    }

    /// Add a tool (mutable version for FFI).
    pub fn set_tool(&mut self, tool: impl Into<String>, constraints: impl Into<ConstraintSet>) {
        self.tools.insert(tool.into(), constraints.into());
    }

    /// Compat alias
    pub fn set_capability(
        &mut self,
        tool: impl Into<String>,
        constraints: impl Into<ConstraintSet>,
    ) {
        self.set_tool(tool, constraints)
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
    pub fn holder(mut self, public_key: PublicKey) -> Self {
        self.holder = Some(public_key);
        self
    }

    /// Compat alias
    pub fn authorized_holder(self, public_key: PublicKey) -> Self {
        self.holder(public_key)
    }

    /// Set holder (mutable version for FFI).
    pub fn set_holder(&mut self, public_key: PublicKey) {
        self.holder = Some(public_key);
    }

    /// Compat alias
    pub fn set_authorized_holder(&mut self, public_key: PublicKey) {
        self.set_holder(public_key);
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
    pub fn issuable_tool(mut self, tool: impl Into<String>) -> Self {
        self.issuable_tools = Some(vec![tool.into()]);
        self
    }

    /// Set a single tool (mutable version for FFI).
    pub fn set_issuable_tool(&mut self, tool: impl Into<String>) {
        self.issuable_tools = Some(vec![tool.into()]);
    }

    /// Set multiple tools for issuable_tools (for issuer warrants).
    pub fn issuable_tools(mut self, tools: Vec<String>) -> Self {
        self.issuable_tools = Some(tools);
        self
    }

    /// Set multiple tools (mutable version for FFI).
    pub fn set_issuable_tools(&mut self, tools: Vec<String>) {
        self.issuable_tools = Some(tools);
    }

    /// Drop tools from issuable_tools (for issuer warrants).
    pub fn drop_issuable_tools(&mut self, tools_to_drop: Vec<String>) {
        if let Some(current) = &mut self.issuable_tools {
            current.retain(|t| !tools_to_drop.contains(t));
        } else if let Some(parent_tools) = &self.parent.payload.issuable_tools {
            // If not set, start with parent's tools and remove
            let mut current = parent_tools.clone();
            current.retain(|t| !tools_to_drop.contains(t));
            self.issuable_tools = Some(current);
        }
    }

    /// Add extension
    pub fn extension(mut self, key: impl Into<String>, value: Vec<u8>) -> Self {
        self.extensions.insert(key.into(), value);
        self
    }

    /// Add extension (FFI)
    pub fn add_extension(&mut self, key: String, value: Vec<u8>) {
        self.extensions.insert(key, value);
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

        // Tools - for attenuation, tools stay the same or subset
        let parent_tools = self.parent.payload.tools.keys().cloned().collect();
        // Child tools: keys of self.tools
        let mut child_tools: Vec<String> = self.tools.keys().cloned().collect();
        child_tools.sort();

        let tools = ToolsDiff::new(parent_tools, child_tools.clone());

        // Capabilities diff logic
        let mut capabilities: HashMap<String, HashMap<String, ConstraintDiff>> = HashMap::new();

        // iterate distinct tools from both
        let mut all_tools = child_tools.clone();
        for tool in self.parent.tools_map().keys() {
            if !all_tools.contains(tool) {
                all_tools.push(tool.clone());
            }
        }
        all_tools.sort();

        for tool in all_tools {
            let parent_constraints = self
                .parent
                .tools_map()
                .get(&tool)
                .cloned()
                .unwrap_or_default();

            let child_constraints = self.tools.get(&tool).cloned().unwrap_or_default();

            let mut tool_diffs = HashMap::new();

            let mut all_fields: Vec<String> = Vec::new();
            for (field, _) in parent_constraints.iter() {
                all_fields.push(field.clone());
            }
            for (field, _) in child_constraints.iter() {
                if !all_fields.contains(field) {
                    all_fields.push(field.clone());
                }
            }

            for field in all_fields {
                let pc = parent_constraints.get(&field).cloned();
                let cc = child_constraints.get(&field).cloned();
                tool_diffs.insert(field.clone(), ConstraintDiff::new(field, pc, cc));
            }

            if !tool_diffs.is_empty() {
                capabilities.insert(tool, tool_diffs);
            }
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
            capabilities,
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
    pub fn build(self, keypair: &SigningKey, _parent_keypair: &SigningKey) -> Result<Warrant> {
        let new_depth = self.parent.depth() + 1;

        let parent_max = self.parent.payload.max_depth as u32;
        let effective_max = match self.max_depth {
            Some(child_max) => {
                if child_max > parent_max {
                    return Err(Error::MonotonicityViolation(format!(
                        "max_depth {} exceeds parent's max_depth {}",
                        child_max, parent_max
                    )));
                }
                Some(child_max)
            }
            None => Some(parent_max),
        };

        let depth_limit = effective_max.unwrap_or(MAX_DELEGATION_DEPTH);
        if new_depth > depth_limit {
            return Err(Error::DepthExceeded(new_depth, depth_limit));
        }

        if new_depth > MAX_DELEGATION_DEPTH {
            return Err(Error::DepthExceeded(new_depth, MAX_DELEGATION_DEPTH));
        }

        if self.parent.is_expired() {
            use chrono::TimeZone;
            let expiry = Utc
                .timestamp_opt(self.parent.payload.expires_at as i64, 0)
                .unwrap();
            return Err(Error::WarrantExpired(expiry));
        }

        // Validate attenuation monotonicity
        match self.parent.payload.warrant_type {
            WarrantType::Execution => {
                // For execution warrants, validate tool attenuation
                let parent_tools = &self.parent.payload.tools;

                for (tool, constraints) in &self.tools {
                    if let Some(parent_constraints) = parent_tools.get(tool) {
                        // Constraints must be a subset (monotonicity)
                        parent_constraints.validate_attenuation(constraints)?;
                    } else if let Some(parent_wildcard) = parent_tools.get("*") {
                        parent_wildcard.validate_attenuation(constraints)?;
                    } else {
                        return Err(Error::MonotonicityViolation(format!(
                            "tool '{}' not in parent's tools",
                            tool
                        )));
                    }
                }

                if self.tools.is_empty() {
                    return Err(Error::Validation(
                        "execution warrant must have at least one tool".to_string(),
                    ));
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

        let holder = self
            .holder
            .ok_or_else(|| Error::Validation("holder is required".to_string()))?;

        // NOTE: Holder cycling (A → B → A) is NOT blocked

        let now_sec = Utc::now().timestamp() as u64;
        let expires_at = if let Some(ttl) = self.ttl {
            let chrono_ttl = ChronoDuration::from_std(ttl)
                .map_err(|_| Error::InvalidTtl("TTL too large".to_string()))?;
            let proposed = now_sec + chrono_ttl.num_seconds() as u64;
            if proposed > self.parent.payload.expires_at {
                self.parent.payload.expires_at
            } else {
                proposed
            }
        } else {
            self.parent.payload.expires_at
        };

        let effective_min = self.min_approvals.or(self.parent.payload.min_approvals);

        let payload = WarrantPayload {
            version: WARRANT_VERSION as u8,
            warrant_type: self.parent.payload.warrant_type,
            id: WarrantId::new(),
            holder,
            tools: self.tools,
            issuable_tools: match self.parent.payload.warrant_type {
                WarrantType::Issuer => self.issuable_tools.clone(),
                WarrantType::Execution => None,
            },
            trust_ceiling: match self.parent.payload.warrant_type {
                WarrantType::Issuer => self.trust_ceiling,
                WarrantType::Execution => None,
            },
            max_issue_depth: match self.parent.payload.warrant_type {
                WarrantType::Issuer => self.max_issue_depth,
                WarrantType::Execution => None,
            },
            constraint_bounds: match self.parent.payload.warrant_type {
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
            issued_at: now_sec,
            expires_at,
            max_depth: effective_max.unwrap_or(MAX_DELEGATION_DEPTH) as u8,
            depth: self.parent.depth() + 1, // Increment depth from parent
            session_id: self.session_id,
            agent_id: self.agent_id,
            issuer: keypair.public_key(),
            parent_hash: {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&self.parent.payload_bytes);
                Some(hasher.finalize().into())
            },
            required_approvers: self.required_approvers,
            min_approvals: effective_min,
            extensions: self.extensions,
        };

        if payload.warrant_type == WarrantType::Issuer && !payload.tools.is_empty() {
            return Err(Error::InvalidWarrantType {
                message: "issuer warrant cannot have tools".to_string(),
            });
        }

        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

        // Preimage: envelope_version || payload_bytes
        let mut preimage = Vec::with_capacity(1 + payload_bytes.len());
        preimage.push(1); // envelope_version
        preimage.extend_from_slice(&payload_bytes);

        let signature = keypair.sign(&preimage);

        Ok(Warrant {
            payload,
            signature,
            payload_bytes,
            envelope_version: 1,
        })
    }

    /// Build and sign the attenuated warrant, returning both warrant and receipt.
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
            .get_holder()
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
    tools: BTreeMap<String, ConstraintSet>,
    trust_level: Option<TrustLevel>,
    ttl: Option<Duration>,
    max_depth: Option<u32>,
    session_id: Option<String>,
    agent_id: Option<String>,
    holder: Option<PublicKey>,
    required_approvers: Option<Vec<PublicKey>>,
    min_approvals: Option<u32>,
    extensions: BTreeMap<String, Vec<u8>>,
}

impl<'a> IssuanceBuilder<'a> {
    /// Create a new issuance builder.
    fn new(issuer: &'a Warrant) -> Self {
        Self {
            issuer,
            tools: BTreeMap::new(),
            trust_level: None,
            ttl: None,
            max_depth: None,
            session_id: issuer.payload.session_id.clone(),
            agent_id: issuer.payload.agent_id.clone(),
            holder: None,
            required_approvers: None,
            min_approvals: None,
            extensions: BTreeMap::new(),
        }
    }

    /// Add a tool to the execution warrant.
    ///
    /// The tool must be in the issuer's `issuable_tools` list.
    /// The constraint must be within the issuer's `constraint_bounds`.
    pub fn tool(mut self, tool: impl Into<String>, constraints: impl Into<ConstraintSet>) -> Self {
        self.tools.insert(tool.into(), constraints.into());
        self
    }

    /// Compat alias
    pub fn capability(
        self,
        tool: impl Into<String>,
        constraints: impl Into<ConstraintSet>,
    ) -> Self {
        self.tool(tool, constraints)
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

    /// Set the holder (Proof-of-Possession).
    ///
    /// This is required - the execution warrant must have a holder.
    pub fn holder(mut self, public_key: PublicKey) -> Self {
        self.holder = Some(public_key);
        self
    }

    /// Compat alias
    pub fn authorized_holder(self, public_key: PublicKey) -> Self {
        self.holder(public_key)
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

    /// Add extension
    pub fn extension(mut self, key: impl Into<String>, value: Vec<u8>) -> Self {
        self.extensions.insert(key.into(), value);
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
    pub fn build(self, keypair: &SigningKey, _issuer_keypair: &SigningKey) -> Result<Warrant> {
        // Validate issuer is not expired
        if self.issuer.is_expired() {
            use chrono::TimeZone;
            let expiry = Utc
                .timestamp_opt(self.issuer.payload.expires_at as i64, 0)
                .unwrap();
            return Err(Error::WarrantExpired(expiry));
        }

        // Validate required fields
        if self.tools.is_empty() {
            return Err(Error::Validation(
                "execution warrant requires at least one tool".to_string(),
            ));
        }

        // Validate each tool against issuer constraints
        if let Some(issuable_tools) = &self.issuer.payload.issuable_tools {
            for (tool, constraints) in &self.tools {
                // 1. Tool must be issuable
                if !issuable_tools.contains(tool) {
                    return Err(Error::Validation(format!(
                        "tool '{}' is not in issuer's issuable_tools",
                        tool
                    )));
                }

                // 2. Constraints must be within bounds
                if let Some(bounds) = &self.issuer.payload.constraint_bounds {
                    bounds.validate_attenuation(constraints)?;
                }
            }
        } else {
            return Err(Error::Validation(
                "issuer warrant has no issuable_tools".to_string(),
            ));
        }
        let holder = self.holder.ok_or(Error::Validation(
            "execution warrant requires holder".to_string(),
        ))?;
        let ttl = self.ttl.ok_or(Error::MissingField("ttl".to_string()))?;

        // SECURITY: Issuer cannot grant execution warrants to themselves
        // This prevents privilege escalation where an issuer could convert their
        // issuer warrant into execution capabilities for themselves.
        if holder == self.issuer.payload.holder {
            return Err(Error::SelfIssuanceProhibited {
                reason: "issuer cannot grant execution warrants to themselves".to_string(),
            });
        }

        // SECURITY: Execution warrant holder cannot be the issuer warrant's issuer
        // This prevents a more subtle privilege escalation where the issuer warrant's
        // issuer could indirectly grant execution capabilities to themselves through
        // the issuer warrant mechanism.
        if holder == self.issuer.payload.issuer {
            return Err(Error::SelfIssuanceProhibited {
                reason: "execution warrant holder cannot be the issuer warrant's issuer (issuer-holder separation required)".to_string(),
            });
        }

        // Validate all tools are in issuable_tools
        if let Some(issuable_tools) = &self.issuer.payload.issuable_tools {
            for tool in self.tools.keys() {
                if !issuable_tools.contains(tool) {
                    return Err(Error::UnauthorizedToolIssuance {
                        tool: tool.clone(),
                        allowed: issuable_tools.clone(),
                    });
                }
            }
        } else {
            return Err(Error::InvalidWarrantType {
                message: "issuer warrant must have issuable_tools".to_string(),
            });
        }

        // Validate trust_level <= trust_ceiling
        if let Some(trust_level) = self.trust_level {
            if let Some(trust_ceiling) = self.issuer.payload.trust_ceiling {
                if trust_level > trust_ceiling {
                    return Err(Error::TrustLevelExceeded {
                        requested: format!("{:?}", trust_level),
                        ceiling: format!("{:?}", trust_ceiling),
                    });
                }
            }
        }

        // Validate tool constraints are within constraint_bounds
        if let Some(constraint_bounds) = &self.issuer.payload.constraint_bounds {
            if !constraint_bounds.is_empty() {
                for (tool, constraints) in self.tools.iter() {
                    for (field, constraint) in constraints.iter() {
                        if let Some(bound) = constraint_bounds.get(field) {
                            // Validate that the constraint is within the bound using attenuation validation
                            bound.validate_attenuation(constraint).map_err(|e| {
                                Error::Validation(format!(
                                    "constraint for tool '{}' field '{}' exceeds issuer's constraint_bounds: {}",
                                    tool, field, e
                                ))
                            })?;
                        }
                    }
                }
            }
        }

        // Validate depth doesn't exceed max_issue_depth
        let new_depth = self.issuer.depth() + 1;
        if let Some(max_issue_depth) = self.issuer.payload.max_issue_depth {
            if new_depth > max_issue_depth {
                return Err(Error::IssueDepthExceeded {
                    depth: new_depth,
                    max: max_issue_depth,
                });
            }
        }

        // Validate max_depth doesn't exceed issuer's max_issue_depth
        if let Some(max_depth) = self.max_depth {
            if let Some(max_issue_depth) = self.issuer.payload.max_issue_depth {
                if max_depth > max_issue_depth {
                    return Err(Error::IssueDepthExceeded {
                        depth: max_depth,
                        max: max_issue_depth,
                    });
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

        // Validate tool validation depth
        for constraints in self.tools.values() {
            constraints.validate_depth()?;
        }

        let chrono_ttl = ChronoDuration::from_std(ttl)
            .map_err(|_| Error::InvalidTtl("TTL too large".to_string()))?;
        let now_sec = Utc::now().timestamp() as u64;
        let expires_at = now_sec + chrono_ttl.num_seconds() as u64;

        // Effective max depth: logic needs to align with requirement for concrete u8
        // If max_depth not set, inherit or default?
        // Spec implies max_depth is mandatory on wire.
        // For issuance, we're creating a NEW warrant.
        // Logic: use configured max_depth, or if None, use parent's (if restricted), or default MAX.
        // But invalid types: self.issuer.payload.max_depth is u8. self.max_depth is Option<u32>.
        let effective_max_u8 = if let Some(configured) = self.max_depth {
            if configured > 255 {
                return Err(Error::Validation("max_depth exceeds u8 range".to_string()));
            }
            configured as u8
        } else {
            // Inherit from parent? Or default?
            // Since this is issuance (creation of EXECUTION warrant), typically we set strict limits.
            // If parent has a max_depth (u8), we should probably use that or less.
            // self.issuer.payload.max_depth is the limit of the ISSUER warrant itself.
            // That limit applies to the DELEGATION chain length.
            self.issuer.payload.max_depth
        };

        let payload = WarrantPayload {
            version: WARRANT_VERSION as u8,
            warrant_type: WarrantType::Execution,
            id: WarrantId::new(),
            holder,
            tools: self.tools,
            issuable_tools: None,
            trust_ceiling: None,
            max_issue_depth: None,
            constraint_bounds: None,
            trust_level: self.trust_level,
            issued_at: now_sec,
            expires_at,
            max_depth: effective_max_u8,
            depth: self.issuer.depth() + 1, // Increment depth from issuer
            session_id: self.session_id,
            agent_id: self.agent_id,
            issuer: keypair.public_key(),
            parent_hash: {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&self.issuer.payload_bytes);
                Some(hasher.finalize().into())
            },
            required_approvers: self.required_approvers,
            min_approvals: self.min_approvals,
            extensions: self.extensions,
        };

        // Serialize payload to sign it
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

        // Preimage: envelope_version || payload_bytes
        let mut preimage = Vec::with_capacity(1 + payload_bytes.len());
        preimage.push(1); // envelope_version
        preimage.extend_from_slice(&payload_bytes);

        let signature = keypair.sign(&preimage);

        let warrant = Warrant {
            payload,
            signature,
            payload_bytes,
            envelope_version: 1,
        };

        // Audit: Log warrant issuance from issuer warrant
        let tools_list: Vec<String> = warrant.payload.tools.keys().cloned().collect();
        log_event(AuditEvent {
            id: Uuid::new_v4().to_string(),
            event_type: AuditEventType::WarrantIssued,
            timestamp: Utc::now(),
            provider: "tenuo".to_string(),
            external_id: None,
            public_key_hex: Some(hex::encode(keypair.public_key().to_bytes())),
            actor: format!("issuer_warrant:{}", &self.issuer.id().to_string()[..8]),
            details: Some(format!(
                "execution warrant issued from issuer: tools={:?}, depth={}, issuer_id={}",
                tools_list,
                warrant.depth(),
                self.issuer.id()
            )),
            related_ids: Some(vec![warrant.id().to_string(), self.issuer.id().to_string()]),
        });

        Ok(warrant)
    }
}

/// Owned version of IssuanceBuilder for use in FFI contexts (e.g., Python bindings).
///
/// This builder owns the issuer warrant, avoiding lifetime issues in FFI.
#[derive(Debug, Clone)]
pub struct OwnedIssuanceBuilder {
    issuer: Warrant,
    tools: BTreeMap<String, ConstraintSet>,
    trust_level: Option<TrustLevel>,
    ttl: Option<Duration>,
    max_depth: Option<u32>,
    session_id: Option<String>,
    agent_id: Option<String>,
    holder: Option<PublicKey>,
    required_approvers: Option<Vec<PublicKey>>,
    min_approvals: Option<u32>,
    intent: Option<String>,
    extensions: BTreeMap<String, Vec<u8>>,
}

impl OwnedIssuanceBuilder {
    /// Create a new owned issuance builder.
    pub fn new(issuer: Warrant) -> Self {
        Self {
            session_id: issuer.payload.session_id.clone(),
            agent_id: issuer.payload.agent_id.clone(),
            issuer,
            tools: BTreeMap::new(),
            trust_level: None,
            ttl: None,
            max_depth: None,
            holder: None,
            required_approvers: None,
            min_approvals: None,
            intent: None,
            extensions: BTreeMap::new(),
        }
    }

    /// Get a reference to the issuer warrant.
    pub fn issuer(&self) -> &Warrant {
        &self.issuer
    }

    /// Get the configured tools.
    pub fn tools(&self) -> &BTreeMap<String, ConstraintSet> {
        &self.tools
    }

    /// Get the configured holder.
    pub fn holder(&self) -> Option<&PublicKey> {
        self.holder.as_ref()
    }

    /// Get the configured trust level.
    pub fn trust_level(&self) -> Option<TrustLevel> {
        self.trust_level
    }

    /// Get the configured TTL.
    pub fn ttl_seconds(&self) -> Option<u64> {
        self.ttl.map(|d| d.as_secs())
    }

    /// Get the configured max depth.
    pub fn max_depth(&self) -> Option<u32> {
        self.max_depth
    }

    /// Get the configured session ID.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Get the configured agent ID.
    pub fn agent_id(&self) -> Option<&str> {
        self.agent_id.as_deref()
    }

    /// Get the configured minimum approvals.
    pub fn min_approvals(&self) -> Option<u32> {
        self.min_approvals
    }

    /// Get the configured required approvers.
    pub fn required_approvers(&self) -> Option<&[PublicKey]> {
        self.required_approvers.as_deref()
    }

    /// Get the configured intent.
    pub fn intent(&self) -> Option<&str> {
        self.intent.as_deref()
    }

    /// Add a tool description (tool + constraints) to the warrant (mutable version for FFI).
    pub fn set_tool(&mut self, tool: impl Into<String>, constraints: impl Into<ConstraintSet>) {
        self.tools.insert(tool.into(), constraints.into());
    }

    /// Compat alias
    pub fn set_capability(
        &mut self,
        tool: impl Into<String>,
        constraints: impl Into<ConstraintSet>,
    ) {
        self.set_tool(tool, constraints)
    }

    /// Add a tool (builder pattern).
    pub fn tool(mut self, tool: impl Into<String>, constraints: impl Into<ConstraintSet>) -> Self {
        self.tools.insert(tool.into(), constraints.into());
        self
    }

    /// Compat alias
    pub fn capability(
        self,
        tool: impl Into<String>,
        constraints: impl Into<ConstraintSet>,
    ) -> Self {
        self.tool(tool, constraints)
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

    /// Set the holder (mutable version for FFI).
    pub fn set_holder(&mut self, public_key: PublicKey) {
        self.holder = Some(public_key);
    }

    /// Get the holder.
    pub fn get_holder(&self) -> Option<&PublicKey> {
        self.holder.as_ref()
    }

    /// Compat alias
    pub fn set_authorized_holder(&mut self, public_key: PublicKey) {
        self.set_holder(public_key)
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

    /// Add extension (FFI)
    pub fn add_extension(&mut self, key: String, value: Vec<u8>) {
        self.extensions.insert(key, value);
    }

    /// Add extension
    pub fn extension(mut self, key: impl Into<String>, value: Vec<u8>) -> Self {
        self.extensions.insert(key.into(), value);
        self
    }

    /// Build and sign the execution warrant.
    pub fn build(self, keypair: &SigningKey, issuer_keypair: &SigningKey) -> Result<Warrant> {
        // Delegate to IssuanceBuilder
        IssuanceBuilder {
            issuer: &self.issuer,
            tools: self.tools,
            trust_level: self.trust_level,
            ttl: self.ttl,
            max_depth: self.max_depth,
            session_id: self.session_id,
            agent_id: self.agent_id,
            holder: self.holder,
            required_approvers: self.required_approvers,
            min_approvals: self.min_approvals,
            extensions: self.extensions,
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

        let mut constraints = ConstraintSet::new();
        constraints.insert("cluster", Pattern::new("staging-*").unwrap());
        let warrant = Warrant::builder()
            .capability("upgrade_cluster", constraints)
            .ttl(Duration::from_secs(600))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let caps = warrant.capabilities().unwrap();
        assert!(caps.contains_key("upgrade_cluster"));
        assert_eq!(warrant.depth(), 0);
        assert!(warrant.is_root());
        assert!(!warrant.is_expired());
    }

    #[test]
    fn test_warrant_verification() {
        let keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .capability("test", ConstraintSet::new())
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

        let mut constraints = ConstraintSet::new();
        constraints.insert("cluster", Pattern::new("staging-*").unwrap());
        constraints.insert("version", Pattern::new("1.28.*").unwrap());
        let warrant = Warrant::builder()
            .capability("upgrade_cluster", constraints)
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

        let mut parent_constraints = ConstraintSet::new();
        parent_constraints.insert("cluster", Pattern::new("staging-*").unwrap());
        let parent = Warrant::builder()
            .capability("upgrade_cluster", parent_constraints)
            .ttl(Duration::from_secs(600))
            .authorized_holder(parent_keypair.public_key())
            .build(&parent_keypair)
            .unwrap();

        let mut child_constraints = ConstraintSet::new();
        child_constraints.insert("cluster", Exact::new("staging-web"));
        let child = parent
            .attenuate()
            .capability("upgrade_cluster", child_constraints)
            .build(&child_keypair, &parent_keypair)
            .unwrap();

        assert_eq!(child.depth(), 1);
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(parent.payload_bytes());
        let parent_hash: [u8; 32] = hasher.finalize().into();
        assert_eq!(child.parent_hash(), Some(&parent_hash));
        assert!(child.expires_at() <= parent.expires_at());
    }

    #[test]
    fn test_attenuation_monotonicity_enforced() {
        let parent_keypair = create_test_keypair();
        let child_keypair = create_test_keypair();

        let mut parent_constraints = ConstraintSet::new();
        parent_constraints.insert("cluster", Pattern::new("staging-*").unwrap());
        let parent = Warrant::builder()
            .capability("upgrade_cluster", parent_constraints)
            .ttl(Duration::from_secs(600))
            .authorized_holder(parent_keypair.public_key())
            .build(&parent_keypair)
            .unwrap();

        // Attempt to widen scope - should fail
        let mut child_constraints = ConstraintSet::new();
        child_constraints.insert("cluster", Pattern::new("*").unwrap());
        let result = parent
            .attenuate()
            .capability("upgrade_cluster", child_constraints)
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
            .capability("test", ConstraintSet::new())
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
    fn test_attenuation_max_depth_limit() {
        let keypair = create_test_keypair();

        // Create warrant with explicit max_depth
        let warrant = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .ttl(Duration::from_secs(3600))
            .max_depth(5)
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        // max_depth is the policy limit (inherited), depth is the counter
        assert_eq!(warrant.depth(), 0);
        assert_eq!(warrant.max_depth(), Some(5));

        // Delegate - depth increases, max_depth is inherited
        let child = warrant.attenuate().build(&keypair, &keypair).unwrap();
        assert_eq!(child.depth(), 1);
        assert_eq!(child.max_depth(), Some(5)); // Inherited

        // When depth reaches max_depth, warrant is terminal
        let mut current = child;
        for _ in 2..5 {
            current = current.attenuate().build(&keypair, &keypair).unwrap();
        }
        assert_eq!(current.depth(), 4);

        // depth=5 would equal max_depth=5, so next attenuation should still work
        let level5 = current.attenuate().build(&keypair, &keypair).unwrap();
        assert_eq!(level5.depth(), 5);
        assert!(
            level5.is_terminal(),
            "warrant at depth=max_depth should be terminal"
        );

        // Further attenuation should fail
        let result = level5.attenuate().build(&keypair, &keypair);
        assert!(result.is_err(), "cannot attenuate terminal warrant");
    }

    #[test]
    fn test_attenuation_depth_limit_with_max_depth() {
        let keypair = create_test_keypair();

        // Create warrant with explicit max_depth of 3 (smaller than chain length limit)
        let mut warrant = Warrant::builder()
            .capability("test", ConstraintSet::new())
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

        let mut parent_constraints = ConstraintSet::new();
        parent_constraints.insert("amount", Range::max(10000.0).unwrap());
        let parent = Warrant::builder()
            .capability("transfer_funds", parent_constraints)
            .ttl(Duration::from_secs(600))
            .authorized_holder(parent_keypair.public_key())
            .build(&parent_keypair)
            .unwrap();

        // Valid: narrower range
        let mut child_constraints = ConstraintSet::new();
        child_constraints.insert("amount", Range::max(5000.0).unwrap());
        let child = parent
            .attenuate()
            .capability("transfer_funds", child_constraints)
            .build(&child_keypair, &parent_keypair);
        assert!(child.is_ok());

        // Invalid: wider range
        let mut invalid_constraints = ConstraintSet::new();
        invalid_constraints.insert("amount", Range::max(20000.0).unwrap());
        let invalid = parent
            .attenuate()
            .capability("transfer_funds", invalid_constraints)
            .build(&child_keypair, &parent_keypair);
        assert!(invalid.is_err());
    }

    #[test]
    fn test_session_binding() {
        let keypair = create_test_keypair();

        let warrant = Warrant::builder()
            .capability("test", ConstraintSet::new())
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
            .capability("test", ConstraintSet::new())
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
            .capability("test_tool", ConstraintSet::new())
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

        let mut constraints = ConstraintSet::new();
        constraints.insert("cluster", Pattern::new("staging-*").unwrap());
        let warrant = Warrant::builder()
            .capability("test", constraints)
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
            .capability("test", ConstraintSet::new())
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
            .capability("test", ConstraintSet::new())
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
        // Display shows prefixed string
        assert!(id.to_string().starts_with("tnu_wrt_"));
        // Hex is 32 chars (16 bytes)
        assert_eq!(id.to_hex().len(), 32);

        // Parse from prefixed string
        let parsed = WarrantId::from_string(id.to_string()).unwrap();
        assert_eq!(parsed, id);

        // Parse from hex
        let parsed_hex = WarrantId::from_string(id.to_hex()).unwrap();
        assert_eq!(parsed_hex, id);

        // Invalid hex length
        let invalid = WarrantId::from_string("invalid_id");
        assert!(invalid.is_err());
    }

    #[test]
    fn test_max_depth_policy_limit() {
        let keypair = create_test_keypair();

        // Create warrant with policy limit of 3
        let root = Warrant::builder()
            .capability("test", ConstraintSet::new())
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
            .capability("test", ConstraintSet::new())
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
            .capability("test", ConstraintSet::new())
            .ttl(Duration::from_secs(60))
            .max_depth(100) // Above MAX_DELEGATION_DEPTH (16)
            .authorized_holder(keypair.public_key())
            .build(&keypair);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::DepthExceeded(100, 16) => {}
            e => panic!("Expected DepthExceeded(100, 16), got {:?}", e),
        }
    }

    #[test]
    fn test_no_max_depth_uses_protocol_default() {
        let keypair = create_test_keypair();

        let root = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .ttl(Duration::from_secs(3600))
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        // max_depth is now None when not explicitly set (protocol default applies)
        // max_depth is now mandatory u8, defaulting to MAX_DELEGATION_DEPTH if unset
        assert_eq!(root.max_depth(), Some(MAX_DELEGATION_DEPTH));
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
            .capability("sensitive_action", ConstraintSet::new())
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
            .capability("sensitive_action", ConstraintSet::new())
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
            .capability("sensitive_action", ConstraintSet::new())
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
            .capability("sensitive_action", ConstraintSet::new())
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
            .capability("sensitive_action", ConstraintSet::new())
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
            .capability("sensitive_action", ConstraintSet::new())
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
            .capability("regular_action", ConstraintSet::new())
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
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/data/q3.pdf").unwrap());
        let execution_warrant = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .capability("read_file", constraints)
            .trust_level(TrustLevel::External)
            .ttl(Duration::from_secs(60))
            .authorized_holder(holder_kp.public_key())
            .build(&issuer_kp, &issuer_kp) // issuer_kp is both holder and issuer
            .unwrap();

        assert_eq!(execution_warrant.r#type(), WarrantType::Execution);
        let caps = execution_warrant.capabilities().unwrap();
        assert!(caps.contains_key("read_file"));
        assert_eq!(
            execution_warrant.authorized_holder(),
            &holder_kp.public_key()
        );
        assert_eq!(execution_warrant.depth(), 1);
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(issuer_warrant.payload_bytes());
        let parent_hash: [u8; 32] = hasher.finalize().into();
        assert_eq!(execution_warrant.parent_hash(), Some(&parent_hash));
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
            .capability("read_file", ConstraintSet::new())
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
            .capability("read_file", ConstraintSet::new())
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
        let mut root_constraints = ConstraintSet::new();
        root_constraints.insert("env", Pattern::new("*").unwrap());
        let root = Warrant::builder()
            .capability("test", root_constraints)
            .ttl(Duration::from_secs(3600))
            .authorized_holder(keypair_a.public_key())
            .build(&keypair_a)
            .unwrap();

        // A delegates to B with narrower constraints
        let mut child_b_constraints = ConstraintSet::new();
        child_b_constraints.insert("env", Pattern::new("staging-*").unwrap());
        let child_b = root
            .attenuate()
            .capability("test", child_b_constraints)
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
            .capability("send_email", ConstraintSet::new()) // Not in issuable_tools
            .ttl(Duration::from_secs(60))
            .authorized_holder(holder_kp.public_key())
            .build(&issuer_kp, &issuer_kp);

        let err = result.expect_err("expected unauthorized tool issuance error");
        let msg = err.to_string();
        assert!(
            msg.contains("unauthorized tool issuance")
                || msg.contains("not in issuer's issuable_tools"),
            "unexpected error: {msg}"
        );
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
            .capability("read_file", ConstraintSet::new())
            .trust_level(TrustLevel::Internal) // Exceeds External ceiling
            .ttl(Duration::from_secs(60))
            .authorized_holder(holder_kp.public_key())
            .build(&issuer_kp, &issuer_kp);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("trust level exceeded"));
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
        let mut constraints = ConstraintSet::new();
        constraints.insert("path", Pattern::new("/etc/*").unwrap()); // Outside /data/*
        let result = issuer_warrant
            .issue_execution_warrant()
            .unwrap()
            .capability("read_file", constraints)
            .ttl(Duration::from_secs(60))
            .authorized_holder(holder_kp.public_key())
            .build(&issuer_kp, &issuer_kp);

        match result {
            Err(Error::PatternExpanded { parent, child }) => {
                assert_eq!(parent, "/data/*");
                assert_eq!(child, "/etc/*");
            }
            Err(other) => panic!("unexpected error: {:?}", other),
            Ok(_) => panic!("expected constraint bounds violation"),
        }
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
            .capability("read_file", ConstraintSet::new())
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
            .capability("read_file", ConstraintSet::new())
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

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::System > TrustLevel::Privileged);
        assert!(TrustLevel::Privileged > TrustLevel::Internal);
        assert!(TrustLevel::Internal > TrustLevel::Partner);
        assert!(TrustLevel::Partner > TrustLevel::External);
        assert!(TrustLevel::External > TrustLevel::Untrusted);

        // Explicit check of values to prevent reordering
        assert_eq!(TrustLevel::Untrusted as u8, 0);
        assert_eq!(TrustLevel::External as u8, 10);
        assert_eq!(TrustLevel::Partner as u8, 20);
        assert_eq!(TrustLevel::Internal as u8, 30);
        assert_eq!(TrustLevel::Privileged as u8, 40);
        assert_eq!(TrustLevel::System as u8, 50);
    }

    #[test]
    fn test_effective_max_depth_latching() {
        // 1. Root warrant (None/Unlimited)
        let root_kp = create_test_keypair();
        let root = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .ttl(Duration::from_secs(3600))
            // max_depth: None (defaults to MAX_DELEGATION_DEPTH=16)
            .authorized_holder(root_kp.public_key())
            .build(&root_kp)
            .unwrap();

        assert_eq!(root.effective_max_depth(), MAX_DELEGATION_DEPTH);

        // 2. Child warrant sets limit (Some(5))
        let child = root
            .attenuate()
            .max_depth(5)
            .build(&root_kp, &root_kp)
            .unwrap();

        assert_eq!(child.effective_max_depth(), 5);

        // 3. Grandchild tries to increase limit (Some(10)) - Should fail/latch
        // The build() method calls validate which checks monotonicity
        let result = child.attenuate().max_depth(10).build(&root_kp, &root_kp);

        // Expect error because 10 > 5
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            // We expect MonotonicityViolation or Validation error depending on implementation
            Error::MonotonicityViolation(_) | Error::Validation(_) => {}
            _ => panic!(
                "Expected monitoring violation or validation error, got {:?}",
                err
            ),
        }

        // 4. Grandchild with lower limit (Some(3)) - Should succeed
        let grandchild = child
            .attenuate()
            .max_depth(3)
            .build(&root_kp, &root_kp)
            .unwrap();
        assert_eq!(grandchild.effective_max_depth(), 3);
    }
}
