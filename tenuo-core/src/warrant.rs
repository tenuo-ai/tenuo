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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

/// A unique identifier for a warrant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WarrantId(String);

impl WarrantId {
    /// Generate a new random warrant ID.
    pub fn new() -> Self {
        Self(format!("tnu_wrt_{}", Uuid::new_v4().simple()))
    }

    /// Create a warrant ID from a string.
    pub fn from_string(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if !s.starts_with("tnu_wrt_") {
            return Err(Error::InvalidWarrantId(
                "warrant ID must start with 'tnu_wrt_'".to_string(),
            ));
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
    /// Parent warrant ID (None for root warrants).
    pub parent_id: Option<WarrantId>,
    /// Session ID for session binding.
    pub session_id: Option<String>,
    /// Public key of the issuer.
    pub issuer: PublicKey,
}

/// A signed warrant - the complete token of authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Get the expiration time.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.payload.expires_at
    }

    /// Get the delegation depth.
    pub fn depth(&self) -> u32 {
        self.payload.depth
    }

    /// Get the parent warrant ID.
    pub fn parent_id(&self) -> Option<&WarrantId> {
        self.payload.parent_id.as_ref()
    }

    /// Get the session ID.
    pub fn session_id(&self) -> Option<&str> {
        self.payload.session_id.as_deref()
    }

    /// Get the issuer's public key.
    pub fn issuer(&self) -> &PublicKey {
        &self.payload.issuer
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
    pub fn authorize(&self, tool: &str, args: &HashMap<String, ConstraintValue>) -> Result<()> {
        // Check expiration
        if self.is_expired() {
            return Err(Error::WarrantExpired(self.payload.expires_at));
        }

        // Check tool name
        if self.payload.tool != tool {
            return Err(Error::ConstraintNotSatisfied {
                field: "tool".to_string(),
                reason: format!(
                    "warrant is for tool '{}', not '{}'",
                    self.payload.tool, tool
                ),
            });
        }

        // Check constraints
        self.payload.constraints.matches(args)
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
    session_id: Option<String>,
}

impl WarrantBuilder {
    /// Create a new warrant builder.
    pub fn new() -> Self {
        Self {
            tool: None,
            constraints: ConstraintSet::new(),
            ttl: None,
            session_id: None,
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

    /// Set the session ID.
    pub fn session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Build and sign the warrant.
    pub fn build(self, keypair: &Keypair) -> Result<Warrant> {
        let tool = self.tool.ok_or(Error::MissingField("tool".to_string()))?;
        let ttl = self.ttl.ok_or(Error::MissingField("ttl".to_string()))?;

        let expires_at = Utc::now() + ChronoDuration::from_std(ttl).unwrap();

        let payload = WarrantPayload {
            id: WarrantId::new(),
            tool,
            constraints: self.constraints,
            expires_at,
            depth: 0,
            parent_id: None,
            session_id: self.session_id,
            issuer: keypair.public_key(),
        };

        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)?;
        let signature = keypair.sign(&payload_bytes);

        Ok(Warrant { payload, signature, payload_bytes })
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
    constraints: ConstraintSet,
    ttl: Option<Duration>,
    session_id: Option<String>,
}

impl<'a> AttenuationBuilder<'a> {
    /// Create a new attenuation builder.
    fn new(parent: &'a Warrant) -> Self {
        Self {
            parent,
            constraints: parent.payload.constraints.clone(),
            ttl: None,
            session_id: parent.payload.session_id.clone(),
        }
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

    /// Set or change the session ID.
    pub fn session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Build and sign the attenuated warrant.
    pub fn build(self, keypair: &Keypair) -> Result<Warrant> {
        // Check depth limit
        let new_depth = self.parent.payload.depth + 1;
        if new_depth > MAX_DELEGATION_DEPTH {
            return Err(Error::DepthExceeded(new_depth, MAX_DELEGATION_DEPTH));
        }

        // Check parent is not expired
        if self.parent.is_expired() {
            return Err(Error::WarrantExpired(self.parent.payload.expires_at));
        }

        // Validate attenuation monotonicity
        self.parent.payload.constraints.validate_attenuation(&self.constraints)?;

        // Calculate expiration (must not exceed parent)
        let expires_at = if let Some(ttl) = self.ttl {
            let proposed = Utc::now() + ChronoDuration::from_std(ttl).unwrap();
            if proposed > self.parent.payload.expires_at {
                self.parent.payload.expires_at
            } else {
                proposed
            }
        } else {
            self.parent.payload.expires_at
        };

        let payload = WarrantPayload {
            id: WarrantId::new(),
            tool: self.parent.payload.tool.clone(),
            constraints: self.constraints,
            expires_at,
            depth: new_depth,
            parent_id: Some(self.parent.payload.id.clone()),
            session_id: self.session_id,
            issuer: keypair.public_key(),
        };

        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)?;
        let signature = keypair.sign(&payload_bytes);

        Ok(Warrant { payload, signature, payload_bytes })
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

        assert!(warrant.authorize("upgrade_cluster", &args).is_ok());

        // Wrong tool
        assert!(warrant.authorize("delete_cluster", &args).is_err());

        // Wrong cluster
        args.insert("cluster".to_string(), ConstraintValue::String("prod-web".to_string()));
        assert!(warrant.authorize("upgrade_cluster", &args).is_err());
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
            Error::MonotonicityViolation(_) => {}
            e => panic!("Expected MonotonicityViolation, got {:?}", e),
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
}

