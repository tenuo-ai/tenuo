//! Revocation System
//!
//! This module provides:
//! - **RevocationRequest**: Signed requests to revoke warrants
//! - **SignedRevocationList (SRL)**: Cryptographically signed lists of revoked warrant IDs
//!
//! ## Revocation Flow
//!
//! ```text
//! [Requestor] --signs--> [RevocationRequest] --submits--> [Control Plane]
//!                                                              |
//!                                                              v
//!                                                    [Validates authority]
//!                                                              |
//!                                                              v
//!                                                    [Builds & signs SRL]
//!                                                              |
//!                                                              v
//!                                                    [Distributes to Authorizers]
//! ```
//!
//! ## Who Can Revoke
//!
//! | Requestor | Can Revoke | Proof Required |
//! |-----------|------------|----------------|
//! | Control Plane | Any warrant | Control Plane signature |
//! | Issuer | Warrants they issued | Issuer signature |
//! | Holder | Their own warrant (surrender) | Holder signature |
//!
//! ## Example: Revocation Request
//!
//! ```rust,ignore
//! // Agent requests revocation of their own warrant (surrender)
//! let request = RevocationRequest::new(
//!     warrant.id().clone(),
//!     "Key compromise detected",
//!     &agent_keypair,
//! );
//!
//! // Control Plane validates and includes in next SRL
//! if control_plane.validate_revocation_request(&request, &warrant)? {
//!     pending_revocations.push(request);
//! }
//! ```

use crate::crypto::{Keypair, PublicKey, Signature};
use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ============================================================================
// Revocation Request
// ============================================================================

/// Maximum age for revocation requests (prevents replay attacks).
/// Requests older than this are rejected.
pub const MAX_REVOCATION_REQUEST_AGE_SECS: i64 = 300; // 5 minutes

/// A signed request to revoke a warrant.
///
/// Authorized parties can submit revocation requests to the Control Plane:
/// - **Control Plane**: Can revoke any warrant
/// - **Issuer**: Can revoke warrants they issued (and cascades to children)
/// - **Holder**: Can surrender their own warrant
///
/// ## Security
///
/// The Control Plane MUST call `validate()` which:
/// 1. Verifies the requestor's signature
/// 2. Checks the warrant actually exists (prevents DoS with fake IDs)
/// 3. Validates the requestor is authorized (issuer, holder, or control plane)
/// 4. Rejects stale requests (replay protection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// The warrant ID to revoke
    pub warrant_id: String,
    /// Human-readable reason for revocation
    pub reason: String,
    /// Public key of the requestor
    pub requestor: PublicKey,
    /// When the request was created
    pub requested_at: DateTime<Utc>,
    /// Signature over (warrant_id, reason, requestor, requested_at)
    signature: Signature,
}

impl RevocationRequest {
    /// Create a new revocation request.
    ///
    /// The requestor signs the request to prove they authorize the revocation.
    pub fn new(
        warrant_id: impl Into<String>,
        reason: impl Into<String>,
        requestor_keypair: &Keypair,
    ) -> Result<Self> {
        let warrant_id = warrant_id.into();
        let reason = reason.into();
        let requested_at = Utc::now();
        let requestor = requestor_keypair.public_key();

        // Sign the request
        let payload = (&warrant_id, &reason, &requestor, requested_at.timestamp());
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        let signature = requestor_keypair.sign(&payload_bytes);

        Ok(Self {
            warrant_id,
            reason,
            requestor,
            requested_at,
            signature,
        })
    }

    /// Verify the request signature only.
    ///
    /// **Note**: For full validation including authorization and replay protection,
    /// use `validate()` instead.
    pub fn verify_signature(&self) -> Result<()> {
        let payload = (
            &self.warrant_id,
            &self.reason,
            &self.requestor,
            self.requested_at.timestamp(),
        );
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

        self.requestor
            .verify(&payload_bytes, &self.signature)
            .map_err(|_| Error::SignatureInvalid("Revocation request signature invalid".into()))
    }

    /// Fully validate a revocation request.
    ///
    /// This is the main validation entry point. It checks:
    /// 1. **Signature**: Request is signed by the claimed requestor
    /// 2. **Warrant exists**: The warrant_id matches the provided warrant
    /// 3. **Authorization**: Requestor is allowed to revoke (issuer, holder, or CP)
    /// 4. **Freshness**: Request is not too old (prevents replay attacks)
    /// 5. **Not expired**: Warrant hasn't already expired (no point revoking)
    ///
    /// # Arguments
    /// * `warrant_issuer` - The public key that issued the warrant
    /// * `warrant_holder` - The authorized holder of the warrant (if any)
    /// * `warrant_expires_at` - When the warrant expires
    /// * `control_plane_key` - The Control Plane's public key
    ///
    /// # Returns
    /// `Ok(())` if the request is valid and should be processed.
    pub fn validate(
        &self,
        warrant_id: &str,
        warrant_issuer: &PublicKey,
        warrant_holder: Option<&PublicKey>,
        warrant_expires_at: DateTime<Utc>,
        control_plane_key: &PublicKey,
    ) -> Result<()> {
        // 1. Verify signature
        self.verify_signature()?;

        // 2. Verify warrant ID matches (proves warrant exists)
        if self.warrant_id != warrant_id {
            return Err(Error::Unauthorized(format!(
                "Request warrant_id '{}' does not match provided warrant '{}'",
                self.warrant_id, warrant_id
            )));
        }

        // 3. Check authorization
        if !self.is_authorized(warrant_issuer, warrant_holder, control_plane_key) {
            return Err(Error::Unauthorized(format!(
                "Requestor {} is not authorized to revoke this warrant",
                hex::encode(self.requestor.to_bytes())
            )));
        }

        // 4. Check request freshness (replay protection)
        let age = Utc::now().signed_duration_since(self.requested_at);
        if age.num_seconds() > MAX_REVOCATION_REQUEST_AGE_SECS {
            return Err(Error::Unauthorized(format!(
                "Revocation request is too old ({} seconds, max {})",
                age.num_seconds(),
                MAX_REVOCATION_REQUEST_AGE_SECS
            )));
        }
        if age.num_seconds() < -60 {
            // Request from the future (clock skew tolerance: 1 minute)
            return Err(Error::Unauthorized(
                "Revocation request timestamp is in the future".into(),
            ));
        }

        // 5. Check warrant hasn't already expired
        if warrant_expires_at < Utc::now() {
            return Err(Error::Unauthorized(
                "Warrant has already expired; revocation unnecessary".into(),
            ));
        }

        Ok(())
    }

    /// Check if the requestor is authorized to revoke this warrant.
    ///
    /// # Arguments
    /// * `warrant_issuer` - The public key that issued the warrant
    /// * `warrant_holder` - The authorized holder of the warrant (if any)
    /// * `control_plane_key` - The Control Plane's public key
    ///
    /// # Returns
    /// `true` if the requestor is authorized to revoke.
    pub fn is_authorized(
        &self,
        warrant_issuer: &PublicKey,
        warrant_holder: Option<&PublicKey>,
        control_plane_key: &PublicKey,
    ) -> bool {
        // Control Plane can revoke anything
        if &self.requestor == control_plane_key {
            return true;
        }

        // Issuer can revoke warrants they issued
        if &self.requestor == warrant_issuer {
            return true;
        }

        // Holder can surrender their own warrant
        if let Some(holder) = warrant_holder {
            if &self.requestor == holder {
                return true;
            }
        }

        false
    }

    /// Serialize to bytes (CBOR).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(self, &mut bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(bytes)
    }

    /// Deserialize from bytes (CBOR).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes).map_err(|e| Error::DeserializationError(e.to_string()))
    }
}

// ============================================================================
// Signed Revocation List (SRL)
// ============================================================================

/// The payload of a signed revocation list.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SrlPayload {
    /// List of revoked warrant IDs
    revoked_ids: Vec<String>,
    /// Monotonically increasing version number (for anti-rollback)
    version: u64,
    /// When this list was issued
    issued_at: DateTime<Utc>,
    /// Public key of the issuer
    issuer: PublicKey,
}

/// A cryptographically signed revocation list.
///
/// The Control Plane signs the list, and authorizers verify the signature
/// before trusting the revocation data. This prevents tampering in transit.
///
/// ## Security Properties
///
/// - **Integrity**: Signature covers all revoked IDs, version, and timestamp
/// - **Anti-rollback**: Version must be >= current to prevent replay attacks
/// - **Authenticity**: Only the Control Plane can create valid lists
///
/// ## Example
///
/// ```rust,ignore
/// // Control Plane creates the list
/// let srl = SignedRevocationList::builder()
///     .revoke("tnu_wrt_compromised_123")
///     .version(42)
///     .build(&control_plane_keypair)?;
///
/// // Authorizer verifies before use
/// srl.verify(&control_plane_public_key)?;
/// if srl.version() >= current_version {
///     authorizer.set_revocation_list(srl, &control_plane_key)?;
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRevocationList {
    payload: SrlPayload,
    signature: Signature,
    #[serde(skip)]
    lookup_cache: Option<HashSet<String>>,
}

impl SignedRevocationList {
    /// Create a builder for constructing a signed revocation list.
    pub fn builder() -> SrlBuilder {
        SrlBuilder::new()
    }

    /// Create an empty signed revocation list.
    ///
    /// Useful for initialization before receiving a real SRL.
    pub fn empty(keypair: &Keypair) -> Result<Self> {
        Self::builder().version(0).build(keypair)
    }

    /// Verify this list was signed by the expected issuer.
    ///
    /// Returns `Ok(())` if the signature is valid.
    /// Returns `Err` if the signature is invalid or doesn't match the issuer.
    pub fn verify(&self, expected_issuer: &PublicKey) -> Result<()> {
        // Check issuer matches
        if &self.payload.issuer != expected_issuer {
            return Err(Error::SignatureInvalid(
                "SRL issuer does not match expected key".into(),
            ));
        }

        // Verify signature
        let payload_bytes = self.payload_bytes()?;
        expected_issuer
            .verify(&payload_bytes, &self.signature)
            .map_err(|_| Error::SignatureInvalid("SRL signature verification failed".into()))
    }

    /// Check if a warrant ID is in this revocation list.
    pub fn is_revoked(&self, warrant_id: &str) -> bool {
        // Use cache if available, otherwise linear search
        if let Some(cache) = &self.lookup_cache {
            cache.contains(warrant_id)
        } else {
            self.payload.revoked_ids.iter().any(|id| id == warrant_id)
        }
    }

    /// Build the lookup cache for O(1) revocation checks.
    ///
    /// Call this after loading/verifying the SRL for better performance.
    pub fn build_cache(&mut self) {
        self.lookup_cache = Some(self.payload.revoked_ids.iter().cloned().collect());
    }

    /// Get the version number.
    pub fn version(&self) -> u64 {
        self.payload.version
    }

    /// Get when this list was issued.
    pub fn issued_at(&self) -> DateTime<Utc> {
        self.payload.issued_at
    }

    /// Get the issuer's public key.
    pub fn issuer(&self) -> &PublicKey {
        &self.payload.issuer
    }

    /// Get the list of revoked IDs.
    pub fn revoked_ids(&self) -> &[String] {
        &self.payload.revoked_ids
    }

    /// Get the number of revoked warrants.
    pub fn len(&self) -> usize {
        self.payload.revoked_ids.len()
    }

    /// Check if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.payload.revoked_ids.is_empty()
    }

    /// Serialize to bytes (CBOR).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(self, &mut bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(bytes)
    }

    /// Deserialize from bytes (CBOR).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut srl: Self = ciborium::de::from_reader(bytes)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        srl.build_cache();
        Ok(srl)
    }

    /// Serialize the payload for signing/verification.
    fn payload_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&self.payload, &mut bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(bytes)
    }
}

/// Builder for creating signed revocation lists.
pub struct SrlBuilder {
    revoked_ids: Vec<String>,
    version: u64,
}

impl SrlBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            revoked_ids: Vec::new(),
            version: 1,
        }
    }

    /// Add a warrant ID to revoke.
    pub fn revoke(mut self, warrant_id: impl Into<String>) -> Self {
        self.revoked_ids.push(warrant_id.into());
        self
    }

    /// Add multiple warrant IDs to revoke.
    pub fn revoke_all(mut self, ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        for id in ids {
            self.revoked_ids.push(id.into());
        }
        self
    }

    /// Import from an existing SRL, optionally filtering out expired warrants.
    pub fn from_existing_pruned<F>(mut self, existing: &SignedRevocationList, is_expired: F) -> Self
    where
        F: Fn(&str) -> bool,
    {
        for id in existing.revoked_ids() {
            if !is_expired(id) {
                self.revoked_ids.push(id.clone());
            }
        }
        self
    }

    /// Import all entries from an existing SRL (no pruning).
    pub fn from_existing(self, existing: &SignedRevocationList) -> Self {
        self.from_existing_pruned(existing, |_| false)
    }

    /// Set the version number.
    ///
    /// Version must be monotonically increasing. Authorizers should reject
    /// lists with version < their current version (anti-rollback).
    pub fn version(mut self, version: u64) -> Self {
        self.version = version;
        self
    }

    /// Build and sign the revocation list.
    pub fn build(self, keypair: &Keypair) -> Result<SignedRevocationList> {
        let payload = SrlPayload {
            revoked_ids: self.revoked_ids.clone(),
            version: self.version,
            issued_at: Utc::now(),
            issuer: keypair.public_key(),
        };

        // Serialize payload for signing
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_bytes)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

        // Sign
        let signature = keypair.sign(&payload_bytes);

        let lookup_cache = Some(self.revoked_ids.into_iter().collect());

        Ok(SignedRevocationList {
            payload,
            signature,
            lookup_cache,
        })
    }
}

impl Default for SrlBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_revocation_list_basic() {
        let keypair = Keypair::generate();

        let srl = SignedRevocationList::builder()
            .revoke("tnu_wrt_compromised_1")
            .revoke("tnu_wrt_compromised_2")
            .version(1)
            .build(&keypair)
            .unwrap();

        // Verify with correct key
        assert!(srl.verify(&keypair.public_key()).is_ok());

        // Check revocation
        assert!(srl.is_revoked("tnu_wrt_compromised_1"));
        assert!(srl.is_revoked("tnu_wrt_compromised_2"));
        assert!(!srl.is_revoked("tnu_wrt_valid"));

        assert_eq!(srl.version(), 1);
        assert_eq!(srl.len(), 2);
    }

    #[test]
    fn test_signed_revocation_list_wrong_key() {
        let keypair = Keypair::generate();
        let other_keypair = Keypair::generate();

        let srl = SignedRevocationList::builder()
            .revoke("tnu_wrt_test")
            .build(&keypair)
            .unwrap();

        // Verify with wrong key should fail
        let result = srl.verify(&other_keypair.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_revocation_list_serialization() {
        let keypair = Keypair::generate();

        let srl = SignedRevocationList::builder()
            .revoke("tnu_wrt_test1")
            .revoke("tnu_wrt_test2")
            .version(42)
            .build(&keypair)
            .unwrap();

        // Serialize
        let bytes = srl.to_bytes().unwrap();

        // Deserialize
        let loaded = SignedRevocationList::from_bytes(&bytes).unwrap();

        // Verify still works
        assert!(loaded.verify(&keypair.public_key()).is_ok());
        assert!(loaded.is_revoked("tnu_wrt_test1"));
        assert!(loaded.is_revoked("tnu_wrt_test2"));
        assert_eq!(loaded.version(), 42);
    }

    #[test]
    fn test_anti_rollback_version() {
        let keypair = Keypair::generate();

        let v1 = SignedRevocationList::builder()
            .revoke("tnu_wrt_old")
            .version(1)
            .build(&keypair)
            .unwrap();

        let v2 = SignedRevocationList::builder()
            .revoke("tnu_wrt_old")
            .revoke("tnu_wrt_new")
            .version(2)
            .build(&keypair)
            .unwrap();

        // Authorizer should check version before accepting
        assert!(v2.version() > v1.version());

        // v2 has more revocations
        assert!(!v1.is_revoked("tnu_wrt_new"));
        assert!(v2.is_revoked("tnu_wrt_new"));
    }

    #[test]
    fn test_empty_srl() {
        let keypair = Keypair::generate();
        let srl = SignedRevocationList::empty(&keypair).unwrap();

        assert!(srl.verify(&keypair.public_key()).is_ok());
        assert!(srl.is_empty());
        assert_eq!(srl.version(), 0);
    }

    #[test]
    fn test_pruning_expired_warrants() {
        let keypair = Keypair::generate();

        // Create initial SRL with 3 revocations
        let v1 = SignedRevocationList::builder()
            .revoke("tnu_wrt_expired_1")
            .revoke("tnu_wrt_still_valid")
            .revoke("tnu_wrt_expired_2")
            .version(1)
            .build(&keypair)
            .unwrap();

        assert_eq!(v1.len(), 3);

        // Create v2 by pruning expired warrants
        let expired_ids = ["tnu_wrt_expired_1", "tnu_wrt_expired_2"];
        let v2 = SignedRevocationList::builder()
            .from_existing_pruned(&v1, |id| expired_ids.contains(&id))
            .version(2)
            .build(&keypair)
            .unwrap();

        // v2 should only have the non-expired warrant
        assert_eq!(v2.len(), 1);
        assert!(v2.is_revoked("tnu_wrt_still_valid"));
        assert!(!v2.is_revoked("tnu_wrt_expired_1"));
        assert!(!v2.is_revoked("tnu_wrt_expired_2"));
    }

    #[test]
    fn test_from_existing_adds_new_revocations() {
        let keypair = Keypair::generate();

        let v1 = SignedRevocationList::builder()
            .revoke("tnu_wrt_old")
            .version(1)
            .build(&keypair)
            .unwrap();

        // Create v2 from v1, adding new revocation
        let v2 = SignedRevocationList::builder()
            .from_existing(&v1)
            .revoke("tnu_wrt_new")
            .version(2)
            .build(&keypair)
            .unwrap();

        assert_eq!(v2.len(), 2);
        assert!(v2.is_revoked("tnu_wrt_old"));
        assert!(v2.is_revoked("tnu_wrt_new"));
    }

    // =========================================================================
    // Revocation Request Tests
    // =========================================================================

    #[test]
    fn test_revocation_request_creation_and_verification() {
        let requestor = Keypair::generate();

        let request =
            RevocationRequest::new("tnu_wrt_compromised", "Key compromise detected", &requestor)
                .unwrap();

        assert_eq!(request.warrant_id, "tnu_wrt_compromised");
        assert_eq!(request.reason, "Key compromise detected");
        assert_eq!(request.requestor, requestor.public_key());

        // Signature should verify
        assert!(request.verify_signature().is_ok());
    }

    #[test]
    fn test_revocation_request_serialization() {
        let requestor = Keypair::generate();

        let request =
            RevocationRequest::new("tnu_wrt_test", "Test revocation", &requestor).unwrap();

        // Serialize
        let bytes = request.to_bytes().unwrap();

        // Deserialize
        let loaded = RevocationRequest::from_bytes(&bytes).unwrap();

        assert_eq!(loaded.warrant_id, request.warrant_id);
        assert_eq!(loaded.reason, request.reason);
        assert!(loaded.verify_signature().is_ok());
    }

    #[test]
    fn test_revocation_request_authorization_control_plane() {
        let control_plane = Keypair::generate();
        let issuer = Keypair::generate();
        let holder = Keypair::generate();

        // Control Plane can revoke anything
        let request =
            RevocationRequest::new("tnu_wrt_any", "Admin revocation", &control_plane).unwrap();

        assert!(request.is_authorized(
            &issuer.public_key(),
            Some(&holder.public_key()),
            &control_plane.public_key(),
        ));
    }

    #[test]
    fn test_revocation_request_authorization_issuer() {
        let control_plane = Keypair::generate();
        let issuer = Keypair::generate();
        let holder = Keypair::generate();

        // Issuer can revoke warrants they issued
        let request = RevocationRequest::new(
            "tnu_wrt_issued_by_me",
            "Revoking delegated warrant",
            &issuer,
        )
        .unwrap();

        assert!(request.is_authorized(
            &issuer.public_key(),
            Some(&holder.public_key()),
            &control_plane.public_key(),
        ));
    }

    #[test]
    fn test_revocation_request_authorization_holder_surrender() {
        let control_plane = Keypair::generate();
        let issuer = Keypair::generate();
        let holder = Keypair::generate();

        // Holder can surrender their own warrant
        let request =
            RevocationRequest::new("tnu_wrt_my_warrant", "Voluntary surrender", &holder).unwrap();

        assert!(request.is_authorized(
            &issuer.public_key(),
            Some(&holder.public_key()),
            &control_plane.public_key(),
        ));
    }

    #[test]
    fn test_revocation_request_unauthorized() {
        let control_plane = Keypair::generate();
        let issuer = Keypair::generate();
        let holder = Keypair::generate();
        let random_attacker = Keypair::generate();

        // Random party cannot revoke
        let request = RevocationRequest::new(
            "tnu_wrt_not_mine",
            "Trying to revoke someone else's warrant",
            &random_attacker,
        )
        .unwrap();

        assert!(!request.is_authorized(
            &issuer.public_key(),
            Some(&holder.public_key()),
            &control_plane.public_key(),
        ));
    }

    #[test]
    fn test_revocation_request_full_validation() {
        let control_plane = Keypair::generate();
        let issuer = Keypair::generate();
        let holder = Keypair::generate();
        let warrant_id = "tnu_wrt_valid_123";
        let expires_at = Utc::now() + chrono::Duration::hours(1);

        // Valid request from holder (surrender)
        let request = RevocationRequest::new(warrant_id, "Voluntary surrender", &holder).unwrap();

        // Full validation should pass
        assert!(request
            .validate(
                warrant_id,
                &issuer.public_key(),
                Some(&holder.public_key()),
                expires_at,
                &control_plane.public_key(),
            )
            .is_ok());
    }

    #[test]
    fn test_revocation_request_wrong_warrant_id() {
        let control_plane = Keypair::generate();
        let issuer = Keypair::generate();
        let expires_at = Utc::now() + chrono::Duration::hours(1);

        // Request for one warrant, but validating against different warrant
        let request =
            RevocationRequest::new("tnu_wrt_requested", "DoS attempt", &control_plane).unwrap();

        // Should fail: warrant ID mismatch (proves warrant doesn't exist)
        let result = request.validate(
            "tnu_wrt_actual", // Different ID!
            &issuer.public_key(),
            None,
            expires_at,
            &control_plane.public_key(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not match"));
    }

    #[test]
    fn test_revocation_request_unauthorized_requestor() {
        let control_plane = Keypair::generate();
        let issuer = Keypair::generate();
        let holder = Keypair::generate();
        let attacker = Keypair::generate();
        let warrant_id = "tnu_wrt_target";
        let expires_at = Utc::now() + chrono::Duration::hours(1);

        // Attacker tries to revoke someone else's warrant
        let request =
            RevocationRequest::new(warrant_id, "Malicious revocation", &attacker).unwrap();

        // Should fail: not authorized
        let result = request.validate(
            warrant_id,
            &issuer.public_key(),
            Some(&holder.public_key()),
            expires_at,
            &control_plane.public_key(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not authorized"));
    }

    #[test]
    fn test_revocation_request_expired_warrant() {
        let control_plane = Keypair::generate();
        let issuer = Keypair::generate();
        let warrant_id = "tnu_wrt_already_expired";
        let expires_at = Utc::now() - chrono::Duration::hours(1); // Already expired

        let request = RevocationRequest::new(
            warrant_id,
            "Trying to revoke expired warrant",
            &control_plane,
        )
        .unwrap();

        // Should fail: warrant already expired
        let result = request.validate(
            warrant_id,
            &issuer.public_key(),
            None,
            expires_at,
            &control_plane.public_key(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already expired"));
    }
}
