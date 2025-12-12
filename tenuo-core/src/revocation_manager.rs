//! Revocation Manager
//!
//! This module provides the `RevocationManager` which is responsible for:
//! 1. Accepting and validating `RevocationRequest`s
//! 2. Maintaining a state of pending revocations
//! 3. Generating signed `SignedRevocationList`s (SRLs)
//!
//! # Example
//!
//! ```rust,ignore
//! let mut manager = RevocationManager::new();
//!
//! // Submit a request
//! manager.submit_request(request, &warrant, &issuer_key, None, &cp_key)?;
//!
//! // Generate SRL
//! let srl = manager.generate_srl(&cp_keypair, 1)?;
//! ```

use crate::crypto::{Keypair, PublicKey};
use crate::error::Result;
use crate::revocation::{RevocationRequest, SignedRevocationList};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Manages revocation requests and SRL generation.
#[derive(Debug, Default)]
pub struct RevocationManager {
    /// Pending revocation requests, keyed by warrant ID.
    pending_requests: HashMap<String, RevocationRequest>,
}

impl RevocationManager {
    /// Create a new empty revocation manager.
    pub fn new() -> Self {
        Self {
            pending_requests: HashMap::new(),
        }
    }

    /// Submit a revocation request.
    ///
    /// Validates the request and adds it to the pending list if valid.
    ///
    /// # Arguments
    /// * `request` - The revocation request
    /// * `warrant_id` - The ID of the warrant to revoke
    /// * `warrant_issuer` - The issuer of the warrant
    /// * `warrant_holder` - The holder of the warrant (if any)
    /// * `warrant_expires_at` - When the warrant expires
    /// * `control_plane_key` - The Control Plane's public key
    pub fn submit_request(
        &mut self,
        request: RevocationRequest,
        warrant_id: &str,
        warrant_issuer: &PublicKey,
        warrant_holder: Option<&PublicKey>,
        warrant_expires_at: DateTime<Utc>,
        control_plane_key: &PublicKey,
    ) -> Result<()> {
        // Validate the request
        request.validate(
            warrant_id,
            warrant_issuer,
            warrant_holder,
            warrant_expires_at,
            control_plane_key,
        )?;

        // Store it
        self.pending_requests
            .insert(request.warrant_id.clone(), request);
        Ok(())
    }

    /// Get all pending warrant IDs for SRL generation.
    pub fn pending_ids(&self) -> impl Iterator<Item = &str> {
        self.pending_requests.keys().map(|s| s.as_str())
    }

    /// Generate a new Signed Revocation List (SRL).
    ///
    /// This aggregates all pending requests into a new SRL.
    ///
    /// # Arguments
    /// * `signer` - The keypair to sign the SRL (usually Control Plane)
    /// * `version` - The version number for the new SRL
    pub fn generate_srl(&self, signer: &Keypair, version: u64) -> Result<SignedRevocationList> {
        let mut builder = SignedRevocationList::builder().version(version);

        // Add revoked warrant IDs
        for request in self.pending_requests.values() {
            builder = builder.revoke(&request.warrant_id);
        }

        builder.build(signer)
    }

    /// Generate an SRL with additional warrant IDs (e.g., from key revocation cascade).
    ///
    /// Use this when `NotaryRegistry.revoke_key()` returns affected warrant IDs.
    pub fn generate_srl_with_cascade(
        &self,
        signer: &Keypair,
        version: u64,
        cascade_ids: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<SignedRevocationList> {
        let mut builder = SignedRevocationList::builder().version(version);

        // Add revoked warrant IDs from requests
        for request in self.pending_requests.values() {
            builder = builder.revoke(&request.warrant_id);
        }

        // Add cascaded IDs from key revocation
        for id in cascade_ids {
            builder = builder.revoke(id.as_ref());
        }

        builder.build(signer)
    }

    /// Prune expired requests.
    ///
    /// Removes requests for warrants that have expired (since they don't need to be in the SRL anymore).
    ///
    /// # Arguments
    /// * `is_expired` - A function that returns true if a warrant ID corresponds to an expired warrant.
    pub fn prune_expired<F>(&mut self, is_expired: F)
    where
        F: Fn(&str) -> bool,
    {
        self.pending_requests
            .retain(|warrant_id, _| !is_expired(warrant_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn test_revocation_manager_flow() {
        let cp = Keypair::generate();
        let issuer = Keypair::generate();
        let holder = Keypair::generate();
        let mut manager = RevocationManager::new();

        // 1. Submit a valid request
        let request = RevocationRequest::new(
            "warrant_1",
            "test",
            &issuer, // Issuer revoking their own warrant
        )
        .unwrap();

        manager
            .submit_request(
                request,
                "warrant_1",
                &issuer.public_key(),
                Some(&holder.public_key()),
                Utc::now() + chrono::Duration::hours(1),
                &cp.public_key(),
            )
            .unwrap();

        // 2. Generate SRL
        let srl = manager.generate_srl(&cp, 1).unwrap();

        assert!(srl.is_revoked("warrant_1"));
    }

    #[test]
    fn test_cascade_from_key_revocation() {
        let cp = Keypair::generate();
        let manager = RevocationManager::new();

        // Simulate cascading revocation: NotaryRegistry.revoke_key()
        // returns affected warrant IDs, which we add to the SRL
        let affected_ids = vec!["warrant_a", "warrant_b", "warrant_c"];

        let srl = manager
            .generate_srl_with_cascade(&cp, 1, &affected_ids)
            .unwrap();

        assert!(srl.is_revoked("warrant_a"));
        assert!(srl.is_revoked("warrant_b"));
        assert!(srl.is_revoked("warrant_c"));
        assert!(!srl.is_revoked("warrant_d"));
    }
}
