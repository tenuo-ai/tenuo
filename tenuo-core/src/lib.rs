//! # Tenuo Core
//!
//! Agent Capability Flow Control - Rust core library.
//!
//! Tenuo provides cryptographically-enforced capability attenuation for AI agent workflows.
//! Unlike traditional IAM systems that answer "Who are you?", Tenuo answers
//! "Does this actor hold a valid, scoped, unexpired token for this specific action?"
//!
//! ## Key Concepts
//!
//! - **Warrant**: A transferable token of authority containing tool name, constraints, TTL, and signature
//! - **Attenuation**: Capabilities can only shrink when delegated, never expand
//! - **Constraints**: Restrictions on argument values (Pattern, Exact, OneOf, Range, CEL)
//!
//! ## Example
//!
//! ```rust,ignore
//! use tenuo_core::{Warrant, Pattern, Keypair};
//! use std::time::Duration;
//!
//! // Create a keypair for the control plane
//! let keypair = Keypair::generate();
//!
//! // Issue a warrant for cluster upgrades
//! let warrant = Warrant::builder()
//!     .tool("upgrade_cluster")
//!     .constraint("cluster", Pattern::new("staging-*"))
//!     .ttl(Duration::from_secs(600))
//!     .build(&keypair)?;
//!
//! // Attenuate to a narrower scope for a worker agent
//! let worker_warrant = warrant.attenuate()
//!     .constraint("cluster", Exact::new("staging-web"))
//!     .build(&worker_keypair)?;
//! ```

pub mod cel;
pub mod constraints;
pub mod crypto;
pub mod error;
pub mod planes;
pub mod warrant;
pub mod wire;

#[cfg(feature = "python")]
pub mod python;

// Re-exports for convenience
pub use constraints::{
    All, Any, CelConstraint, Constraint, ConstraintSet, ConstraintValue,
    Contains, Exact, Not, OneOf, Pattern, Range, RegexConstraint, Subset,
};
pub use crypto::{Keypair, PublicKey, Signature};
pub use error::{Error, Result};
pub use planes::{
    Authorizer, ChainStep, ChainVerificationResult, ControlPlane, DataPlane,
    DEFAULT_CLOCK_TOLERANCE_SECS,
};
pub use revocation::RevocationList;
pub use warrant::{Warrant, WarrantBuilder, WarrantId};

/// Maximum delegation depth to prevent unbounded chains
pub const MAX_DELEGATION_DEPTH: u32 = 16;

/// Context string for Ed25519 signatures (prevents cross-protocol attacks)
pub const SIGNATURE_CONTEXT: &[u8] = b"tenuo-warrant-v1";

/// Current wire format version
pub const WIRE_VERSION: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_basic_warrant_creation() {
        let keypair = Keypair::generate();
        
        let warrant = Warrant::builder()
            .tool("upgrade_cluster")
            .constraint("cluster", Pattern::new("staging-*").unwrap())
            .ttl(Duration::from_secs(600))
            .build(&keypair)
            .unwrap();

        assert_eq!(warrant.tool(), "upgrade_cluster");
        assert!(warrant.verify(&keypair.public_key()).is_ok());
    }

    #[test]
    fn test_attenuation_narrows_constraints() {
        let keypair = Keypair::generate();
        let child_keypair = Keypair::generate();

        let parent = Warrant::builder()
            .tool("upgrade_cluster")
            .constraint("cluster", Pattern::new("staging-*").unwrap())
            .ttl(Duration::from_secs(600))
            .build(&keypair)
            .unwrap();

        let child = parent
            .attenuate()
            .constraint("cluster", Exact::new("staging-web"))
            .build(&child_keypair)
            .unwrap();

        assert!(child.expires_at() <= parent.expires_at());
        assert_eq!(child.depth(), parent.depth() + 1);
    }
}

