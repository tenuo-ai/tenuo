//! # Tenuo Core
//!
//! Agent Capability Flow Control - Rust core library.
//!
//! Tenuo provides cryptographically-enforced capability attenuation for AI agent workflows.
//! Unlike traditional IAM systems that answer "Who are you?", Tenuo answers
//! "Who delegated this authority, what task context does it carry, and is this action
//! within the delegated bounds?"
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

pub mod approval;
pub mod audit;
pub mod cel;
pub mod constraints;
pub mod crypto;
pub mod error;
pub mod extraction;
pub mod gateway_config;
pub mod mcp;
pub mod planes;
pub mod revocation;
pub mod revocation_manager;
pub mod warrant;
pub mod wire;

// Re-export extraction types
pub use extraction::{
    CompiledExtractionRule, CompiledExtractionRules, CompiledPath, ExtractionRule,
    ExtractionSource, RequestContext,
};

// Re-export gateway config types
pub use gateway_config::{
    CompiledGatewayConfig, CompiledRoute, GatewayConfig, GatewaySettings, MethodMask, RouteConfig,
    RouteMatch, ToolConfig,
};

// Re-export MCP config types
pub use mcp::{CompiledMcpConfig, CompiledTool, McpConfig, McpSettings};

#[cfg(feature = "python")]
pub mod python;

// Re-exports for convenience
pub use constraints::{
    All, Any, CelConstraint, Constraint, ConstraintSet, ConstraintValue, Contains, Exact, Not,
    NotOneOf, OneOf, Pattern, Range, RegexConstraint, Subset, Wildcard, MAX_CONSTRAINT_DEPTH,
};
pub use crypto::{Keypair, PublicKey, Signature};
pub use error::{Error, Result};
pub use planes::{
    Authorizer, ChainStep, ChainVerificationResult, ControlPlane, DataPlane,
    DEFAULT_CLOCK_TOLERANCE_SECS,
};
pub use revocation::{
    RevocationRequest, SignedRevocationList, SrlBuilder, MAX_REVOCATION_REQUEST_AGE_SECS,
};
pub use revocation_manager::RevocationManager;
pub use warrant::{
    Warrant, WarrantBuilder, WarrantId, POP_TIMESTAMP_WINDOW_SECS, WARRANT_ID_PREFIX,
};
pub use wire::MAX_WARRANT_SIZE;

/// Maximum delegation depth to prevent unbounded chains (protocol-level hard cap).
///
/// Individual warrants can set a lower limit via `max_depth` in the payload.
/// This constant prevents DoS attacks from extremely deep chains.
pub const MAX_DELEGATION_DEPTH: u32 = 64;

/// Context string for Ed25519 signatures (prevents cross-protocol attacks).
///
/// All signatures are computed over: `SIGNATURE_CONTEXT || payload`
///
/// This prevents a signature from one protocol being valid in another.
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
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        assert_eq!(warrant.tool(), Some("upgrade_cluster"));
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
            .authorized_holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let child = parent
            .attenuate()
            .constraint("cluster", Exact::new("staging-web"))
            .build(&child_keypair, &keypair) // keypair is the parent issuer
            .unwrap();

        assert!(child.expires_at() <= parent.expires_at());
        assert_eq!(child.depth(), parent.depth() + 1);
    }
}
