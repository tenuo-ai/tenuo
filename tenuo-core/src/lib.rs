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
//! use tenuo::{Warrant, Pattern, Keypair};
//! use std::time::Duration;
//!
//! // Create a keypair for the control plane
//! let keypair = SigningKey::generate();
//!
//! // Issue a warrant for cluster upgrades
//! let warrant = Warrant::builder()
//!     .capability("upgrade_cluster")
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
pub mod diff;
pub mod domain;
pub mod error;
pub mod extraction;
pub mod gateway_config;
pub mod mcp;
pub mod payload;
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
    All, Any, CelConstraint, Cidr, Constraint, ConstraintSet, ConstraintValue, Contains, Exact,
    Not, NotOneOf, OneOf, Pattern, Range, RegexConstraint, Subset, UrlPattern, Wildcard,
    MAX_CONSTRAINT_DEPTH,
};
pub use crypto::{PublicKey, Signature, SigningKey};
pub use error::{Error, Result};
pub use planes::{
    Authorizer, AuthorizerBuilder, ChainStep, ChainVerificationResult, ControlPlane, DataPlane,
    DEFAULT_CLOCK_TOLERANCE_SECS,
};
pub use revocation::{
    RevocationRequest, SignedRevocationList, SrlBuilder, MAX_REVOCATION_REQUEST_AGE_SECS,
};
pub use revocation_manager::RevocationManager;
pub use warrant::{
    Clearance, OwnedAttenuationBuilder, OwnedIssuanceBuilder, Warrant, WarrantBuilder, WarrantId,
    WarrantType, POP_TIMESTAMP_WINDOW_SECS, WARRANT_ID_PREFIX,
};
pub use wire::MAX_WARRANT_SIZE;

// Re-export diff types
pub use diff::{
    ChangeType, ClearanceDiff, ConstraintDiff, DelegationDiff, DelegationReceipt, DepthDiff,
    ToolsDiff, TtlDiff,
};

/// Maximum delegation depth to prevent unbounded chains (protocol-level hard cap).
///
/// Individual warrants can set a lower limit via `max_depth` in the payload.
/// This constant prevents DoS attacks from extremely deep chains.
///
/// 64 levels is sufficient for complex storage hierarchies or extensive delegation chains,
/// while still preventing unbounded recursion or DoS attacks.
///
/// **SAFETY**: This MUST NOT exceed 255 because `WarrantPayload.max_depth` is `u8`.
pub const MAX_DELEGATION_DEPTH: u32 = 64;

// Compile-time assertion: MAX_DELEGATION_DEPTH must fit in u8 (wire format uses u8)
const _: () = assert!(
    MAX_DELEGATION_DEPTH <= 255,
    "MAX_DELEGATION_DEPTH must not exceed 255 (u8 max) for wire format compatibility"
);

/// Protocol-level maximum TTL (90 days).
///
/// This is the absolute ceiling enforced by the protocol. Deployments can
/// (and should) configure stricter limits via `Authorizer::with_max_ttl()`.
///
/// 90 days aligns with industry precedent (e.g., Let's Encrypt certificates)
/// while being generous enough for edge cases. Most warrants should use
/// much shorter TTLs (minutes to hours).
pub const MAX_WARRANT_TTL_SECS: u64 = 90 * 24 * 60 * 60; // 7,776,000 seconds

/// Default TTL when not specified (5 minutes).
///
/// Short by design - task-scoped warrants should expire quickly.
/// Expand only as needed for specific use cases.
pub const DEFAULT_WARRANT_TTL_SECS: u64 = 5 * 60; // 300 seconds

/// Context string for Ed25519 signatures (prevents cross-protocol attacks).
///
/// All signatures are computed over: `SIGNATURE_CONTEXT || payload`
///
/// This prevents a signature from one protocol being valid in another.
pub use domain::WARRANT_CONTEXT as SIGNATURE_CONTEXT;

/// Current wire format version
pub const WIRE_VERSION: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_basic_warrant_creation() {
        let keypair = SigningKey::generate();

        let mut constraints = ConstraintSet::new();
        constraints.insert("cluster".to_string(), Pattern::new("staging-*").unwrap());

        let warrant = Warrant::builder()
            .capability("upgrade_cluster", constraints)
            .ttl(Duration::from_secs(600))
            .holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let caps = warrant.capabilities().unwrap();
        assert!(caps.contains_key("upgrade_cluster"));
        assert!(warrant.verify(&keypair.public_key()).is_ok());
    }

    #[test]
    fn test_attenuation_narrows_constraints() {
        let keypair = SigningKey::generate();
        let _child_keypair = SigningKey::generate(); // Unused with new delegation API

        let mut p_constraints = ConstraintSet::new();
        p_constraints.insert("cluster".to_string(), Pattern::new("staging-*").unwrap());

        let parent = Warrant::builder()
            .capability("upgrade_cluster", p_constraints)
            .ttl(Duration::from_secs(600))
            .holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        let mut c_constraints = ConstraintSet::new();
        c_constraints.insert("cluster".to_string(), Exact::new("staging-web"));

        let child = parent
            .attenuate()
            .capability("upgrade_cluster", c_constraints)
            .build(&keypair) // keypair is parent's holder
            .unwrap();

        assert!(child.expires_at() <= parent.expires_at());
        assert_eq!(child.depth(), parent.depth() + 1);
    }
}
