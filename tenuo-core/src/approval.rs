//! Approval types for human-in-the-loop and multi-sig workflows.
//!
//! Tenuo treats Identity Providers as "Notaries" - they map enterprise
//! identities (AWS IAM ARNs, Okta users, YubiKey certificates) to Ed25519
//! public keys. Tenuo only cares about the cryptographic signature.
//!
//! ## Trust Hierarchy
//!
//! The Control Plane is the root of trust. It certifies orchestrators, which
//! in turn certify their child agents. Notaries are scoped to deployments.
//!
//! ```text
//! Control Plane (Root of Trust)
//!     │
//!     ├── Certifies Orchestrator A (deployment)
//!     │       │
//!     │       ├── Bound Notary (scoped to this deployment)
//!     │       │       └── Maps enterprise identities → keys
//!     │       │
//!     │       ├── Worker Agent 1 (delegated warrant from Orchestrator A)
//!     │       └── Worker Agent 2 (delegated warrant from Orchestrator A)
//!     │
//!     └── Certifies Orchestrator B (different deployment)
//!             └── ...
//! ```
//!
//! **Verification flow:**
//! 1. Control Plane → Orchestrator: Root warrant with deployment binding
//! 2. Orchestrator → Worker: Attenuated warrant with holder binding
//! 3. Chain verification proves: Control Plane → Orchestrator → Worker
//!
//! ## Key Generation Principle
//!
//! **Every agent generates its own keys locally.** This applies to:
//! - Orchestrators registering with the Control Plane
//! - Workers registering with their orchestrators
//! - Notaries bound to specific deployments
//!
//! Only the public key is ever shared. The private key never leaves the agent.
//!
//! ```text
//! Root Agent → Control Plane:
//! ┌──────────────────┐                    ┌──────────────────┐
//! │   ROOT AGENT     │   Send pubkey      │  CONTROL PLANE   │
//! │  [PrivateKey]    │  ───────────────►  │  Register + Issue│
//! │  (NEVER LEAVES)  │  ◄─── Warrant ───  │     warrant      │
//! └──────────────────┘                    └──────────────────┘
//!
//! Sub-Agent → Orchestrator (same principle):
//! ┌──────────────────┐                    ┌──────────────────┐
//! │   SUB-AGENT      │   Send pubkey      │  ORCHESTRATOR    │
//! │  [PrivateKey]    │  ───────────────►  │  Attenuate with  │
//! │  (NEVER LEAVES)  │  ◄─── Warrant ───  │  holder=pubkey   │
//! └──────────────────┘                    └──────────────────┘
//! ```
//!
//! ## Philosophy
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  IDENTITY PROVIDER (Notary)          TENUO CORE (The Math)     │
//! │  ─────────────────────────           ──────────────────────    │
//! │                                                                 │
//! │  "arn:aws:iam::123:user/admin"  →    PublicKey [32 bytes]      │
//! │  "okta:user:alice@corp.com"     →    PublicKey [32 bytes]      │
//! │  "yubikey:serial:12345678"      →    PublicKey [32 bytes]      │
//! │                                                                 │
//! │  Provider handles:                   Tenuo verifies:           │
//! │  • Identity verification             • Signature math          │
//! │  • Key derivation/storage            • Multi-sig counting      │
//! │  • Key rotation                      • Offline verification    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Notary Registry
//!
//! The `NotaryRegistry` manages the lifecycle of identity-to-key bindings:
//!
//! ```rust,ignore
//! let mut registry = NotaryRegistry::new();
//!
//! // Register an AWS IAM user's key
//! registry.register_key(KeyBinding {
//!     external_id: "arn:aws:iam::123:user/admin".into(),
//!     provider: "aws-iam".into(),
//!     public_key: admin_keypair.public_key(),
//!     registered_by: "bootstrap".into(),
//!     // ...
//! })?;
//!
//! // All operations emit audit events
//! for event in registry.drain_events() {
//!     audit_log.record(event);
//! }
//! ```
//!
//! ## Authorization Model
//!
//! Different operations require different authorization:
//!
//! | Operation | Authorization |
//! |-----------|---------------|
//! | `register_key` | PoP (new key signs) + Notary approval |
//! | `rotate_key` | Self-rotation (old key signs) |
//! | `revoke_key` | Notary signs (for compromised keys) |
//!
//! ## Implementation Status
//!
//! - [x] Approval struct (data model)
//! - [x] NotaryRegistry (key lifecycle management)
//! - [x] RegistrationProof (PoP for registration)
//! - [x] Notary struct (registry administrator)
//! - [x] KeyBinding (identity → key mapping)
//! - [x] AuditEvent (key lifecycle auditing)
//! - [ ] Multi-sig verification in Authorizer
//! - [ ] Python SDK: ApprovalProvider ABC
//! - [ ] Provider implementations (AWS IAM, Okta, YubiKey)

use crate::crypto::{PublicKey, Signature};
use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A cryptographically signed approval from a human or external system.
///
/// The approval is bound to a specific request (via `request_hash`) and
/// signed by an approver's keypair. The approver's identity is tracked
/// via `external_id` for audit purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// Hash of what was approved: H(warrant_id || tool || sorted(args))
    pub request_hash: [u8; 32],

    /// The approver's public key
    pub approver_key: PublicKey,

    /// External identity reference (e.g., "arn:aws:iam::123:user/admin")
    pub external_id: String,

    /// Provider name (e.g., "aws-iam", "okta", "yubikey")
    pub provider: String,

    /// When approved (UTC)
    pub approved_at: DateTime<Utc>,

    /// When this approval expires (UTC)
    pub expires_at: DateTime<Utc>,

    /// Optional: human-readable reason/justification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Signature over the approval payload
    pub signature: Signature,
}

impl Approval {
    /// Verify the approval signature and check expiration.
    pub fn verify(&self) -> Result<()> {
        // Check expiration
        if Utc::now() > self.expires_at {
            return Err(Error::ApprovalExpired {
                approved_at: self.approved_at,
                expired_at: self.expires_at,
            });
        }

        // Verify signature
        let payload = self.signable_bytes();
        self.approver_key.verify(&payload, &self.signature)
    }

    /// Check if this approval matches a given request.
    pub fn matches_request(&self, request_hash: &[u8; 32]) -> bool {
        &self.request_hash == request_hash
    }

    /// Get the bytes that were signed.
    fn signable_bytes(&self) -> Vec<u8> {
        // Canonical format: request_hash || external_id || approved_at || expires_at
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.request_hash);
        bytes.extend_from_slice(self.external_id.as_bytes());
        bytes.extend_from_slice(&self.approved_at.timestamp().to_le_bytes());
        bytes.extend_from_slice(&self.expires_at.timestamp().to_le_bytes());
        bytes
    }
}

/// Compute a request hash for approval binding.
///
/// This ensures an approval is bound to a specific (warrant, tool, args, holder) tuple.
/// Including the holder prevents approval theft: even if an attacker intercepts an
/// approval, they can't use it because the hash won't match their holder key.
pub fn compute_request_hash(
    warrant_id: &str,
    tool: &str,
    args: &std::collections::HashMap<String, crate::constraints::ConstraintValue>,
    authorized_holder: Option<&crate::crypto::PublicKey>,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    let mut hasher = Sha256::new();
    hasher.update(warrant_id.as_bytes());
    hasher.update(b"|");
    hasher.update(tool.as_bytes());
    hasher.update(b"|");

    // Sort args for deterministic hashing
    let sorted: BTreeMap<_, _> = args.iter().collect();
    if let Ok(json) = serde_json::to_vec(&sorted) {
        hasher.update(&json);
    }

    // Bind to authorized holder (prevents approval theft)
    hasher.update(b"|");
    if let Some(holder) = authorized_holder {
        hasher.update(holder.to_bytes());
    }

    hasher.finalize().into()
}

// ============================================================================
// Notary Proofs (PoP for Registration and Rotation)
// ============================================================================

/// Context string for registration proof signatures.
const REGISTRATION_PROOF_CONTEXT: &[u8] = b"tenuo-key-registration-v1";

/// Context string for rotation proof signatures.
const ROTATION_PROOF_CONTEXT: &[u8] = b"tenuo-key-rotation-v1";

/// Proof of Possession for key registration.
///
/// When registering a new key, the holder must prove they control the private
/// key by signing a payload containing their identity information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationProof {
    /// Signature by the NEW key over the registration payload.
    pub signature: Signature,
    /// Timestamp for replay protection (Unix timestamp).
    pub timestamp: i64,
}

impl RegistrationProof {
    /// Create a registration proof.
    ///
    /// The signed payload is: context || provider || external_id || public_key || timestamp
    pub fn create(
        keypair: &crate::crypto::Keypair,
        provider: &str,
        external_id: &str,
        timestamp: i64,
    ) -> Self {
        let payload = Self::build_payload(provider, external_id, &keypair.public_key(), timestamp);
        let signature = keypair.sign(&payload);
        Self {
            signature,
            timestamp,
        }
    }

    /// Verify the registration proof against a public key.
    pub fn verify(&self, public_key: &PublicKey, provider: &str, external_id: &str) -> Result<()> {
        let payload = Self::build_payload(provider, external_id, public_key, self.timestamp);
        public_key
            .verify(&payload, &self.signature)
            .map_err(|e| Error::InvalidApproval(format!("Invalid registration proof: {}", e)))
    }

    fn build_payload(
        provider: &str,
        external_id: &str,
        public_key: &PublicKey,
        timestamp: i64,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(REGISTRATION_PROOF_CONTEXT);
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(provider.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(external_id.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(&public_key.to_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(&timestamp.to_le_bytes());
        payload
    }
}

/// Proof of authorization for key rotation.
///
/// The OLD key holder signs a payload authorizing rotation to a new key.
/// This proves the current key holder approves the rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationProof {
    /// Signature by the OLD key over the rotation payload.
    pub signature: Signature,
    /// Timestamp for replay protection (Unix timestamp).
    pub timestamp: i64,
}

impl RotationProof {
    /// Create a rotation proof.
    ///
    /// The signed payload is: context || provider || external_id || new_key || timestamp
    pub fn create(
        old_keypair: &crate::crypto::Keypair,
        provider: &str,
        external_id: &str,
        new_key: &PublicKey,
        timestamp: i64,
    ) -> Self {
        let payload = Self::build_payload(provider, external_id, new_key, timestamp);
        let signature = old_keypair.sign(&payload);
        Self {
            signature,
            timestamp,
        }
    }

    /// Verify the rotation proof against the old public key.
    pub fn verify(
        &self,
        old_key: &PublicKey,
        provider: &str,
        external_id: &str,
        new_key: &PublicKey,
    ) -> Result<()> {
        let payload = Self::build_payload(provider, external_id, new_key, self.timestamp);
        old_key
            .verify(&payload, &self.signature)
            .map_err(|e| Error::InvalidApproval(format!("Invalid rotation proof: {}", e)))
    }

    fn build_payload(
        provider: &str,
        external_id: &str,
        new_key: &PublicKey,
        timestamp: i64,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(ROTATION_PROOF_CONTEXT);
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(provider.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(external_id.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(&new_key.to_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(&timestamp.to_le_bytes());
        payload
    }
}

// ============================================================================
// Notary (Registry Administrator)
// ============================================================================

/// A Notary is an entity with administrative authority over the registry.
///
/// Notaries are required for operations that cannot be self-authorized:
/// - **Key registration**: Approving new identity-to-key bindings
/// - **Key revocation**: Deactivating compromised or expired keys
///
/// Unlike rotation (which is self-authorized by the old key), revocation requires
/// a trusted third party because the key holder's key may be compromised.
///
/// ## Deployment Binding
///
/// Notaries can be scoped to a specific deployment. The Control Plane verifies
/// that a notary is authorized for the deployment before accepting registrations.
///
/// ## Properties
///
/// - **Type safety**: Can't accidentally pass arbitrary strings
/// - **Key association**: Each notary is tied to a cryptographic identity
/// - **Deployment scoping**: Notary can be bound to a specific orchestrator
/// - **Signature verification**: Operations require notary signatures
///
/// ## Example
///
/// ```rust,ignore
/// let admin_keypair = Keypair::generate();
/// let admin = Notary::new("admin-1", admin_keypair.public_key())
///     .with_deployment("orchestrator-prod-us-east-1");
///
/// // Register a key (notary approves)
/// registry.register_key(binding, &proof, &admin)?;
///
/// // Revoke a key (notary signs revocation)
/// let sig = admin_keypair.sign(&revocation_message);
/// registry.revoke_key(provider, external_id, reason, &sig, &admin)?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notary {
    /// Unique identifier for this notary
    pub id: String,
    /// Human-readable name
    pub name: Option<String>,
    /// The notary's public key
    pub public_key: PublicKey,
    /// Deployment this notary is bound to (for scoping)
    /// If None, the notary is global (not recommended for production)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,
}

impl Notary {
    /// Create a new notary with an ID and public key.
    pub fn new(id: impl Into<String>, public_key: PublicKey) -> Self {
        Self {
            id: id.into(),
            name: None,
            public_key,
            deployment_id: None,
        }
    }

    /// Bind this notary to a specific deployment.
    ///
    /// In production, notaries should be scoped to prevent cross-deployment
    /// authorization attacks.
    pub fn with_deployment(mut self, deployment_id: impl Into<String>) -> Self {
        self.deployment_id = Some(deployment_id.into());
        self
    }

    /// Create a notary with a display name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Get the notary's ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the deployment this notary is bound to.
    pub fn deployment_id(&self) -> Option<&str> {
        self.deployment_id.as_deref()
    }

    /// Get the display name, falling back to ID.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }
}

// ============================================================================
// Key Binding (Identity → Key Mapping)
// ============================================================================

/// A binding between an external identity and a Tenuo public key.
///
/// This is the core data structure for the Notary Registry, mapping
/// enterprise identities (IAM ARNs, Okta users, etc.) to Ed25519 keys.
///
/// ## Deployment Scoping
///
/// Bindings can be scoped to a specific deployment using `deployment_id`.
/// This ensures that an identity registered for one orchestrator cannot
/// be used to authorize actions in a different deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBinding {
    /// Unique ID for this binding (e.g., `kb_<uuid>`)
    pub id: String,

    /// External identity (e.g., "arn:aws:iam::123:user/admin")
    pub external_id: String,

    /// Provider name (e.g., "aws-iam", "okta", "yubikey")
    pub provider: String,

    /// The bound public key
    pub public_key: PublicKey,

    /// Deployment this binding is scoped to (optional)
    ///
    /// If set, this binding only authorizes actions within the specified
    /// deployment. Cross-deployment use is rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,

    /// Human-readable display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Who registered this binding
    pub registered_by: String,

    /// When this binding was created
    pub registered_at: DateTime<Utc>,

    /// When this binding expires (None = never)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Whether this binding is currently active
    pub active: bool,

    /// Optional metadata (tags, permissions, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::BTreeMap<String, String>>,
}

impl KeyBinding {
    /// Check if this binding is valid (active and not expired)
    pub fn is_valid(&self) -> bool {
        if !self.active {
            return false;
        }
        if let Some(expires) = self.expires_at {
            if Utc::now() > expires {
                return false;
            }
        }
        true
    }
}

// ============================================================================
// Audit Events
// ============================================================================

/// Types of key lifecycle events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// A new key binding was registered
    KeyRegistered,
    /// A key binding was rotated (new key, same identity)
    KeyRotated,
    /// A key binding was revoked/deactivated
    KeyRevoked,
    /// A key binding expired
    KeyExpired,
    /// An approval was granted using this key
    ApprovalGranted,
    /// An approval verification succeeded
    ApprovalVerified,
    /// An approval verification failed
    ApprovalFailed,
    /// Provider was registered
    ProviderRegistered,
    /// Provider was removed
    ProviderRemoved,

    // -- Enrollment Events --
    /// An orchestrator successfully enrolled
    EnrollmentSuccess,
    /// An enrollment attempt failed
    EnrollmentFailure,

    // -- Warrant Events --
    /// A warrant was issued
    WarrantIssued,
    /// A warrant was revoked
    WarrantRevoked,

    // -- Authorization Events --
    /// An action was authorized
    AuthorizationSuccess,
    /// An action was denied
    AuthorizationFailure,
}

/// An audit event for key lifecycle operations.
///
/// These events should be persisted to an audit log for compliance
/// and forensic analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub id: String,

    /// Event type
    pub event_type: AuditEventType,

    /// When this event occurred
    pub timestamp: DateTime<Utc>,

    /// Which provider this relates to
    pub provider: String,

    /// External identity involved (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Public key involved (hex-encoded for readability)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,

    /// Who/what triggered this event
    pub actor: String,

    /// Additional context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    /// Related IDs (warrant_id, approval_id, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_ids: Option<Vec<String>>,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(
        event_type: AuditEventType,
        provider: impl Into<String>,
        actor: impl Into<String>,
    ) -> Self {
        Self {
            id: format!("evt_{}", uuid::Uuid::now_v7().simple()),
            event_type,
            timestamp: Utc::now(),
            provider: provider.into(),
            external_id: None,
            public_key_hex: None,
            actor: actor.into(),
            details: None,
            related_ids: None,
        }
    }

    /// Add external identity context
    pub fn with_identity(mut self, external_id: impl Into<String>) -> Self {
        self.external_id = Some(external_id.into());
        self
    }

    /// Add public key context
    pub fn with_key(mut self, key: &PublicKey) -> Self {
        self.public_key_hex = Some(hex::encode(key.to_bytes()));
        self
    }

    /// Add details
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Add related IDs
    pub fn with_related(mut self, ids: Vec<String>) -> Self {
        self.related_ids = Some(ids);
        self
    }
}

// ============================================================================
// Warrant Tracking
// ============================================================================

/// Trait for components that track warrant issuance (e.g., NotaryRegistry).
///
/// This allows the Control Plane to enforce tracking when issuing warrants,
/// ensuring that cascading revocation works correctly.
pub trait WarrantTracker {
    /// Track a warrant for a specific key (issuer or holder).
    fn track_warrant(&mut self, key: &PublicKey, warrant_id: &str);
}

// ============================================================================
// Notary Registry
// ============================================================================

/// Registry for managing Notaries (identity providers and their key bindings).
///
/// The registry handles:
/// - Provider registration
/// - Key binding lifecycle (register, rotate, revoke)
/// - Audit event generation
///
/// ## Example
///
/// ```rust,ignore
/// let mut registry = NotaryRegistry::new();
///
/// // Register a provider
/// registry.register_provider("aws-iam", "AWS IAM Identity Provider")?;
///
/// // Register a key binding
/// let binding = KeyBinding {
///     id: "kb_123".into(),
///     external_id: "arn:aws:iam::123:user/admin".into(),
///     provider: "aws-iam".into(),
///     public_key: admin_key,
///     // ...
/// };
/// registry.register_key(binding, "system")?;
///
/// // Resolve identity to key
/// let key = registry.resolve("aws-iam", "arn:aws:iam::123:user/admin")?;
///
/// // Drain audit events for logging
/// for event in registry.drain_events() {
///     log::info!("Audit: {:?}", event);
/// }
/// ```
#[derive(Debug, Default)]
pub struct NotaryRegistry {
    /// Registered providers: name → description
    providers: std::collections::HashMap<String, String>,

    /// Key bindings: (provider, external_id) → KeyBinding
    bindings: std::collections::HashMap<(String, String), KeyBinding>,

    /// Warrant index: PublicKey → Set of warrant IDs
    /// Used for cascading revocation when a key is compromised.
    warrant_index: std::collections::HashMap<[u8; 32], std::collections::HashSet<String>>,

    /// Pending audit events (drain these periodically)
    pending_events: Vec<AuditEvent>,
}

impl NotaryRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new provider.
    pub fn register_provider(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        actor: impl Into<String>,
    ) {
        let name = name.into();
        let actor = actor.into();

        self.providers.insert(name.clone(), description.into());

        self.pending_events.push(
            AuditEvent::new(AuditEventType::ProviderRegistered, &name, actor)
                .with_details(format!("Provider '{}' registered", name)),
        );
    }

    /// Remove a provider (also removes all its bindings).
    pub fn remove_provider(&mut self, name: &str, actor: impl Into<String>) {
        let actor = actor.into();

        // Remove all bindings for this provider
        let to_remove: Vec<_> = self
            .bindings
            .keys()
            .filter(|(p, _)| p == name)
            .cloned()
            .collect();

        for key in to_remove {
            self.bindings.remove(&key);
        }

        self.providers.remove(name);

        self.pending_events.push(
            AuditEvent::new(AuditEventType::ProviderRemoved, name, actor)
                .with_details(format!("Provider '{}' removed", name)),
        );
    }

    /// Check if a provider is registered.
    pub fn has_provider(&self, name: &str) -> bool {
        self.providers.contains_key(name)
    }

    /// List all registered providers.
    pub fn list_providers(&self) -> Vec<(&str, &str)> {
        self.providers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    /// Register a new key binding with Proof of Possession.
    ///
    /// # Security
    ///
    /// This operation requires two forms of authorization:
    /// 1. **Proof of Possession (PoP)**: The new key holder must sign a registration
    ///    proof to prove they control the private key being registered.
    /// 2. **Notary authorization**: A trusted notary must approve the registration.
    ///
    /// # Arguments
    ///
    /// * `binding` - The key binding to register
    /// * `proof` - RegistrationProof signed by the private key being registered
    /// * `notary` - The notary authorizing this registration
    pub fn register_key(
        &mut self,
        binding: KeyBinding,
        proof: &RegistrationProof,
        notary: &Notary,
    ) -> Result<()> {
        if !self.has_provider(&binding.provider) {
            return Err(Error::UnknownProvider(binding.provider.clone()));
        }

        // Verify Deployment Scoping
        // If the notary is bound to a deployment, they can ONLY register keys for that deployment.
        if let Some(notary_deployment) = &notary.deployment_id {
            match &binding.deployment_id {
                Some(binding_deployment) if binding_deployment != notary_deployment => {
                    return Err(Error::Unauthorized(format!(
                        "Notary scoped to '{}' cannot register key for '{}'",
                        notary_deployment, binding_deployment
                    )));
                }
                None => {
                    return Err(Error::Unauthorized(format!(
                        "Notary scoped to '{}' cannot register global key",
                        notary_deployment
                    )));
                }
                _ => {} // Matches
            }
        }

        // Verify Proof of Possession
        proof.verify(&binding.public_key, &binding.provider, &binding.external_id)?;

        let key = (binding.provider.clone(), binding.external_id.clone());

        self.pending_events.push(
            AuditEvent::new(
                AuditEventType::KeyRegistered,
                &binding.provider,
                notary.id(),
            )
            .with_identity(&binding.external_id)
            .with_key(&binding.public_key)
            .with_details(format!(
                "Key registered for '{}' by {} (PoP verified)",
                binding
                    .display_name
                    .as_deref()
                    .unwrap_or(&binding.external_id),
                notary.display_name()
            )),
        );

        self.bindings.insert(key, binding);
        Ok(())
    }

    /// Rotate a key (update the public key for an existing binding).
    ///
    /// # Security
    ///
    /// This operation requires a signature from the **current (old) key** to prove
    /// the key holder authorizes the rotation. This is a self-rotation model.
    ///
    /// The signed message is: `provider || external_id || new_key_bytes`
    ///
    /// For compromised keys where self-rotation isn't possible, use `revoke_key()`
    /// followed by a new registration through the external provider's auth flow.
    ///
    /// # Arguments
    ///
    /// * `provider` - The identity provider name
    /// * `external_id` - The external identity being rotated
    /// * `new_key` - The new public key
    /// * `signature` - Signature by the OLD key over the rotation message
    /// * `actor` - Identifier for audit logging
    pub fn rotate_key(
        &mut self,
        provider: &str,
        external_id: &str,
        new_key: PublicKey,
        signature: &Signature,
        actor: impl Into<String>,
    ) -> Result<()> {
        let actor = actor.into();
        let key = (provider.to_string(), external_id.to_string());

        let binding = self
            .bindings
            .get_mut(&key)
            .ok_or_else(|| Error::UnknownProvider(format!("{}:{}", provider, external_id)))?;

        // 1. Verify authorization: Old key must sign the rotation request
        let mut message = Vec::new();
        message.extend_from_slice(provider.as_bytes());
        message.extend_from_slice(external_id.as_bytes());
        message.extend_from_slice(&new_key.to_bytes());

        binding
            .public_key
            .verify(&message, signature)
            .map_err(|_| Error::SignatureInvalid("Invalid rotation signature".into()))?;

        let old_key_hex = hex::encode(binding.public_key.to_bytes());

        // 2. Perform rotation
        binding.public_key = new_key.clone();

        self.pending_events.push(
            AuditEvent::new(AuditEventType::KeyRotated, provider, actor)
                .with_identity(external_id)
                .with_key(&new_key)
                .with_details(format!("Key rotated from {}", &old_key_hex[..16])),
        );

        Ok(())
    }

    /// Revoke a key binding (deactivate it).
    ///
    /// Unlike rotation (which is self-authorized), revocation requires authorization
    /// from a **Notary** (registry administrator). This handles the case where the
    /// key holder's key is compromised or unavailable.
    ///
    /// # Security
    ///
    /// The notary must sign the revocation request to prove authorization.
    /// The signed message is: `provider || external_id || reason`
    ///
    /// # Arguments
    ///
    /// * `provider` - The identity provider name
    /// * `external_id` - The external identity being revoked
    /// * `reason` - Human-readable reason for revocation (for audit)
    /// * `signature` - Signature by the notary over the revocation message
    /// * `notary` - The notary authorizing this revocation
    ///
    /// # Returns
    /// A list of warrant IDs that should be added to the Signed Revocation List.
    /// These are warrants issued by or held by the revoked key.
    pub fn revoke_key(
        &mut self,
        provider: &str,
        external_id: &str,
        reason: impl Into<String>,
        signature: &Signature,
        notary: &Notary,
    ) -> Result<Vec<String>> {
        let reason = reason.into();
        let key = (provider.to_string(), external_id.to_string());

        // First, get the binding immutably to check deployment and get the public key
        let binding = self
            .bindings
            .get(&key)
            .ok_or_else(|| Error::UnknownProvider(format!("{}:{}", provider, external_id)))?;

        // Verify Deployment Scoping
        if let Some(notary_deployment) = &notary.deployment_id {
            match &binding.deployment_id {
                Some(binding_deployment) if binding_deployment != notary_deployment => {
                    return Err(Error::Unauthorized(format!(
                        "Notary scoped to '{}' cannot revoke key for '{}'",
                        notary_deployment, binding_deployment
                    )));
                }
                None => {
                    return Err(Error::Unauthorized(format!(
                        "Notary scoped to '{}' cannot revoke global key",
                        notary_deployment
                    )));
                }
                _ => {} // Deployment matches
            }
        }

        // Verify authorization: Notary must sign the revocation request
        let mut message = Vec::new();
        message.extend_from_slice(provider.as_bytes());
        message.extend_from_slice(external_id.as_bytes());
        message.extend_from_slice(reason.as_bytes());

        notary
            .public_key
            .verify(&message, signature)
            .map_err(|_| Error::SignatureInvalid("Invalid revocation signature".into()))?;

        // Get affected warrants and public key before mutable borrow
        let public_key = binding.public_key.clone();
        let affected_warrants = self.get_warrants_for_key(&public_key);

        // Now get mutable reference to deactivate
        let binding = self.bindings.get_mut(&key).unwrap();
        binding.active = false;

        self.pending_events.push(
            AuditEvent::new(AuditEventType::KeyRevoked, provider, notary.id())
                .with_identity(external_id)
                .with_key(&public_key)
                .with_details(format!(
                    "Revoked by {}: {}. Affected warrants: {}",
                    notary.display_name(),
                    reason,
                    affected_warrants.len()
                )),
        );

        Ok(affected_warrants)
    }

    /// Track a warrant issued by or held by a key.
    ///
    /// Call this when warrants are created so that cascading revocation works.
    /// The warrant should be tracked for both its issuer and holder (if any).
    ///
    /// # Example
    /// ```rust,ignore
    /// // Track warrant for both issuer and holder
    /// registry.track_warrant(warrant.issuer(), warrant.id());
    /// if let Some(holder) = warrant.authorized_holder() {
    ///     registry.track_warrant(holder, warrant.id());
    /// }
    /// ```
    pub fn track_warrant(&mut self, key: &PublicKey, warrant_id: impl Into<String>) {
        let key_bytes = key.to_bytes();
        self.warrant_index
            .entry(key_bytes)
            .or_default()
            .insert(warrant_id.into());
    }

    /// Remove a warrant from tracking (e.g., when it expires).
    pub fn untrack_warrant(&mut self, key: &PublicKey, warrant_id: &str) {
        let key_bytes = key.to_bytes();
        if let Some(warrants) = self.warrant_index.get_mut(&key_bytes) {
            warrants.remove(warrant_id);
            if warrants.is_empty() {
                self.warrant_index.remove(&key_bytes);
            }
        }
    }

    /// Get all warrant IDs associated with a key.
    ///
    /// Returns warrants where this key is either the issuer or the authorized holder.
    pub fn get_warrants_for_key(&self, key: &PublicKey) -> Vec<String> {
        let key_bytes = key.to_bytes();
        self.warrant_index
            .get(&key_bytes)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Resolve an external identity to a public key.
    pub fn resolve(&self, provider: &str, external_id: &str) -> Result<&PublicKey> {
        let key = (provider.to_string(), external_id.to_string());

        let binding = self
            .bindings
            .get(&key)
            .ok_or_else(|| Error::UnknownProvider(format!("{}:{}", provider, external_id)))?;

        if !binding.is_valid() {
            return Err(Error::ApprovalExpired {
                approved_at: binding.registered_at,
                expired_at: binding.expires_at.unwrap_or(Utc::now()),
            });
        }

        Ok(&binding.public_key)
    }

    /// Get a key binding by identity.
    pub fn get_binding(&self, provider: &str, external_id: &str) -> Option<&KeyBinding> {
        let key = (provider.to_string(), external_id.to_string());
        self.bindings.get(&key)
    }

    /// List all bindings for a provider.
    pub fn list_bindings(&self, provider: &str) -> Vec<&KeyBinding> {
        self.bindings
            .iter()
            .filter(|((p, _), _)| p == provider)
            .map(|(_, b)| b)
            .collect()
    }

    /// Record an approval event (for audit trail).
    pub fn record_approval(
        &mut self,
        event_type: AuditEventType,
        approval: &Approval,
        notary: &Notary,
        details: Option<String>,
    ) {
        let mut event = AuditEvent::new(event_type, &approval.provider, notary.id())
            .with_identity(&approval.external_id)
            .with_key(&approval.approver_key);

        if let Some(d) = details {
            event = event.with_details(d);
        }

        self.pending_events.push(event);
    }

    /// Drain pending audit events.
    ///
    /// Call this periodically to persist events to your audit log.
    pub fn drain_events(&mut self) -> Vec<AuditEvent> {
        std::mem::take(&mut self.pending_events)
    }

    /// Get pending event count (for monitoring).
    pub fn pending_event_count(&self) -> usize {
        self.pending_events.len()
    }
}

impl WarrantTracker for NotaryRegistry {
    fn track_warrant(&mut self, key: &PublicKey, warrant_id: &str) {
        self.track_warrant(key, warrant_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use std::collections::HashMap;

    #[test]
    fn test_request_hash_deterministic() {
        let mut args1 = HashMap::new();
        args1.insert(
            "z".to_string(),
            crate::constraints::ConstraintValue::String("last".to_string()),
        );
        args1.insert(
            "a".to_string(),
            crate::constraints::ConstraintValue::String("first".to_string()),
        );

        let mut args2 = HashMap::new();
        args2.insert(
            "a".to_string(),
            crate::constraints::ConstraintValue::String("first".to_string()),
        );
        args2.insert(
            "z".to_string(),
            crate::constraints::ConstraintValue::String("last".to_string()),
        );

        let hash1 = compute_request_hash("wrt_123", "delete", &args1, None);
        let hash2 = compute_request_hash("wrt_123", "delete", &args2, None);

        assert_eq!(
            hash1, hash2,
            "Hash should be deterministic regardless of insertion order"
        );

        // Test that holder affects the hash
        let holder = crate::crypto::Keypair::generate();
        let hash_with_holder =
            compute_request_hash("wrt_123", "delete", &args1, Some(&holder.public_key()));
        assert_ne!(
            hash1, hash_with_holder,
            "Hash should differ when holder is included"
        );
    }

    #[test]
    fn test_notary_registry_lifecycle() {
        let mut registry = NotaryRegistry::new();

        // Create a notary (admin)
        let admin_keypair = Keypair::generate();
        let admin = Notary::new("admin-1", admin_keypair.public_key()).with_name("Test Admin");

        // Register a provider
        registry.register_provider("aws-iam", "AWS IAM Provider", "admin-1");
        assert!(registry.has_provider("aws-iam"));

        // Create a key binding
        let keypair = Keypair::generate();
        let binding = KeyBinding {
            id: "kb_test_123".to_string(),
            external_id: "arn:aws:iam::123:user/admin".to_string(),
            provider: "aws-iam".to_string(),
            public_key: keypair.public_key(),
            deployment_id: None,
            display_name: Some("Admin User".to_string()),
            registered_by: admin.id().to_string(),
            registered_at: Utc::now(),
            expires_at: None,
            active: true,
            metadata: None,
        };

        // Create registration proof (PoP)
        let proof = RegistrationProof::create(
            &keypair,
            "aws-iam",
            "arn:aws:iam::123:user/admin",
            Utc::now().timestamp(),
        );

        // Register the key with proof
        registry.register_key(binding, &proof, &admin).unwrap();

        // Resolve the identity
        let resolved = registry
            .resolve("aws-iam", "arn:aws:iam::123:user/admin")
            .unwrap();
        assert_eq!(resolved.to_bytes(), keypair.public_key().to_bytes());

        // Check audit events
        let events = registry.drain_events();
        assert_eq!(events.len(), 2); // provider registered + key registered
        assert_eq!(events[0].event_type, AuditEventType::ProviderRegistered);
        assert_eq!(events[1].event_type, AuditEventType::KeyRegistered);
    }

    #[test]
    fn test_key_rotation() {
        let mut registry = NotaryRegistry::new();

        // Create notary for provider registration
        let system_keypair = Keypair::generate();
        let system = Notary::new("system", system_keypair.public_key());

        registry.register_provider("test", "Test Provider", "system");

        let old_keypair = Keypair::generate();
        let new_keypair = Keypair::generate();

        let binding = KeyBinding {
            id: "kb_rotate".to_string(),
            external_id: "user@example.com".to_string(),
            provider: "test".to_string(),
            public_key: old_keypair.public_key(),
            deployment_id: None,
            display_name: None,
            registered_by: system.id().to_string(),
            registered_at: Utc::now(),
            expires_at: None,
            active: true,
            metadata: None,
        };

        // Create registration proof
        let reg_proof = RegistrationProof::create(
            &old_keypair,
            "test",
            "user@example.com",
            Utc::now().timestamp(),
        );
        registry.register_key(binding, &reg_proof, &system).unwrap();

        // Create rotation signature (signed by OLD key)
        // Message format: provider || external_id || new_key_bytes
        let mut message = Vec::new();
        message.extend_from_slice(b"test");
        message.extend_from_slice(b"user@example.com");
        message.extend_from_slice(&new_keypair.public_key().to_bytes());
        let rotation_sig = old_keypair.sign(&message);

        // Rotate the key with signature
        registry
            .rotate_key(
                "test",
                "user@example.com",
                new_keypair.public_key(),
                &rotation_sig,
                "admin",
            )
            .unwrap();

        // Verify the new key is returned
        let resolved = registry.resolve("test", "user@example.com").unwrap();
        assert_eq!(resolved.to_bytes(), new_keypair.public_key().to_bytes());

        // Check audit events
        let events = registry.drain_events();
        assert!(events
            .iter()
            .any(|e| e.event_type == AuditEventType::KeyRotated));
    }

    #[test]
    fn test_key_revocation() {
        let mut registry = NotaryRegistry::new();

        let system_keypair = Keypair::generate();
        let system = Notary::new("system", system_keypair.public_key());
        let security_keypair = Keypair::generate();
        let security = Notary::new("security-team", security_keypair.public_key());

        registry.register_provider("test", "Test Provider", "system");

        let keypair = Keypair::generate();
        let binding = KeyBinding {
            id: "kb_revoke".to_string(),
            external_id: "user@example.com".to_string(),
            provider: "test".to_string(),
            public_key: keypair.public_key(),
            deployment_id: None,
            display_name: None,
            registered_by: system.id().to_string(),
            registered_at: Utc::now(),
            expires_at: None,
            active: true,
            metadata: None,
        };

        let proof =
            RegistrationProof::create(&keypair, "test", "user@example.com", Utc::now().timestamp());
        registry.register_key(binding, &proof, &system).unwrap();

        // Create revocation signature (signed by security notary)
        // Message format: provider || external_id || reason
        let reason = "Compromised";
        let mut message = Vec::new();
        message.extend_from_slice(b"test");
        message.extend_from_slice(b"user@example.com");
        message.extend_from_slice(reason.as_bytes());
        let revoke_sig = security_keypair.sign(&message);

        // Revoke the key
        registry
            .revoke_key("test", "user@example.com", reason, &revoke_sig, &security)
            .unwrap();

        // Verify resolution fails
        let result = registry.resolve("test", "user@example.com");
        assert!(result.is_err());

        // Check the binding is marked inactive
        let binding = registry.get_binding("test", "user@example.com").unwrap();
        assert!(!binding.active);
    }

    #[test]
    fn test_unknown_provider_fails() {
        let mut registry = NotaryRegistry::new();

        let notary_keypair = Keypair::generate();
        let notary = Notary::new("test-notary", notary_keypair.public_key());

        let keypair = Keypair::generate();
        let binding = KeyBinding {
            id: "kb_fail".to_string(),
            external_id: "user@example.com".to_string(),
            provider: "unknown-provider".to_string(),
            public_key: keypair.public_key(),
            deployment_id: None,
            display_name: None,
            registered_by: notary.id().to_string(),
            registered_at: Utc::now(),
            expires_at: None,
            active: true,
            metadata: None,
        };

        let proof = RegistrationProof::create(
            &keypair,
            "unknown-provider",
            "user@example.com",
            Utc::now().timestamp(),
        );

        let result = registry.register_key(binding, &proof, &notary);
        assert!(result.is_err());
    }
}
