//! Approval types for human-in-the-loop and multi-sig workflows.
//!
//! Tenuo treats Identity Providers as "Notaries" - they map enterprise
//! identities (AWS IAM ARNs, Okta users, YubiKey certificates) to Ed25519
//! public keys. Tenuo only cares about the cryptographic signature.
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
//! ## Implementation Status
//!
//! - [x] Approval struct (data model)
//! - [x] NotaryRegistry (key lifecycle management)
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
// Key Binding (Identity → Key Mapping)
// ============================================================================

/// A binding between an external identity and a Tenuo public key.
///
/// This is the core data structure for the Notary Registry, mapping
/// enterprise identities (IAM ARNs, Okta users, etc.) to Ed25519 keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBinding {
    /// Unique ID for this binding (e.g., "kb_<uuid>")
    pub id: String,

    /// External identity (e.g., "arn:aws:iam::123:user/admin")
    pub external_id: String,

    /// Provider name (e.g., "aws-iam", "okta", "yubikey")
    pub provider: String,

    /// The bound public key
    pub public_key: PublicKey,

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

    /// Register a new key binding.
    pub fn register_key(
        &mut self,
        binding: KeyBinding,
        actor: impl Into<String>,
    ) -> Result<()> {
        let actor = actor.into();

        if !self.has_provider(&binding.provider) {
            return Err(Error::UnknownProvider(binding.provider.clone()));
        }

        let key = (binding.provider.clone(), binding.external_id.clone());

        self.pending_events.push(
            AuditEvent::new(AuditEventType::KeyRegistered, &binding.provider, &actor)
                .with_identity(&binding.external_id)
                .with_key(&binding.public_key)
                .with_details(format!(
                    "Key registered for '{}'",
                    binding.display_name.as_deref().unwrap_or(&binding.external_id)
                )),
        );

        self.bindings.insert(key, binding);
        Ok(())
    }

    /// Rotate a key (update the public key for an existing binding).
    pub fn rotate_key(
        &mut self,
        provider: &str,
        external_id: &str,
        new_key: PublicKey,
        actor: impl Into<String>,
    ) -> Result<()> {
        let actor = actor.into();
        let key = (provider.to_string(), external_id.to_string());

        let binding = self.bindings.get_mut(&key).ok_or_else(|| {
            Error::UnknownProvider(format!("{}:{}", provider, external_id))
        })?;

        let old_key_hex = hex::encode(binding.public_key.to_bytes());

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
    pub fn revoke_key(
        &mut self,
        provider: &str,
        external_id: &str,
        reason: impl Into<String>,
        actor: impl Into<String>,
    ) -> Result<()> {
        let actor = actor.into();
        let reason = reason.into();
        let key = (provider.to_string(), external_id.to_string());

        let binding = self.bindings.get_mut(&key).ok_or_else(|| {
            Error::UnknownProvider(format!("{}:{}", provider, external_id))
        })?;

        binding.active = false;

        self.pending_events.push(
            AuditEvent::new(AuditEventType::KeyRevoked, provider, actor)
                .with_identity(external_id)
                .with_key(&binding.public_key)
                .with_details(format!("Revoked: {}", reason)),
        );

        Ok(())
    }

    /// Resolve an external identity to a public key.
    pub fn resolve(&self, provider: &str, external_id: &str) -> Result<&PublicKey> {
        let key = (provider.to_string(), external_id.to_string());

        let binding = self.bindings.get(&key).ok_or_else(|| {
            Error::UnknownProvider(format!("{}:{}", provider, external_id))
        })?;

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
        actor: impl Into<String>,
        details: Option<String>,
    ) {
        let mut event = AuditEvent::new(event_type, &approval.provider, actor)
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

        assert_eq!(hash1, hash2, "Hash should be deterministic regardless of insertion order");

        // Test that holder affects the hash
        let holder = crate::crypto::Keypair::generate();
        let hash_with_holder = compute_request_hash("wrt_123", "delete", &args1, Some(&holder.public_key()));
        assert_ne!(hash1, hash_with_holder, "Hash should differ when holder is included");
    }

    #[test]
    fn test_notary_registry_lifecycle() {
        let mut registry = NotaryRegistry::new();

        // Register a provider
        registry.register_provider("aws-iam", "AWS IAM Provider", "test");
        assert!(registry.has_provider("aws-iam"));

        // Create a key binding
        let keypair = Keypair::generate();
        let binding = KeyBinding {
            id: "kb_test_123".to_string(),
            external_id: "arn:aws:iam::123:user/admin".to_string(),
            provider: "aws-iam".to_string(),
            public_key: keypair.public_key(),
            display_name: Some("Admin User".to_string()),
            registered_by: "test".to_string(),
            registered_at: Utc::now(),
            expires_at: None,
            active: true,
            metadata: None,
        };

        // Register the key
        registry.register_key(binding, "test").unwrap();

        // Resolve the identity
        let resolved = registry.resolve("aws-iam", "arn:aws:iam::123:user/admin").unwrap();
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
        registry.register_provider("test", "Test Provider", "system");

        let old_keypair = Keypair::generate();
        let new_keypair = Keypair::generate();

        let binding = KeyBinding {
            id: "kb_rotate".to_string(),
            external_id: "user@example.com".to_string(),
            provider: "test".to_string(),
            public_key: old_keypair.public_key(),
            display_name: None,
            registered_by: "system".to_string(),
            registered_at: Utc::now(),
            expires_at: None,
            active: true,
            metadata: None,
        };

        registry.register_key(binding, "system").unwrap();

        // Rotate the key
        registry.rotate_key("test", "user@example.com", new_keypair.public_key(), "admin").unwrap();

        // Verify the new key is returned
        let resolved = registry.resolve("test", "user@example.com").unwrap();
        assert_eq!(resolved.to_bytes(), new_keypair.public_key().to_bytes());

        // Check audit events
        let events = registry.drain_events();
        assert!(events.iter().any(|e| e.event_type == AuditEventType::KeyRotated));
    }

    #[test]
    fn test_key_revocation() {
        let mut registry = NotaryRegistry::new();
        registry.register_provider("test", "Test Provider", "system");

        let keypair = Keypair::generate();
        let binding = KeyBinding {
            id: "kb_revoke".to_string(),
            external_id: "user@example.com".to_string(),
            provider: "test".to_string(),
            public_key: keypair.public_key(),
            display_name: None,
            registered_by: "system".to_string(),
            registered_at: Utc::now(),
            expires_at: None,
            active: true,
            metadata: None,
        };

        registry.register_key(binding, "system").unwrap();

        // Revoke the key
        registry.revoke_key("test", "user@example.com", "Compromised", "security-team").unwrap();

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

        let keypair = Keypair::generate();
        let binding = KeyBinding {
            id: "kb_fail".to_string(),
            external_id: "user@example.com".to_string(),
            provider: "unknown-provider".to_string(),
            public_key: keypair.public_key(),
            display_name: None,
            registered_by: "test".to_string(),
            registered_at: Utc::now(),
            expires_at: None,
            active: true,
            metadata: None,
        };

        let result = registry.register_key(binding, "test");
        assert!(result.is_err());
    }
}

