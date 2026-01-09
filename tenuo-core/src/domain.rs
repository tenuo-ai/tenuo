//! Domain separation constants for cryptographic signatures.
//!
//! These context prefixes prevent cross-protocol signature reuse attacks.
//! Each operation type has a unique prefix that is prepended to the
//! signable payload before signing/verification.
//!
//! ## Security Rationale
//!
//! Without domain separation, a signature for one context could be replayed
//! in another. For example, a PoP signature could potentially be reused as
//! an approval signature if both used the same format.
//!
//! By prefixing each signature type with a unique context string, we ensure
//! signatures are only valid for their intended purpose.

/// Domain separation context for Proof-of-Possession signatures.
///
/// Used when an agent proves it controls the private key bound to a warrant.
pub const POP_CONTEXT: &[u8] = b"tenuo-pop-v1";

/// Domain separation context for Approval signatures.
///
/// Used in human-in-the-loop and multi-sig workflows when an approver
/// signs off on a specific request.
pub const APPROVAL_CONTEXT: &[u8] = b"tenuo-approval-v1";

/// Domain separation context for key registration proofs.
///
/// Used when registering a new key with a notary to prove ownership.
pub const REGISTRATION_PROOF_CONTEXT: &[u8] = b"tenuo-key-registration-v1";

/// Domain separation context for key rotation proofs.
///
/// Used when rotating keys to prove control of both old and new keys.
pub const ROTATION_PROOF_CONTEXT: &[u8] = b"tenuo-key-rotation-v1";

/// Domain separation context for warrant signatures.
///
/// Used when signing warrant payloads during issuance.
pub const WARRANT_CONTEXT: &[u8] = b"tenuo-warrant-v1";

