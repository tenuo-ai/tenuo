//! Property-based tests for Tenuo's cryptographic invariants.
//!
//! These tests verify the core security guarantees:
//! 1. Attenuation Monotonicity - capabilities can only shrink
//! 2. Authorization Soundness - authorize returns true only when valid
//! 3. Signature Integrity - signatures are unforgeable
//! 4. Delegation Depth Bounded - depth never exceeds MAX_DEPTH

use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;
use tenuo::{
    constraints::{ConstraintSet, ConstraintValue, Pattern, Range},
    crypto::SigningKey,
    warrant::Warrant,
    wire,
};

// Reasonable chain length for property tests (MAX_DELEGATION_DEPTH is 16)
const TEST_MAX_CHAIN_LENGTH: u32 = 10;

// ============================================================================
// Strategies for generating test data
// ============================================================================

fn arb_tool_name() -> impl Strategy<Value = String> {
    "[a-z_]{1,20}".prop_map(|s| s)
}

fn arb_ttl_secs() -> impl Strategy<Value = u64> {
    1u64..3600u64
}

// ============================================================================
// Invariant 1: Attenuation Monotonicity
// ============================================================================

proptest! {
    /// Child warrant expiration must never exceed parent expiration.
    #[test]
    fn attenuation_ttl_never_exceeds_parent(
        ttl_parent in arb_ttl_secs(),
        ttl_child in arb_ttl_secs(),
    ) {
        let parent_kp = SigningKey::generate();
        let child_kp = SigningKey::generate();

        let parent = Warrant::builder()
            .capability("test_tool", ConstraintSet::new())
            .ttl(Duration::from_secs(ttl_parent))
            .authorized_holder(child_kp.public_key())
            .build(&parent_kp)
            .unwrap();

        // POLA: inherit_all to get parent capabilities
        let child = parent
            .attenuate()
            .inherit_all()
            .ttl(Duration::from_secs(ttl_child))
            .authorized_holder(child_kp.public_key())
            .build(&child_kp, &child_kp)
            .unwrap();

        // INVARIANT: child.expires_at <= parent.expires_at
        prop_assert!(child.expires_at() <= parent.expires_at());
    }

    /// Child warrant depth is always parent depth + 1.
    /// Note: Limited to TEST_MAX_CHAIN_LENGTH for reasonable test duration.
    #[test]
    fn attenuation_increments_depth(depth_limit in 1u32..=TEST_MAX_CHAIN_LENGTH) {
        let kp = SigningKey::generate();

        let mut warrant = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .ttl(Duration::from_secs(3600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .unwrap();

        prop_assert_eq!(warrant.depth(), 0);

        for expected_depth in 1..=depth_limit {
            // POLA: inherit_all
            warrant = warrant.attenuate().inherit_all().authorized_holder(kp.public_key()).build(&kp, &kp).unwrap();
            prop_assert_eq!(warrant.depth(), expected_depth);
        }
    }

    /// Attenuation to a wider pattern must fail.
    #[test]
    fn attenuation_pattern_cannot_widen(
        prefix in "[a-z]{1,3}",
    ) {
        let parent_kp = SigningKey::generate();
        let child_kp = SigningKey::generate();

        // Parent has narrow pattern
        let mut parent_constraints = ConstraintSet::new();
        parent_constraints.insert("field", Pattern::new(&format!("{}-*", prefix)).unwrap());
        let parent = Warrant::builder()
            .capability("test", parent_constraints)
            .ttl(Duration::from_secs(600))
            .authorized_holder(child_kp.public_key())
            .build(&parent_kp)
            .unwrap();

        // Attempt to widen to "*" should fail
        let mut child_constraints = ConstraintSet::new();
        child_constraints.insert("field", Pattern::new("*").unwrap());
        let result = parent
            .attenuate()
            .capability("test", child_constraints)
            .authorized_holder(child_kp.public_key())
            .build(&child_kp, &child_kp);

        prop_assert!(result.is_err());
    }

    /// Attenuation of Range cannot increase max bound.
    #[test]
    fn attenuation_range_cannot_increase_max(
        parent_max in 100.0f64..10000.0f64,
        child_delta in 1.0f64..1000.0f64,
    ) {
        let parent_kp = SigningKey::generate();
        let child_kp = SigningKey::generate();

        let mut parent_constraints = ConstraintSet::new();
        parent_constraints.insert("amount", Range::max(parent_max).unwrap());
        let parent = Warrant::builder()
            .capability("test", parent_constraints)
            .ttl(Duration::from_secs(600))
            .authorized_holder(child_kp.public_key())
            .build(&parent_kp)
            .unwrap();

        // Attempting to increase max should fail
        let mut bad_constraints = ConstraintSet::new();
        bad_constraints.insert("amount", Range::max(parent_max + child_delta).unwrap());
        let result = parent
            .attenuate()
            .capability("test", bad_constraints)
            .authorized_holder(child_kp.public_key())
            .build(&child_kp, &child_kp);

        prop_assert!(result.is_err());

        // Decreasing max should succeed
        let mut narrow_constraints = ConstraintSet::new();
        narrow_constraints.insert("amount", Range::max(parent_max - child_delta.min(parent_max - 1.0)).unwrap());
        let narrower = parent
            .attenuate()
            .capability("test", narrow_constraints)
            .authorized_holder(child_kp.public_key())
            .build(&child_kp, &child_kp);

        prop_assert!(narrower.is_ok());
    }
}

// ============================================================================
// Invariant 2: Authorization Soundness
// ============================================================================

proptest! {
    /// Authorization succeeds only when constraints are satisfied.
    #[test]
    fn authorization_requires_matching_tool(
        tool1 in arb_tool_name(),
        tool2 in arb_tool_name(),
    ) {
        prop_assume!(tool1 != tool2);

        let kp = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability(&tool1, ConstraintSet::new())
            .ttl(Duration::from_secs(600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .unwrap();

        let args = HashMap::new();

        // Same tool should succeed
        let sig = warrant.create_pop_signature(&kp, &tool1, &args).unwrap();
        let res = warrant.authorize(&tool1, &args, Some(&sig));
        prop_assert!(res.is_ok());

        // Different tool should fail
        // Note: create_pop_signature might fail if tool doesn't match warrant tool,
        // but here we are testing authorize. Even if we sign for tool2, authorize should reject.
        // Actually, create_pop_signature doesn't check warrant tool, it just signs.
        let sig = warrant.create_pop_signature(&kp, &tool2, &args).unwrap();
        prop_assert!(warrant.authorize(&tool2, &args, Some(&sig)).is_err());
    }

    /// Authorization fails when pattern constraint doesn't match.
    #[test]
    fn authorization_pattern_rejects_non_matching(
        prefix in "[a-z]{1,3}",
        suffix in "[a-z]{1,5}",
    ) {
        let kp = SigningKey::generate();

        let mut constraints = ConstraintSet::new();
        constraints.insert("cluster", Pattern::new(&format!("{}-*", prefix)).unwrap());
        let warrant = Warrant::builder()
            .capability("test", constraints)
            .ttl(Duration::from_secs(600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .unwrap();

        // Matching value should pass
        let mut matching_args = HashMap::new();
        matching_args.insert(
            "cluster".to_string(),
            ConstraintValue::String(format!("{}-{}", prefix, suffix)),
        );
        let sig = warrant.create_pop_signature(&kp, "test", &matching_args).unwrap();
        prop_assert!(warrant.authorize("test", &matching_args, Some(&sig)).is_ok());

        // Non-matching value should fail
        let mut non_matching_args = HashMap::new();
        non_matching_args.insert(
            "cluster".to_string(),
            ConstraintValue::String(format!("other-{}", suffix)),
        );
        let sig = warrant.create_pop_signature(&kp, "test", &non_matching_args).unwrap();
        prop_assert!(warrant.authorize("test", &non_matching_args, Some(&sig)).is_err());
    }

    /// Authorization fails when range constraint exceeds bound.
    #[test]
    fn authorization_range_rejects_exceeding(
        max_val in 100.0f64..10000.0f64,
        delta in 1.0f64..1000.0f64,
    ) {
        let kp = SigningKey::generate();

        let mut constraints = ConstraintSet::new();
        constraints.insert("amount", Range::max(max_val).unwrap());
        let warrant = Warrant::builder()
            .capability("transfer", constraints)
            .ttl(Duration::from_secs(600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .unwrap();

        // Within range should pass
        let mut within_args = HashMap::new();
        within_args.insert(
            "amount".to_string(),
            ConstraintValue::Float(max_val - delta.min(max_val - 1.0)),
        );
        let sig = warrant.create_pop_signature(&kp, "transfer", &within_args).unwrap();
        prop_assert!(warrant.authorize("transfer", &within_args, Some(&sig)).is_ok());

        // Exceeding range should fail
        let mut exceeding_args = HashMap::new();
        exceeding_args.insert(
            "amount".to_string(),
            ConstraintValue::Float(max_val + delta),
        );
        let sig = warrant.create_pop_signature(&kp, "transfer", &exceeding_args).unwrap();
        prop_assert!(warrant.authorize("transfer", &exceeding_args, Some(&sig)).is_err());
    }
}

// ============================================================================
// Invariant 3: Signature Integrity
// ============================================================================

proptest! {
    /// Warrant verification succeeds only with correct public key.
    #[test]
    fn signature_verification_requires_correct_key(
        tool in arb_tool_name(),
        ttl in arb_ttl_secs(),
    ) {
        let issuer_kp = SigningKey::generate();
        let attacker_kp = SigningKey::generate();

        let warrant = Warrant::builder()
            .capability(&tool, ConstraintSet::new())
            .ttl(Duration::from_secs(ttl))
            .authorized_holder(issuer_kp.public_key())
            .build(&issuer_kp)
            .unwrap();

        // Verification with correct key should succeed
        prop_assert!(warrant.verify(&issuer_kp.public_key()).is_ok());

        // Verification with wrong key should fail
        prop_assert!(warrant.verify(&attacker_kp.public_key()).is_err());
    }

    /// Wire format roundtrip preserves warrant and signature.
    #[test]
    fn wire_roundtrip_preserves_warrant(
        tool in arb_tool_name(),
        ttl in arb_ttl_secs(),
    ) {
        let kp = SigningKey::generate();

        let original = Warrant::builder()
            .capability(&tool, ConstraintSet::new())
            .ttl(Duration::from_secs(ttl))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .unwrap();

        // Binary roundtrip
        let encoded = wire::encode(&original).unwrap();
        let decoded = wire::decode(&encoded).unwrap();

        prop_assert_eq!(decoded.id().to_string(), original.id().to_string());
        prop_assert_eq!(decoded.tools(), original.tools());
        prop_assert!(decoded.verify(&kp.public_key()).is_ok());

        // Base64 roundtrip
        let b64 = wire::encode_base64(&original).unwrap();
        let from_b64 = wire::decode_base64(&b64).unwrap();

        prop_assert_eq!(from_b64.id().to_string(), original.id().to_string());
        prop_assert!(from_b64.verify(&kp.public_key()).is_ok());
    }
}

// ============================================================================
// Invariant 4: Bounded Delegation Depth
// ============================================================================

proptest! {
    /// Delegation chain respects max_depth constraint.
    /// When depth reaches max_depth, the warrant is terminal.
    #[test]
    fn max_depth_limits_delegation(initial_max_depth in 2u32..10u32) {
        let kp = SigningKey::generate();

        let mut warrant = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .ttl(Duration::from_secs(36000)) // Long TTL to not expire during test
            .max_depth(initial_max_depth)
            .authorized_holder(kp.public_key())
            .build(&kp)
            .unwrap();

        prop_assert_eq!(warrant.depth(), 0);
        prop_assert_eq!(warrant.max_depth(), Some(initial_max_depth));

        // Delegate until depth reaches max_depth (POLA: inherit_all)
        for expected_depth in 1..=initial_max_depth {
            let result = warrant.attenuate().inherit_all().authorized_holder(kp.public_key()).build(&kp, &kp);
            if result.is_err() {
                // Expected to fail when terminal (depth >= max_depth)
                break;
            }
            warrant = result.unwrap();
            prop_assert_eq!(warrant.depth(), expected_depth, "depth should increment");
            prop_assert_eq!(warrant.max_depth(), Some(initial_max_depth), "max_depth is inherited");
        }

        // After max_depth delegations, warrant should be terminal
        prop_assert!(warrant.is_terminal() || warrant.depth() == initial_max_depth,
            "warrant should be terminal when depth reaches max_depth");
    }
}

// ============================================================================
// Invariant 5: Unique Warrant IDs
// ============================================================================

proptest! {
    /// Every warrant gets a unique ID.
    #[test]
    fn warrant_ids_are_unique(count in 10usize..100usize) {
        let kp = SigningKey::generate();

        let mut ids = std::collections::HashSet::new();

        for _ in 0..count {
            let warrant = Warrant::builder()
                .capability("test", ConstraintSet::new())
                .ttl(Duration::from_secs(60))
                .authorized_holder(kp.public_key())
                .build(&kp)
                .unwrap();

            let id = warrant.id().to_string().to_string();
            prop_assert!(!ids.contains(&id), "Duplicate warrant ID: {}", id);
            ids.insert(id);
        }
    }
}

// ============================================================================
// Chain of custody tests
// ============================================================================

proptest! {
    /// Parent hash is correctly set through delegation chain.
    /// Note: Limited to TEST_MAX_CHAIN_LENGTH for reasonable test duration.
    #[test]
    fn parent_hash_chain_is_correct(chain_length in 2u32..=TEST_MAX_CHAIN_LENGTH) {
        let kp = SigningKey::generate();

        let root = Warrant::builder()
            .capability("test", ConstraintSet::new())
            .ttl(Duration::from_secs(3600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .unwrap();

        prop_assert!(root.parent_hash().is_none());

        let mut parent = root;
        for _ in 1..chain_length {
            // POLA: inherit_all
            let child = parent.attenuate().inherit_all().authorized_holder(kp.public_key()).build(&kp, &kp).unwrap();

            let mut hasher = Sha256::new();
            hasher.update(parent.payload_bytes());
            let parent_hash: [u8; 32] = hasher.finalize().into();

            prop_assert_eq!(
                child.parent_hash(),
                Some(&parent_hash)
            );
            parent = child;
        }
    }
}
