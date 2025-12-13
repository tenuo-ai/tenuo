//! Property-based tests for Tenuo's cryptographic invariants.
//!
//! These tests verify the core security guarantees:
//! 1. Attenuation Monotonicity - capabilities can only shrink
//! 2. Authorization Soundness - authorize returns true only when valid
//! 3. Signature Integrity - signatures are unforgeable
//! 4. Delegation Depth Bounded - depth never exceeds MAX_DEPTH

use proptest::prelude::*;
use std::collections::HashMap;
use std::time::Duration;
use tenuo_core::{
    constraints::{ConstraintValue, Pattern, Range},
    crypto::Keypair,
    warrant::Warrant,
    wire, Error, MAX_DELEGATION_DEPTH,
};

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
        let parent_kp = Keypair::generate();
        let child_kp = Keypair::generate();

        let parent = Warrant::builder()
            .tool("test_tool")
            .ttl(Duration::from_secs(ttl_parent))
            .authorized_holder(child_kp.public_key())
            .build(&parent_kp)
            .unwrap();

        let child = parent
            .attenuate()
            .ttl(Duration::from_secs(ttl_child))
            .authorized_holder(child_kp.public_key())
            .build(&child_kp, &child_kp)
            .unwrap();

        // INVARIANT: child.expires_at <= parent.expires_at
        prop_assert!(child.expires_at() <= parent.expires_at());
    }

    /// Child warrant depth is always parent depth + 1.
    #[test]
    fn attenuation_increments_depth(depth_limit in 1u32..=MAX_DELEGATION_DEPTH) {
        let kp = Keypair::generate();

        let mut warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(3600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .unwrap();

        prop_assert_eq!(warrant.depth(), 0);

        for expected_depth in 1..=depth_limit {
            warrant = warrant.attenuate().authorized_holder(kp.public_key()).build(&kp, &kp).unwrap();
            prop_assert_eq!(warrant.depth(), expected_depth);
        }
    }

    /// Attenuation to a wider pattern must fail.
    #[test]
    fn attenuation_pattern_cannot_widen(
        prefix in "[a-z]{1,3}",
    ) {
        let parent_kp = Keypair::generate();
        let child_kp = Keypair::generate();

        // Parent has narrow pattern
        let parent = Warrant::builder()
            .tool("test")
            .constraint("field", Pattern::new(&format!("{}-*", prefix)).unwrap())
            .ttl(Duration::from_secs(600))
            .authorized_holder(child_kp.public_key())
            .build(&parent_kp)
            .unwrap();

        // Attempt to widen to "*" should fail
        let result = parent
            .attenuate()
            .constraint("field", Pattern::new("*").unwrap())
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
        let parent_kp = Keypair::generate();
        let child_kp = Keypair::generate();

        let parent = Warrant::builder()
            .tool("test")
            .constraint("amount", Range::max(parent_max))
            .ttl(Duration::from_secs(600))
            .authorized_holder(child_kp.public_key())
            .build(&parent_kp)
            .unwrap();

        // Attempting to increase max should fail
        let result = parent
            .attenuate()
            .constraint("amount", Range::max(parent_max + child_delta))
            .authorized_holder(child_kp.public_key())
            .build(&child_kp, &child_kp);

        prop_assert!(result.is_err());

        // Decreasing max should succeed
        let narrower = parent
            .attenuate()
            .constraint("amount", Range::max(parent_max - child_delta.min(parent_max - 1.0)))
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

        let kp = Keypair::generate();
        let warrant = Warrant::builder()
            .tool(&tool1)
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
        let kp = Keypair::generate();

        let warrant = Warrant::builder()
            .tool("test")
            .constraint("cluster", Pattern::new(&format!("{}-*", prefix)).unwrap())
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
        let kp = Keypair::generate();

        let warrant = Warrant::builder()
            .tool("transfer")
            .constraint("amount", Range::max(max_val))
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
        let issuer_kp = Keypair::generate();
        let attacker_kp = Keypair::generate();

        let warrant = Warrant::builder()
            .tool(&tool)
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
        let kp = Keypair::generate();

        let original = Warrant::builder()
            .tool(&tool)
            .ttl(Duration::from_secs(ttl))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .unwrap();

        // Binary roundtrip
        let encoded = wire::encode(&original).unwrap();
        let decoded = wire::decode(&encoded).unwrap();

        prop_assert_eq!(decoded.id().as_str(), original.id().as_str());
        prop_assert_eq!(decoded.tool(), original.tool());
        prop_assert!(decoded.verify(&kp.public_key()).is_ok());

        // Base64 roundtrip
        let b64 = wire::encode_base64(&original).unwrap();
        let from_b64 = wire::decode_base64(&b64).unwrap();

        prop_assert_eq!(from_b64.id().as_str(), original.id().as_str());
        prop_assert!(from_b64.verify(&kp.public_key()).is_ok());
    }
}

// ============================================================================
// Invariant 4: Bounded Delegation Depth
// ============================================================================

proptest! {
    /// Delegation depth cannot exceed MAX_DELEGATION_DEPTH.
    #[test]
    fn depth_cannot_exceed_max(extra_attempts in 1u32..5u32) {
        let kp = Keypair::generate();

        let mut warrant = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(36000)) // Long TTL to not expire during test
            .authorized_holder(kp.public_key())
            .build(&kp)
            .unwrap();

        // Delegate up to max
        for _ in 0..MAX_DELEGATION_DEPTH {
            warrant = warrant.attenuate().authorized_holder(kp.public_key()).build(&kp, &kp).unwrap();
        }

        prop_assert_eq!(warrant.depth(), MAX_DELEGATION_DEPTH);

        // Any further delegation should fail
        for _ in 0..extra_attempts {
            let result = warrant.attenuate().authorized_holder(kp.public_key()).build(&kp, &kp);
            prop_assert!(result.is_err());
            match result.unwrap_err() {
                Error::DepthExceeded(got, max) => {
                    prop_assert_eq!(got, MAX_DELEGATION_DEPTH + 1);
                    prop_assert_eq!(max, MAX_DELEGATION_DEPTH);
                }
                e => prop_assert!(false, "Expected DepthExceeded, got {:?}", e),
            }
        }
    }
}

// ============================================================================
// Invariant 5: Unique Warrant IDs
// ============================================================================

proptest! {
    /// Every warrant gets a unique ID.
    #[test]
    fn warrant_ids_are_unique(count in 10usize..100usize) {
        let kp = Keypair::generate();

        let mut ids = std::collections::HashSet::new();

        for _ in 0..count {
            let warrant = Warrant::builder()
                .tool("test")
                .ttl(Duration::from_secs(60))
                .authorized_holder(kp.public_key())
                .build(&kp)
                .unwrap();

            let id = warrant.id().as_str().to_string();
            prop_assert!(!ids.contains(&id), "Duplicate warrant ID: {}", id);
            ids.insert(id);
        }
    }
}

// ============================================================================
// Chain of custody tests
// ============================================================================

proptest! {
    /// Parent ID is correctly set through delegation chain.
    #[test]
    fn parent_id_chain_is_correct(chain_length in 2u32..=10u32) {
        let kp = Keypair::generate();

        let root = Warrant::builder()
            .tool("test")
            .ttl(Duration::from_secs(3600))
            .authorized_holder(kp.public_key())
            .build(&kp)
            .unwrap();

        prop_assert!(root.parent_id().is_none());

        let mut parent = root;
        for _ in 1..chain_length {
            let child = parent.attenuate().authorized_holder(kp.public_key()).build(&kp, &kp).unwrap();
            prop_assert_eq!(
                child.parent_id().map(|id| id.as_str()),
                Some(parent.id().as_str())
            );
            parent = child;
        }
    }
}
