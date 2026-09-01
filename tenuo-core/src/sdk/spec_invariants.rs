//! Spec S-invariants and security-model checks for the shipped SDK surface.

use super::authority::{AuthorityError, PresentedAuthority, ReceivedAuthorization};
use super::call::{Call, VerifiedProjection};
use super::decision::{Denial, GuardError, Retryability, SdkDenialKind};
use super::guard::{Guard, GuardBuildError, RevocationMode};
use super::observe::{
    ObserveBuildError, ObservedOutcome, ObservingGuard, ObservingGuardBuilder, PresentedRequest,
};
use super::signer::{HolderSigner, LocalSigner, PopSigningRequest, SignerError};
use crate::approval_gate::{encode_approval_gate_map, ApprovalGateMap, ToolApprovalGate};
use crate::constraints::{ConstraintSet, ConstraintValue, Exact};
use crate::crypto::{Signature, SigningKey};
use crate::error::ErrorCode;
use crate::planes::Authorizer;
use crate::revocation::SignedRevocationList;
use crate::warrant::Warrant;
use crate::SIGNATURE_CONTEXT;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn mint(issuer: &SigningKey, holder: &SigningKey, tool: &str, ttl: Duration) -> Warrant {
    Warrant::builder()
        .capability(tool, ConstraintSet::new())
        .holder(holder.public_key())
        .ttl(ttl)
        .build(issuer)
        .expect("mint")
}

fn mint_constrained(
    issuer: &SigningKey,
    holder: &SigningKey,
    tool: &str,
    key: &str,
    value: &str,
) -> Warrant {
    let mut constraints = ConstraintSet::new();
    constraints.insert(key.to_string(), Exact::new(value));
    Warrant::builder()
        .capability(tool, constraints)
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .build(issuer)
        .expect("mint")
}

fn guard_for(issuer: &SigningKey) -> Guard {
    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    authorizer.set_clock_tolerance(chrono::Duration::zero());
    Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .build()
        .expect("guard")
}

fn authority(chain: Vec<Warrant>, holder: SigningKey) -> PresentedAuthority {
    PresentedAuthority::new(chain, Arc::new(LocalSigner::new(holder))).expect("authority")
}

fn deny_runs(err: GuardError<&str>, runs: &AtomicUsize) -> Denial {
    assert_eq!(runs.load(Ordering::SeqCst), 0, "S11: deny must not run op");
    match err {
        GuardError::Denied(denial) => denial,
        GuardError::Operation(_) => panic!("S11: operation must not run"),
    }
}

/// S1 / S11: an empty chain cannot become a presented authority, so guard
/// cannot be entered with no authority.
#[test]
fn s1_empty_authority_never_reaches_operation() {
    let holder = SigningKey::generate();
    assert_eq!(
        PresentedAuthority::new(vec![], Arc::new(LocalSigner::new(holder)))
            .err()
            .unwrap(),
        AuthorityError::EmptyChain
    );
}

/// S2: empty trust store is rejected; a self-signed attacker root is denied.
#[test]
fn s2_empty_trust_and_self_signed_attacker() {
    let empty = Guard::builder()
        .authorizer(Authorizer::new())
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(60),
        })
        .build()
        .err()
        .unwrap();
    assert_eq!(empty, GuardBuildError::EmptyTrustStore);

    let real_root = SigningKey::generate();
    let attacker = SigningKey::generate();
    let warrant = mint(&attacker, &attacker, "read", Duration::from_secs(300));
    let authority = authority(vec![warrant], attacker);
    let args = HashMap::new();
    let call = Call::borrowed("read", &args);
    let runs = AtomicUsize::new(0);
    let denial = deny_runs(
        guard_for(&real_root)
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .unwrap(),
        &runs,
    );
    assert!(denial.protocol_code().is_some());
}

/// S3: an expired warrant is denied at call time through Guard, not an
/// SDK-side predicate. Tolerance is zero so a 1s TTL is expired after 1.1s.
#[test]
fn s3_expired_warrant_denied_at_call_time() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = mint(&issuer, &holder, "read", Duration::from_secs(1));
    let authority = authority(vec![warrant], holder);
    let guard = guard_for(&issuer);
    std::thread::sleep(Duration::from_millis(1100));
    let args = HashMap::new();
    let call = Call::borrowed("read", &args);
    let runs = AtomicUsize::new(0);
    let denial = deny_runs(
        guard
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .unwrap(),
        &runs,
    );
    assert_eq!(denial.protocol_code(), Some(ErrorCode::WarrantExpired));
}

/// Security model: constraints are scoped; a mismatched argument is denied.
#[test]
fn scoped_constraint_mismatch_denies() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = mint_constrained(&issuer, &holder, "read", "path", "/data");
    let authority = authority(vec![warrant], holder);
    let guard = guard_for(&issuer);
    let mut args = HashMap::new();
    args.insert("path".into(), ConstraintValue::from("/etc"));
    let call = Call::borrowed("read", &args);
    let runs = AtomicUsize::new(0);
    let denial = deny_runs(
        guard
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .unwrap(),
        &runs,
    );
    assert_eq!(denial.protocol_code(), Some(ErrorCode::ConstraintViolation));
}

/// S5 / Bound: stolen chain without the leaf key is rejected.
#[test]
fn s5_stolen_warrant_without_holder_key_rejected() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let thief = SigningKey::generate();
    let warrant = mint(&issuer, &holder, "read", Duration::from_secs(300));
    assert_eq!(
        PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(thief)))
            .err()
            .unwrap(),
        AuthorityError::SignerMismatch
    );
}

/// S7: a boolean does not satisfy an approval gate.
#[test]
fn s7_approval_gate_not_satisfied_by_absence() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let approver = SigningKey::generate();
    let mut gates = ApprovalGateMap::new();
    gates.insert("sensitive".into(), ToolApprovalGate::whole_tool());
    let warrant = Warrant::builder()
        .capability("sensitive", ConstraintSet::new())
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .required_approvers(vec![approver.public_key()])
        .min_approvals(1)
        .extension(
            "tenuo.approval_gates",
            encode_approval_gate_map(&gates).unwrap(),
        )
        .build(&issuer)
        .unwrap();
    let authority = authority(vec![warrant], holder);
    let guard = guard_for(&issuer);
    let args = HashMap::new();
    let call = Call::borrowed("sensitive", &args);
    let runs = AtomicUsize::new(0);
    let denial = deny_runs(
        guard
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .unwrap(),
        &runs,
    );
    assert_eq!(denial.protocol_code(), Some(ErrorCode::ApprovalRequired));
    assert!(denial.needs_approval());
    assert!(denial.approval_request().is_some());
    assert_eq!(denial.retryability(), Retryability::AfterApproval);
}

/// S8: SignedSrl does not fall back to TtlOnly.
#[test]
fn s8_signed_srl_does_not_fallback() {
    let issuer = SigningKey::generate();
    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    let err = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::SignedSrl)
        .build()
        .err()
        .unwrap();
    assert_eq!(err, GuardBuildError::SignedSrlUnavailable);
}

/// S8 / S34: a SignedSrl snapshot is what decides, including a revoked leaf.
#[test]
fn s8_s34_signed_srl_revokes_at_guard() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = mint(&issuer, &holder, "read", Duration::from_secs(300));
    let srl = SignedRevocationList::builder()
        .revoke(warrant.id().to_string())
        .version(1)
        .build(&issuer)
        .unwrap();
    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    authorizer
        .set_revocation_list(srl, &issuer.public_key())
        .unwrap();
    let guard = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::SignedSrl)
        .build()
        .unwrap();
    let authority = authority(vec![warrant], holder);
    let args = HashMap::new();
    let call = Call::borrowed("read", &args);
    let runs = AtomicUsize::new(0);
    let denial = deny_runs(
        guard
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .unwrap(),
        &runs,
    );
    assert_eq!(denial.protocol_code(), Some(ErrorCode::WarrantRevoked));
}

/// S17 / S33: secrets and diagnostics stay out of caller-visible denial text.
#[test]
fn s17_s33_no_key_or_diagnostic_leak_in_denial() {
    let secret = [0x5a_u8; 32];
    let issuer = SigningKey::from_bytes(&secret);
    let holder = SigningKey::generate();
    let warrant = mint(&issuer, &holder, "read", Duration::from_secs(300));
    let leaf_id = warrant.id().to_string();
    let authority = authority(vec![warrant], holder);
    let guard = guard_for(&issuer);
    let args = HashMap::new();
    let call = Call::borrowed("write", &args);
    let denial = guard.check(&authority, &call).err().unwrap();

    let secret_hex = hex::encode(secret);
    let surfaces = [
        format!("{denial}"),
        format!("{denial:?}"),
        denial.message().to_string(),
        format!("{:?}", LocalSigner::new(issuer.clone())),
        format!("{}", LocalSigner::new(issuer)),
        format!("{authority:?}"),
    ];
    for text in &surfaces {
        assert!(
            !text.contains(&secret_hex),
            "S17: secret material leaked: {text}"
        );
    }
    assert_eq!(denial.message(), ErrorCode::ToolNotAuthorized.description());
    let diag = guard.diagnostics(&authority).explain_denial(&denial);
    assert_ne!(denial.message(), diag);
    assert!(diag.contains(&leaf_id));
    assert!(!denial.message().contains(&leaf_id));
    assert!(!denial.to_string().contains(&leaf_id));
}

/// S22: the SDK module has no ambient authority slots.
#[test]
fn s22_authority_is_an_explicit_argument() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/sdk/guard.rs"));
    for needle in ["thread_local!", "task_local!", "std::env::", "OnceLock"] {
        assert!(
            !src.contains(needle),
            "S22: ambient authority primitive {needle} found in guard.rs"
        );
    }
}

/// S24: borrowed and owned views are identical; split views require a projection.
#[test]
fn s24_borrowed_and_owned_views_are_identical() {
    let mut args = HashMap::new();
    args.insert("n".into(), ConstraintValue::from(1_i64));
    let borrowed = Call::borrowed("read", &args);
    assert!(std::ptr::eq(
        borrowed.pop_args(),
        borrowed.constraint_args()
    ));

    let owned = Call::owned("read", args.clone()).unwrap();
    assert_eq!(owned.pop_args(), owned.constraint_args());

    let mut pop = HashMap::new();
    pop.insert("n".into(), ConstraintValue::from(1_i64));
    let mut constraints = HashMap::new();
    constraints.insert("n".into(), ConstraintValue::from(2_i64));
    let projection = VerifiedProjection::split(pop, constraints);
    let split = Call::from_transport("read", &projection);
    assert_ne!(split.pop_args(), split.constraint_args());
}

/// S26 / S27: core denials keep ErrorCode; signer outage is not approval-required.
#[test]
fn s26_s27_protocol_code_and_signer_outage() {
    struct FailingSigner {
        key: SigningKey,
    }
    impl HolderSigner for FailingSigner {
        fn public_key(&self) -> crate::crypto::PublicKey {
            self.key.public_key()
        }
        fn sign_pop(&self, _: &PopSigningRequest<'_>) -> Result<Signature, SignerError> {
            Err(SignerError::Unavailable)
        }
        fn sign_delegation(
            &self,
            _: &super::DelegationSigningRequest<'_>,
        ) -> Result<Signature, SignerError> {
            Err(SignerError::Unavailable)
        }
    }

    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = mint(&issuer, &holder, "read", Duration::from_secs(300));
    let authority =
        PresentedAuthority::new(vec![warrant], Arc::new(FailingSigner { key: holder })).unwrap();
    let guard = guard_for(&issuer);
    let args = HashMap::new();
    let call = Call::borrowed("read", &args);
    let denial = guard.check(&authority, &call).err().unwrap();
    assert_eq!(denial.sdk_kind(), Some(SdkDenialKind::SignerUnavailable));
    assert_ne!(denial.protocol_code(), Some(ErrorCode::ApprovalRequired));
    assert!(!denial.needs_approval());
    assert_eq!(denial.retryability(), Retryability::AfterBackoff);
}

/// S28 / S40 / S42: Guard decides only through check_chain_with_context.
#[test]
fn s28_s40_guard_uses_context_decision_only() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/sdk/guard.rs"));
    assert!(src.contains("check_chain_with_context"));
    assert!(!src.contains("check_chain_with_pop_args("));
    assert!(!src.contains("authorize_one("));
    assert!(!src.contains("check_chain("));
}

/// S37: TtlOnly ceiling applies through Guard, not only the core helper.
#[test]
fn s37_ttl_only_ceiling_denies_overlong_warrant() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = mint(&issuer, &holder, "read", Duration::from_secs(3600));
    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    let guard = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(60),
        })
        .build()
        .unwrap();
    let authority = authority(vec![warrant], holder);
    let args = HashMap::new();
    let call = Call::borrowed("read", &args);
    let runs = AtomicUsize::new(0);
    let denial = deny_runs(
        guard
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .unwrap(),
        &runs,
    );
    assert_eq!(denial.protocol_code(), Some(ErrorCode::TTLExceeded));
}

/// S35 / S39: a raw signer over final_signing_bytes verifies; double-prefix does not.
#[test]
fn s35_s39_raw_signer_verifies_double_prefix_does_not() {
    struct RawSigner(SigningKey);
    impl HolderSigner for RawSigner {
        fn public_key(&self) -> crate::crypto::PublicKey {
            self.0.public_key()
        }
        fn sign_pop(&self, request: &PopSigningRequest<'_>) -> Result<Signature, SignerError> {
            Ok(self.0.sign_raw(&request.final_signing_bytes()))
        }
        fn sign_delegation(
            &self,
            request: &super::DelegationSigningRequest<'_>,
        ) -> Result<Signature, SignerError> {
            Ok(self.0.sign_raw(request.final_signing_bytes()))
        }
    }

    struct DoublePrefixSigner(SigningKey);
    impl HolderSigner for DoublePrefixSigner {
        fn public_key(&self) -> crate::crypto::PublicKey {
            self.0.public_key()
        }
        fn sign_pop(&self, request: &PopSigningRequest<'_>) -> Result<Signature, SignerError> {
            Ok(self.0.sign(&request.final_signing_bytes()))
        }
        fn sign_delegation(
            &self,
            request: &super::DelegationSigningRequest<'_>,
        ) -> Result<Signature, SignerError> {
            Ok(self.0.sign(request.final_signing_bytes()))
        }
    }

    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = mint(&issuer, &holder, "read", Duration::from_secs(300));
    let args = HashMap::new();
    let call = Call::borrowed("read", &args);
    let guard = guard_for(&issuer);

    let raw = PresentedAuthority::new(vec![warrant.clone()], Arc::new(RawSigner(holder.clone())))
        .unwrap();
    guard
        .check(&raw, &call)
        .expect("S35/S39 raw signer must verify");

    let doubled =
        PresentedAuthority::new(vec![warrant], Arc::new(DoublePrefixSigner(holder))).unwrap();
    let denial = guard.check(&doubled, &call).err().unwrap();
    assert!(matches!(
        denial.protocol_code(),
        Some(ErrorCode::PopSignatureInvalid | ErrorCode::SignatureInvalid)
    ));
}

/// S39: LocalSigner final bytes are SIGNATURE_CONTEXT || preimage, signed raw.
#[test]
fn s39_final_signing_bytes_are_context_plus_preimage() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = mint(&issuer, &holder, "read", Duration::from_secs(300));
    let args = HashMap::new();
    let preimage = warrant
        .pop_preimage("read", &args, 1_700_000_000, 30)
        .unwrap();
    let request = PopSigningRequest::new(preimage.clone(), "read", warrant.id().to_string());
    let final_bytes = request.final_signing_bytes();
    assert!(final_bytes.starts_with(SIGNATURE_CONTEXT));
    assert_eq!(&final_bytes[SIGNATURE_CONTEXT.len()..], preimage.as_slice());

    let local = LocalSigner::new(holder.clone());
    let via_local = local.sign_pop(&request).unwrap();
    let via_raw = holder.sign_raw(&final_bytes);
    assert_eq!(via_local.to_bytes(), via_raw.to_bytes());
}

/// S40: received path never invokes a holder signer.
#[test]
fn s40_received_path_does_not_sign() {
    struct Counting(LocalSigner, AtomicUsize);
    impl HolderSigner for Counting {
        fn public_key(&self) -> crate::crypto::PublicKey {
            self.0.public_key()
        }
        fn sign_pop(&self, request: &PopSigningRequest<'_>) -> Result<Signature, SignerError> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.sign_pop(request)
        }
        fn sign_delegation(
            &self,
            request: &super::DelegationSigningRequest<'_>,
        ) -> Result<Signature, SignerError> {
            self.0.sign_delegation(request)
        }
    }

    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = mint(&issuer, &holder, "read", Duration::from_secs(300));
    let signer = Arc::new(Counting(LocalSigner::new(holder), AtomicUsize::new(0)));
    let presented = PresentedAuthority::new(vec![warrant], signer.clone()).unwrap();
    let guard = guard_for(&issuer);
    let args = HashMap::new();
    let call = Call::borrowed("read", &args);
    let pop = guard
        .guard(&presented, &call, |authorized| {
            Ok::<_, &str>(authorized.pop_signature().clone())
        })
        .unwrap()
        .into_inner();
    let after_holder = signer.1.load(Ordering::SeqCst);
    assert_eq!(after_holder, 1);

    let received = ReceivedAuthorization::new(presented.chain(), &pop, &[]).unwrap();
    let projection = VerifiedProjection::identical(HashMap::new());
    let inbound = Call::from_transport("read", &projection);
    let _ = guard
        .guard_received(&received, &inbound, |_| Ok::<_, &str>(()))
        .unwrap();
    assert_eq!(
        signer.1.load(Ordering::SeqCst),
        after_holder,
        "S40: received path must not sign"
    );
}

/// S41: HTTP encode emits the AuthorizedCall PoP, not a new signature.
#[cfg(feature = "http-transport")]
#[test]
fn s41_http_encode_reuses_authorized_pop() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = mint(&issuer, &holder, "read", Duration::from_secs(300));
    let presented = authority(vec![warrant], holder);
    let guard = guard_for(&issuer);
    let args = HashMap::new();
    let call = Call::borrowed("read", &args);
    let _ = guard
        .guard(&presented, &call, |authorized| {
            let headers = super::transport::http::headers_from_authorized(authorized).unwrap();
            let owned = super::transport::http::extract_headers(&headers).unwrap();
            assert_eq!(owned.signature(), authorized.pop_signature());
            Ok::<_, &str>(())
        })
        .unwrap();
}

/// S43: Guard builder only resolves TtlOnly or Snapshot.
#[test]
fn s43_guard_cannot_select_not_configured() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/sdk/guard.rs"));
    assert!(!src.contains("NotConfigured"));
    assert!(src.contains("ResolvedRevocation::TtlOnly") || src.contains("TtlOnly {"));
}

/// Security model: PoP is required; a received envelope with a junk signature
/// cannot run the operation.
#[test]
fn pop_required_junk_signature_denied() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let other = SigningKey::generate();
    let warrant = mint(&issuer, &holder, "read", Duration::from_secs(300));
    let presented = authority(vec![warrant], holder);
    let junk = other.sign_raw(b"replay");
    let received = ReceivedAuthorization::new(presented.chain(), &junk, &[]).unwrap();
    let projection = VerifiedProjection::identical(HashMap::new());
    let inbound = Call::from_transport("read", &projection);
    let runs = AtomicUsize::new(0);
    let _ = deny_runs(
        guard_for(&issuer)
            .guard_received(&received, &inbound, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .unwrap(),
        &runs,
    );
}

/// S29 / S44: ObservingGuard is a distinct type with no reverse conversion.
#[test]
fn s29_s44_observer_is_not_a_guard() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/sdk/observe.rs"));
    let deref_impl = format!("impl {}::ops::{}", "std", "Deref");
    let deref_fn = ["fn ", "deref("].concat();
    assert!(!src.contains(&deref_impl) && !src.contains(&deref_fn));
    assert!(!src.contains(&["fn into", "_guard"].concat()));
    assert_eq!(
        ObservingGuard::builder().build().err().unwrap(),
        ObserveBuildError::MissingGuard
    );
}

/// S30: construction requires an expiry; an expired observer does not invoke.
#[test]
fn s30_expired_observer_does_not_invoke() {
    let issuer = SigningKey::generate();
    let guard = guard_for(&issuer);
    assert_eq!(
        ObservingGuardBuilder::from_guard(&guard)
            .build()
            .err()
            .unwrap(),
        ObserveBuildError::MissingExpiry
    );
    let observer = guard.observe_until(chrono::Utc::now() - chrono::Duration::seconds(1));
    let args = HashMap::new();
    let call = Call::borrowed("read", &args);
    let runs = AtomicUsize::new(0);
    let err = observer
        .observe(PresentedRequest::Missing, &call, || {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &str>(())
        })
        .err()
        .unwrap();
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    assert!(matches!(err, super::observe::ObserveError::Expired));
}

/// S31: observe runs the same decision stages, labels observe-only, no receipt.
#[test]
fn s31_observe_matches_enforcement_and_is_labeled() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let presented = authority(
        vec![mint(&issuer, &holder, "read", Duration::from_secs(300))],
        holder,
    );
    let guard = guard_for(&issuer);
    let args = HashMap::new();
    let allow_call = Call::borrowed("read", &args);
    let deny_call = Call::borrowed("write", &args);
    assert!(guard.check(&presented, &allow_call).is_ok());
    assert!(guard.check(&presented, &deny_call).is_err());

    let observer = guard.observe_until(chrono::Utc::now() + chrono::Duration::hours(1));
    let allowed = observer
        .observe(PresentedRequest::Holder(&presented), &allow_call, || {
            Ok::<_, &str>(())
        })
        .unwrap();
    assert!(matches!(allowed.outcome, ObservedOutcome::WouldAllow));
    assert!(allowed.observation.is_observe_only());
    assert_eq!(allowed.observation.policy_mode(), "observe");

    let denied = observer
        .observe(PresentedRequest::Holder(&presented), &deny_call, || {
            Ok::<_, &str>(())
        })
        .unwrap();
    assert!(matches!(denied.outcome, ObservedOutcome::WouldDeny(_)));

    let missing = observer
        .observe(PresentedRequest::Missing, &allow_call, || Ok::<_, &str>(()))
        .unwrap();
    assert!(matches!(
        missing.outcome,
        ObservedOutcome::WouldDenyNoAuthority
    ));
}

/// S9: the sync builder rejects a deadline it cannot enforce.
#[cfg(feature = "async")]
#[test]
fn s9_sync_surface_rejects_deadline() {
    let issuer = SigningKey::generate();
    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    let err = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .deadline(Duration::from_secs(30))
        .build()
        .err()
        .unwrap();
    assert_eq!(err, GuardBuildError::DeadlineNotEnforceable);
}

/// S12: BestEffort evidence failure does not change allow.
#[cfg(feature = "receipts")]
#[test]
fn s12_best_effort_receipt_failure_does_not_deny() {
    use super::evidence::{
        EvidencePolicy, LocalReceiptSigner, ReceiptRef, ReceiptSink, ReceiptSinkError,
    };
    use crate::receipt::Receipt;
    struct FailSink;
    impl ReceiptSink for FailSink {
        fn persist(&self, _: &Receipt) -> Result<ReceiptRef, ReceiptSinkError> {
            Err(ReceiptSinkError::Unavailable)
        }
    }
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let presented = authority(
        vec![mint(&issuer, &holder, "read", Duration::from_secs(300))],
        holder,
    );
    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    let guard = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .evidence_policy(EvidencePolicy::BestEffort)
        .receipt_signer(Arc::new(LocalReceiptSigner::for_development()))
        .receipt_sink(Arc::new(FailSink))
        .build()
        .unwrap();
    let args = HashMap::new();
    let call = Call::borrowed("read", &args);
    let decision = guard.check(&presented, &call).expect("S12: still allow");
    assert!(decision.receipt.is_some());
}
