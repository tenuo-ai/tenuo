use super::authority::{PresentedAuthority, ReceivedAuthorization};
use super::call::Call;
use super::decision::{
    Decision, DecisionMetadata, Denial, DenialReporting, GuardError, Retryability, SdkDenialKind,
};
use super::diagnostics::Diagnostics;
use super::signer::PopSigningRequest;
use crate::approval::SignedApproval;
use crate::constraints::ConstraintValue;
use crate::crypto::Signature;
use crate::planes::Authorizer;
use crate::verification::{
    RevocationSnapshot, RevocationState, VerificationContext, VerificationInstant,
};
use crate::warrant::Warrant;
use chrono::Utc;
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

/// Explicit revocation policy. No implicit fallback from SignedSrl to TtlOnly.
#[derive(Clone, Debug)]
pub enum RevocationMode {
    TtlOnly { max_lifetime: Duration },
    SignedSrl,
}

/// Enforcement surface. Holds configuration, nothing per-call.
pub struct Guard {
    authorizer: Authorizer,
    revocation: ResolvedRevocation,
    denial_reporting: DenialReporting,
}

enum ResolvedRevocation {
    TtlOnly { max_lifetime: Duration },
    Snapshot(RevocationSnapshot),
}

impl Guard {
    pub fn builder() -> GuardBuilder {
        GuardBuilder::default()
    }

    pub fn check(
        &self,
        authority: &PresentedAuthority,
        call: &Call<'_>,
    ) -> Result<Decision, Denial> {
        self.check_attempt(authority, AuthorizationAttempt::new(call))
    }

    pub fn check_attempt(
        &self,
        authority: &PresentedAuthority,
        attempt: AuthorizationAttempt<'_, '_>,
    ) -> Result<Decision, Denial> {
        let authorized = self.authorize_holder(authority, &attempt)?;
        Ok(authorized.into_decision())
    }

    pub fn guard<T, E>(
        &self,
        authority: &PresentedAuthority,
        call: &Call<'_>,
        op: impl FnOnce(&AuthorizedCall<'_>) -> Result<T, E>,
    ) -> Result<Guarded<T>, GuardError<E>> {
        self.guard_attempt(authority, AuthorizationAttempt::new(call), op)
    }

    pub fn guard_attempt<T, E>(
        &self,
        authority: &PresentedAuthority,
        attempt: AuthorizationAttempt<'_, '_>,
        op: impl FnOnce(&AuthorizedCall<'_>) -> Result<T, E>,
    ) -> Result<Guarded<T>, GuardError<E>> {
        let authorized = self
            .authorize_holder(authority, &attempt)
            .map_err(GuardError::Denied)?;
        let decision = authorized.as_decision();
        let value = op(&authorized).map_err(GuardError::Operation)?;
        Ok(Guarded { value, decision })
    }

    pub fn check_received(
        &self,
        received: &ReceivedAuthorization<'_>,
        call: &Call<'_>,
    ) -> Result<Decision, Denial> {
        let authorized = self.authorize_received(received, call)?;
        Ok(authorized.into_decision())
    }

    pub fn guard_received<T, E>(
        &self,
        received: &ReceivedAuthorization<'_>,
        call: &Call<'_>,
        op: impl FnOnce(&AuthorizedCall<'_>) -> Result<T, E>,
    ) -> Result<Guarded<T>, GuardError<E>> {
        let authorized = self
            .authorize_received(received, call)
            .map_err(GuardError::Denied)?;
        let decision = authorized.as_decision();
        let value = op(&authorized).map_err(GuardError::Operation)?;
        Ok(Guarded { value, decision })
    }

    /// Operator-side explanation. Never for caller-visible text.
    pub fn diagnostics<'a>(&'a self, authority: &'a PresentedAuthority) -> Diagnostics<'a> {
        Diagnostics::holder(self, authority)
    }

    pub fn diagnostics_received<'a>(
        &'a self,
        received: &'a ReceivedAuthorization<'a>,
    ) -> Diagnostics<'a> {
        Diagnostics::received(self, received)
    }

    #[allow(dead_code)]
    pub(crate) fn denial_reporting(&self) -> DenialReporting {
        self.denial_reporting
    }

    fn authorize_holder<'a>(
        &'a self,
        authority: &'a PresentedAuthority,
        attempt: &AuthorizationAttempt<'a, 'a>,
    ) -> Result<AuthorizedCall<'a>, Denial> {
        let as_of = Utc::now();
        let instant = VerificationInstant::new(as_of);

        if !authority.signer_matches_leaf() {
            return Err(Denial::sdk(
                SdkDenialKind::SignerUnavailable,
                Retryability::AfterBackoff,
                "holder signer does not match leaf",
            ));
        }

        let call = attempt.call;
        let leaf = authority.leaf();
        let (window_secs, _) = self.authorizer.pop_window_config();
        let preimage = leaf
            .pop_preimage(
                call.capability(),
                call.pop_args(),
                as_of.timestamp(),
                window_secs,
            )
            .map_err(Denial::from_core)?;
        let request = PopSigningRequest::new(preimage, call.capability(), leaf.id().to_string());
        let pop_signature = authority.signer().sign_pop(&request).map_err(|_| {
            Denial::sdk(
                SdkDenialKind::SignerUnavailable,
                Retryability::AfterBackoff,
                "holder signer unavailable",
            )
        })?;

        self.decide(
            authority.chain(),
            pop_signature,
            attempt.approvals,
            call,
            instant,
        )
    }

    fn authorize_received<'a>(
        &'a self,
        received: &'a ReceivedAuthorization<'a>,
        call: &'a Call<'a>,
    ) -> Result<AuthorizedCall<'a>, Denial> {
        let instant = VerificationInstant::new(Utc::now());
        self.decide(
            received.chain(),
            received.signature().clone(),
            received.approvals(),
            call,
            instant,
        )
    }

    fn decide<'a>(
        &'a self,
        chain: &'a [Warrant],
        pop_signature: Signature,
        approvals: &'a [SignedApproval],
        call: &'a Call<'a>,
        instant: VerificationInstant,
    ) -> Result<AuthorizedCall<'a>, Denial> {
        let _ = self.denial_reporting;
        let revocation = match &self.revocation {
            ResolvedRevocation::TtlOnly { max_lifetime } => RevocationState::TtlOnly {
                max_lifetime: *max_lifetime,
            },
            ResolvedRevocation::Snapshot(snapshot) => RevocationState::Snapshot(snapshot),
        };
        let context = VerificationContext::new(instant.as_datetime(), revocation);

        self.authorizer
            .check_chain_with_context(
                chain,
                call.capability(),
                call.pop_args(),
                call.constraint_args(),
                Some(&pop_signature),
                approvals,
                &context,
            )
            .map_err(Denial::from_core)?;

        let invocation_id = uuid::Uuid::new_v4().to_string();
        let decision_id = uuid::Uuid::new_v4().to_string();
        let dedup_key = format!("{}:{}", call.capability(), invocation_id);

        Ok(AuthorizedCall {
            invocation_id,
            dedup_key,
            decision_id,
            capability: call.capability(),
            instant,
            execution_args: call.constraint_args(),
            pop_signature,
            chain,
            approvals,
        })
    }
}

/// Zero-approval or approval-bearing holder attempt.
pub struct AuthorizationAttempt<'attempt, 'args> {
    call: &'attempt Call<'args>,
    approvals: &'attempt [SignedApproval],
}

impl<'attempt, 'args> AuthorizationAttempt<'attempt, 'args> {
    pub fn new(call: &'attempt Call<'args>) -> Self {
        Self {
            call,
            approvals: &[],
        }
    }

    pub fn with_approvals(
        call: &'attempt Call<'args>,
        approvals: &'attempt [SignedApproval],
    ) -> Self {
        Self { call, approvals }
    }
}

/// Borrow scoped to one allowed invocation. Not a capability.
pub struct AuthorizedCall<'a> {
    invocation_id: String,
    dedup_key: String,
    decision_id: String,
    capability: &'a str,
    instant: VerificationInstant,
    execution_args: &'a HashMap<String, ConstraintValue>,
    pop_signature: Signature,
    chain: &'a [Warrant],
    approvals: &'a [SignedApproval],
}

impl<'a> AuthorizedCall<'a> {
    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    pub fn dedup_key(&self) -> &str {
        &self.dedup_key
    }

    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    pub fn capability(&self) -> &str {
        self.capability
    }

    pub fn instant(&self) -> VerificationInstant {
        self.instant
    }

    pub fn execution_args(&self) -> &HashMap<String, ConstraintValue> {
        self.execution_args
    }

    pub fn pop_signature(&self) -> &Signature {
        &self.pop_signature
    }

    pub fn chain(&self) -> &[Warrant] {
        self.chain
    }

    pub fn approvals(&self) -> &[SignedApproval] {
        self.approvals
    }

    fn as_decision(&self) -> Decision {
        Decision {
            metadata: DecisionMetadata {
                decision_id: self.decision_id.clone(),
                invocation_id: self.invocation_id.clone(),
                dedup_key: self.dedup_key.clone(),
                capability: self.capability.to_string(),
                chain_depth: self.chain.len(),
                timestamp: self.instant.as_datetime(),
            },
            receipt: None,
        }
    }

    fn into_decision(self) -> Decision {
        self.as_decision()
    }
}

/// Result of an allowed guarded operation.
#[must_use]
pub struct Guarded<T> {
    pub value: T,
    pub decision: Decision,
}

impl<T> Guarded<T> {
    pub fn into_inner(self) -> T {
        self.value
    }
}

/// Build a [`Guard`]. Rejects an empty trust store and a missing revocation mode.
#[derive(Default)]
pub struct GuardBuilder {
    authorizer: Option<Authorizer>,
    revocation: Option<RevocationMode>,
    denial_reporting: DenialReporting,
}

impl GuardBuilder {
    pub fn authorizer(mut self, authorizer: Authorizer) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    pub fn revocation(mut self, mode: RevocationMode) -> Self {
        self.revocation = Some(mode);
        self
    }

    pub fn denial_reporting(mut self, reporting: DenialReporting) -> Self {
        self.denial_reporting = reporting;
        self
    }

    pub fn build(self) -> Result<Guard, GuardBuildError> {
        let authorizer = self.authorizer.ok_or(GuardBuildError::MissingAuthorizer)?;
        if !authorizer.has_trusted_roots() {
            return Err(GuardBuildError::EmptyTrustStore);
        }
        let mode = self
            .revocation
            .ok_or(GuardBuildError::MissingRevocationMode)?;
        let revocation = match mode {
            RevocationMode::TtlOnly { max_lifetime } => {
                ResolvedRevocation::TtlOnly { max_lifetime }
            }
            RevocationMode::SignedSrl => {
                let list = authorizer
                    .installed_revocation_list()
                    .cloned()
                    .ok_or(GuardBuildError::SignedSrlUnavailable)?;
                ResolvedRevocation::Snapshot(RevocationSnapshot::from_accepted_list(list))
            }
        };
        Ok(Guard {
            authorizer,
            revocation,
            denial_reporting: self.denial_reporting,
        })
    }
}

/// Failure constructing a [`Guard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardBuildError {
    MissingAuthorizer,
    EmptyTrustStore,
    MissingRevocationMode,
    SignedSrlUnavailable,
}

impl fmt::Display for GuardBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAuthorizer => write!(f, "guard requires an authorizer"),
            Self::EmptyTrustStore => write!(f, "guard authorizer has an empty trust store"),
            Self::MissingRevocationMode => write!(f, "guard requires an explicit revocation mode"),
            Self::SignedSrlUnavailable => {
                write!(f, "SignedSrl requires a revocation list on the authorizer")
            }
        }
    }
}

impl std::error::Error for GuardBuildError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::ConstraintSet;
    use crate::crypto::SigningKey;
    use crate::error::ErrorCode;
    use crate::sdk::signer::{HolderSigner, LocalSigner, SignerError};
    use crate::sdk::{Call, PresentedAuthority, ReceivedAuthorization, VerifiedProjection};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    fn mint(issuer: &SigningKey, holder: &SigningKey, tool: &str) -> Warrant {
        Warrant::builder()
            .capability(tool, ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(issuer)
            .expect("mint")
    }

    fn guard_for(issuer: &SigningKey) -> Guard {
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
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

    #[test]
    fn allow_runs_operation_once() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let runs = AtomicUsize::new(0);

        let guarded = guard
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(7)
            })
            .expect("allow");

        assert_eq!(guarded.value, 7);
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(guarded.decision.metadata.capability, "read");
        assert_eq!(guarded.decision.metadata.chain_depth, 1);
    }

    #[test]
    fn deny_does_not_run_operation() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("write", &args);
        let runs = AtomicUsize::new(0);

        let err = guard
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .expect("deny");

        assert_eq!(runs.load(Ordering::SeqCst), 0);
        match err {
            GuardError::Denied(denial) => {
                assert_eq!(denial.protocol_code(), Some(ErrorCode::ToolNotAuthorized));
                assert!(!denial.is_infrastructure());
            }
            GuardError::Operation(_) => panic!("operation must not run"),
        }
    }

    #[test]
    fn empty_chain_rejected() {
        let holder = SigningKey::generate();
        let err = PresentedAuthority::new(vec![], Arc::new(LocalSigner::new(holder)))
            .err()
            .expect("empty");
        assert_eq!(err, crate::sdk::AuthorityError::EmptyChain);
    }

    #[test]
    fn signer_mismatch_rejected_at_construction() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let other = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let err = PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(other)))
            .err()
            .expect("mismatch");
        assert_eq!(err, crate::sdk::AuthorityError::SignerMismatch);
    }

    #[test]
    fn empty_trust_store_rejected() {
        let err = Guard::builder()
            .authorizer(Authorizer::new())
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(60),
            })
            .build()
            .err()
            .expect("empty trust");
        assert_eq!(err, GuardBuildError::EmptyTrustStore);
    }

    #[test]
    fn missing_revocation_mode_rejected() {
        let issuer = SigningKey::generate();
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let err = Guard::builder()
            .authorizer(authorizer)
            .build()
            .err()
            .expect("missing mode");
        assert_eq!(err, GuardBuildError::MissingRevocationMode);
    }

    #[test]
    fn signed_srl_without_list_rejected() {
        let issuer = SigningKey::generate();
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let err = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::SignedSrl)
            .build()
            .err()
            .expect("no srl");
        assert_eq!(err, GuardBuildError::SignedSrlUnavailable);
    }

    #[test]
    fn same_authority_denied_by_other_trust_store() {
        let issuer = SigningKey::generate();
        let other_root = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);

        assert!(guard_for(&issuer).check(&authority, &call).is_ok());

        let mut stranger = Authorizer::new();
        stranger.add_trusted_root(other_root.public_key());
        let other_guard = Guard::builder()
            .authorizer(stranger)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(3600),
            })
            .build()
            .unwrap();
        let denial = other_guard
            .check(&authority, &call)
            .err()
            .expect("untrusted");
        assert!(
            matches!(
                denial.protocol_code(),
                Some(ErrorCode::UntrustedRoot | ErrorCode::SignatureInvalid)
            ),
            "expected a protocol denial, got {:?}",
            denial.protocol_code()
        );
    }

    struct FlipSigner {
        matching: SigningKey,
        other: SigningKey,
        flip: AtomicBool,
    }

    impl HolderSigner for FlipSigner {
        fn public_key(&self) -> crate::crypto::PublicKey {
            if self.flip.load(Ordering::SeqCst) {
                self.other.public_key()
            } else {
                self.matching.public_key()
            }
        }

        fn sign_pop(
            &self,
            request: &crate::sdk::PopSigningRequest<'_>,
        ) -> Result<Signature, SignerError> {
            Ok(self.matching.sign_raw(&request.final_signing_bytes()))
        }

        fn sign_delegation(
            &self,
            request: &crate::sdk::DelegationSigningRequest<'_>,
        ) -> Result<Signature, SignerError> {
            Ok(self.matching.sign_raw(request.final_signing_bytes()))
        }
    }

    #[test]
    fn signer_mismatch_at_call_time_denies_without_running() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let other = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let signer = Arc::new(FlipSigner {
            matching: holder,
            other,
            flip: AtomicBool::new(false),
        });
        let authority = PresentedAuthority::new(vec![warrant], signer.clone()).expect("construct");
        signer.flip.store(true, Ordering::SeqCst);

        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let runs = AtomicUsize::new(0);
        let err = guard
            .guard(&authority, &call, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .expect("deny");
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        match err {
            GuardError::Denied(denial) => {
                assert_eq!(denial.sdk_kind(), Some(SdkDenialKind::SignerUnavailable));
                assert_eq!(denial.retryability(), Retryability::AfterBackoff);
            }
            GuardError::Operation(_) => panic!("operation must not run"),
        }
    }

    struct CountingSigner {
        inner: LocalSigner,
        pops: AtomicUsize,
    }

    impl HolderSigner for CountingSigner {
        fn public_key(&self) -> crate::crypto::PublicKey {
            self.inner.public_key()
        }

        fn sign_pop(
            &self,
            request: &crate::sdk::PopSigningRequest<'_>,
        ) -> Result<Signature, SignerError> {
            self.pops.fetch_add(1, Ordering::SeqCst);
            self.inner.sign_pop(request)
        }

        fn sign_delegation(
            &self,
            request: &crate::sdk::DelegationSigningRequest<'_>,
        ) -> Result<Signature, SignerError> {
            self.inner.sign_delegation(request)
        }
    }

    #[test]
    fn holder_path_always_signs_locally() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let signer = Arc::new(CountingSigner {
            inner: LocalSigner::new(holder),
            pops: AtomicUsize::new(0),
        });
        let authority = PresentedAuthority::new(vec![warrant], signer.clone()).unwrap();
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        guard.check(&authority, &call).expect("allow");
        assert_eq!(signer.pops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn denial_reporting_does_not_change_execution() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let args = HashMap::new();
        let call = Call::borrowed("write", &args);

        for reporting in [
            DenialReporting::Error,
            DenialReporting::Warn,
            DenialReporting::Debug,
        ] {
            let mut authorizer = Authorizer::new();
            authorizer.add_trusted_root(issuer.public_key());
            let guard = Guard::builder()
                .authorizer(authorizer)
                .revocation(RevocationMode::TtlOnly {
                    max_lifetime: Duration::from_secs(3600),
                })
                .denial_reporting(reporting)
                .build()
                .unwrap();
            let runs = AtomicUsize::new(0);
            let err = guard
                .guard(&authority, &call, |_| {
                    runs.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, &str>(())
                })
                .err()
                .unwrap();
            assert_eq!(runs.load(Ordering::SeqCst), 0);
            match err {
                GuardError::Denied(denial) => {
                    assert_eq!(denial.protocol_code(), Some(ErrorCode::ToolNotAuthorized));
                }
                GuardError::Operation(_) => panic!("operation must not run"),
            }
        }
    }

    #[test]
    fn diagnostics_explain_denied_call() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("write", &args);
        let why = guard
            .diagnostics(&authority)
            .why_denied(&call)
            .expect("denied");
        assert!(why.contains("tool-not-authorized"));
        assert!(guard
            .diagnostics(&authority)
            .explain_authority()
            .contains("read"));
    }

    #[test]
    fn owned_call_rejects_empty_capability() {
        let err = Call::owned("", HashMap::new()).err().expect("empty");
        assert_eq!(err, crate::sdk::ArgumentError::EmptyCapability);
    }

    #[test]
    fn received_empty_chain_rejected() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let pop = guard
            .guard(&authority, &call, |authorized| {
                Ok::<_, &str>(authorized.pop_signature().clone())
            })
            .unwrap()
            .into_inner();
        let err = ReceivedAuthorization::new(&[], &pop, &[])
            .err()
            .expect("empty");
        assert_eq!(err, crate::sdk::AuthorityError::EmptyChain);
    }

    #[test]
    fn received_allows_without_signing() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let client = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let pop = client
            .guard(&authority, &call, |authorized| {
                Ok::<_, &str>(authorized.pop_signature().clone())
            })
            .unwrap()
            .into_inner();

        let received = ReceivedAuthorization::new(authority.chain(), &pop, &[]).unwrap();
        let projection = VerifiedProjection::identical(HashMap::new());
        let inbound = Call::from_transport("read", &projection);
        let server = guard_for(&issuer);
        let runs = AtomicUsize::new(0);
        let _ = server
            .guard_received(&received, &inbound, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .expect("allow");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn received_wrong_signature_denies_without_running() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let other = SigningKey::generate();
        let warrant = mint(&issuer, &holder, "read");
        let authority = authority(vec![warrant], holder);
        let client = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        client.check(&authority, &call).expect("holder allow");
        let junk = other.sign_raw(b"not-the-pop");

        let received = ReceivedAuthorization::new(authority.chain(), &junk, &[]).unwrap();
        let projection = VerifiedProjection::identical(HashMap::new());
        let inbound = Call::from_transport("read", &projection);
        let server = guard_for(&issuer);
        let runs = AtomicUsize::new(0);
        let err = server
            .guard_received(&received, &inbound, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .expect("deny");
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        match err {
            GuardError::Denied(denial) => {
                assert!(
                    matches!(
                        denial.protocol_code(),
                        Some(ErrorCode::PopSignatureInvalid | ErrorCode::SignatureInvalid)
                    ),
                    "expected a PoP/signature denial, got {:?}",
                    denial.protocol_code()
                );
            }
            GuardError::Operation(_) => panic!("operation must not run"),
        }
    }
}
