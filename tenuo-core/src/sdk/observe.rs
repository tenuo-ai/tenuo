//! Observe-only assessment. Distinct from [`Guard`]; never an enforcement type.

use super::authority::{AuthorityError, PresentedAuthority, ReceivedAuthorization};
use super::call::Call;
use super::decision::{Denial, Retryability, SdkDenialKind};
use super::guard::Guard;
use crate::approval::ApprovalRequest;
use crate::constraints::ConstraintValue;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// Assessment surface copied from a [`Guard`]. Cannot be used where `Guard` is required.
pub struct ObservingGuard {
    guard: Guard,
    expires_at: DateTime<Utc>,
    argument_shape: ArgumentShapePolicy,
}

impl Guard {
    /// Copies this guard's configuration. There is no reverse conversion.
    pub fn observe_until(&self, expires_at: DateTime<Utc>) -> ObservingGuard {
        ObservingGuard {
            guard: self.snapshot_for_observe(),
            expires_at,
            argument_shape: ArgumentShapePolicy::KeysAndClasses,
        }
    }
}

impl ObservingGuard {
    pub fn builder() -> ObservingGuardBuilder {
        ObservingGuardBuilder::default()
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// How argument information is summarized on each record. Default is
    /// keys and value classes — enough to draft constraints, not raw values.
    pub fn argument_shape_policy(mut self, policy: ArgumentShapePolicy) -> Self {
        self.argument_shape = policy;
        self
    }

    pub fn observe<T, E>(
        &self,
        request: PresentedRequest<'_>,
        call: &Call<'_>,
        op: impl FnOnce() -> Result<T, E>,
    ) -> Result<Observed<T>, ObserveError<E>> {
        if self.guard.now() >= self.expires_at {
            return Err(ObserveError::Expired);
        }

        let outcome = match request {
            PresentedRequest::Holder(authority) => classify(self.guard.check(authority, call)),
            PresentedRequest::Received(received) => {
                classify(self.guard.check_received(received, call))
            }
            PresentedRequest::Missing => ObservedOutcome::WouldDenyNoAuthority,
            PresentedRequest::Malformed(err) => ObservedOutcome::WouldDeny(Denial::sdk(
                SdkDenialKind::AuthorityMalformed,
                Retryability::No,
                match err {
                    AuthorityError::EmptyChain => "authority chain is empty",
                    AuthorityError::SignerMismatch => "signer does not match leaf holder",
                    AuthorityError::MissingSignature => {
                        "received authorization is missing a signature"
                    }
                },
            )),
        };
        #[cfg(feature = "otel")]
        {
            let (otel_outcome, reason) = match &outcome {
                ObservedOutcome::WouldAllow => ("allow", "allowed"),
                ObservedOutcome::WouldDeny(denial) => ("deny", denial.code()),
                ObservedOutcome::WouldRequireApproval(_) => ("deny", "approval-required"),
                ObservedOutcome::WouldDenyNoAuthority => ("deny", "authority-missing"),
            };
            super::telemetry::record_authorize(otel_outcome, reason, true);
        }

        let value = op().map_err(ObserveError::Operation)?;
        let verdict = ObservationVerdict::from(&outcome);
        Ok(Observed {
            value,
            outcome,
            observation: ObservationRecord {
                observe_only: true,
                expires_at: self.expires_at,
                capability: call.capability().to_string(),
                verdict,
                argument_shape: summarize_args(call.constraint_args(), self.argument_shape),
            },
        })
    }
}

fn classify(result: Result<super::decision::Decision, Denial>) -> ObservedOutcome {
    match result {
        Ok(decision) => {
            let _ = decision.receipt;
            ObservedOutcome::WouldAllow
        }
        Err(denial) => {
            if let Some(request) = denial.approval_request().cloned() {
                ObservedOutcome::WouldRequireApproval(request)
            } else {
                ObservedOutcome::WouldDeny(denial)
            }
        }
    }
}

/// Construction from a [`Guard`] plus an explicit expiry. No independent policy.
#[derive(Default)]
pub struct ObservingGuardBuilder {
    guard: Option<Guard>,
    expires_at: Option<DateTime<Utc>>,
    argument_shape: ArgumentShapePolicy,
}

impl ObservingGuardBuilder {
    pub fn from_guard(guard: &Guard) -> Self {
        Self {
            guard: Some(guard.snapshot_for_observe()),
            expires_at: None,
            argument_shape: ArgumentShapePolicy::KeysAndClasses,
        }
    }

    pub fn argument_shape_policy(mut self, policy: ArgumentShapePolicy) -> Self {
        self.argument_shape = policy;
        self
    }

    pub fn expires_at(mut self, when: DateTime<Utc>) -> Self {
        self.expires_at = Some(when);
        self
    }

    pub fn build(self) -> Result<ObservingGuard, ObserveBuildError> {
        let guard = self.guard.ok_or(ObserveBuildError::MissingGuard)?;
        let expires_at = self.expires_at.ok_or(ObserveBuildError::MissingExpiry)?;
        Ok(ObservingGuard {
            guard,
            expires_at,
            argument_shape: self.argument_shape,
        })
    }
}

/// What the caller actually presented — including nothing at all.
pub enum PresentedRequest<'a> {
    Holder(&'a PresentedAuthority),
    Received(&'a ReceivedAuthorization<'a>),
    Malformed(AuthorityError),
    Missing,
}

/// Result of an observation. The operation ran regardless of the would-outcome.
pub struct Observed<T> {
    pub value: T,
    pub outcome: ObservedOutcome,
    pub observation: ObservationRecord,
}

/// What enforcement would have decided. Never an allow token.
pub enum ObservedOutcome {
    WouldAllow,
    WouldDeny(Denial),
    WouldRequireApproval(ApprovalRequest),
    WouldDenyNoAuthority,
}

/// Persistable would-outcome. The full [`ObservedOutcome`] stays on [`Observed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationVerdict {
    WouldAllow,
    WouldDeny,
    WouldRequireApproval,
    WouldDenyNoAuthority,
}

impl From<&ObservedOutcome> for ObservationVerdict {
    fn from(outcome: &ObservedOutcome) -> Self {
        match outcome {
            ObservedOutcome::WouldAllow => Self::WouldAllow,
            ObservedOutcome::WouldDeny(_) => Self::WouldDeny,
            ObservedOutcome::WouldRequireApproval(_) => Self::WouldRequireApproval,
            ObservedOutcome::WouldDenyNoAuthority => Self::WouldDenyNoAuthority,
        }
    }
}

/// How much argument information an observation record may carry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ArgumentShapePolicy {
    /// Key names only.
    KeysOnly,
    /// Key names and value classes. Default — enough to draft constraints.
    #[default]
    KeysAndClasses,
    /// Key names, value classes, and SHA-256 of each value. Never raw values.
    KeysClassesAndHashes,
}

/// Privacy-safe argument summary for an assessment window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgumentShape {
    keys: Vec<String>,
    classes: BTreeMap<String, ValueClass>,
    hashes: BTreeMap<String, String>,
}

impl ArgumentShape {
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    pub fn classes(&self) -> &BTreeMap<String, ValueClass> {
        &self.classes
    }

    pub fn hashes(&self) -> &BTreeMap<String, String> {
        &self.hashes
    }
}

/// Coarse class of a constraint value. Not the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueClass {
    String,
    Integer,
    Float,
    Boolean,
    List,
    Object,
    Null,
}

/// Labeled observe-only record. Not an authorization receipt.
#[derive(Clone, Debug)]
pub struct ObservationRecord {
    observe_only: bool,
    expires_at: DateTime<Utc>,
    capability: String,
    verdict: ObservationVerdict,
    argument_shape: ArgumentShape,
}

impl ObservationRecord {
    pub fn is_observe_only(&self) -> bool {
        self.observe_only
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn verdict(&self) -> ObservationVerdict {
        self.verdict
    }

    pub fn argument_shape(&self) -> &ArgumentShape {
        &self.argument_shape
    }

    pub fn policy_mode(&self) -> &'static str {
        "observe"
    }
}

fn summarize_args(
    args: &std::collections::HashMap<String, ConstraintValue>,
    policy: ArgumentShapePolicy,
) -> ArgumentShape {
    let mut keys: Vec<String> = args.keys().cloned().collect();
    keys.sort();
    let mut classes = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    if matches!(
        policy,
        ArgumentShapePolicy::KeysAndClasses | ArgumentShapePolicy::KeysClassesAndHashes
    ) {
        for (key, value) in args {
            classes.insert(key.clone(), value_class(value));
        }
    }
    if policy == ArgumentShapePolicy::KeysClassesAndHashes {
        for (key, value) in args {
            hashes.insert(key.clone(), hash_value(value));
        }
    }
    ArgumentShape {
        keys,
        classes,
        hashes,
    }
}

fn value_class(value: &ConstraintValue) -> ValueClass {
    match value {
        ConstraintValue::String(_) => ValueClass::String,
        ConstraintValue::Integer(_) => ValueClass::Integer,
        ConstraintValue::Float(_) => ValueClass::Float,
        ConstraintValue::Boolean(_) => ValueClass::Boolean,
        ConstraintValue::List(_) => ValueClass::List,
        ConstraintValue::Object(_) => ValueClass::Object,
        ConstraintValue::Null => ValueClass::Null,
    }
}

fn hash_value(value: &ConstraintValue) -> String {
    let mut hasher = Sha256::new();
    hash_into(&mut hasher, value);
    hex::encode(hasher.finalize())
}

fn hash_into(hasher: &mut Sha256, value: &ConstraintValue) {
    match value {
        ConstraintValue::String(s) => {
            hasher.update([1]);
            hasher.update(s.as_bytes());
        }
        ConstraintValue::Integer(i) => {
            hasher.update([2]);
            hasher.update(i.to_be_bytes());
        }
        ConstraintValue::Float(f) => {
            hasher.update([3]);
            hasher.update(f.to_bits().to_be_bytes());
        }
        ConstraintValue::Boolean(b) => {
            hasher.update([4]);
            hasher.update([u8::from(*b)]);
        }
        ConstraintValue::List(items) => {
            hasher.update([5]);
            hasher.update((items.len() as u32).to_be_bytes());
            for item in items {
                hash_into(hasher, item);
            }
        }
        ConstraintValue::Object(map) => {
            hasher.update([6]);
            hasher.update((map.len() as u32).to_be_bytes());
            for (key, item) in map {
                hasher.update(key.as_bytes());
                hasher.update([0]);
                hash_into(hasher, item);
            }
        }
        ConstraintValue::Null => hasher.update([7]),
    }
}

/// Failure while observing an already-built [`ObservingGuard`].
#[derive(Debug)]
pub enum ObserveError<E> {
    Expired,
    Operation(E),
}

impl<E: fmt::Display> fmt::Display for ObserveError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => write!(f, "observation period has expired"),
            Self::Operation(err) => write!(f, "operation failed: {err}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for ObserveError<E> {}

/// Failure constructing an [`ObservingGuard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserveBuildError {
    MissingGuard,
    MissingExpiry,
}

impl fmt::Display for ObserveBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingGuard => write!(
                f,
                "ObservingGuard requires configuration copied from a Guard"
            ),
            Self::MissingExpiry => write!(f, "ObservingGuard requires an explicit expiry"),
        }
    }
}

impl std::error::Error for ObserveBuildError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::ConstraintSet;
    use crate::crypto::SigningKey;
    use crate::planes::Authorizer;
    use crate::sdk::signer::LocalSigner;
    use crate::sdk::{Call, RevocationMode};
    use crate::warrant::Warrant;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

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

    fn live(guard: &Guard) -> ObservingGuard {
        guard.observe_until(Utc::now() + chrono::Duration::hours(1))
    }

    #[test]
    fn missing_authority_is_a_finding_and_still_runs() {
        let issuer = SigningKey::generate();
        let observer = live(&guard_for(&issuer));
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let runs = AtomicUsize::new(0);
        let observed = observer
            .observe(PresentedRequest::Missing, &call, || {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .expect("observe");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(matches!(
            observed.outcome,
            ObservedOutcome::WouldDenyNoAuthority
        ));
        assert!(observed.observation.is_observe_only());
        assert_eq!(observed.observation.policy_mode(), "observe");
        assert!(observed.value == ());
    }

    #[test]
    fn expired_observer_refuses_to_run() {
        let issuer = SigningKey::generate();
        let observer = guard_for(&issuer).observe_until(Utc::now() - chrono::Duration::seconds(1));
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let runs = AtomicUsize::new(0);
        let err = observer
            .observe(PresentedRequest::Missing, &call, || {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .err()
            .expect("expired");
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        assert!(matches!(err, ObserveError::Expired));
    }

    #[test]
    fn holder_would_allow_matches_guard_and_runs() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let presented = authority(vec![mint(&issuer, &holder, "read")], holder);
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        assert!(guard.check(&presented, &call).is_ok());
        let runs = AtomicUsize::new(0);
        let observed = live(&guard)
            .observe(PresentedRequest::Holder(&presented), &call, || {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(11)
            })
            .expect("observe");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(observed.value, 11);
        assert!(matches!(observed.outcome, ObservedOutcome::WouldAllow));
        assert!(observed.observation.is_observe_only());
    }

    #[test]
    fn holder_would_deny_still_runs() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let presented = authority(vec![mint(&issuer, &holder, "read")], holder);
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("write", &args);
        assert!(guard.check(&presented, &call).is_err());
        let runs = AtomicUsize::new(0);
        let observed = live(&guard)
            .observe(PresentedRequest::Holder(&presented), &call, || {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .expect("observe");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(matches!(observed.outcome, ObservedOutcome::WouldDeny(_)));
    }

    #[test]
    fn received_would_allow_matches_guard() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let presented = authority(vec![mint(&issuer, &holder, "read")], holder);
        let guard = guard_for(&issuer);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let decision = guard.check(&presented, &call).expect("holder allow");
        let _ = decision;
        let authorized = guard
            .guard(&presented, &call, |authorized| {
                Ok::<_, &str>(authorized.pop_signature().clone())
            })
            .expect("sign");
        let pop = authorized.value;
        let received = ReceivedAuthorization::new(presented.chain(), &pop, &[]).expect("received");
        assert!(guard.check_received(&received, &call).is_ok());
        let observed = live(&guard)
            .observe(PresentedRequest::Received(&received), &call, || {
                Ok::<_, &str>(())
            })
            .expect("observe");
        assert!(matches!(observed.outcome, ObservedOutcome::WouldAllow));
    }

    #[test]
    fn malformed_short_circuits_without_usable_authority() {
        let issuer = SigningKey::generate();
        let observer = live(&guard_for(&issuer));
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let observed = observer
            .observe(
                PresentedRequest::Malformed(AuthorityError::EmptyChain),
                &call,
                || Ok::<_, &str>(()),
            )
            .expect("observe");
        match observed.outcome {
            ObservedOutcome::WouldDeny(denial) => {
                assert_eq!(denial.sdk_kind(), Some(SdkDenialKind::AuthorityMalformed));
            }
            ObservedOutcome::WouldAllow
            | ObservedOutcome::WouldRequireApproval(_)
            | ObservedOutcome::WouldDenyNoAuthority => {
                panic!("expected malformed denial")
            }
        }
    }

    #[test]
    fn construction_requires_guard_and_expiry() {
        assert_eq!(
            ObservingGuard::builder().build().err().unwrap(),
            ObserveBuildError::MissingGuard
        );
        let issuer = SigningKey::generate();
        let guard = guard_for(&issuer);
        assert_eq!(
            ObservingGuardBuilder::from_guard(&guard)
                .build()
                .err()
                .unwrap(),
            ObserveBuildError::MissingExpiry
        );
        let observer = ObservingGuardBuilder::from_guard(&guard)
            .expires_at(Utc::now() + chrono::Duration::minutes(5))
            .build()
            .unwrap();
        assert!(observer.expires_at() > Utc::now());
    }

    #[test]
    fn argument_shape_summarizes_without_raw_values() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let presented = authority(vec![mint(&issuer, &holder, "read")], holder);
        let mut args = HashMap::new();
        args.insert(
            "cluster".into(),
            crate::constraints::ConstraintValue::String("staging-web".into()),
        );
        let call = Call::borrowed("read", &args);
        let observed = live(&guard_for(&issuer))
            .observe(PresentedRequest::Holder(&presented), &call, || {
                Ok::<_, &str>(())
            })
            .unwrap();
        let shape = observed.observation.argument_shape();
        assert_eq!(shape.keys(), &["cluster".to_string()]);
        assert_eq!(shape.classes().get("cluster"), Some(&ValueClass::String));
        assert!(shape.hashes().is_empty());
        let debug = format!("{shape:?}");
        assert!(
            !debug.contains("staging-web"),
            "observe must not persist raw argument values: {debug}"
        );
        assert_eq!(
            observed.observation.verdict(),
            ObservationVerdict::WouldAllow
        );
    }

    #[test]
    fn no_receipt_and_no_reverse_conversion_in_source() {
        let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/sdk/observe.rs"));
        let deref_impl = format!("impl {}::ops::{}", "std", "Deref");
        let deref_fn = ["fn ", "deref("].concat();
        assert!(
            !src.contains(&deref_impl) && !src.contains(&deref_fn),
            "S29: ObservingGuard must not Deref to Guard"
        );
        assert!(
            !src.contains(&["fn into", "_guard"].concat()),
            "S29/S44: no reverse conversion"
        );
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let presented = authority(vec![mint(&issuer, &holder, "read")], holder);
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let observed = live(&guard_for(&issuer))
            .observe(PresentedRequest::Holder(&presented), &call, || {
                Ok::<_, &str>(())
            })
            .unwrap();
        match observed.outcome {
            ObservedOutcome::WouldAllow => {}
            ObservedOutcome::WouldDeny(_)
            | ObservedOutcome::WouldRequireApproval(_)
            | ObservedOutcome::WouldDenyNoAuthority => {}
        }
        // Observation is not a Decision and carries no receipt field.
        let _ = observed.observation.is_observe_only();
    }
}
