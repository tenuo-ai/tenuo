use super::authority::{AuthorityError, PresentedAuthority};
use super::decision::DenialReporting;
use super::guard::{Guard, GuardBuildError, RevocationMode};
use super::signer::LocalSigner;
use crate::crypto::{PublicKey, SigningKey};
use crate::planes::Authorizer;
use crate::warrant::Warrant;
use std::marker::PhantomData;
use std::sync::Arc;

/// Quickstart constructors. Typestate `build()` is only available after the
/// required pieces are supplied; revocation never defaults.
pub struct Tenuo;

impl Tenuo {
    /// Holder-sign quickstart: trusted root, chain, signer, explicit revocation.
    ///
    /// Returns a guard and the authority it will accept. Each required piece is
    /// enforced by the type system, so a guard with no trust root or no
    /// revocation policy does not compile.
    ///
    /// ```
    /// use std::time::Duration;
    /// use tenuo::sdk::prelude::*;
    /// use tenuo::{args, constraints};
    ///
    /// // In production the root key lives in your control plane and the warrant
    /// // arrives already minted. Both are generated here to keep the example runnable.
    /// let root = SigningKey::generate();
    /// let holder = SigningKey::generate();
    ///
    /// let warrant = Warrant::builder()
    ///     .capability(
    ///         "read_file",
    ///         constraints! { "path" => Pattern::new("/data/*")? },
    ///     )
    ///     .holder(holder.public_key())
    ///     .ttl(Duration::from_secs(300))
    ///     .build(&root)?;
    ///
    /// let (guard, authority) = Tenuo::local()
    ///     .trusted_root(root.public_key())
    ///     .chain(vec![warrant])
    ///     .signer(holder)
    ///     .revocation(RevocationMode::TtlOnly {
    ///         max_lifetime: Duration::from_secs(600),
    ///     })
    ///     .build()?;
    ///
    /// // Inside the constraint: the operation runs.
    /// let allowed = Call::owned("read_file", args! { "path" => "/data/report.csv" })?;
    /// let out = guard.guard(&authority, &allowed, |_| Ok::<_, std::io::Error>("read"))?;
    /// assert_eq!(out.into_inner(), "read");
    ///
    /// // Outside it: denied, and the closure never runs.
    /// let refused = Call::owned("read_file", args! { "path" => "/etc/shadow" })?;
    /// assert!(guard.check(&authority, &refused).is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn local() -> LocalBuilder<NeedRoot> {
        LocalBuilder {
            roots: Vec::new(),
            chain: None,
            signer: None,
            revocation: None,
            denial_reporting: DenialReporting::Error,
            _state: PhantomData,
        }
    }

    /// Enforcement-point quickstart: trusted root and explicit revocation.
    /// Inbound calls arrive as `ReceivedAuthorization`.
    pub fn enforcement() -> EnforcementBuilder<NeedRoot> {
        EnforcementBuilder {
            roots: Vec::new(),
            revocation: None,
            denial_reporting: DenialReporting::Error,
            _state: PhantomData,
        }
    }
}

pub struct NeedRoot;
pub struct NeedChain;
pub struct NeedSigner;
pub struct NeedRevocation;
pub struct Ready;

/// Builds a holder-side guard and its authority together. Typestate: each required
/// piece moves the builder forward, and `build` exists only once all are supplied.
pub struct LocalBuilder<S> {
    roots: Vec<PublicKey>,
    chain: Option<Vec<Warrant>>,
    signer: Option<SigningKey>,
    revocation: Option<RevocationMode>,
    denial_reporting: DenialReporting,
    _state: PhantomData<S>,
}

impl LocalBuilder<NeedRoot> {
    /// Root this guard will trust. Required first.
    pub fn trusted_root(mut self, key: PublicKey) -> LocalBuilder<NeedChain> {
        self.roots.push(key);
        LocalBuilder {
            roots: self.roots,
            chain: self.chain,
            signer: self.signer,
            revocation: self.revocation,
            denial_reporting: self.denial_reporting,
            _state: PhantomData,
        }
    }
}

impl LocalBuilder<NeedChain> {
    /// Add another trusted root.
    pub fn trusted_root(mut self, key: PublicKey) -> Self {
        self.roots.push(key);
        self
    }

    /// Warrant chain the holder will present, root first. Required.
    pub fn chain(mut self, chain: Vec<Warrant>) -> LocalBuilder<NeedSigner> {
        self.chain = Some(chain);
        LocalBuilder {
            roots: self.roots,
            chain: self.chain,
            signer: self.signer,
            revocation: self.revocation,
            denial_reporting: self.denial_reporting,
            _state: PhantomData,
        }
    }
}

impl LocalBuilder<NeedSigner> {
    /// Key holding the chain's leaf. Required.
    pub fn signer(mut self, key: SigningKey) -> LocalBuilder<NeedRevocation> {
        self.signer = Some(key);
        LocalBuilder {
            roots: self.roots,
            chain: self.chain,
            signer: self.signer,
            revocation: self.revocation,
            denial_reporting: self.denial_reporting,
            _state: PhantomData,
        }
    }
}

impl LocalBuilder<NeedRevocation> {
    /// Revocation policy. Required — there is no default; see [`RevocationMode`].
    pub fn revocation(mut self, mode: RevocationMode) -> LocalBuilder<Ready> {
        self.revocation = Some(mode);
        LocalBuilder {
            roots: self.roots,
            chain: self.chain,
            signer: self.signer,
            revocation: self.revocation,
            denial_reporting: self.denial_reporting,
            _state: PhantomData,
        }
    }
}

impl LocalBuilder<Ready> {
    /// Log level for denials. Never changes whether the operation runs.
    pub fn denial_reporting(mut self, reporting: DenialReporting) -> Self {
        self.denial_reporting = reporting;
        self
    }

    /// Build the guard and its authority.
    pub fn build(self) -> Result<(Guard, PresentedAuthority), TenuoBuildError> {
        let mut authorizer = Authorizer::new();
        for root in self.roots {
            authorizer.add_trusted_root(root);
        }
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(self.revocation.expect("typestate requires revocation"))
            .denial_reporting(self.denial_reporting)
            .build()?;
        let authority = PresentedAuthority::new(
            self.chain.expect("typestate requires chain"),
            Arc::new(LocalSigner::new(
                self.signer.expect("typestate requires signer"),
            )),
        )?;
        Ok((guard, authority))
    }
}

/// Builds an enforcement-point guard, which verifies what peers present and holds no
/// chain or signer of its own.
pub struct EnforcementBuilder<S> {
    roots: Vec<PublicKey>,
    revocation: Option<RevocationMode>,
    denial_reporting: DenialReporting,
    _state: PhantomData<S>,
}

impl EnforcementBuilder<NeedRoot> {
    /// Root this guard will trust. Required first.
    pub fn trusted_root(mut self, key: PublicKey) -> EnforcementBuilder<NeedRevocation> {
        self.roots.push(key);
        EnforcementBuilder {
            roots: self.roots,
            revocation: self.revocation,
            denial_reporting: self.denial_reporting,
            _state: PhantomData,
        }
    }
}

impl EnforcementBuilder<NeedRevocation> {
    /// Add another trusted root.
    pub fn trusted_root(mut self, key: PublicKey) -> Self {
        self.roots.push(key);
        self
    }

    /// Revocation policy. Required — there is no default; see [`RevocationMode`].
    pub fn revocation(mut self, mode: RevocationMode) -> EnforcementBuilder<Ready> {
        self.revocation = Some(mode);
        EnforcementBuilder {
            roots: self.roots,
            revocation: self.revocation,
            denial_reporting: self.denial_reporting,
            _state: PhantomData,
        }
    }
}

impl EnforcementBuilder<Ready> {
    /// Log level for denials. Never changes whether the operation runs.
    pub fn denial_reporting(mut self, reporting: DenialReporting) -> Self {
        self.denial_reporting = reporting;
        self
    }

    /// Build the guard.
    pub fn build(self) -> Result<Guard, TenuoBuildError> {
        let mut authorizer = Authorizer::new();
        for root in self.roots {
            authorizer.add_trusted_root(root);
        }
        Ok(Guard::builder()
            .authorizer(authorizer)
            .revocation(self.revocation.expect("typestate requires revocation"))
            .denial_reporting(self.denial_reporting)
            .build()?)
    }
}

/// Failure constructing a quickstart `Guard` / `PresentedAuthority`.
#[derive(Debug)]
pub enum TenuoBuildError {
    /// The guard could not be built.
    Guard(GuardBuildError),
    /// The authority could not be built.
    Authority(AuthorityError),
}

impl From<GuardBuildError> for TenuoBuildError {
    fn from(value: GuardBuildError) -> Self {
        Self::Guard(value)
    }
}

impl From<AuthorityError> for TenuoBuildError {
    fn from(value: AuthorityError) -> Self {
        Self::Authority(value)
    }
}

impl std::fmt::Display for TenuoBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Guard(err) => write!(f, "{err}"),
            Self::Authority(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for TenuoBuildError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::ConstraintSet;
    use crate::sdk::Call;
    use crate::ErrorCode;
    use std::time::Duration;

    #[test]
    fn local_quickstart_allows_and_names_constraint_field() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let mut constraints = ConstraintSet::new();
        constraints.insert("to".to_string(), crate::constraints::Exact::new("a@b.com"));
        let warrant = Warrant::builder()
            .capability("send_email", constraints)
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();

        let (guard, authority) = Tenuo::local()
            .trusted_root(issuer.public_key())
            .chain(vec![warrant])
            .signer(holder)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(3600),
            })
            .build()
            .unwrap();

        let args = crate::args! { "to" => "evil@b.com" };
        let call = Call::owned("send_email", args).unwrap();
        let denial = guard.check(&authority, &call).err().unwrap();
        assert!(denial.is_policy());
        assert_eq!(denial.code(), ErrorCode::ConstraintViolation.name());
        let why = guard.diagnostics(&authority).explain_denial(&denial);
        assert!(why.contains("to"), "diagnostics must name the field: {why}");
        assert!(!denial.message().contains("to"));
    }

    #[test]
    fn enforcement_quickstart_builds_a_guard() {
        let issuer = SigningKey::generate();
        let guard = Tenuo::enforcement()
            .trusted_root(issuer.public_key())
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(60),
            })
            .build()
            .unwrap();
        let _ = guard;
    }

    #[test]
    fn try_from_json_rejects_u64_and_non_object() {
        let huge = serde_json::json!({ "n": u64::MAX });
        assert_eq!(
            Call::try_from_json("t", &huge).err().unwrap(),
            crate::sdk::ArgumentError::IntegerOutOfRange
        );
        assert_eq!(
            Call::try_from_json("t", &serde_json::json!([1]))
                .err()
                .unwrap(),
            crate::sdk::ArgumentError::NotAnObject
        );
        let ok = Call::try_from_json("send", &serde_json::json!({ "to": "a@b.com", "size": 12 }))
            .unwrap();
        assert_eq!(ok.capability(), "send");
        assert_eq!(ok.args().len(), 2);
    }
}
