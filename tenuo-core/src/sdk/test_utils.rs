//! Scaffolding for testing your own guarded code. Behind `test-utils`.
//!
//! These helpers mint a throwaway root and a short-lived warrant so a test can
//! reach a real allow or deny in a few lines instead of assembling a trust
//! root, a chain, a signer, and a guard by hand.
//!
//! Not for production: every helper generates keys in-process and returns them
//! or drops them, and [`TestHarness::guard`] uses [`RevocationMode::TtlOnly`].

use std::sync::Arc;
use std::time::Duration;

use crate::constraints::ConstraintSet;
use crate::crypto::SigningKey;
use crate::planes::Authorizer;
use crate::warrant::Warrant;

use super::authority::PresentedAuthority;
use super::guard::{Guard, RevocationMode};
use super::signer::LocalSigner;

/// A guard, a matching authority, and the keys behind them.
///
/// Everything is throwaway. Hold the issuer when a test needs to mint a second
/// warrant, revoke one, or build a delegation chain.
pub struct TestHarness {
    /// Enforcement surface trusting [`TestHarness::issuer`].
    pub guard: Guard,
    /// Authority whose leaf holds the granted capability.
    pub authority: PresentedAuthority,
    /// Root key the guard trusts. Use it to mint further warrants.
    pub issuer: SigningKey,
    /// Holder key the authority signs with.
    pub holder: SigningKey,
}

/// A guard and authority granting one capability with no argument constraints.
///
/// The fastest path to a passing allow, for tests whose subject is the code
/// around Tenuo rather than the policy itself.
///
/// ```
/// use tenuo::sdk::test_utils::local_guard;
/// use tenuo::{args, Call};
///
/// let h = local_guard("read_file");
/// let call = Call::owned("read_file", args! { "path" => "/data/x" })
///     .expect("call");
/// let out = h
///     .guard
///     .guard(&h.authority, &call, |_| Ok::<_, std::io::Error>("ran"))
///     .expect("allow");
/// assert_eq!(out.into_inner(), "ran");
/// ```
pub fn local_guard(capability: &str) -> TestHarness {
    local_guard_with(capability, ConstraintSet::new())
}

/// A guard and authority granting one capability under `constraints`.
///
/// Use this to test that a denial actually denies.
///
/// ```
/// use tenuo::sdk::test_utils::local_guard_with;
/// use tenuo::{args, constraints, Call, Pattern};
///
/// let h = local_guard_with(
///     "read_file",
///     constraints! { "path" => Pattern::new("/data/*").expect("glob") },
/// );
/// let call = Call::owned("read_file", args! { "path" => "/etc/shadow" })
///     .expect("call");
/// assert!(h.guard.check(&h.authority, &call).is_err());
/// ```
pub fn local_guard_with(capability: &str, constraints: ConstraintSet) -> TestHarness {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();

    let warrant = Warrant::builder()
        .capability(capability, constraints)
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .build(&issuer)
        .expect("test warrant");

    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());

    let guard = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .build()
        .expect("test guard");

    let authority =
        PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder.clone())))
            .expect("test authority");

    TestHarness {
        guard,
        authority,
        issuer,
        holder,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::Pattern;
    use crate::sdk::Call;

    #[test]
    fn local_guard_allows_the_granted_capability() {
        let h = local_guard("read_file");
        let args = crate::args! { "path" => "/anything" };
        let call = Call::borrowed("read_file", &args);
        assert!(h.guard.check(&h.authority, &call).is_ok());
    }

    #[test]
    fn local_guard_denies_another_capability() {
        let h = local_guard("read_file");
        let args = crate::args! {};
        let call = Call::borrowed("write_file", &args);
        assert!(h.guard.check(&h.authority, &call).is_err());
    }

    #[test]
    fn constrained_harness_denies_outside_the_pattern() {
        let mut set = ConstraintSet::new();
        set.insert("path", Pattern::new("/data/*").expect("glob"));
        let h = local_guard_with("read_file", set);

        let ok = crate::args! { "path" => "/data/report" };
        assert!(h
            .guard
            .check(&h.authority, &Call::borrowed("read_file", &ok))
            .is_ok());

        let bad = crate::args! { "path" => "/etc/shadow" };
        assert!(h
            .guard
            .check(&h.authority, &Call::borrowed("read_file", &bad))
            .is_err());
    }

    #[test]
    fn issuer_can_mint_a_second_warrant() {
        let h = local_guard("read_file");
        let other = SigningKey::generate();
        let second = Warrant::builder()
            .capability("write_file", ConstraintSet::new())
            .holder(other.public_key())
            .ttl(Duration::from_secs(60))
            .build(&h.issuer)
            .expect("second warrant");
        let authority =
            PresentedAuthority::new(vec![second], Arc::new(LocalSigner::new(other))).expect("auth");
        let args = crate::args! {};
        assert!(h
            .guard
            .check(&authority, &Call::borrowed("write_file", &args))
            .is_ok());
    }
}
