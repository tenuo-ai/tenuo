//! Explicit verification time and revocation state for one authorization decision.
//!
//! [`Authorizer::check_chain_with_context`] is the authoritative decision.
//! It does not read the clock and does not consult the authorizer's stored
//! revocation list — the caller supplies both.

use crate::revocation::SignedRevocationList;
use crate::warrant::Warrant;
use chrono::{DateTime, Utc};
use std::time::Duration;

/// One committed evaluation instant plus the revocation state that decides it.
///
/// Fields are private. Application code does not construct a live historical
/// context; the public wrapper builds a current-time context only. Guard (M2)
/// and crate tests use [`VerificationContext::new`].
pub struct VerificationContext<'a> {
    as_of: DateTime<Utc>,
    revocation: RevocationState<'a>,
}

impl<'a> VerificationContext<'a> {
    /// Crate-internal constructor. Not a public live-authorization API.
    pub(crate) fn new(as_of: DateTime<Utc>, revocation: RevocationState<'a>) -> Self {
        Self { as_of, revocation }
    }

    pub fn as_of(&self) -> DateTime<Utc> {
        self.as_of
    }

    pub(crate) fn as_of_unix(&self) -> i64 {
        self.as_of.timestamp()
    }

    pub(crate) fn revocation(&self) -> &RevocationState<'a> {
        &self.revocation
    }
}

/// How this decision treats revocation.
pub enum RevocationState<'a> {
    /// This exact accepted snapshot decides.
    Snapshot(&'a RevocationSnapshot),
    /// No SRL. Every warrant in the chain must have `expires_at - issued_at`
    /// no greater than `max_lifetime`.
    TtlOnly { max_lifetime: Duration },
    /// Legacy wrapper only: the authorizer has no configured SRL and no
    /// lifetime ceiling. Guard must not construct this variant.
    NotConfigured,
}

/// Opaque proof that one signed SRL was accepted for a decision.
///
/// No public constructor. The wrapper mints one from an SRL already installed
/// via [`crate::Authorizer::set_revocation_list`]. Freshness is a later
/// tracker concern and is not applied here.
pub struct RevocationSnapshot {
    srl: SignedRevocationList,
}

impl RevocationSnapshot {
    pub(crate) fn from_accepted_list(srl: SignedRevocationList) -> Self {
        Self { srl }
    }

    pub(crate) fn is_revoked(&self, warrant: &Warrant) -> bool {
        self.srl.is_revoked(&warrant.id().to_string())
    }
}

impl RevocationState<'_> {
    pub(crate) fn is_revoked(&self, warrant: &Warrant) -> bool {
        match self {
            Self::Snapshot(snapshot) => snapshot.is_revoked(warrant),
            Self::TtlOnly { .. } | Self::NotConfigured => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::ConstraintValue;
    use crate::crypto::SigningKey;
    use crate::planes::Authorizer;
    use crate::warrant::{Warrant, POP_TIMESTAMP_WINDOW_SECS};
    use crate::Error;
    use std::collections::HashMap;
    use std::time::Duration as StdDuration;

    fn mint_bound(
        issuer: &SigningKey,
        holder: &SigningKey,
        tool: &str,
        ttl: StdDuration,
    ) -> Warrant {
        Warrant::builder()
            .capability(tool, crate::constraints::ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(ttl)
            .build(issuer)
            .expect("mint")
    }

    fn args() -> HashMap<String, ConstraintValue> {
        HashMap::new()
    }

    #[test]
    fn pop_preimage_matches_verify_reconstruction() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint_bound(&issuer, &holder, "read", StdDuration::from_secs(300));
        let timestamp = 1_700_000_030_i64;
        let window_secs = POP_TIMESTAMP_WINDOW_SECS;
        let preimage = warrant
            .pop_preimage("read", &args(), timestamp, window_secs)
            .unwrap();

        let window_ts = (timestamp / window_secs) * window_secs;
        let reconstructed = warrant
            .pop_preimage("read", &args(), window_ts, window_secs)
            .unwrap();
        assert_eq!(preimage, reconstructed);

        let signature = holder.sign(&preimage);
        warrant
            .verify_pop_at(
                "read",
                &args(),
                Some(&signature),
                window_secs,
                5,
                DateTime::from_timestamp(timestamp, 0).unwrap(),
            )
            .expect("preimage bytes must verify for the same window");
    }

    #[test]
    fn sign_with_timestamp_uses_pop_preimage() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint_bound(&issuer, &holder, "read", StdDuration::from_secs(300));
        let timestamp = 1_700_000_000_i64;
        let preimage = warrant
            .pop_preimage("read", &args(), timestamp, POP_TIMESTAMP_WINDOW_SECS)
            .unwrap();
        let via_sign = warrant
            .sign_with_timestamp(&holder, "read", &args(), Some(timestamp))
            .unwrap();
        let via_raw = holder.sign(&preimage);
        assert_eq!(via_sign.to_bytes(), via_raw.to_bytes());
    }

    #[test]
    fn as_of_determines_expiry_and_pop_window() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint_bound(&issuer, &holder, "read", StdDuration::from_secs(60));
        let issued = warrant.issued_at().timestamp();
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        authorizer.set_clock_tolerance(chrono::Duration::zero());
        authorizer.set_pop_window(POP_TIMESTAMP_WINDOW_SECS, 5);

        let live = DateTime::from_timestamp(issued + 10, 0).unwrap();
        let pop = warrant
            .sign_with_timestamp(&holder, "read", &args(), Some(live.timestamp()))
            .unwrap();
        let ctx = VerificationContext::new(live, RevocationState::NotConfigured);
        authorizer
            .check_chain_with_context(
                std::slice::from_ref(&warrant),
                "read",
                &args(),
                &args(),
                Some(&pop),
                &[],
                &ctx,
            )
            .expect("live instant must allow");

        let expired = DateTime::from_timestamp(issued + 120, 0).unwrap();
        let ctx = VerificationContext::new(expired, RevocationState::NotConfigured);
        let err = authorizer
            .check_chain_with_context(
                std::slice::from_ref(&warrant),
                "read",
                &args(),
                &args(),
                Some(&pop),
                &[],
                &ctx,
            )
            .expect_err("expired instant must deny");
        assert!(matches!(err, Error::WarrantExpired { .. }));
    }

    #[test]
    fn wrapper_none_is_not_configured_not_ttl_only() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint_bound(
            &issuer,
            &holder,
            "read",
            StdDuration::from_secs(7 * 24 * 3600),
        );
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let pop = warrant.sign(&holder, "read", &args()).unwrap();
        authorizer
            .check_chain_with_pop_args(
                std::slice::from_ref(&warrant),
                "read",
                &args(),
                &args(),
                Some(&pop),
                &[],
            )
            .expect("long-lived warrant must still pass when no SRL is configured");
    }

    #[test]
    fn ttl_only_rejects_over_ceiling_on_every_warrant() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint_bound(&issuer, &holder, "read", StdDuration::from_secs(3600));
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let as_of = warrant.issued_at() + chrono::Duration::seconds(5);
        let pop = warrant
            .sign_with_timestamp(&holder, "read", &args(), Some(as_of.timestamp()))
            .unwrap();
        let ctx = VerificationContext::new(
            as_of,
            RevocationState::TtlOnly {
                max_lifetime: StdDuration::from_secs(60),
            },
        );
        let err = authorizer
            .check_chain_with_context(
                std::slice::from_ref(&warrant),
                "read",
                &args(),
                &args(),
                Some(&pop),
                &[],
                &ctx,
            )
            .expect_err("1h warrant exceeds 60s ceiling");
        assert!(matches!(err, Error::InvalidTtl(_)));
    }

    #[test]
    fn context_revocation_not_authorizer_list() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint_bound(&issuer, &holder, "read", StdDuration::from_secs(300));
        let srl = crate::revocation::SignedRevocationList::builder()
            .revoke(&warrant.id().to_string())
            .version(1)
            .build(&issuer)
            .unwrap();

        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        authorizer
            .set_revocation_list(srl.clone(), &issuer.public_key())
            .unwrap();

        let as_of = warrant.issued_at() + chrono::Duration::seconds(5);
        let pop = warrant
            .sign_with_timestamp(&holder, "read", &args(), Some(as_of.timestamp()))
            .unwrap();

        let ctx = VerificationContext::new(as_of, RevocationState::NotConfigured);
        authorizer
            .check_chain_with_context(
                std::slice::from_ref(&warrant),
                "read",
                &args(),
                &args(),
                Some(&pop),
                &[],
                &ctx,
            )
            .expect("NotConfigured must ignore the authorizer's stored SRL");

        let snapshot = RevocationSnapshot::from_accepted_list(srl);
        let ctx = VerificationContext::new(as_of, RevocationState::Snapshot(&snapshot));
        let err = authorizer
            .check_chain_with_context(
                std::slice::from_ref(&warrant),
                "read",
                &args(),
                &args(),
                Some(&pop),
                &[],
                &ctx,
            )
            .expect_err("snapshot must revoke");
        assert!(matches!(err, Error::WarrantRevoked(_)));
    }

    #[test]
    fn one_instant_one_pop_window() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = mint_bound(&issuer, &holder, "read", StdDuration::from_secs(300));
        let window = POP_TIMESTAMP_WINDOW_SECS;
        let in_window = 1_700_000_015_i64;
        let preimage = warrant
            .pop_preimage("read", &args(), in_window, window)
            .unwrap();
        let same_window = warrant
            .pop_preimage("read", &args(), 1_700_000_029, window)
            .unwrap();
        let next_window = warrant
            .pop_preimage("read", &args(), 1_700_000_040, window)
            .unwrap();
        assert_eq!(preimage, same_window);
        assert_ne!(preimage, next_window);
    }
}
