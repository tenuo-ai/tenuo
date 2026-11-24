//! Attenuating Agent Tokens in their JWT/JWS encoding.
//!
//! Verifies a presentation, a chain of signed JWTs plus a proof-of-possession
//! JWT, by the chain verification algorithm of
//! `draft-niyikiza-oauth-attenuating-agent-tokens-02`, Section 8.
//!
//! This is a second token encoding beside the CBOR [`Warrant`](crate::Warrant).
//! The two never convert: a JWS token is signed over different bytes. Issuing
//! and deriving JWS tokens is not implemented here.
//!
//! ```no_run
//! use tenuo::aat::{verify_chain, TrustAnchor, VerifyOptions};
//! # fn demo(issuer_key: tenuo::PublicKey, chain: Vec<String>, pop: String) {
//! let anchors = [TrustAnchor {
//!     issuer: "https://auth.example.com".into(),
//!     key: issuer_key,
//! }];
//! let chain: Vec<&str> = chain.iter().map(String::as_str).collect();
//! let mut opts = VerifyOptions::new("https://tools.example.com", 1_704_067_500);
//! match verify_chain(&chain, &pop, &anchors, "read_file", r#"{"path":"/data/q3.pdf"}"#, &mut opts) {
//!     Ok(verified) => println!("permit, issued by {}", verified.issuer),
//!     Err(denied) => println!("deny: {denied}"),
//! }
//! # }
//! ```

mod constraint;
mod jose;
mod json;
mod verify;

use crate::crypto::PublicKey;
use std::fmt;

/// A root issuer this enforcement point trusts.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// The issuer identifier a root token's `iss` must equal.
    pub issuer: String,
    /// The key that verifies root tokens from this issuer.
    pub key: PublicKey,
}

/// Verification limits. The defaults are the draft's recommended values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// `MAX_IAT_SKEW`: how far in the future an `iat` may be, in seconds.
    pub max_iat_skew: u32,
    /// `MAX_TOKEN_LIFETIME` of a root token, in seconds.
    pub max_token_lifetime: u64,
    /// `MAX_DELEGATION_DEPTH`.
    pub max_delegation_depth: u8,
    /// `MAX_CONSTRAINT_DEPTH`: nesting of `all` and `any`.
    pub max_constraint_depth: usize,
    /// `MAX_TOKEN_SIZE`: encoded size of one token, in bytes.
    pub max_token_size: usize,
    /// `MAX_CHAIN_SIZE`: encoded size of all tokens together, in bytes.
    pub max_chain_size: usize,
    /// How far a PoP `iat` may be from now, either way, in seconds.
    pub pop_window: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_iat_skew: 30,
            max_token_lifetime: 90 * 24 * 3600,
            max_delegation_depth: 8,
            max_constraint_depth: 32,
            max_token_size: 65_536,
            max_chain_size: 262_144,
            pop_window: 30,
        }
    }
}

/// Remembers accepted PoP `jti` values (step 7i).
///
/// The verifier calls [`record`](ReplayStore::record) once, after every other
/// check has passed. An implementation only needs to remember a `jti` for as
/// long as a PoP with that `iat` stays inside the clock window.
pub trait ReplayStore {
    /// Record `pop_jti` as accepted. Returns `false` if it was already
    /// recorded, which denies the presentation.
    fn record(&mut self, pop_jti: &str) -> bool;
}

/// What this enforcement point requires of a presentation.
pub struct VerifyOptions<'a> {
    /// The identifier of this enforcement point. A PoP `aat_aud` and every
    /// chain `aud` that is present must name it.
    pub audience: &'a str,
    /// The current time, in seconds since the Unix epoch.
    pub now: i64,
    /// Size, depth and clock limits.
    pub limits: Limits,
    /// Deny a PoP that carries no `aat_aud`.
    pub require_pop_aud: bool,
    /// Deny a chain in which no token carries `aud`.
    pub require_chain_aud: bool,
    /// A nonce this enforcement point issued; the PoP must carry it.
    pub nonce: Option<&'a str>,
    /// Replay tracking for PoP `jti` values. `None` leaves replay bounded by
    /// the clock window alone.
    pub replay: Option<&'a mut dyn ReplayStore>,
}

impl<'a> VerifyOptions<'a> {
    /// Default limits, no audience or nonce requirement, no replay tracking.
    pub fn new(audience: &'a str, now: i64) -> Self {
        Self {
            audience,
            now,
            limits: Limits::default(),
            require_pop_aud: false,
            require_chain_aud: false,
            nonce: None,
            replay: None,
        }
    }
}

/// A permitted invocation.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The trust anchor issuer whose key verified the root token.
    pub issuer: String,
    /// The `jti` of every token in the chain, root first.
    pub token_ids: Vec<String>,
    /// The leaf holder's key, which signed the PoP.
    pub holder: PublicKey,
}

/// A denied presentation.
///
/// `step` is the first Section 8 step that failed. It and `reason` are for
/// logs; a caller should treat every denial the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// The Section 8 step, for example `"4p4"`.
    pub step: &'static str,
    /// Why the step failed.
    pub reason: String,
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "step {}: {}", self.step, self.reason)
    }
}

impl std::error::Error for Denied {}

fn deny(step: &'static str, reason: impl Into<String>) -> Denied {
    Denied {
        step,
        reason: reason.into(),
    }
}

/// Verify a presentation for one tool invocation (Section 8).
///
/// `chain` is the `aat_chain` of the presentation, root first, each token in
/// JWS Compact Serialization, and `pop` is its `aat_pop`. `args_json` is the
/// invocation's arguments as the JSON text that arrived, so that a repeated
/// member name or a number JCS would change is seen before anything collapses
/// it; passing a re-serialized value defeats both checks.
///
/// Fails closed: anything that is not a complete, valid presentation for
/// exactly this tool and these arguments is [`Denied`].
pub fn verify_chain(
    chain: &[&str],
    pop: &str,
    anchors: &[TrustAnchor],
    tool: &str,
    args_json: &str,
    opts: &mut VerifyOptions<'_>,
) -> Result<Verified, Denied> {
    verify::verify_chain(chain, pop, anchors, tool, args_json, opts)
}
