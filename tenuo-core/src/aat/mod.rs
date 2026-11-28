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
//!     key: issuer_key.into(),
//! }];
//! let chain: Vec<&str> = chain.iter().map(String::as_str).collect();
//! let mut opts = VerifyOptions::new("https://tools.example.com", 1_704_067_500);
//! match verify_chain(&chain, &pop, &anchors, "read_file", r#"{"path":"/data/q3.pdf"}"#, &mut opts) {
//!     Ok(verified) => println!("permit, issued by {}", verified.issuer),
//!     Err(denied) => println!("deny: {denied}"),
//! }
//! # }
//! ```
//!
//! # Signature algorithms
//!
//! Tokens and proofs of possession are signed with `Ed25519`, which the
//! draft makes mandatory to implement. The `aat-es256` feature adds `ES256`
//! for P-256 keys, the second algorithm the draft recommends.
//!
//! An enforcement point names the algorithms it permits in
//! [`VerifyOptions::algorithms`]. The default is `Ed25519` alone, and the
//! list applies to every token in a chain and to the PoP JWT, each on its
//! own. The type of a key fixes the one algorithm it is used with, so the
//! `alg` a token names never chooses how a key is used.
//!
//! An ES256 signature has a second valid form, so one token can be written
//! as more than one compact text. Identify a token by its `jti`, not by its
//! text. Verification already does: `par_hash` and `aat_hash` cover the JWS
//! Signing Input, and replay is tracked by the PoP `jti`.
//!
//! ```no_run
//! # #[cfg(feature = "aat-es256")]
//! # fn demo(x: [u8; 32], y: [u8; 32]) -> Option<()> {
//! use tenuo::aat::{Algorithm, P256PublicKey, TrustAnchor, VerifyOptions};
//!
//! // An issuer that signs root tokens with ES256.
//! let anchors = [TrustAnchor {
//!     issuer: "https://auth.example.com".into(),
//!     key: P256PublicKey::from_coordinates(&x, &y)?.into(),
//! }];
//! let mut opts = VerifyOptions::new("https://tools.example.com", 1_704_067_500);
//! opts.algorithms = &[Algorithm::Ed25519, Algorithm::Es256];
//! # let _ = anchors;
//! # Some(())
//! # }
//! ```

mod constraint;
mod jose;
mod json;
mod verify;

use crate::crypto::PublicKey;
use std::fmt;

/// A P-256 public key, used with the JWS `alg` value `ES256`.
#[cfg(feature = "aat-es256")]
#[cfg_attr(docsrs, doc(cfg(feature = "aat-es256")))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P256PublicKey {
    x: [u8; 32],
    y: [u8; 32],
    key: p256::ecdsa::VerifyingKey,
}

#[cfg(feature = "aat-es256")]
impl std::hash::Hash for P256PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // The coordinates determine the key.
        self.x.hash(state);
        self.y.hash(state);
    }
}

#[cfg(feature = "aat-es256")]
impl P256PublicKey {
    /// The key with the affine coordinates of a JWK's `x` and `y`, or `None`
    /// when they are not a point on the curve.
    pub fn from_coordinates(x: &[u8; 32], y: &[u8; 32]) -> Option<Self> {
        // SEC 1 uncompressed form: 0x04 || X || Y.
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(x);
        sec1[33..].copy_from_slice(y);
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).ok()?;
        Some(Self { x: *x, y: *y, key })
    }

    /// The affine coordinates, as a JWK's `x` and `y` carry them.
    pub fn coordinates(&self) -> (&[u8; 32], &[u8; 32]) {
        (&self.x, &self.y)
    }

    /// Verify an ECDSA P-256 SHA-256 signature given as `R || S`, the form
    /// a JWS carries (RFC 7518 Section 3.4).
    pub(crate) fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        use p256::ecdsa::signature::Verifier;
        p256::ecdsa::Signature::from_slice(signature)
            .is_ok_and(|signature| self.key.verify(message, &signature).is_ok())
    }
}

/// A JWS signature algorithm this verifier implements, by its
/// fully-specified `alg` value (RFC 9864).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// `Ed25519`. Mandatory to implement.
    Ed25519,
    /// `ES256`: ECDSA using P-256 and SHA-256.
    #[cfg(feature = "aat-es256")]
    #[cfg_attr(docsrs, doc(cfg(feature = "aat-es256")))]
    Es256,
}

impl Algorithm {
    /// The JWS `alg` header value.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            #[cfg(feature = "aat-es256")]
            Self::Es256 => "ES256",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A key that verifies the signature of an AAT or a PoP JWT. The type of the
/// key fixes the one algorithm it is used with: [`Algorithm::Ed25519`] for an
/// Ed25519 key and `Algorithm::Es256` for a P-256 key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VerifyingKey {
    /// An Ed25519 key. Mandatory to implement.
    Ed25519(PublicKey),
    /// A P-256 key.
    #[cfg(feature = "aat-es256")]
    #[cfg_attr(docsrs, doc(cfg(feature = "aat-es256")))]
    P256(P256PublicKey),
}

impl VerifyingKey {
    /// The one algorithm this key is used with.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            #[cfg(feature = "aat-es256")]
            Self::P256(_) => Algorithm::Es256,
        }
    }

    /// The Ed25519 key, or `None` for a key of another type.
    pub fn as_ed25519(&self) -> Option<&PublicKey> {
        match self {
            Self::Ed25519(key) => Some(key),
            #[cfg(feature = "aat-es256")]
            Self::P256(_) => None,
        }
    }

    /// The RFC 7638 thumbprint of this key as an RFC 9278 URI. It is the
    /// `iss` of a token this key signs as a holder, and it identifies a key
    /// of either type.
    pub fn thumbprint_uri(&self) -> String {
        jose::Jwk::from_key(self).thumbprint_uri()
    }
}

impl From<PublicKey> for VerifyingKey {
    fn from(key: PublicKey) -> Self {
        Self::Ed25519(key)
    }
}

#[cfg(feature = "aat-es256")]
impl From<P256PublicKey> for VerifyingKey {
    fn from(key: P256PublicKey) -> Self {
        Self::P256(key)
    }
}

/// A root issuer this enforcement point trusts.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// The issuer identifier a root token's `iss` must equal.
    pub issuer: String,
    /// The key that verifies root tokens from this issuer.
    pub key: VerifyingKey,
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

/// What this enforcement point requires of a presentation. Build one with
/// [`VerifyOptions::new`] and set the fields that differ from its defaults.
#[non_exhaustive]
pub struct VerifyOptions<'a> {
    /// The identifier of this enforcement point. A PoP `aat_aud` and every
    /// chain `aud` that is present must name it.
    pub audience: &'a str,
    /// The current time, in seconds since the Unix epoch.
    pub now: i64,
    /// Size, depth and clock limits.
    pub limits: Limits,
    /// The signature algorithms this enforcement point permits (Section
    /// 9.11). The list is applied to every token in the chain and to the PoP
    /// JWT, each on its own: a signature made with an algorithm that is not
    /// listed is denied, and so is a `cnf.jwk` of a key type that only an
    /// unlisted algorithm uses. A trust anchor's key type does not add its
    /// algorithm to the list. The default permits `Ed25519` only.
    pub algorithms: &'a [Algorithm],
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
    /// Default limits, `Ed25519` only, no audience or nonce requirement, no
    /// replay tracking.
    pub fn new(audience: &'a str, now: i64) -> Self {
        Self {
            audience,
            now,
            limits: Limits::default(),
            algorithms: &[Algorithm::Ed25519],
            require_pop_aud: false,
            require_chain_aud: false,
            nonce: None,
            replay: None,
        }
    }
}

/// A permitted invocation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Verified {
    /// The trust anchor issuer whose key verified the root token.
    pub issuer: String,
    /// The `jti` of every token in the chain, root first.
    pub token_ids: Vec<String>,
    /// The leaf holder's key, which signed the PoP.
    pub holder: VerifyingKey,
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
