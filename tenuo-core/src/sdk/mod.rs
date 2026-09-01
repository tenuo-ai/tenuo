//! Framework-independent enforcement surface.
//!
//! Default-off (`sdk` feature). Holder-sign and received-verify share one
//! `Authorizer` decision. Transport bindings are extra features.

mod authority;
mod call;
mod decision;
mod diagnostics;
mod guard;
#[macro_use]
mod macros;
mod signer;
mod tenuo;

#[cfg(any(feature = "mcp-transport", feature = "http-transport"))]
pub mod transport;

pub use authority::{
    AuthorityError, CapabilityView, OwnedReceivedAuthorization, PresentedAuthority,
    ReceivedAuthorization,
};
pub use call::{ArgumentError, Call, VerifiedProjection};
pub use decision::{
    Decision, DecisionMetadata, Denial, DenialReporting, GuardError, Retryability, SdkDenialKind,
};
pub use diagnostics::Diagnostics;
pub use guard::{
    AuthorizationAttempt, AuthorizedCall, Guard, GuardBuildError, GuardBuilder, Guarded,
    RevocationMode,
};
pub use signer::{
    DelegationSigningRequest, HolderSigner, LocalSigner, PopSigningRequest, SignerError,
};
pub use tenuo::{EnforcementBuilder, LocalBuilder, Tenuo, TenuoBuildError};

#[cfg(test)]
mod spec_invariants;
