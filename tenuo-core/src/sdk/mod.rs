//! Framework-independent enforcement surface.
//!
//! Default-off (`sdk` feature). Holder-sign path only in this milestone;
//! received-verify and transport bindings follow.

mod authority;
mod call;
mod decision;
mod diagnostics;
mod guard;
mod signer;

pub use authority::{AuthorityError, CapabilityView, PresentedAuthority};
pub use call::{ArgumentError, Call};
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
