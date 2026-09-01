//! Framework-independent enforcement surface.
//!
//! Default-off (`sdk` feature). Holder-sign and received-verify share one
//! `Authorizer` decision. Transport bindings are extra features.
//!
//! `ObservingGuard` is an assessment window, not enforcement. Receipts, async,
//! and OpenTelemetry are separate default-off features.

mod approvals;
mod authority;
mod call;
mod clock;
mod decision;
mod delegation;
mod diagnostics;
mod guard;
#[macro_use]
mod macros;
mod observe;
pub mod prelude;
mod signer;
mod tenuo;

#[cfg(feature = "test-utils")]
pub mod test_utils;

#[cfg(feature = "async")]
mod async_api;
#[cfg(feature = "receipts")]
mod evidence;
#[cfg(feature = "otel")]
mod telemetry;

#[cfg(any(feature = "mcp-transport", feature = "http-transport"))]
pub mod transport;

pub use approvals::{ApprovalError, ApprovalProvider, LocalApprovalSigner};
pub use authority::{
    AuthorityError, CapabilityView, OwnedReceivedAuthorization, PresentedAuthority,
    ReceivedAuthorization,
};
pub use call::{ArgumentError, Call, VerifiedProjection};
#[cfg(feature = "test-utils")]
pub use clock::FixedClock;
pub use clock::{Clock, SystemClock};
pub use decision::{
    Decision, DecisionMetadata, Denial, DenialReporting, GuardError, Retryability, SdkDenialKind,
};
pub use delegation::{DelegationError, DelegationProfile};
pub use diagnostics::Diagnostics;
pub use guard::{
    AuthorizationAttempt, AuthorizedCall, Guard, GuardBuildError, GuardBuilder, Guarded,
    RevocationMode,
};
pub use observe::{
    ArgumentShape, ArgumentShapePolicy, ObservationRecord, ObservationVerdict, ObserveBuildError,
    ObserveError, Observed, ObservedOutcome, ObservingGuard, ObservingGuardBuilder,
    PresentedRequest, ValueClass,
};
pub use signer::{
    DelegationSigningRequest, HolderSigner, LocalSigner, PopSigningRequest, SignerError,
};
pub use tenuo::{EnforcementBuilder, LocalBuilder, Tenuo, TenuoBuildError};

#[cfg(feature = "async")]
pub use async_api::{
    AsyncHolderSigner, AsyncRevocationProvider, AttemptControl, PresentedAsyncAuthority,
};
#[cfg(feature = "receipts")]
pub use evidence::{
    EvidencePolicy, LocalReceiptSigner, MemoryReceiptSink, ReceiptRef, ReceiptSigner,
    ReceiptSignerError, ReceiptSigningRequest, ReceiptSink, ReceiptSinkError,
};

#[cfg(test)]
mod spec_invariants;
