//! Authorization receipts: signer, sink, and evidence policy.

use crate::crypto::{PublicKey, Signature, SigningKey};
use crate::receipt::{Receipt, RECEIPT_VERSION};
use crate::SIGNATURE_CONTEXT;
use std::fmt;
use std::sync::Mutex;

/// How receipt persistence interacts with the authorization outcome.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EvidencePolicy {
    #[default]
    Disabled,
    BestEffort,
    RequiredBeforeExecution,
}

/// Raw signature over a receipt's complete final signing bytes.
pub trait ReceiptSigner: Send + Sync {
    fn public_key(&self) -> PublicKey;
    fn sign_receipt(
        &self,
        request: &ReceiptSigningRequest<'_>,
    ) -> Result<Signature, ReceiptSignerError>;
}

/// Local non-blocking persistence. Remote durable sinks belong on the async surface.
pub trait ReceiptSink: Send + Sync {
    fn persist(&self, receipt: &Receipt) -> Result<ReceiptRef, ReceiptSinkError>;
}

/// `SIGNATURE_CONTEXT || RECEIPT_CONTEXT || version || payload`.
pub struct ReceiptSigningRequest<'a> {
    preimage: &'a [u8],
}

impl<'a> ReceiptSigningRequest<'a> {
    pub(crate) fn new(preimage: &'a [u8]) -> Self {
        Self { preimage }
    }

    pub fn purpose(&self) -> &'static str {
        "receipt"
    }

    pub fn final_signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNATURE_CONTEXT.len() + self.preimage.len());
        out.extend_from_slice(SIGNATURE_CONTEXT);
        out.extend_from_slice(self.preimage);
        out
    }
}

/// In-process receipt key. `for_development` is not a production default.
pub struct LocalReceiptSigner {
    key: SigningKey,
}

impl LocalReceiptSigner {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    /// Per-process generated signer. Unattributed; not the production default.
    pub fn for_development() -> Self {
        Self {
            key: SigningKey::generate(),
        }
    }
}

impl ReceiptSigner for LocalReceiptSigner {
    fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    fn sign_receipt(
        &self,
        request: &ReceiptSigningRequest<'_>,
    ) -> Result<Signature, ReceiptSignerError> {
        Ok(self.key.sign_raw(&request.final_signing_bytes()))
    }
}

/// In-memory sink for tests and local RequiredBeforeExecution.
#[derive(Default)]
pub struct MemoryReceiptSink {
    stored: Mutex<Vec<Receipt>>,
}

impl MemoryReceiptSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stored(&self) -> Vec<Receipt> {
        self.stored.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl ReceiptSink for MemoryReceiptSink {
    fn persist(&self, receipt: &Receipt) -> Result<ReceiptRef, ReceiptSinkError> {
        let mut stored = self
            .stored
            .lock()
            .map_err(|_| ReceiptSinkError::Unavailable)?;
        stored.push(receipt.clone());
        Ok(ReceiptRef {
            id: format!("mem:{}", stored.len()),
        })
    }
}

/// Handle returned by a sink. Not a capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRef {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptSignerError {
    Unavailable,
}

impl fmt::Display for ReceiptSignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(f, "receipt signer unavailable"),
        }
    }
}

impl std::error::Error for ReceiptSignerError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptSinkError {
    Unavailable,
}

impl fmt::Display for ReceiptSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(f, "receipt sink unavailable"),
        }
    }
}

impl std::error::Error for ReceiptSinkError {}

pub(crate) fn sign_payload(
    payload_bytes: &[u8],
    signer: &dyn ReceiptSigner,
) -> Result<Receipt, ReceiptSignerError> {
    let preimage = Receipt::signing_preimage(RECEIPT_VERSION, payload_bytes);
    let request = ReceiptSigningRequest::new(&preimage);
    let signature = signer.sign_receipt(&request)?;
    Ok(Receipt {
        receipt_version: RECEIPT_VERSION,
        payload: payload_bytes.to_vec(),
        signer_key: signer.public_key(),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use crate::receipt::{Receipt, ReceiptPayload};

    #[test]
    fn local_signer_verifies_against_core() {
        let signer = LocalReceiptSigner::for_development();
        let payload = ReceiptPayload::allow(
            vec![0xA1, 0x01, 0x02],
            "tool:read",
            1_700_000_000,
            "inv-1",
            [3u8; 64],
        );
        let bytes = payload.to_cbor().unwrap();
        let receipt = sign_payload(&bytes, &signer).unwrap();
        let verified = receipt.verify_signature().unwrap();
        assert_eq!(verified.action, "tool:read");
        assert_eq!(verified.request_id, "inv-1");
    }

    #[test]
    fn memory_sink_round_trips() {
        let sink = MemoryReceiptSink::new();
        let signer = LocalReceiptSigner::for_development();
        let payload = ReceiptPayload::allow(vec![0xA0], "tool:read", 1, "inv-2", [1u8; 64]);
        let receipt = sign_payload(&payload.to_cbor().unwrap(), &signer).unwrap();
        let reference = sink.persist(&receipt).unwrap();
        assert!(reference.id.starts_with("mem:"));
        assert_eq!(sink.stored().len(), 1);
    }

    #[test]
    fn required_persist_failure_denies_without_running() {
        use crate::constraints::ConstraintSet;
        use crate::planes::Authorizer;
        use crate::sdk::signer::LocalSigner;
        use crate::sdk::{Call, Guard, PresentedAuthority, RevocationMode};
        use crate::warrant::Warrant;
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        struct FailSink;
        impl ReceiptSink for FailSink {
            fn persist(&self, _: &Receipt) -> Result<ReceiptRef, ReceiptSinkError> {
                Err(ReceiptSinkError::Unavailable)
            }
        }

        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(3600),
            })
            .evidence_policy(EvidencePolicy::RequiredBeforeExecution)
            .receipt_signer(Arc::new(LocalReceiptSigner::for_development()))
            .receipt_sink(Arc::new(FailSink))
            .build()
            .unwrap();
        let authority =
            PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder))).unwrap();
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
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
            crate::sdk::GuardError::Denied(denial) => {
                assert_eq!(
                    denial.sdk_kind(),
                    Some(crate::sdk::SdkDenialKind::EvidenceUnavailable)
                );
            }
            crate::sdk::GuardError::Operation(_) => panic!("operation must not run"),
        }
    }

    #[test]
    fn best_effort_persist_failure_still_allows() {
        use crate::constraints::ConstraintSet;
        use crate::planes::Authorizer;
        use crate::sdk::signer::LocalSigner;
        use crate::sdk::{Call, Guard, PresentedAuthority, RevocationMode};
        use crate::warrant::Warrant;
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Duration;

        struct FailSink;
        impl ReceiptSink for FailSink {
            fn persist(&self, _: &Receipt) -> Result<ReceiptRef, ReceiptSinkError> {
                Err(ReceiptSinkError::Unavailable)
            }
        }

        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(3600),
            })
            .evidence_policy(EvidencePolicy::BestEffort)
            .receipt_signer(Arc::new(LocalReceiptSigner::for_development()))
            .receipt_sink(Arc::new(FailSink))
            .build()
            .unwrap();
        let authority =
            PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder))).unwrap();
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        let decision = guard.check(&authority, &call).expect("allow");
        assert!(decision.receipt.is_some());
        decision.receipt.unwrap().verify_signature().unwrap();
    }

    #[test]
    fn observer_does_not_emit_receipts() {
        use crate::constraints::ConstraintSet;
        use crate::planes::Authorizer;
        use crate::sdk::signer::LocalSigner;
        use crate::sdk::{Call, Guard, PresentedAuthority, PresentedRequest, RevocationMode};
        use crate::warrant::Warrant;
        use chrono::Utc;
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Duration;

        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let sink = Arc::new(MemoryReceiptSink::new());
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(3600),
            })
            .evidence_policy(EvidencePolicy::BestEffort)
            .receipt_signer(Arc::new(LocalReceiptSigner::for_development()))
            .receipt_sink(sink.clone())
            .build()
            .unwrap();
        let authority =
            PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder))).unwrap();
        let args = HashMap::new();
        let call = Call::borrowed("read", &args);
        assert!(guard.check(&authority, &call).unwrap().receipt.is_some());
        assert_eq!(sink.stored().len(), 1);
        guard
            .observe_until(Utc::now() + chrono::Duration::hours(1))
            .observe(PresentedRequest::Holder(&authority), &call, || {
                Ok::<_, &str>(())
            })
            .unwrap();
        assert_eq!(sink.stored().len(), 1);
    }
}
