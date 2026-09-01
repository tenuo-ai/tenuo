use super::authority::{PresentedAuthority, ReceivedAuthorization};
use super::call::Call;
use super::decision::Denial;
use super::guard::Guard;

/// Operator-side explanation. Never for caller-visible text.
pub struct Diagnostics<'a> {
    guard: &'a Guard,
    subject: Subject<'a>,
}

enum Subject<'a> {
    Holder(&'a PresentedAuthority),
    Received(&'a ReceivedAuthorization<'a>),
}

impl<'a> Diagnostics<'a> {
    pub(crate) fn holder(guard: &'a Guard, authority: &'a PresentedAuthority) -> Self {
        Self {
            guard,
            subject: Subject::Holder(authority),
        }
    }

    pub(crate) fn received(guard: &'a Guard, received: &'a ReceivedAuthorization<'a>) -> Self {
        Self {
            guard,
            subject: Subject::Received(received),
        }
    }

    pub fn explain_denial(&self, denial: &Denial) -> String {
        let leaf = self.leaf_id();
        match (denial.protocol_code(), denial.sdk_kind()) {
            (Some(code), _) => {
                format!("denied {} ({}) for leaf {}", code.name(), code.code(), leaf)
            }
            (None, Some(kind)) => format!("denied {:?} for leaf {}", kind, leaf),
            (None, None) => format!("denied for leaf {}", leaf),
        }
    }

    pub fn why_denied(&self, call: &Call<'_>) -> Option<String> {
        let result = match self.subject {
            Subject::Holder(authority) => self.guard.check(authority, call),
            Subject::Received(received) => self.guard.check_received(received, call),
        };
        match result {
            Ok(_) => None,
            Err(denial) => Some(self.explain_denial(&denial)),
        }
    }

    pub fn explain_authority(&self) -> String {
        match self.subject {
            Subject::Holder(authority) => {
                let caps = authority.capabilities();
                format!(
                    "leaf {} depth {} expires {} holder {} capabilities {:?}",
                    authority.leaf().id(),
                    authority.chain().len(),
                    authority.expires_at(),
                    authority.holder().fingerprint(),
                    caps.names()
                )
            }
            Subject::Received(received) => format!(
                "received leaf {} depth {} approvals {}",
                received.leaf().id(),
                received.chain().len(),
                received.approvals().len()
            ),
        }
    }

    fn leaf_id(&self) -> String {
        match self.subject {
            Subject::Holder(authority) => authority.leaf().id().to_string(),
            Subject::Received(received) => received.leaf().id().to_string(),
        }
    }
}
