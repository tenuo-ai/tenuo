use super::authority::PresentedAuthority;
use super::call::Call;
use super::decision::Denial;
use super::guard::Guard;

/// Operator-side explanation. Never for caller-visible text.
pub struct Diagnostics<'a> {
    guard: &'a Guard,
    authority: &'a PresentedAuthority,
}

impl<'a> Diagnostics<'a> {
    pub(crate) fn new(guard: &'a Guard, authority: &'a PresentedAuthority) -> Self {
        Self { guard, authority }
    }

    pub fn explain_denial(&self, denial: &Denial) -> String {
        match (denial.protocol_code(), denial.sdk_kind()) {
            (Some(code), _) => format!(
                "denied {} ({}) for leaf {}",
                code.name(),
                code.code(),
                self.authority.leaf().id()
            ),
            (None, Some(kind)) => {
                format!("denied {:?} for leaf {}", kind, self.authority.leaf().id())
            }
            (None, None) => format!("denied for leaf {}", self.authority.leaf().id()),
        }
    }

    pub fn why_denied(&self, call: &Call<'_>) -> Option<String> {
        match self.guard.check(self.authority, call) {
            Ok(_) => None,
            Err(denial) => Some(self.explain_denial(&denial)),
        }
    }

    pub fn explain_authority(&self) -> String {
        let caps = self.authority.capabilities();
        format!(
            "leaf {} depth {} expires {} holder {} capabilities {:?}",
            self.authority.leaf().id(),
            self.authority.chain().len(),
            self.authority.expires_at(),
            self.authority.holder().fingerprint(),
            caps.names()
        )
    }
}
