use super::{decode_owned, encode_authorized, DecodeLimits, TransportError};
use crate::sdk::authority::OwnedReceivedAuthorization;
use crate::sdk::AuthorizedCall;
use crate::wire::{APPROVALS_HEADER, POP_HEADER, WARRANT_HEADER};

/// Encoded HTTP headers. Encode always emits a stack; approvals omitted when empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedHeaders {
    pub warrant: String,
    pub pop: String,
    pub approvals: Option<String>,
}

impl EncodedHeaders {
    pub fn header_pairs(&self) -> Vec<(&'static str, &str)> {
        let mut pairs = vec![
            (WARRANT_HEADER, self.warrant.as_str()),
            (POP_HEADER, self.pop.as_str()),
        ];
        if let Some(approvals) = &self.approvals {
            pairs.push((APPROVALS_HEADER, approvals.as_str()));
        }
        pairs
    }
}

pub fn headers_from_authorized(
    call: &AuthorizedCall<'_>,
) -> Result<EncodedHeaders, TransportError> {
    let (warrant, pop, approvals) = encode_authorized(call)?;
    Ok(EncodedHeaders {
        warrant,
        pop,
        approvals,
    })
}

pub fn extract_headers(
    headers: &EncodedHeaders,
) -> Result<OwnedReceivedAuthorization, TransportError> {
    decode_owned(
        &headers.warrant,
        &headers.pop,
        headers.approvals.as_deref(),
        DecodeLimits::http(),
    )
}

pub fn extract_from_pairs<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<OwnedReceivedAuthorization, TransportError> {
    let mut warrant = None;
    let mut pop = None;
    let mut approvals = None;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case(WARRANT_HEADER) {
            warrant = Some(value);
        } else if name.eq_ignore_ascii_case(POP_HEADER) {
            pop = Some(value);
        } else if name.eq_ignore_ascii_case(APPROVALS_HEADER) {
            approvals = Some(value);
        }
    }
    let warrant = warrant.ok_or(TransportError::MissingField(WARRANT_HEADER))?;
    let pop = pop.ok_or(TransportError::MissingField(POP_HEADER))?;
    decode_owned(warrant, pop, approvals, DecodeLimits::http())
}
