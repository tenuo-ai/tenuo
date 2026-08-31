//! Authorization receipts (v1).
//!
//! A receipt is a self-contained, signed record of one authorization decision:
//! which authority was presented, which tool was requested, what was decided,
//! and when. This module implements the artifact and its byte encoding.
//!
//! Two properties drive the shape of the code here:
//!
//! - **Self-containment.** The artifact carries the public key it was signed
//!   under, so a verifier can check the signature with no directory lookup and
//!   no live service. Whether that key was legitimately the enforcement
//!   point's is a separate, deliberately separate, question.
//! - **Verify before deserialize.** The signature covers the payload bytes
//!   exactly as received. Callers get the structured payload only after the
//!   signature checks out, so a malformed payload from an unauthenticated
//!   source is never parsed into a decision.

use serde::de::{Error as DeError, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;
use std::fmt;

use crate::crypto::{PublicKey, Signature, SigningKey};
use crate::domain::RECEIPT_CONTEXT;
use crate::error::{Error, Result};

/// The receipt format version this module produces.
pub const RECEIPT_VERSION: u8 = 1;

/// SHA-256 over the revocation list bytes exactly as loaded, for
/// [`ReceiptPayload::srl_hash`].
///
/// Hashes the wire bytes rather than a re-serialization so every
/// implementation derives the same commitment without having to agree on a
/// canonical re-encoding of a list it only ever received as bytes.
pub fn srl_commitment_digest(srl_bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(srl_bytes);
    hasher.finalize().into()
}

/// The decision an enforcement point reached.
///
/// Encoded as the text `"allow"` or `"deny"`. A boolean encoding is
/// non-conformant, which is why this is an enum rather than a `bool`: the wire
/// form cannot drift from the spec without changing this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    Deny,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Deny => "deny",
        }
    }
}

impl Serialize for Outcome {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Outcome {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "allow" => Ok(Outcome::Allow),
            "deny" => Ok(Outcome::Deny),
            other => Err(D::Error::custom(format!(
                "outcome must be \"allow\" or \"deny\", got {:?}",
                other
            ))),
        }
    }
}

/// The signed content of a receipt.
///
/// Encoded as a CBOR map with unsigned integer keys. Absent optional fields are
/// omitted from the map rather than encoded as null, so that two
/// implementations agree on the bytes of the same logical receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptPayload {
    /// Key 0. Must equal [`RECEIPT_VERSION`] and the artifact's `receipt_version`.
    pub version: u8,

    /// Key 1. Deployment-assigned label for the enforcement point.
    ///
    /// Descriptive only, and deliberately so: `signer_key` is the
    /// cryptographic identity and the only field a verifier may key trust on.
    /// This is a human-readable aid for operators reading receipts, never a
    /// lookup key into an authorizer registry — two enforcement points may
    /// carry the same label, and the label may change without the key changing.
    /// Resolving a `signer_key` to a legitimate enforcement point is an
    /// out-of-band concern this artifact does not attempt to answer.
    pub authorizer_id: Option<String>,

    /// Key 2. CBOR-encoded warrant stack for the presented chain, as a byte string.
    pub warrant_chain: Vec<u8>,

    /// Key 3. `"tool:" || tool_name`.
    pub action: String,

    /// Key 4. The decision.
    pub outcome: Outcome,

    /// Key 5. Unix seconds at decision time. Also the basis for recovering PoP
    /// windows during forensic verification.
    pub timestamp: i64,

    /// Key 6. Root principal identifier when known.
    pub root_principal: Option<String>,

    /// Key 7. Commitment to the canonical request. Omitted, never zero-filled,
    /// when the arguments could not be canonicalized.
    pub request_hash: Option<[u8; 32]>,

    /// Key 8. The holder's proof-of-possession signature for this invocation.
    pub pop_signature: Option<[u8; 64]>,

    /// Key 9. Invocation identity, distinguishing repeats that a
    /// window-bound PoP cannot.
    pub request_id: String,

    /// Key 10. Canonical kebab-case error name for a denial. Required when
    /// `outcome` is [`Outcome::Deny`].
    pub decision_code: Option<String>,

    /// Key 11. Commitment to the enforcement point's policy configuration in
    /// force at decision time.
    pub policy_definition_hash: Option<[u8; 32]>,

    /// Key 12. Version of the revocation list in force at decision time.
    ///
    /// Present only when the loaded list carries a version — a published,
    /// monotonic SRL. `None` alongside a present [`Self::srl_hash`] means the
    /// enforcement point held an unversioned list.
    pub srl_version: Option<u64>,

    /// Key 13. SHA-256 over the canonical bytes of the revocation list in
    /// force at decision time.
    ///
    /// Absent means the enforcement point had no revocation data loaded, which
    /// is a different claim from having loaded a list that revoked nothing. A
    /// verifier needs to tell those apart: the first says revocation was never
    /// consulted, the second says it was consulted and did not match. Without
    /// this field a stale or absent list is indistinguishable from a current
    /// one, and "the warrant was not revoked when this ran" is unfalsifiable.
    pub srl_hash: Option<[u8; 32]>,
}

impl ReceiptPayload {
    /// Create a payload for an allowed decision.
    ///
    /// `pop_signature` is required rather than optional. Proof-of-possession is
    /// invariant I6, so an allow cannot have happened without one, and the PoP is
    /// what anchors the decision instant: because the holder signs over a
    /// timestamp window and the window is derived from `timestamp` during
    /// verification, the recorded instant is attested by a key the enforcement
    /// point does not hold. Comparing that window against the issuer-signed
    /// validity bounds is what makes "this warrant was live when this request was
    /// made" checkable rather than merely asserted. An allow without a PoP is
    /// evidence of nothing but the signer's word.
    pub fn allow(
        warrant_chain: Vec<u8>,
        action: impl Into<String>,
        timestamp: i64,
        request_id: impl Into<String>,
        pop_signature: [u8; 64],
    ) -> Self {
        Self {
            version: RECEIPT_VERSION,
            authorizer_id: None,
            warrant_chain,
            action: action.into(),
            outcome: Outcome::Allow,
            timestamp,
            root_principal: None,
            request_hash: None,
            pop_signature: Some(pop_signature),
            request_id: request_id.into(),
            decision_code: None,
            policy_definition_hash: None,
            srl_version: None,
            srl_hash: None,
        }
    }

    /// Create a payload for a denial that occurred *after* proof-of-possession
    /// verified — a constraint violation, a missing approval, and so on.
    ///
    /// The PoP is required here for the same reason it is on an allow: the
    /// enforcement point holds a valid one, and discarding it would throw away
    /// the only second-party attestation of when the request was made.
    ///
    /// `decision_code` must be a canonical kebab-case error name such as
    /// `"constraint-violation"`. It must not carry free text or argument values,
    /// which would reintroduce disclosure into a field intended to be safe to
    /// retain indefinitely.
    pub fn deny(
        warrant_chain: Vec<u8>,
        action: impl Into<String>,
        timestamp: i64,
        request_id: impl Into<String>,
        decision_code: impl Into<String>,
        pop_signature: [u8; 64],
    ) -> Self {
        Self {
            version: RECEIPT_VERSION,
            authorizer_id: None,
            warrant_chain,
            action: action.into(),
            outcome: Outcome::Deny,
            timestamp,
            root_principal: None,
            request_hash: None,
            pop_signature: Some(pop_signature),
            request_id: request_id.into(),
            decision_code: Some(decision_code.into()),
            policy_definition_hash: None,
            srl_version: None,
            srl_hash: None,
        }
    }

    /// Create a payload for a denial that occurred *at or before*
    /// proof-of-possession verification — a broken or untrusted chain, an expired
    /// warrant, or a PoP that was absent or did not verify.
    ///
    /// This is the only shape in which a receipt legitimately carries no
    /// `pop_signature`, because no valid one exists to record. Chain verification
    /// strictly precedes PoP evaluation, so which denials fall here is determined
    /// by where verification stopped, not by the reason code alone — that is why
    /// this is a distinct constructor rather than a rule a verifier can infer.
    ///
    /// A reader must not treat the absent PoP as "not checked": possession was
    /// checked and not established, which is a finding rather than a gap.
    pub fn deny_before_pop(
        warrant_chain: Vec<u8>,
        action: impl Into<String>,
        timestamp: i64,
        request_id: impl Into<String>,
        decision_code: impl Into<String>,
    ) -> Self {
        Self {
            version: RECEIPT_VERSION,
            authorizer_id: None,
            warrant_chain,
            action: action.into(),
            outcome: Outcome::Deny,
            timestamp,
            root_principal: None,
            request_hash: None,
            pop_signature: None,
            request_id: request_id.into(),
            decision_code: Some(decision_code.into()),
            policy_definition_hash: None,
            srl_version: None,
            srl_hash: None,
        }
    }

    /// Check the requirements that depend on other fields rather than on presence alone.
    ///
    /// This is deliberately not called during deserialization: a verifier needs
    /// to observe that a receipt omits a conditionally-required field in order
    /// to report the corresponding claim as failed, which it cannot do if
    /// parsing rejected the receipt outright.
    pub fn check_conditional_requirements(&self) -> Result<()> {
        if self.outcome == Outcome::Deny && self.decision_code.is_none() {
            return Err(Error::InvalidReceipt(
                "decision_code is required when outcome is \"deny\"".to_string(),
            ));
        }
        if self.outcome == Outcome::Allow && self.pop_signature.is_none() {
            return Err(Error::InvalidReceipt(
                "pop_signature is required when outcome is \"allow\"".to_string(),
            ));
        }
        Ok(())
    }

    /// Serialize to deterministic CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes).map_err(|e| {
            Error::InvalidReceipt(format!("failed to serialize receipt payload: {}", e))
        })?;
        Ok(bytes)
    }
}

impl Serialize for ReceiptPayload {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let optional_present = [
            self.authorizer_id.is_some(),
            self.root_principal.is_some(),
            self.request_hash.is_some(),
            self.pop_signature.is_some(),
            self.decision_code.is_some(),
            self.policy_definition_hash.is_some(),
            self.srl_version.is_some(),
            self.srl_hash.is_some(),
        ]
        .iter()
        .filter(|present| **present)
        .count();

        // Keys 0, 2, 3, 4, 5 and 9 are always present.
        let mut map = serializer.serialize_map(Some(6 + optional_present))?;

        map.serialize_entry(&0u8, &self.version)?;
        if let Some(authorizer_id) = &self.authorizer_id {
            map.serialize_entry(&1u8, authorizer_id)?;
        }
        map.serialize_entry(&2u8, serde_bytes::Bytes::new(&self.warrant_chain))?;
        map.serialize_entry(&3u8, &self.action)?;
        map.serialize_entry(&4u8, &self.outcome)?;
        map.serialize_entry(&5u8, &self.timestamp)?;
        if let Some(root_principal) = &self.root_principal {
            map.serialize_entry(&6u8, root_principal)?;
        }
        if let Some(request_hash) = &self.request_hash {
            map.serialize_entry(&7u8, serde_bytes::Bytes::new(request_hash))?;
        }
        if let Some(pop_signature) = &self.pop_signature {
            map.serialize_entry(&8u8, serde_bytes::Bytes::new(pop_signature))?;
        }
        map.serialize_entry(&9u8, &self.request_id)?;
        if let Some(decision_code) = &self.decision_code {
            map.serialize_entry(&10u8, decision_code)?;
        }
        if let Some(policy_definition_hash) = &self.policy_definition_hash {
            map.serialize_entry(&11u8, serde_bytes::Bytes::new(policy_definition_hash))?;
        }
        if let Some(srl_version) = &self.srl_version {
            map.serialize_entry(&12u8, srl_version)?;
        }
        if let Some(srl_hash) = &self.srl_hash {
            map.serialize_entry(&13u8, serde_bytes::Bytes::new(srl_hash))?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ReceiptPayload {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct ReceiptPayloadVisitor;

        fn fixed<const N: usize, E: DeError>(
            bytes: Vec<u8>,
            field: &str,
        ) -> std::result::Result<[u8; N], E> {
            let len = bytes.len();
            bytes
                .try_into()
                .map_err(|_| E::custom(format!("{} must be {} bytes, got {}", field, N, len)))
        }

        impl<'de> Visitor<'de> for ReceiptPayloadVisitor {
            type Value = ReceiptPayload;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("CBOR map of receipt payload with integer keys")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut seen = HashSet::new();

                let mut version = None;
                let mut authorizer_id = None;
                let mut warrant_chain: Option<Vec<u8>> = None;
                let mut action = None;
                let mut outcome = None;
                let mut timestamp = None;
                let mut root_principal = None;
                let mut request_hash = None;
                let mut pop_signature = None;
                let mut request_id = None;
                let mut decision_code = None;
                let mut policy_definition_hash = None;
                let mut srl_version = None;
                let mut srl_hash = None;

                while let Some(key) = map.next_key::<u8>()? {
                    if !seen.insert(key) {
                        return Err(A::Error::custom(format!("duplicate key {}", key)));
                    }
                    match key {
                        0 => version = Some(map.next_value()?),
                        1 => authorizer_id = Some(map.next_value()?),
                        2 => {
                            let bytes: serde_bytes::ByteBuf = map.next_value()?;
                            warrant_chain = Some(bytes.into_vec());
                        }
                        3 => action = Some(map.next_value()?),
                        4 => outcome = Some(map.next_value()?),
                        5 => timestamp = Some(map.next_value()?),
                        6 => root_principal = Some(map.next_value()?),
                        7 => {
                            let bytes: serde_bytes::ByteBuf = map.next_value()?;
                            request_hash = Some(fixed(bytes.into_vec(), "request_hash")?);
                        }
                        8 => {
                            let bytes: serde_bytes::ByteBuf = map.next_value()?;
                            pop_signature = Some(fixed(bytes.into_vec(), "pop_signature")?);
                        }
                        9 => request_id = Some(map.next_value()?),
                        10 => decision_code = Some(map.next_value()?),
                        11 => {
                            let bytes: serde_bytes::ByteBuf = map.next_value()?;
                            policy_definition_hash =
                                Some(fixed(bytes.into_vec(), "policy_definition_hash")?);
                        }
                        12 => srl_version = Some(map.next_value()?),
                        13 => {
                            let bytes: serde_bytes::ByteBuf = map.next_value()?;
                            srl_hash = Some(fixed(bytes.into_vec(), "srl_hash")?);
                        }
                        _ => {
                            return Err(A::Error::custom(format!(
                                "unknown receipt payload key {}",
                                key
                            )));
                        }
                    }
                }

                Ok(ReceiptPayload {
                    version: version.ok_or_else(|| A::Error::custom("missing version"))?,
                    authorizer_id,
                    warrant_chain: warrant_chain
                        .ok_or_else(|| A::Error::custom("missing warrant_chain"))?,
                    action: action.ok_or_else(|| A::Error::custom("missing action"))?,
                    outcome: outcome.ok_or_else(|| A::Error::custom("missing outcome"))?,
                    timestamp: timestamp.ok_or_else(|| A::Error::custom("missing timestamp"))?,
                    root_principal,
                    request_hash,
                    pop_signature,
                    request_id: request_id.ok_or_else(|| A::Error::custom("missing request_id"))?,
                    decision_code,
                    policy_definition_hash,
                    srl_version,
                    srl_hash,
                })
            }
        }

        deserializer.deserialize_map(ReceiptPayloadVisitor)
    }
}

/// A signed authorization receipt.
///
/// Mirrors the shape of [`crate::approval::SignedApproval`]: a version readable
/// before parsing, the opaque signed bytes, the signer's public key extracted
/// for convenience, and the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Selects the preimage construction before any parsing. Unauthenticated by
    /// necessity, and cross-checked against payload key 0 during verification.
    pub receipt_version: u8,

    /// The exact deterministic CBOR bytes of the payload, carried opaquely.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,

    /// Public key of the signing enforcement point (extracted for convenience;
    /// not itself signed).
    pub signer_key: PublicKey,

    /// Ed25519 signature over `RECEIPT_CONTEXT || receipt_version || payload`.
    pub signature: Signature,
}

impl Receipt {
    /// Sign a payload, producing a receipt.
    pub fn create(payload: &ReceiptPayload, signing_key: &SigningKey) -> Result<Self> {
        let payload_bytes = payload.to_cbor()?;
        let preimage = Self::build_preimage(RECEIPT_VERSION, &payload_bytes);

        Ok(Self {
            receipt_version: RECEIPT_VERSION,
            payload: payload_bytes,
            signer_key: signing_key.public_key(),
            signature: signing_key.sign(&preimage),
        })
    }

    /// Verify the signature and return the parsed payload.
    ///
    /// This establishes *authenticity* only: that `signer_key` signed these
    /// payload bytes. It says nothing about whether that key was legitimately
    /// the enforcement point's, nor whether the chain, arguments, or decision
    /// hold up — those are separate claims produced by the claim-set verifier.
    /// Callers must not treat a successful return as authorization evidence.
    pub fn verify_signature(&self) -> Result<ReceiptPayload> {
        if self.receipt_version != RECEIPT_VERSION {
            return Err(Error::UnsupportedVersion(self.receipt_version));
        }

        let preimage = Self::build_preimage(self.receipt_version, &self.payload);
        self.signer_key
            .verify(&preimage, &self.signature)
            .map_err(|e| Error::InvalidReceipt(format!("signature does not verify: {}", e)))?;

        let payload: ReceiptPayload = ciborium::from_reader(&self.payload[..])
            .map_err(|e| Error::InvalidReceipt(format!("failed to deserialize payload: {}", e)))?;

        // A payload version that disagrees with the artifact would let a
        // transport downgrade a receipt by rewriting the unauthenticated field.
        if payload.version != self.receipt_version {
            return Err(Error::InvalidReceipt(format!(
                "payload version {} does not match artifact version {}",
                payload.version, self.receipt_version
            )));
        }

        Ok(payload)
    }

    /// Build the domain-separated signing preimage.
    ///
    /// Format: `RECEIPT_CONTEXT || receipt_version || payload_bytes`
    fn build_preimage(receipt_version: u8, payload_bytes: &[u8]) -> Vec<u8> {
        let mut preimage = Vec::with_capacity(RECEIPT_CONTEXT.len() + 1 + payload_bytes.len());
        preimage.extend_from_slice(RECEIPT_CONTEXT);
        preimage.push(receipt_version);
        preimage.extend_from_slice(payload_bytes);
        preimage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;

    fn payload() -> ReceiptPayload {
        ReceiptPayload::allow(
            vec![0xA1, 0x01, 0x02],
            "tool:read_file",
            1_700_000_000,
            "req-1",
            [9u8; 64],
        )
    }

    fn full_payload() -> ReceiptPayload {
        ReceiptPayload {
            version: RECEIPT_VERSION,
            authorizer_id: Some("authorizer-1".to_string()),
            warrant_chain: vec![0xA1, 0x01, 0x02],
            action: "tool:delete_file".to_string(),
            outcome: Outcome::Deny,
            timestamp: 1_700_000_000,
            root_principal: Some("root@example.com".to_string()),
            request_hash: Some([7u8; 32]),
            pop_signature: Some([9u8; 64]),
            request_id: "req-2".to_string(),
            decision_code: Some("tool-not-authorized".to_string()),
            policy_definition_hash: Some([3u8; 32]),
            srl_version: Some(47),
            srl_hash: Some([5u8; 32]),
        }
    }

    /// An unversioned list still commits: key 13 present, key 12 absent. This
    /// is the shape produced by a plain `SignedRevocationList`, and it must not
    /// be confused with having loaded nothing at all.
    #[test]
    fn round_trips_an_unversioned_revocation_commitment() {
        let mut original = full_payload();
        original.srl_version = None;
        original.srl_hash = Some([5u8; 32]);

        let bytes = original.to_cbor().unwrap();
        let decoded: ReceiptPayload = ciborium::from_reader(&bytes[..]).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(decoded.srl_version, None);
        assert_eq!(decoded.srl_hash, Some([5u8; 32]));
    }

    /// No revocation data loaded omits both keys rather than encoding null, so
    /// two implementations agree on the bytes of the same logical receipt.
    #[test]
    fn omits_revocation_keys_when_no_list_was_loaded() {
        let original = payload();
        assert_eq!(original.srl_version, None);
        assert_eq!(original.srl_hash, None);

        let bytes = original.to_cbor().unwrap();
        let map: ciborium::Value = ciborium::from_reader(&bytes[..]).unwrap();
        let keys: Vec<i128> = match map {
            ciborium::Value::Map(entries) => entries
                .iter()
                .filter_map(|(k, _)| k.as_integer().map(i128::from))
                .collect(),
            other => panic!("payload must encode as a CBOR map, got {:?}", other),
        };

        assert!(!keys.contains(&12), "key 12 must be omitted, not null");
        assert!(!keys.contains(&13), "key 13 must be omitted, not null");
    }

    #[test]
    fn rejects_an_srl_hash_that_is_not_32_bytes() {
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &ciborium::Value::Map(vec![
                (ciborium::Value::Integer(13u8.into()), ciborium::Value::Bytes(vec![0u8; 31])),
            ]),
            &mut bytes,
        )
        .unwrap();

        let decoded: std::result::Result<ReceiptPayload, _> = ciborium::from_reader(&bytes[..]);
        let message = decoded.unwrap_err().to_string();
        assert!(
            message.contains("srl_hash") && message.contains("32"),
            "error must name the field and the expected length, got: {message}"
        );
    }

    #[test]
    fn round_trips_a_minimal_payload() {
        let original = payload();
        let bytes = original.to_cbor().unwrap();
        let decoded: ReceiptPayload = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn round_trips_a_payload_with_every_field_present() {
        let original = full_payload();
        let bytes = original.to_cbor().unwrap();
        let decoded: ReceiptPayload = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encoding_is_deterministic() {
        let payload = full_payload();
        assert_eq!(payload.to_cbor().unwrap(), payload.to_cbor().unwrap());
    }

    #[test]
    fn absent_optional_fields_are_omitted_not_null() {
        let bytes = payload().to_cbor().unwrap();
        let value: ciborium::Value = ciborium::from_reader(&bytes[..]).unwrap();
        let entries = value.as_map().expect("payload must encode as a CBOR map");

        let keys: Vec<i128> = entries
            .iter()
            .map(|(k, _)| k.as_integer().expect("keys must be integers").into())
            .collect();
        assert_eq!(keys, vec![0, 2, 3, 4, 5, 8, 9]);
        assert!(entries.iter().all(|(_, v)| !v.is_null()));
    }

    #[test]
    fn integer_keys_are_encoded_in_numeric_order() {
        let bytes = full_payload().to_cbor().unwrap();
        let value: ciborium::Value = ciborium::from_reader(&bytes[..]).unwrap();
        let keys: Vec<i128> = value
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_integer().unwrap().into())
            .collect();
        assert_eq!(keys, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
    }

    #[test]
    fn byte_fields_encode_as_cbor_byte_strings_not_arrays() {
        let bytes = full_payload().to_cbor().unwrap();
        let value: ciborium::Value = ciborium::from_reader(&bytes[..]).unwrap();
        let entries = value.as_map().unwrap();

        for key in [2i128, 7, 8, 11, 13] {
            let (_, field) = entries
                .iter()
                .find(|(k, _)| i128::from(k.as_integer().unwrap()) == key)
                .unwrap();
            assert!(
                field.is_bytes(),
                "key {} must encode as a CBOR byte string, got {:?}",
                key,
                field
            );
        }
    }

    #[test]
    fn outcome_encodes_as_text_not_boolean() {
        let bytes = payload().to_cbor().unwrap();
        let value: ciborium::Value = ciborium::from_reader(&bytes[..]).unwrap();
        let (_, outcome) = value
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| i128::from(k.as_integer().unwrap()) == 4)
            .unwrap();
        assert_eq!(outcome.as_text(), Some("allow"));
    }

    #[test]
    fn rejects_a_boolean_outcome() {
        let encoded = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(0.into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer(2.into()),
                ciborium::Value::Bytes(vec![0xA1]),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Text("tool:read".into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Bool(true),
            ),
            (
                ciborium::Value::Integer(5.into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer(9.into()),
                ciborium::Value::Text("req".into()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&encoded, &mut bytes).unwrap();

        let decoded: std::result::Result<ReceiptPayload, _> = ciborium::from_reader(&bytes[..]);
        assert!(decoded.is_err(), "a boolean outcome must be rejected");
    }

    #[test]
    fn rejects_unknown_payload_keys() {
        let mut bytes = Vec::new();
        let encoded = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(0.into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer(2.into()),
                ciborium::Value::Bytes(vec![0xA1]),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Text("tool:read".into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Text("allow".into()),
            ),
            (
                ciborium::Value::Integer(5.into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer(9.into()),
                ciborium::Value::Text("req".into()),
            ),
            (
                ciborium::Value::Integer(99.into()),
                ciborium::Value::Text("surprise".into()),
            ),
        ]);
        ciborium::into_writer(&encoded, &mut bytes).unwrap();

        let decoded: std::result::Result<ReceiptPayload, _> = ciborium::from_reader(&bytes[..]);
        assert!(decoded.is_err(), "unknown keys must fail closed");
    }

    #[test]
    fn rejects_a_wrong_length_request_hash() {
        let mut bytes = Vec::new();
        let encoded = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(0.into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer(2.into()),
                ciborium::Value::Bytes(vec![0xA1]),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Text("tool:read".into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Text("allow".into()),
            ),
            (
                ciborium::Value::Integer(5.into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer(7.into()),
                ciborium::Value::Bytes(vec![0u8; 31]),
            ),
            (
                ciborium::Value::Integer(9.into()),
                ciborium::Value::Text("req".into()),
            ),
        ]);
        ciborium::into_writer(&encoded, &mut bytes).unwrap();

        let decoded: std::result::Result<ReceiptPayload, _> = ciborium::from_reader(&bytes[..]);
        assert!(decoded.is_err(), "a 31-byte request_hash must be rejected");
    }

    #[test]
    fn signs_and_verifies() {
        let key = SigningKey::generate();
        let receipt = Receipt::create(&full_payload(), &key).unwrap();

        assert_eq!(receipt.receipt_version, RECEIPT_VERSION);
        assert_eq!(receipt.signer_key, key.public_key());
        assert_eq!(receipt.verify_signature().unwrap(), full_payload());
    }

    #[test]
    fn verification_fails_when_payload_is_tampered_with() {
        let key = SigningKey::generate();
        let mut receipt = Receipt::create(&full_payload(), &key).unwrap();

        let last = receipt.payload.len() - 1;
        receipt.payload[last] ^= 0xFF;

        assert!(receipt.verify_signature().is_err());
    }

    #[test]
    fn verification_fails_under_a_different_signer_key() {
        let key = SigningKey::generate();
        let other = SigningKey::generate();
        let mut receipt = Receipt::create(&full_payload(), &key).unwrap();

        receipt.signer_key = other.public_key();

        assert!(receipt.verify_signature().is_err());
    }

    #[test]
    fn domain_separation_rejects_a_signature_over_the_bare_payload() {
        let key = SigningKey::generate();
        let payload_bytes = full_payload().to_cbor().unwrap();

        let receipt = Receipt {
            receipt_version: RECEIPT_VERSION,
            payload: payload_bytes.clone(),
            signer_key: key.public_key(),
            signature: key.sign(&payload_bytes),
        };

        assert!(
            receipt.verify_signature().is_err(),
            "a signature omitting the domain context must not verify"
        );
    }

    #[test]
    fn artifact_version_cannot_be_downgraded_without_detection() {
        let key = SigningKey::generate();
        let mut receipt = Receipt::create(&full_payload(), &key).unwrap();

        receipt.receipt_version = 2;

        // Rewriting the unauthenticated field changes the preimage, so this is
        // caught at the signature rather than at the version cross-check.
        assert!(receipt.verify_signature().is_err());
    }

    #[test]
    fn payload_version_must_match_artifact_version() {
        let key = SigningKey::generate();
        let mut payload = full_payload();
        payload.version = 2;

        let payload_bytes = payload.to_cbor().unwrap();
        let preimage = Receipt::build_preimage(RECEIPT_VERSION, &payload_bytes);
        let receipt = Receipt {
            receipt_version: RECEIPT_VERSION,
            payload: payload_bytes,
            signer_key: key.public_key(),
            signature: key.sign(&preimage),
        };

        let error = receipt.verify_signature().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match artifact version"),
            "expected a version mismatch, got: {}",
            error
        );
    }

    #[test]
    fn the_artifact_round_trips_through_cbor() {
        let key = SigningKey::generate();
        let receipt = Receipt::create(&full_payload(), &key).unwrap();

        let mut bytes = Vec::new();
        ciborium::into_writer(&receipt, &mut bytes).unwrap();
        let decoded: Receipt = ciborium::from_reader(&bytes[..]).unwrap();

        assert_eq!(decoded.verify_signature().unwrap(), full_payload());
    }

    #[test]
    fn a_denial_without_a_decision_code_is_rejected_by_the_conditional_check() {
        let mut payload = full_payload();
        payload.decision_code = None;

        assert!(payload.check_conditional_requirements().is_err());
        assert!(full_payload().check_conditional_requirements().is_ok());
    }

    #[test]
    fn an_allow_without_a_pop_signature_is_rejected_by_the_conditional_check() {
        let mut allowed = payload();
        allowed.pop_signature = None;

        assert!(allowed.check_conditional_requirements().is_err());
        assert!(payload().check_conditional_requirements().is_ok());
    }

    #[test]
    fn a_denial_before_pop_verification_may_omit_the_pop_signature() {
        let denied = ReceiptPayload::deny_before_pop(
            vec![0xA1, 0x01, 0x02],
            "tool:read_file",
            1_700_000_000,
            "req-3",
            "pop-signature-invalid",
        );

        assert!(denied.pop_signature.is_none());
        assert!(denied.check_conditional_requirements().is_ok());
    }
}
