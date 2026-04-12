//! Connect token support for streamlined onboarding.
//!
//! A connect token (`tenuo_ct_<base64url-json>`) bundles all credentials needed
//! to register an authorizer with the Tenuo Cloud control plane into a single
//! copy-pasteable string. The token is created via the dashboard's Quick Connect
//! dialog and can be shared across multiple authorizer instances.
//!
//! # Token format (v1)
//!
//! ```text
//! tenuo_ct_<base64url({"v":1,"e":"<endpoint>","k":"<api_key>","a":"<agent_id>","t":"<reg_token>"})>
//! ```
//!
//! The `e` field may or may not include a `/v1` suffix; [`ConnectToken::parse`]
//! normalizes it to the bare origin so callers can uniformly build
//! `{endpoint}/v1/…` paths.
//!
//! Fields `a` (agent ID) and `t` (registration token) are optional — when absent
//! the token acts as a pure authorizer credential without agent binding.

use base64::Engine;
use serde::{Deserialize, Serialize};

const TOKEN_PREFIX: &str = "tenuo_ct_";

/// Parsed connect token payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectToken {
    /// Token format version (currently 1).
    #[serde(rename = "v", default = "default_version")]
    pub version: u8,
    /// Control plane API base endpoint (e.g. `https://staging.tenuo.cloud`).
    ///
    /// Callers append `/v1/…` paths to this value. If the token's `e` field
    /// contains a trailing `/v1` it is stripped during [`ConnectToken::parse`]
    /// so all URL construction is consistent.
    #[serde(rename = "e")]
    pub endpoint: String,
    /// API key with `authorizer` scope.
    #[serde(rename = "k")]
    pub api_key: String,
    /// Pre-created agent ID (omitted for authorizer-only tokens).
    #[serde(rename = "a", default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// One-time registration token for claiming the agent.
    #[serde(rename = "t", default, skip_serializing_if = "Option::is_none")]
    pub registration_token: Option<String>,
}

fn default_version() -> u8 {
    1
}

/// Errors specific to connect token operations.
#[derive(Debug)]
pub enum ConnectTokenError {
    /// Token string does not start with the expected prefix.
    MissingPrefix,
    /// Base64 decoding failed.
    Base64(String),
    /// JSON parsing failed.
    Json(String),
    /// A required field is empty.
    MissingField(&'static str),
    /// Agent claim HTTP request failed.
    ClaimFailed(String),
    /// Token version is newer than this SDK supports.
    UnsupportedVersion(u8),
}

impl std::fmt::Display for ConnectTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPrefix => write!(f, "token must start with '{}'", TOKEN_PREFIX),
            Self::Base64(e) => write!(f, "base64 decode error: {}", e),
            Self::Json(e) => write!(f, "JSON parse error: {}", e),
            Self::MissingField(name) => write!(f, "required field '{}' is empty", name),
            Self::ClaimFailed(e) => write!(f, "agent claim failed: {}", e),
            Self::UnsupportedVersion(v) => write!(
                f,
                "connect token version {} is not supported by this SDK (max: 1). \
                 Upgrade tenuo to use this token.",
                v
            ),
        }
    }
}

impl std::error::Error for ConnectTokenError {}

impl ConnectToken {
    /// Parse a raw `tenuo_ct_…` string into a [`ConnectToken`].
    pub fn parse(raw: &str) -> Result<Self, ConnectTokenError> {
        let encoded = raw
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(ConnectTokenError::MissingPrefix)?;

        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| ConnectTokenError::Base64(e.to_string()))?;

        let token: ConnectToken = serde_json::from_slice(&json_bytes)
            .map_err(|e| ConnectTokenError::Json(e.to_string()))?;

        const MAX_SUPPORTED_VERSION: u8 = 1;
        if token.version > MAX_SUPPORTED_VERSION {
            return Err(ConnectTokenError::UnsupportedVersion(token.version));
        }

        if token.endpoint.is_empty() {
            return Err(ConnectTokenError::MissingField("endpoint"));
        }
        if token.api_key.is_empty() {
            return Err(ConnectTokenError::MissingField("api_key"));
        }

        // Normalize: strip trailing `/v1` (and trailing slashes) so all
        // callers can uniformly prepend `/v1/…` paths without doubling.
        let mut ep = token.endpoint;
        ep = ep.trim_end_matches('/').to_string();
        if ep.ends_with("/v1") {
            ep.truncate(ep.len() - 3);
        }

        Ok(ConnectToken {
            endpoint: ep,
            ..token
        })
    }

    /// Claim the pre-created agent using the embedded registration token.
    ///
    /// This is a no-op when `agent_id` or `registration_token` is absent.
    /// HTTP 409 (already claimed) is treated as success so the same token can
    /// be safely reused by multiple authorizer instances.
    pub async fn claim_agent(
        &self,
        signing_key: &crate::crypto::SigningKey,
    ) -> Result<(), ConnectTokenError> {
        let (agent_id, reg_token) = match (&self.agent_id, &self.registration_token) {
            (Some(a), Some(t)) if !a.is_empty() && !t.is_empty() => (a, t),
            _ => return Ok(()),
        };

        let public_key_hex = hex::encode(signing_key.public_key().to_bytes());
        let claim_url = format!("{}/v1/agents/claim", self.endpoint.trim_end_matches('/'));

        let body = serde_json::json!({
            "agent_id": agent_id,
            "public_key": public_key_hex,
            "registration_token": reg_token,
        });

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| ConnectTokenError::ClaimFailed(e.to_string()))?;

        tracing::debug!(agent_id = %agent_id, "claiming agent via connect token");

        let resp = client
            .post(&claim_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| ConnectTokenError::ClaimFailed(e.to_string()))?;

        let status = resp.status().as_u16();
        match status {
            200..=299 => {
                tracing::info!(agent_id = %agent_id, "agent claimed successfully");
                Ok(())
            }
            409 => {
                tracing::debug!(agent_id = %agent_id, "agent already claimed (idempotent)");
                Ok(())
            }
            _ => {
                let msg = resp.text().await.unwrap_or_default();
                tracing::warn!(agent_id = %agent_id, status, body = %msg, "agent claim returned non-success");
                Err(ConnectTokenError::ClaimFailed(format!(
                    "HTTP {}: {}",
                    status, msg
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token_str(payload: &str) -> String {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        format!("{}{}", TOKEN_PREFIX, encoded)
    }

    #[test]
    fn parse_full_token() {
        let raw = make_token_str(
            r#"{"v":1,"e":"https://api.tenuo.cloud/v1","k":"tc_abc","a":"my-agent","t":"tok123"}"#,
        );
        let ct = ConnectToken::parse(&raw).unwrap();
        assert_eq!(ct.version, 1);
        assert_eq!(ct.endpoint, "https://api.tenuo.cloud");
        assert_eq!(ct.api_key, "tc_abc");
        assert_eq!(ct.agent_id.as_deref(), Some("my-agent"));
        assert_eq!(ct.registration_token.as_deref(), Some("tok123"));
    }

    #[test]
    fn parse_token_without_v1_suffix() {
        let raw = make_token_str(
            r#"{"v":1,"e":"https://api.tenuo.cloud","k":"tc_abc","a":"my-agent","t":"tok123"}"#,
        );
        let ct = ConnectToken::parse(&raw).unwrap();
        assert_eq!(ct.endpoint, "https://api.tenuo.cloud");
    }

    #[test]
    fn parse_token_with_trailing_slash() {
        let raw = make_token_str(r#"{"v":1,"e":"https://api.tenuo.cloud/v1/","k":"tc_abc"}"#);
        let ct = ConnectToken::parse(&raw).unwrap();
        assert_eq!(ct.endpoint, "https://api.tenuo.cloud");
    }

    #[test]
    fn parse_authorizer_only_token() {
        let raw = make_token_str(r#"{"v":1,"e":"https://api.tenuo.cloud/v1","k":"tc_xyz"}"#);
        let ct = ConnectToken::parse(&raw).unwrap();
        assert_eq!(ct.version, 1);
        assert_eq!(ct.endpoint, "https://api.tenuo.cloud");
        assert!(ct.agent_id.is_none());
        assert!(ct.registration_token.is_none());
    }

    #[test]
    fn parse_v0_token_without_version() {
        let raw =
            make_token_str(r#"{"e":"https://api.tenuo.cloud/v1","k":"tc_old","a":"ag","t":"rt"}"#);
        let ct = ConnectToken::parse(&raw).unwrap();
        assert_eq!(ct.version, 1); // default
    }

    #[test]
    fn reject_missing_prefix() {
        assert!(ConnectToken::parse("not_a_token").is_err());
    }

    #[test]
    fn reject_empty_endpoint() {
        let raw = make_token_str(r#"{"v":1,"e":"","k":"tc_abc"}"#);
        assert!(matches!(
            ConnectToken::parse(&raw),
            Err(ConnectTokenError::MissingField("endpoint"))
        ));
    }

    #[test]
    fn reject_empty_api_key() {
        let raw = make_token_str(r#"{"v":1,"e":"https://api.tenuo.cloud","k":""}"#);
        assert!(matches!(
            ConnectToken::parse(&raw),
            Err(ConnectTokenError::MissingField("api_key"))
        ));
    }

    #[test]
    fn reject_future_version() {
        let raw = make_token_str(r#"{"v":2,"e":"https://api.tenuo.cloud","k":"tc_abc"}"#);
        assert!(matches!(
            ConnectToken::parse(&raw),
            Err(ConnectTokenError::UnsupportedVersion(2))
        ));
    }
}
