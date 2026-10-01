//! JSON text parsing that rejects a repeated key.
//!
//! `serde_json::Value`, `json.loads`, and `JSON.parse` keep the last value for
//! a repeated key. This walk happens before that collapse, including inside
//! nested objects and arrays. Text that a host has already turned into an
//! object cannot be checked.

use serde::Deserialize;
use std::fmt;

const DUPLICATE_JSON_KEY: &str = "duplicate JSON key";

/// Failure from [`parse_json_strict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrictJsonError {
    /// An object repeated a key. The last value must not win.
    DuplicateKey,
    /// The text was not a single JSON value.
    Malformed(String),
}

impl fmt::Display for StrictJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey => write!(f, "{DUPLICATE_JSON_KEY}"),
            Self::Malformed(message) => write!(f, "malformed JSON: {message}"),
        }
    }
}

impl std::error::Error for StrictJsonError {}

/// Parse one JSON value, rejecting a repeated key in any object.
pub fn parse_json_strict(input: &str) -> Result<serde_json::Value, StrictJsonError> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let StrictValue(value) =
        StrictValue::deserialize(&mut deserializer).map_err(classify_json_error)?;
    deserializer.end().map_err(classify_json_error)?;
    Ok(value)
}

fn classify_json_error(err: serde_json::Error) -> StrictJsonError {
    let message = err.to_string();
    if message.contains(DUPLICATE_JSON_KEY) {
        StrictJsonError::DuplicateKey
    } else {
        StrictJsonError::Malformed(message)
    }
}

struct StrictValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| serde::de::Error::custom("non-finite JSON number"))?;
        Ok(StrictValue(serde_json::Value::Number(number)))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::String(value.to_owned())))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::String(value)))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Null))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Null))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(StrictValue(value)) = seq.next_element()? {
            items.push(value);
        }
        Ok(StrictValue(serde_json::Value::Array(items)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(serde::de::Error::custom(DUPLICATE_JSON_KEY));
            }
            let StrictValue(value) = map.next_value()?;
            object.insert(key, value);
        }
        Ok(StrictValue(serde_json::Value::Object(object)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUPLICATE_ARGUMENT_KEY: &str =
        include_str!("../../tests/vectors/duplicate-argument-keys.json");

    #[test]
    fn rejects_the_shared_duplicate_key_vector() {
        assert_eq!(
            parse_json_strict(DUPLICATE_ARGUMENT_KEY).unwrap_err(),
            StrictJsonError::DuplicateKey
        );
    }

    #[test]
    fn rejects_a_nested_duplicate_key() {
        assert_eq!(
            parse_json_strict(r#"{"meta":{"a":1,"a":2}}"#).unwrap_err(),
            StrictJsonError::DuplicateKey
        );
    }

    #[test]
    fn keeps_unique_keys() {
        let value = parse_json_strict(r#"{"path":"/data/ok","n":1,"ok":true}"#).unwrap();
        assert_eq!(value["path"], "/data/ok");
        assert_eq!(value["n"], 1);
        assert_eq!(value["ok"], true);
    }

    #[test]
    fn rejects_trailing_data() {
        let err = parse_json_strict(r#"{"a":1}{}"#).unwrap_err();
        assert!(matches!(err, StrictJsonError::Malformed(_)), "{err}");
    }
}
