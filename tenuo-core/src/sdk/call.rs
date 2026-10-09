use crate::constraints::ConstraintValue;
use crate::strict_json::StrictJsonError;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

const MAX_OWNED_ARGS: usize = 256;

/// One invocation: capability plus the argument view used for both PoP and constraints.
pub struct Call<'a> {
    capability: Cow<'a, str>,
    args: ArgsStorage<'a>,
}

enum ArgsStorage<'a> {
    Borrowed(&'a HashMap<String, ConstraintValue>),
    Owned(HashMap<String, ConstraintValue>),
    Split(&'a VerifiedProjection),
}

impl<'a> Call<'a> {
    /// Borrowed common case: one view for both PoP and constraints.
    ///
    /// This is the constructor. There is no `Call::simple`.
    pub fn borrowed(capability: &'a str, args: &'a HashMap<String, ConstraintValue>) -> Self {
        Self {
            capability: Cow::Borrowed(capability),
            args: ArgsStorage::Borrowed(args),
        }
    }

    /// Enforcement-point-only. Pairs with `check_received` / `guard_received`.
    pub fn from_transport(capability: &'a str, projection: &'a VerifiedProjection) -> Self {
        Self {
            capability: Cow::Borrowed(capability),
            args: ArgsStorage::Split(projection),
        }
    }

    /// Capability name this call names.
    pub fn capability(&self) -> &str {
        &self.capability
    }

    /// The argument view, when both views are the same map.
    pub fn args(&self) -> &HashMap<String, ConstraintValue> {
        self.pop_args()
    }

    /// Arguments the proof of possession is computed over — what the holder signs.
    pub fn pop_args(&self) -> &HashMap<String, ConstraintValue> {
        match &self.args {
            ArgsStorage::Borrowed(args) => args,
            ArgsStorage::Owned(args) => args,
            ArgsStorage::Split(projection) => &projection.pop_args,
        }
    }

    /// Arguments matched against the warrant's constraints.
    ///
    /// Equal to [`Self::pop_args`] unless the call came from a transport that extracts a
    /// separate view; see [`VerifiedProjection`].
    pub fn constraint_args(&self) -> &HashMap<String, ConstraintValue> {
        match &self.args {
            ArgsStorage::Borrowed(args) => args,
            ArgsStorage::Owned(args) => args,
            ArgsStorage::Split(projection) => &projection.constraint_args,
        }
    }
}

impl Call<'static> {
    /// Owned common case. Applies conversion and structural bounds.
    pub fn owned(
        capability: impl Into<String>,
        args: HashMap<String, ConstraintValue>,
    ) -> Result<Self, ArgumentError> {
        let capability = capability.into();
        if capability.is_empty() {
            return Err(ArgumentError::EmptyCapability);
        }
        if args.len() > MAX_OWNED_ARGS {
            return Err(ArgumentError::TooManyArguments);
        }
        Ok(Self {
            capability: Cow::Owned(capability),
            args: ArgsStorage::Owned(args),
        })
    }

    /// Convert a JSON object into an owned call. Pure conversion; no policy.
    ///
    /// `value` is already parsed, so a repeated key is not visible. Parse text
    /// with [`Self::try_from_json_str`].
    pub fn try_from_json(
        capability: impl Into<String>,
        value: &serde_json::Value,
    ) -> Result<Self, ArgumentError> {
        let object = value.as_object().ok_or(ArgumentError::NotAnObject)?;
        let mut args = HashMap::with_capacity(object.len());
        for (key, raw) in object {
            if key.len() > MAX_JSON_STRING {
                return Err(ArgumentError::ValueTooLarge);
            }
            args.insert(key.clone(), json_to_constraint(raw, 0)?);
        }
        Self::owned(capability, args)
    }

    /// Parse argument JSON text, rejecting a repeated key, then build a call.
    pub fn try_from_json_str(
        capability: impl Into<String>,
        json: &str,
    ) -> Result<Self, ArgumentError> {
        let value = crate::parse_json_strict(json).map_err(|err| match err {
            StrictJsonError::DuplicateKey => ArgumentError::DuplicateKey,
            StrictJsonError::LimitExceeded => ArgumentError::ValueTooLarge,
            StrictJsonError::Malformed(message) => ArgumentError::MalformedJson(message),
        })?;
        Self::try_from_json(capability, &value)
    }
}

const MAX_JSON_DEPTH: usize = 8;
const MAX_JSON_STRING: usize = 8 * 1024;
const MAX_JSON_LIST: usize = 256;

fn json_to_constraint(
    value: &serde_json::Value,
    depth: usize,
) -> Result<ConstraintValue, ArgumentError> {
    if depth > MAX_JSON_DEPTH {
        return Err(ArgumentError::TooDeep);
    }
    match value {
        serde_json::Value::Null => Ok(ConstraintValue::Null),
        serde_json::Value::Bool(b) => Ok(ConstraintValue::Boolean(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(ConstraintValue::Integer(i))
            } else if n.as_u64().is_some() {
                Err(ArgumentError::IntegerOutOfRange)
            } else if let Some(f) = n.as_f64() {
                // Same number rule as `_meta.tenuo`, so `1.0` signs like `1`.
                Ok(crate::meta_envelope::integral_i64(f)
                    .map_or(ConstraintValue::Float(f), ConstraintValue::Integer))
            } else {
                Err(ArgumentError::UnsupportedJson)
            }
        }
        serde_json::Value::String(s) => {
            if s.len() > MAX_JSON_STRING {
                return Err(ArgumentError::ValueTooLarge);
            }
            Ok(ConstraintValue::String(s.clone()))
        }
        serde_json::Value::Array(items) => {
            if items.len() > MAX_JSON_LIST {
                return Err(ArgumentError::TooManyArguments);
            }
            let converted = items
                .iter()
                .map(|item| json_to_constraint(item, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ConstraintValue::List(converted))
        }
        serde_json::Value::Object(map) => {
            if map.len() > MAX_OWNED_ARGS {
                return Err(ArgumentError::TooManyArguments);
            }
            let mut object = std::collections::BTreeMap::new();
            for (key, raw) in map {
                if key.len() > MAX_JSON_STRING {
                    return Err(ArgumentError::ValueTooLarge);
                }
                object.insert(key.clone(), json_to_constraint(raw, depth + 1)?);
            }
            Ok(ConstraintValue::Object(object))
        }
    }
}

/// Split argument views produced from one received message.
#[derive(Clone, Debug)]
pub struct VerifiedProjection {
    pop_args: HashMap<String, ConstraintValue>,
    constraint_args: HashMap<String, ConstraintValue>,
}

impl VerifiedProjection {
    /// Both views are the same map (typical HTTP / MCP without extraction).
    pub fn identical(args: HashMap<String, ConstraintValue>) -> Self {
        Self {
            pop_args: args.clone(),
            constraint_args: args,
        }
    }

    /// Build a split PoP / constraint view from an enforcement-point extraction.
    ///
    /// The two maps are not checked against each other. A narrower PoP view
    /// paired with a friendlier constraint view is exactly the misuse S24
    /// exists to make visible. Call this only after extraction rules produced
    /// both views from one received message.
    pub fn from_enforcement_point_unchecked(
        pop_args: HashMap<String, ConstraintValue>,
        constraint_args: HashMap<String, ConstraintValue>,
    ) -> Self {
        Self {
            pop_args,
            constraint_args,
        }
    }

    /// Arguments the proof of possession covers.
    pub fn pop_args(&self) -> &HashMap<String, ConstraintValue> {
        &self.pop_args
    }

    /// Arguments matched against constraints.
    pub fn constraint_args(&self) -> &HashMap<String, ConstraintValue> {
        &self.constraint_args
    }
}

/// Structural failure constructing an owned call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArgumentError {
    /// The capability name was empty.
    EmptyCapability,
    /// More arguments than the configured bound.
    TooManyArguments,
    /// The JSON value was not an object.
    NotAnObject,
    /// Nesting exceeded the configured bound.
    TooDeep,
    /// A value exceeded the configured size bound.
    ValueTooLarge,
    /// A JSON number does not map losslessly onto the supported numeric domain.
    IntegerOutOfRange,
    /// A JSON construct has no `ConstraintValue` representation.
    UnsupportedJson,
    /// An object repeated a key. The last value must not win.
    DuplicateKey,
    /// The text was not a single JSON value.
    MalformedJson(String),
}

impl fmt::Display for ArgumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCapability => write!(f, "capability must not be empty"),
            Self::TooManyArguments => write!(f, "too many arguments"),
            Self::NotAnObject => write!(f, "JSON arguments must be an object"),
            Self::TooDeep => write!(f, "JSON arguments nested too deeply"),
            Self::ValueTooLarge => write!(f, "JSON argument value is too large"),
            Self::IntegerOutOfRange => write!(f, "JSON integer does not fit in i64"),
            Self::UnsupportedJson => write!(f, "JSON argument value is not supported"),
            Self::DuplicateKey => write!(f, "{DUPLICATE_JSON_KEY}"),
            Self::MalformedJson(message) => write!(f, "malformed JSON: {message}"),
        }
    }
}

impl std::error::Error for ArgumentError {}

const DUPLICATE_JSON_KEY: &str = "duplicate JSON key";

#[cfg(test)]
mod tests {
    use super::*;

    const DUPLICATE_ARGUMENT_KEY: &str =
        include_str!("../../../tests/vectors/duplicate-argument-keys.json");

    #[test]
    fn try_from_json_str_rejects_the_shared_duplicate_key_vector() {
        assert!(matches!(
            Call::try_from_json_str("read_file", DUPLICATE_ARGUMENT_KEY),
            Err(ArgumentError::DuplicateKey)
        ));
    }

    #[test]
    fn integral_float_is_the_same_argument_as_an_integer() {
        let whole = serde_json::json!({"n": 1.0});
        let call = Call::try_from_json("calc", &whole).unwrap();
        assert_eq!(call.args()["n"], ConstraintValue::Integer(1));

        let fraction = serde_json::json!({"n": 1.5});
        let call = Call::try_from_json("calc", &fraction).unwrap();
        assert_eq!(call.args()["n"], ConstraintValue::Float(1.5));

        // 2^63 has no i64; it stays a float, as in the envelope.
        let above = serde_json::json!({"n": 9223372036854775808.0});
        let call = Call::try_from_json("calc", &above).unwrap();
        assert_eq!(
            call.args()["n"],
            ConstraintValue::Float(9223372036854775808.0)
        );
    }
}
