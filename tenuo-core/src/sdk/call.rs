use crate::constraints::ConstraintValue;
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

    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn args(&self) -> &HashMap<String, ConstraintValue> {
        self.pop_args()
    }

    pub fn pop_args(&self) -> &HashMap<String, ConstraintValue> {
        match &self.args {
            ArgsStorage::Borrowed(args) => args,
            ArgsStorage::Owned(args) => args,
            ArgsStorage::Split(projection) => &projection.pop_args,
        }
    }

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
                Ok(ConstraintValue::Float(f))
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

    pub fn pop_args(&self) -> &HashMap<String, ConstraintValue> {
        &self.pop_args
    }

    pub fn constraint_args(&self) -> &HashMap<String, ConstraintValue> {
        &self.constraint_args
    }
}

/// Structural failure constructing an owned call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgumentError {
    EmptyCapability,
    TooManyArguments,
    NotAnObject,
    TooDeep,
    ValueTooLarge,
    IntegerOutOfRange,
    UnsupportedJson,
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
        }
    }
}

impl std::error::Error for ArgumentError {}
