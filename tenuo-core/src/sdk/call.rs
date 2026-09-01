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
}

impl<'a> Call<'a> {
    /// Borrowed common case: one view for both PoP and constraints.
    pub fn borrowed(capability: &'a str, args: &'a HashMap<String, ConstraintValue>) -> Self {
        Self {
            capability: Cow::Borrowed(capability),
            args: ArgsStorage::Borrowed(args),
        }
    }

    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn args(&self) -> &HashMap<String, ConstraintValue> {
        match &self.args {
            ArgsStorage::Borrowed(args) => args,
            ArgsStorage::Owned(args) => args,
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
}

/// Structural failure constructing an owned call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgumentError {
    EmptyCapability,
    TooManyArguments,
}

impl fmt::Display for ArgumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCapability => write!(f, "capability must not be empty"),
            Self::TooManyArguments => write!(f, "too many arguments"),
        }
    }
}

impl std::error::Error for ArgumentError {}
