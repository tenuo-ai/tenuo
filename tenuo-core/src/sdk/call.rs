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

    pub fn split(
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
