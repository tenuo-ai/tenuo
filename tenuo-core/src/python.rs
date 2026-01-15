//! Python bindings for Tenuo via PyO3.
//!
//! This module provides Python-friendly wrappers around the core Rust types.

// PyO3 macros generate code that triggers false positive clippy warnings
#![allow(clippy::useless_conversion)]

use crate::approval::{compute_request_hash, Approval as RustApproval};
use crate::constraints::{
    All, Any, CelConstraint, Cidr, Constraint, ConstraintValue, Contains, Exact, Not, NotOneOf,
    OneOf, Pattern, Range, RegexConstraint, Subpath, Subset, UrlPattern, UrlSafe, Wildcard,
};
use crate::crypto::{
    PublicKey as RustPublicKey, Signature as RustSignature, SigningKey as RustSigningKey,
};
use crate::diff::{
    ChangeType as RustChangeType, ClearanceDiff as RustClearanceDiff,
    ConstraintDiff as RustConstraintDiff, DelegationDiff as RustDelegationDiff,
    DelegationReceipt as RustDelegationReceipt, DepthDiff as RustDepthDiff,
    ToolsDiff as RustToolsDiff, TtlDiff as RustTtlDiff,
};
use crate::mcp::{CompiledMcpConfig, McpConfig};
use crate::planes::{
    Authorizer as RustAuthorizer, ChainStep as RustChainStep,
    ChainVerificationResult as RustChainVerificationResult,
};
use crate::warrant::{
    Clearance, OwnedAttenuationBuilder, OwnedIssuanceBuilder, Warrant as RustWarrant, WarrantType,
};
use crate::wire;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PySequence, PyTuple};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

fn to_py_err(e: crate::error::Error) -> PyErr {
    Python::with_gil(|py| {
        let exceptions = match py.import("tenuo.exceptions") {
            Ok(m) => m,
            Err(e) => return e,
        };

        let (exc_name, args) = match &e {
            // Crypto
            crate::error::Error::SignatureInvalid(m) => {
                ("SignatureInvalid", PyTuple::new(py, [m.as_str()]))
            }
            crate::error::Error::MissingSignature(m) => {
                ("MissingSignature", PyTuple::new(py, [m.as_str()]))
            }
            crate::error::Error::CryptoError(m) => ("CryptoError", PyTuple::new(py, [m.as_str()])),

            // Lifecycle
            crate::error::Error::WarrantRevoked(id) => {
                ("RevokedError", PyTuple::new(py, [id.as_str()]))
            }
            crate::error::Error::WarrantExpired(t) => {
                // Python ExpiredError expects (warrant_id, expired_at)
                // We don't have warrant_id here easily, so pass "unknown"
                (
                    "ExpiredError",
                    PyTuple::new(py, ["unknown", t.to_rfc3339().as_str()]),
                )
            }
            crate::error::Error::DepthExceeded(d, m) => {
                ("DepthExceeded", PyTuple::new(py, [*d, *m]))
            }
            crate::error::Error::InvalidWarrantId(m) => {
                ("InvalidWarrantId", PyTuple::new(py, [m.as_str()]))
            }
            crate::error::Error::InvalidTtl(m) => ("InvalidTtl", PyTuple::new(py, [m.as_str()])),
            crate::error::Error::ConstraintDepthExceeded { depth, max } => {
                ("ConstraintDepthExceeded", PyTuple::new(py, [*depth, *max]))
            }
            crate::error::Error::PayloadTooLarge { size, max } => {
                ("PayloadTooLarge", PyTuple::new(py, [*size, *max]))
            }
            crate::error::Error::ParentRequired => ("ParentRequired", Ok(PyTuple::empty(py))),
            crate::error::Error::ToolMismatch { parent, child } => (
                "ToolMismatch",
                PyTuple::new(py, [parent.as_str(), child.as_str()]),
            ),

            // Monotonicity
            crate::error::Error::MonotonicityViolation(m) => {
                ("MonotonicityError", PyTuple::new(py, [m.as_str()]))
            }
            crate::error::Error::IncompatibleConstraintTypes {
                parent_type,
                child_type,
            } => (
                "IncompatibleConstraintTypes",
                PyTuple::new(py, [parent_type.as_str(), child_type.as_str()]),
            ),
            crate::error::Error::WildcardExpansion { parent_type } => (
                "WildcardExpansion",
                PyTuple::new(py, [parent_type.as_str()]),
            ),
            crate::error::Error::EmptyResultSet { parent_type, count } => (
                "EmptyResultSet",
                PyTuple::new(py, [parent_type.as_str(), &count.to_string()]),
            ), // count is usize, convert to string or int? Python expects int? Let's check.
            // EmptyResultSet(parent_type: str, count: int)
            // But PyTuple::new takes ToPyObject. usize implements it.
            crate::error::Error::ExclusionRemoved { value } => {
                ("ExclusionRemoved", PyTuple::new(py, [value.as_str()]))
            }
            crate::error::Error::ValueNotInParentSet { value } => {
                ("ValueNotInParentSet", PyTuple::new(py, [value.as_str()]))
            }
            crate::error::Error::RangeExpanded {
                bound,
                parent_value,
                child_value,
            } => (
                "RangeExpanded",
                PyTuple::new(
                    py,
                    [
                        bound.as_str(),
                        &parent_value.to_string(),
                        &child_value.to_string(),
                    ],
                ),
            ), // float to string to avoid precision issues? Or pass float? Python expects float.

            crate::error::Error::PatternExpanded { parent, child } => (
                "PatternExpanded",
                PyTuple::new(py, [parent.as_str(), child.as_str()]),
            ),
            crate::error::Error::RequiredValueRemoved { value } => {
                ("RequiredValueRemoved", PyTuple::new(py, [value.as_str()]))
            }
            crate::error::Error::ExactValueMismatch { parent, child } => (
                "ExactValueMismatch",
                PyTuple::new(py, [parent.as_str(), child.as_str()]),
            ),

            // Constraints
            crate::error::Error::ConstraintNotSatisfied { field, reason } => (
                "ConstraintViolation",
                PyTuple::new(py, [field.as_str(), reason.as_str()]),
            ),

            // Syntax
            // Python InvalidPattern(pattern, reason)
            // Rust InvalidPattern(msg) -> We only have msg. Pass msg as pattern? Or split?
            // Let's pass msg as pattern for now, reason empty.
            crate::error::Error::InvalidPattern(m) => {
                ("InvalidPattern", PyTuple::new(py, [m.as_str()]))
            }
            crate::error::Error::InvalidRange(m) => {
                ("InvalidRange", PyTuple::new(py, [m.as_str()]))
            }
            crate::error::Error::InvalidRegex(m) => {
                ("InvalidRegex", PyTuple::new(py, [m.as_str()]))
            }
            crate::error::Error::CelError(m) => ("CelError", PyTuple::new(py, [m.as_str()])),

            // Serialization
            crate::error::Error::SerializationError(m) => {
                ("SerializationError", PyTuple::new(py, [m.as_str()]))
            }
            crate::error::Error::DeserializationError(m) => {
                ("DeserializationError", PyTuple::new(py, [m.as_str()]))
            }
            crate::error::Error::UnsupportedVersion(v) => {
                ("UnsupportedVersion", PyTuple::new(py, [*v]))
            }

            // General
            crate::error::Error::MissingField(m) => {
                ("MissingField", PyTuple::new(py, [m.as_str()]))
            }
            crate::error::Error::ChainVerificationFailed(m) => {
                ("ChainError", PyTuple::new(py, [m.as_str()]))
            } // ChainError takes message? Yes.
            crate::error::Error::Validation(m) => {
                ("ValidationError", PyTuple::new(py, [m.as_str()]))
            }
            crate::error::Error::Unauthorized(m) => {
                ("Unauthorized", PyTuple::new(py, [m.as_str()]))
            }

            // Approval
            crate::error::Error::ApprovalExpired {
                approved_at,
                expired_at,
            } => (
                "ApprovalExpired",
                PyTuple::new(
                    py,
                    [
                        approved_at.to_rfc3339().as_str(),
                        expired_at.to_rfc3339().as_str(),
                    ],
                ),
            ),
            crate::error::Error::InsufficientApprovals { required, received } => (
                "InsufficientApprovals",
                PyTuple::new(py, [*required, *received]),
            ),
            crate::error::Error::InvalidApproval(m) => {
                ("InvalidApproval", PyTuple::new(py, [m.as_str()]))
            }
            crate::error::Error::UnknownProvider(m) => {
                ("UnknownProvider", PyTuple::new(py, [m.as_str()]))
            }

            // Issuance errors
            crate::error::Error::ClearanceLevelExceeded { requested, limit } => (
                "ClearanceLevelExceeded",
                PyTuple::new(py, [requested.as_str(), limit.as_str()]),
            ),
            crate::error::Error::UnauthorizedToolIssuance { tool, allowed } => (
                "UnauthorizedToolIssuance",
                PyTuple::new(
                    py,
                    [
                        tool.as_str(),
                        &format!("{:?}", allowed), // Convert Vec<String> to string repr
                    ],
                ),
            ),
            crate::error::Error::SelfIssuanceProhibited { reason } => (
                "SelfIssuanceProhibited",
                PyTuple::new(py, [reason.as_str()]),
            ),
            crate::error::Error::IssueDepthExceeded { depth, max } => {
                ("IssueDepthExceeded", PyTuple::new(py, [*depth, *max]))
            }
            crate::error::Error::InvalidWarrantType { message } => {
                ("InvalidWarrantType", PyTuple::new(py, [message.as_str()]))
            }
            crate::error::Error::IssuerChainTooLong { length, max } => {
                ("IssuerChainTooLong", PyTuple::new(py, [*length, *max]))
            }

            // Range security errors
            crate::error::Error::RangeInclusivityExpanded {
                bound,
                value,
                parent_inclusive: _,
                child_inclusive: _,
            } => (
                "RangeExpanded",
                PyTuple::new(
                    py,
                    [
                        bound.as_str(),
                        &format!("{} (inclusivity)", value),
                        &format!("{} (inclusive)", value),
                    ],
                ),
            ),
            crate::error::Error::ValueNotInRange { value, min, max } => (
                "RangeExpanded",
                PyTuple::new(
                    py,
                    ["value", &format!("{:?}-{:?}", min, max), &value.to_string()],
                ),
            ),

            // CIDR errors
            crate::error::Error::InvalidCidr { cidr, reason } => (
                "ValidationError",
                PyTuple::new(py, [&format!("Invalid CIDR '{}': {}", cidr, reason)]),
            ),
            crate::error::Error::InvalidIpAddress { ip, reason } => (
                "ValidationError",
                PyTuple::new(py, [&format!("Invalid IP address '{}': {}", ip, reason)]),
            ),
            crate::error::Error::IpNotInCidr { ip, cidr } => (
                "ConstraintViolation",
                PyTuple::new(
                    py,
                    ["source_ip", &format!("IP '{}' not in CIDR '{}'", ip, cidr)],
                ),
            ),
            crate::error::Error::CidrNotSubnet { parent, child } => (
                "MonotonicityError",
                PyTuple::new(
                    py,
                    [&format!("CIDR '{}' is not a subnet of '{}'", child, parent)],
                ),
            ),

            // URL errors
            crate::error::Error::InvalidUrl { url, reason } => (
                "ValidationError",
                PyTuple::new(py, [&format!("Invalid URL '{}': {}", url, reason)]),
            ),
            crate::error::Error::UrlSchemeExpanded { parent, child } => (
                "MonotonicityError",
                PyTuple::new(
                    py,
                    [&format!(
                        "URL scheme '{}' not allowed by parent scheme '{}'",
                        child, parent
                    )],
                ),
            ),
            crate::error::Error::UrlHostExpanded { parent, child } => (
                "MonotonicityError",
                PyTuple::new(
                    py,
                    [&format!(
                        "URL host '{}' not allowed by parent host '{}'",
                        child, parent
                    )],
                ),
            ),
            crate::error::Error::UrlPortExpanded { parent, child } => (
                "MonotonicityError",
                PyTuple::new(
                    py,
                    [&format!(
                        "URL port '{:?}' not allowed by parent port '{:?}'",
                        child, parent
                    )],
                ),
            ),
            crate::error::Error::UrlPathExpanded { parent, child } => (
                "MonotonicityError",
                PyTuple::new(
                    py,
                    [&format!(
                        "URL path '{}' not allowed by parent path '{}'",
                        child, parent
                    )],
                ),
            ),
            crate::error::Error::UrlMismatch { reason } => (
                "ConstraintViolation",
                PyTuple::new(py, ["url", reason.as_str()]),
            ),
            crate::error::Error::DelegationAuthorityError { expected, actual } => (
                "DelegationAuthorityError",
                PyTuple::new(py, [expected.as_str(), actual.as_str()]),
            ),
            crate::error::Error::InsufficientClearance {
                tool,
                required,
                actual,
            } => (
                "Unauthorized",
                PyTuple::new(
                    py,
                    [&format!(
                        "insufficient clearance for tool '{}': requires {}, has {}",
                        tool, required, actual
                    )],
                ),
            ),
            crate::error::Error::ConfigurationError(msg) => (
                "ConfigurationError",
                PyTuple::new(py, [msg.as_str()]),
            ),
            crate::error::Error::FeatureNotEnabled { feature } => (
                "RuntimeError",
                PyTuple::new(
                    py,
                    [&format!(
                        "{} requires the '{}' feature. Enable with: tenuo = {{ features = [\"{}\"] }}",
                        feature, feature, feature
                    )],
                ),
            ),
            crate::error::Error::PathNotContained { path, root } => (
                "ConstraintViolation",
                PyTuple::new(
                    py,
                    [
                        "path",
                        &format!("path '{}' not contained in root '{}'", path, root),
                    ],
                ),
            ),
            crate::error::Error::InvalidPath { path, reason } => {
                // Use Python's built-in ValueError directly since it's not in tenuo.exceptions
                return PyValueError::new_err(format!("invalid path '{}': {}", path, reason));
            }
            crate::error::Error::UrlNotSafe { url, reason } => (
                "ConstraintViolation",
                PyTuple::new(
                    py,
                    [
                        "url",
                        &format!("URL '{}' blocked: {}", url, reason),
                    ],
                ),
            ),
        };

        // Unwrap the args Result (PyTuple::new can fail on conversion)
        let args = match args {
            Ok(a) => a,
            Err(e) => {
                return PyRuntimeError::new_err(format!("Failed to create args tuple: {}", e))
            }
        };

        match exceptions.getattr(exc_name) {
            Ok(cls) => {
                // Call constructor with the tuple of arguments
                // Note: call1 takes a tuple of arguments. Our 'args' IS that tuple.
                PyErr::from_value(cls.call1(args).unwrap_or_else(|e| {
                    // Fallback if constructor fails
                    PyRuntimeError::new_err(e.to_string())
                        .value(py)
                        .as_any()
                        .clone()
                }))
            }
            Err(e) => PyRuntimeError::new_err(e.to_string()),
        }
    })
}

/// Convert a ConfigError to a Python exception.
fn config_err_to_py(e: crate::gateway_config::ConfigError) -> PyErr {
    Python::with_gil(|py| match py.import("tenuo.exceptions") {
        Ok(m) => match m.getattr("ConfigurationError") {
            Ok(cls) => PyErr::from_value(cls.call1((e.to_string(),)).unwrap_or_else(|_| {
                PyValueError::new_err(e.to_string())
                    .value(py)
                    .as_any()
                    .clone()
            })),
            Err(_) => PyValueError::new_err(e.to_string()),
        },
        Err(_) => PyValueError::new_err(e.to_string()),
    })
}

/// Python wrapper for Pattern constraint.
#[pyclass(name = "Pattern")]
#[derive(Clone)]
pub struct PyPattern {
    inner: Pattern,
}

#[pymethods]
impl PyPattern {
    #[new]
    fn new(pattern: &str) -> PyResult<Self> {
        let inner = Pattern::new(pattern).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Validate that another Pattern is a valid attenuation (narrowing) of this one.
    ///
    /// A child Pattern is valid if it matches a subset of what parent matches.
    ///
    /// Args:
    ///     child: The child Pattern to validate.
    ///
    /// Raises:
    ///     MonotonicityError: If child would expand capabilities.
    fn validate_attenuation(&self, child: &PyPattern) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }

    /// Check if a value matches this glob pattern.
    ///
    /// This is the runtime check used for Tier 1 authorization.
    ///
    /// Args:
    ///     value: Value to check against the pattern
    ///
    /// Returns:
    ///     True if value matches the glob pattern
    ///
    /// Example:
    ///     >>> p = Pattern("staging-*")
    ///     >>> p.matches("staging-web")
    ///     True
    ///     >>> p.matches("production-web")
    ///     False
    fn matches(&self, value: &str) -> PyResult<bool> {
        let cv = ConstraintValue::String(value.to_string());
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    ///
    /// This is the preferred method for runtime authorization checks.
    /// It provides a consistent API across all constraint types.
    ///
    /// Args:
    ///     value: Value to check (will be converted to appropriate type)
    ///
    /// Returns:
    ///     True if value satisfies the constraint
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!("Pattern('{}')", self.inner.pattern)
    }

    #[getter]
    fn pattern(&self) -> String {
        self.inner.pattern.clone()
    }
}

/// Python wrapper for Exact constraint.
#[pyclass(name = "Exact")]
#[derive(Clone)]
pub struct PyExact {
    inner: Exact,
}

#[pymethods]
impl PyExact {
    #[new]
    fn new(value: &str) -> Self {
        Self {
            inner: Exact::new(value),
        }
    }

    /// Check if a value matches this exact constraint.
    ///
    /// This is the runtime check used for Tier 1 authorization.
    ///
    /// Args:
    ///     value: Value to check (will be converted to string for comparison)
    ///
    /// Returns:
    ///     True if value matches exactly, False otherwise
    ///
    /// Example:
    ///     >>> e = Exact("production")
    ///     >>> e.matches("production")
    ///     True
    ///     >>> e.matches("staging")
    ///     False
    fn matches(&self, value: &str) -> bool {
        self.inner.value.as_str() == Some(value)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!("Exact('{}')", self.inner.value)
    }

    #[getter]
    fn value(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| constraint_value_to_py(py, &self.inner.value))
    }
}

/// Python wrapper for OneOf constraint.
#[pyclass(name = "OneOf")]
#[derive(Clone)]
pub struct PyOneOf {
    inner: OneOf,
}

#[pymethods]
impl PyOneOf {
    #[new]
    fn new(values: Vec<String>) -> Self {
        Self {
            inner: OneOf::new(values),
        }
    }

    /// Validate that another OneOf is a valid attenuation (narrowing) of this one.
    ///
    /// A child OneOf is valid if its values are a subset of parent's values.
    fn validate_attenuation(&self, child: &PyOneOf) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }

    /// Check if a value is in the allowed set.
    ///
    /// This is the runtime check used for Tier 1 authorization.
    ///
    /// Args:
    ///     value: Value to check
    ///
    /// Returns:
    ///     True if value is in the allowed set, False otherwise
    ///
    /// Example:
    ///     >>> o = OneOf(["staging", "production"])
    ///     >>> o.contains("staging")
    ///     True
    ///     >>> o.contains("development")
    ///     False
    fn contains(&self, value: &str) -> bool {
        let cv = ConstraintValue::String(value.to_string());
        self.inner.contains(&cv)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!("OneOf({:?})", self.inner.values)
    }

    #[getter]
    fn values(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let list = pyo3::types::PyList::empty(py);
            for v in &self.inner.values {
                list.append(constraint_value_to_py(py, v)?)?;
            }
            Ok(list.into())
        })
    }
}

/// Python wrapper for NotOneOf constraint.
#[pyclass(name = "NotOneOf")]
#[derive(Clone)]
pub struct PyNotOneOf {
    inner: NotOneOf,
}

#[pymethods]
impl PyNotOneOf {
    #[new]
    fn new(values: Vec<String>) -> Self {
        Self {
            inner: NotOneOf::new(values),
        }
    }

    /// Validate that another NotOneOf is a valid attenuation (narrowing) of this one.
    ///
    /// A child NotOneOf is valid if it excludes at least everything parent excludes.
    fn validate_attenuation(&self, child: &PyNotOneOf) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }

    /// Check if a value is allowed (not in the excluded set).
    ///
    /// This is the runtime check used for Tier 1 authorization.
    ///
    /// Args:
    ///     value: Value to check
    ///
    /// Returns:
    ///     True if value is NOT in the excluded set, False if it is excluded
    ///
    /// Example:
    ///     >>> n = NotOneOf(["admin", "root"])
    ///     >>> n.allows("user")
    ///     True
    ///     >>> n.allows("admin")
    ///     False
    fn allows(&self, value: &str) -> bool {
        let cv = ConstraintValue::String(value.to_string());
        !self.inner.excluded.contains(&cv)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Get the excluded values.
    #[getter]
    fn excluded(&self) -> PyResult<Vec<PyObject>> {
        Python::with_gil(|py| {
            self.inner
                .excluded
                .iter()
                .map(|v| constraint_value_to_py(py, v))
                .collect()
        })
    }

    fn __repr__(&self) -> String {
        format!("NotOneOf({:?})", self.inner.excluded)
    }
}

/// Python wrapper for Contains constraint.
#[pyclass(name = "Contains")]
#[derive(Clone)]
pub struct PyContains {
    inner: Contains,
}

#[pymethods]
impl PyContains {
    #[new]
    fn new(values: Vec<PyObject>) -> PyResult<Self> {
        let rust_values = Python::with_gil(|py| -> PyResult<Vec<ConstraintValue>> {
            let mut vec = Vec::new();
            for obj in values {
                let bound = obj.into_bound(py);
                vec.push(py_to_constraint_value(&bound)?);
            }
            Ok(vec)
        })?;
        Ok(Self {
            inner: Contains::new(rust_values),
        })
    }

    /// Validate that another Contains is a valid attenuation (narrowing) of this one.
    ///
    /// A child Contains is valid if it requires at least everything parent requires.
    fn validate_attenuation(&self, child: &PyContains) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }

    /// Check if a list contains all required values.
    ///
    /// This is the runtime check used for Tier 1 authorization.
    ///
    /// Args:
    ///     value: List to check (must contain all required values)
    ///
    /// Returns:
    ///     True if value contains all required values
    ///
    /// Example:
    ///     >>> c = Contains(["admin"])
    ///     >>> c.matches(["admin", "user"])
    ///     True
    ///     >>> c.matches(["user"])
    ///     False
    fn matches(&self, value: Vec<PyObject>) -> PyResult<bool> {
        let rust_values = Python::with_gil(|py| -> PyResult<Vec<ConstraintValue>> {
            let mut vec = Vec::new();
            for obj in value {
                let bound = obj.into_bound(py);
                vec.push(py_to_constraint_value(&bound)?);
            }
            Ok(vec)
        })?;
        let cv = ConstraintValue::List(rust_values);
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Get the required values.
    #[getter]
    fn required(&self) -> PyResult<Vec<PyObject>> {
        Python::with_gil(|py| {
            self.inner
                .required
                .iter()
                .map(|v| constraint_value_to_py(py, v))
                .collect()
        })
    }

    fn __repr__(&self) -> String {
        format!("Contains({:?})", self.inner.required)
    }
}

/// Python wrapper for Subset constraint.
#[pyclass(name = "Subset")]
#[derive(Clone)]
pub struct PySubset {
    inner: Subset,
}

#[pymethods]
impl PySubset {
    #[new]
    fn new(values: Vec<PyObject>) -> PyResult<Self> {
        let rust_values = Python::with_gil(|py| -> PyResult<Vec<ConstraintValue>> {
            let mut vec = Vec::new();
            for obj in values {
                let bound = obj.into_bound(py);
                vec.push(py_to_constraint_value(&bound)?);
            }
            Ok(vec)
        })?;
        Ok(Self {
            inner: Subset::new(rust_values),
        })
    }

    /// Validate that another Subset is a valid attenuation (narrowing) of this one.
    ///
    /// A child Subset is valid if its allowed values are a subset of parent's.
    fn validate_attenuation(&self, child: &PySubset) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }

    /// Check if all values in a list are within the allowed set.
    ///
    /// This is the runtime check used for Tier 1 authorization.
    ///
    /// Args:
    ///     value: List to check (all elements must be in allowed set)
    ///
    /// Returns:
    ///     True if value is a subset of allowed values
    ///
    /// Example:
    ///     >>> s = Subset(["read", "write", "delete"])
    ///     >>> s.matches(["read", "write"])
    ///     True
    ///     >>> s.matches(["read", "admin"])
    ///     False
    fn matches(&self, value: Vec<PyObject>) -> PyResult<bool> {
        let rust_values = Python::with_gil(|py| -> PyResult<Vec<ConstraintValue>> {
            let mut vec = Vec::new();
            for obj in value {
                let bound = obj.into_bound(py);
                vec.push(py_to_constraint_value(&bound)?);
            }
            Ok(vec)
        })?;
        let cv = ConstraintValue::List(rust_values);
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Get the allowed values.
    #[getter]
    fn allowed(&self) -> PyResult<Vec<PyObject>> {
        Python::with_gil(|py| {
            self.inner
                .allowed
                .iter()
                .map(|v| constraint_value_to_py(py, v))
                .collect()
        })
    }

    fn __repr__(&self) -> String {
        format!("Subset({:?})", self.inner.allowed)
    }
}

/// Python wrapper for All constraint.
#[pyclass(name = "All")]
#[derive(Clone)]
pub struct PyAll {
    inner: All,
}

#[pymethods]
impl PyAll {
    #[new]
    fn new(constraints: Vec<PyObject>) -> PyResult<Self> {
        let rust_constraints = Python::with_gil(|py| -> PyResult<Vec<Constraint>> {
            let mut vec = Vec::new();
            for obj in constraints {
                let bound = obj.into_bound(py);
                vec.push(py_to_constraint(&bound)?);
            }
            Ok(vec)
        })?;
        Ok(Self {
            inner: All::new(rust_constraints),
        })
    }

    /// Validate that another All is a valid attenuation (narrowing) of this one.
    ///
    /// A child All is valid if it has all parent's constraints plus optionally more.
    fn validate_attenuation(&self, child: &PyAll) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }

    /// Check if a value matches ALL constraints in this set.
    ///
    /// This is the runtime check used for Tier 1 authorization.
    ///
    /// Args:
    ///     value: Value to check against all constraints
    ///
    /// Returns:
    ///     True if value matches all constraints
    fn matches(&self, value: &str) -> PyResult<bool> {
        let cv = ConstraintValue::String(value.to_string());
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        "All(...)".to_string()
    }
}

/// Python wrapper for AnyOf constraint.
#[pyclass(name = "AnyOf")]
#[derive(Clone)]
pub struct PyAnyOf {
    inner: Any,
}

#[pymethods]
impl PyAnyOf {
    #[new]
    fn new(constraints: Vec<PyObject>) -> PyResult<Self> {
        let rust_constraints = Python::with_gil(|py| -> PyResult<Vec<Constraint>> {
            let mut vec = Vec::new();
            for obj in constraints {
                let bound = obj.into_bound(py);
                vec.push(py_to_constraint(&bound)?);
            }
            Ok(vec)
        })?;
        Ok(Self {
            inner: Any::new(rust_constraints),
        })
    }

    /// Check if a value matches ANY constraint in this set.
    ///
    /// This is the runtime check used for Tier 1 authorization.
    ///
    /// Args:
    ///     value: Value to check against constraints
    ///
    /// Returns:
    ///     True if value matches at least one constraint
    fn matches(&self, value: &str) -> PyResult<bool> {
        let cv = ConstraintValue::String(value.to_string());
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        "AnyOf(...)".to_string()
    }
}

/// Python wrapper for Not constraint.
#[pyclass(name = "Not")]
#[derive(Clone)]
pub struct PyNot {
    inner: Not,
}

#[pymethods]
impl PyNot {
    #[new]
    fn new(constraint: PyObject) -> PyResult<Self> {
        let rust_constraint = Python::with_gil(|py| -> PyResult<Constraint> {
            let bound = constraint.into_bound(py);
            py_to_constraint(&bound)
        })?;
        Ok(Self {
            inner: Not::new(rust_constraint),
        })
    }

    /// Check if a value does NOT match the inner constraint.
    ///
    /// This is the runtime check used for Tier 1 authorization.
    ///
    /// Args:
    ///     value: Value to check
    ///
    /// Returns:
    ///     True if value does NOT match the inner constraint
    fn matches(&self, value: &str) -> PyResult<bool> {
        let cv = ConstraintValue::String(value.to_string());
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        "Not(...)".to_string()
    }
}

/// Python wrapper for Range constraint.
#[pyclass(name = "Range")]
#[derive(Clone)]
pub struct PyRange {
    inner: Range,
}

#[pymethods]
impl PyRange {
    #[new]
    #[pyo3(signature = (min=None, max=None))]
    fn new(min: Option<f64>, max: Option<f64>) -> PyResult<Self> {
        Ok(Self {
            inner: Range::new(min, max).map_err(to_py_err)?,
        })
    }

    #[staticmethod]
    fn max_value(max: f64) -> PyResult<Self> {
        Ok(Self {
            inner: Range::max(max).map_err(to_py_err)?,
        })
    }

    #[staticmethod]
    fn min_value(min: f64) -> PyResult<Self> {
        Ok(Self {
            inner: Range::min(min).map_err(to_py_err)?,
        })
    }

    /// Validate that another Range is a valid attenuation (narrowing) of this one.
    ///
    /// A child Range is valid if its bounds are within parent's bounds.
    fn validate_attenuation(&self, child: &PyRange) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }

    /// Check if a value is within this range.
    ///
    /// This is the runtime check used for Tier 1 authorization.
    ///
    /// Args:
    ///     value: Numeric value to check
    ///
    /// Returns:
    ///     True if value is within [min, max], False otherwise
    ///
    /// Example:
    ///     >>> r = Range(1, 10)
    ///     >>> r.contains(5)
    ///     True
    ///     >>> r.contains(100)
    ///     False
    fn contains(&self, value: f64) -> bool {
        self.inner.contains_value(value)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!("Range(min={:?}, max={:?})", self.inner.min, self.inner.max)
    }

    #[getter]
    fn min(&self) -> Option<f64> {
        self.inner.min
    }

    #[getter]
    fn max(&self) -> Option<f64> {
        self.inner.max
    }
}

/// Python wrapper for CIDR constraint.
///
/// Validates that an IP address is within a network range.
///
/// Example (Python):
///
/// ```text
/// cidr = Cidr("10.0.0.0/8")
/// cidr = Cidr("192.168.1.0/24")
/// cidr = Cidr("2001:db8::/32")  # IPv6
/// ```
#[pyclass(name = "Cidr")]
#[derive(Clone)]
pub struct PyCidr {
    inner: Cidr,
}

#[pymethods]
impl PyCidr {
    /// Create a new CIDR constraint.
    ///
    /// Args:
    ///     cidr: CIDR notation string (e.g., "10.0.0.0/8", "192.168.1.0/24")
    ///
    /// Raises:
    ///     ValueError: If the CIDR notation is invalid.
    #[new]
    fn new(cidr: &str) -> PyResult<Self> {
        Ok(Self {
            inner: Cidr::new(cidr).map_err(to_py_err)?,
        })
    }

    /// Check if an IP address is within this CIDR network.
    ///
    /// Args:
    ///     ip: IP address string (e.g., "10.1.2.3", "192.168.1.100")
    ///
    /// Returns:
    ///     True if the IP is within the network, False otherwise.
    fn contains(&self, ip: &str) -> PyResult<bool> {
        self.inner.contains_ip(ip).map_err(to_py_err)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Validate that another Cidr is a valid attenuation (narrowing) of this one.
    ///
    /// A child Cidr is valid if its network is a subnet of parent's network.
    fn validate_attenuation(&self, child: &PyCidr) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!("Cidr('{}')", self.inner.cidr_string)
    }

    fn __str__(&self) -> String {
        self.inner.cidr_string.clone()
    }

    /// The CIDR string representation.
    #[getter]
    fn network(&self) -> String {
        self.inner.cidr_string.clone()
    }
}

/// Python wrapper for URL pattern constraint.
///
/// Validates URLs against scheme, host, port, and path patterns.
/// Safer than using Pattern or Regex for URL matching.
///
/// Example (Python):
///
/// ```text
/// url_pattern = UrlPattern("https://api.example.com/*")
/// url_pattern = UrlPattern("*://*.example.com/api/v1/*")
/// ```
#[pyclass(name = "UrlPattern")]
#[derive(Clone)]
pub struct PyUrlPattern {
    inner: UrlPattern,
}

#[pymethods]
impl PyUrlPattern {
    /// Create a new URL pattern constraint.
    ///
    /// Pattern format: `scheme://host[:port][/path]`
    ///
    /// - Scheme: Required. Use `*` for any scheme.
    /// - Host: Required. Supports wildcards (`*.example.com`).
    /// - Port: Optional. Omit for default port.
    /// - Path: Optional. Supports glob patterns (`/api/*`).
    ///
    /// Examples:
    ///     UrlPattern("https://api.example.com/*")  # HTTPS, specific host, any path
    ///     UrlPattern("*://example.com/api/v1/*")   # Any scheme, specific host/path
    ///     UrlPattern("https://*.example.com:8443/api/*")  # Subdomain wildcard
    ///
    /// Args:
    ///     pattern: URL pattern string.
    ///
    /// Raises:
    ///     ValueError: If the pattern is not a valid URL pattern.
    #[new]
    fn new(pattern: &str) -> PyResult<Self> {
        Ok(Self {
            inner: UrlPattern::new(pattern).map_err(to_py_err)?,
        })
    }

    /// Check if a URL matches this pattern.
    ///
    /// Args:
    ///     url: URL string to check.
    ///
    /// Returns:
    ///     True if the URL matches the pattern, False otherwise.
    fn matches(&self, url: &str) -> PyResult<bool> {
        self.inner.matches_url(url).map_err(to_py_err)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Validate that another UrlPattern is a valid attenuation (narrowing) of this one.
    ///
    /// A child UrlPattern is valid if it matches a subset of URLs that parent matches.
    fn validate_attenuation(&self, child: &PyUrlPattern) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!("UrlPattern('{}')", self.inner.pattern)
    }

    fn __str__(&self) -> String {
        self.inner.pattern.clone()
    }

    /// The pattern string.
    #[getter]
    fn pattern(&self) -> String {
        self.inner.pattern.clone()
    }

    /// Allowed schemes (empty means any).
    #[getter]
    fn schemes(&self) -> Vec<String> {
        self.inner.schemes.clone()
    }

    /// Host pattern (may include wildcards).
    #[getter]
    fn host_pattern(&self) -> Option<String> {
        self.inner.host_pattern.clone()
    }

    /// Required port (None means any/default).
    #[getter]
    fn port(&self) -> Option<u16> {
        self.inner.port
    }

    /// Path pattern (may include globs).
    #[getter]
    fn path_pattern(&self) -> Option<String> {
        self.inner.path_pattern.clone()
    }
}

/// Python wrapper for CEL constraint.
#[pyclass(name = "CEL")]
#[derive(Clone)]
pub struct PyCel {
    inner: CelConstraint,
}

#[pymethods]
impl PyCel {
    #[new]
    fn new(expression: &str) -> Self {
        Self {
            inner: CelConstraint::new(expression),
        }
    }

    /// Validate that another CEL is a valid attenuation (narrowing) of this one.
    ///
    /// CEL attenuation is conservative: requires exact match or logical AND extension.
    fn validate_attenuation(&self, child: &PyCel) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }

    /// Check if a value matches this CEL expression.
    ///
    /// Note: CEL evaluation requires a CEL engine. This method evaluates
    /// the expression with the value bound to the "value" variable.
    ///
    /// Args:
    ///     value: Value to check (bound as "value" in CEL context)
    ///
    /// Returns:
    ///     True if CEL expression evaluates to true
    ///
    /// Example:
    ///     >>> c = CEL("value < 100")
    ///     >>> c.matches(50)
    ///     True
    fn matches(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        self.matches(value)
    }

    fn __repr__(&self) -> String {
        format!("CEL('{}')", self.inner.expression)
    }

    #[getter]
    fn expression(&self) -> String {
        self.inner.expression.clone()
    }
}

/// Python wrapper for Regex constraint.
#[pyclass(name = "Regex")]
#[derive(Clone)]
pub struct PyRegex {
    inner: RegexConstraint,
}

#[pymethods]
impl PyRegex {
    #[new]
    fn new(pattern: &str) -> PyResult<Self> {
        let inner = RegexConstraint::new(pattern).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Validate that another Regex is a valid attenuation (narrowing) of this one.
    ///
    /// Regex attenuation is conservative: requires exact pattern match.
    fn validate_attenuation(&self, child: &PyRegex) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }

    /// Check if a value matches this regex pattern.
    ///
    /// This is the runtime check used for Tier 1 authorization.
    /// Uses fullmatch semantics (entire string must match).
    ///
    /// Args:
    ///     value: Value to check against the regex
    ///
    /// Returns:
    ///     True if value matches the regex pattern
    ///
    /// Example:
    ///     >>> r = Regex("^prod-[a-z]+$")
    ///     >>> r.matches("prod-web")
    ///     True
    ///     >>> r.matches("staging-web")
    ///     False
    fn matches(&self, value: &str) -> PyResult<bool> {
        let cv = ConstraintValue::String(value.to_string());
        self.inner.matches(&cv).map_err(to_py_err)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!("Regex('{}')", self.inner.pattern)
    }

    #[getter]
    fn pattern(&self) -> String {
        self.inner.pattern.clone()
    }
}

/// Python wrapper for Wildcard constraint.
///
/// Wildcard matches ANY value - it is the universal superset.
/// Use this in root warrants for fields you want to leave unconstrained
/// but allow children to restrict.
///
/// SECURITY INVARIANTS (enforced by Rust core):
/// 1. Wildcard can attenuate TO anything (it's the superset)
/// 2. NOTHING can attenuate TO Wildcard (would expand permissions)
///    - Attempting this raises WildcardExpansion error
/// 3. Runtime check always returns True (matches everything)
///
/// Example:
///     >>> from tenuo_core import Wildcard
///     >>> w = Wildcard()
///     >>> w.matches("anything")  # Always True
///     True
///     >>> w.matches(12345)  # Any type
///     True
#[pyclass(name = "Wildcard")]
#[derive(Clone)]
pub struct PyWildcard {
    inner: Wildcard,
}

#[pymethods]
impl PyWildcard {
    #[new]
    fn new() -> Self {
        Self { inner: Wildcard }
    }

    /// Check if a value matches this constraint.
    ///
    /// Wildcard ALWAYS returns True - it matches any value.
    /// This is the runtime check used for Tier 1 authorization.
    ///
    /// Note: The security is in the ATTENUATION check, not here.
    /// You cannot attenuate TO a Wildcard from any other constraint.
    ///
    /// Args:
    ///     value: Value to check (ignored - always matches)
    ///
    /// Returns:
    ///     True (always)
    #[pyo3(signature = (_value=None))]
    fn matches(&self, _value: Option<&str>) -> bool {
        // Wildcard matches everything - this is by design.
        // Security is enforced via validate_attenuation which
        // prevents any constraint from attenuating TO Wildcard.
        true
    }

    /// Validate that a child constraint is a valid narrowing.
    ///
    /// Wildcard can attenuate TO any constraint (it's the universal superset).
    /// This method always succeeds because Wildcard is the top of the lattice.
    ///
    /// Args:
    ///     child: Any constraint (will always be valid)
    ///
    /// Returns:
    ///     None (always succeeds)
    ///
    /// Example:
    ///     >>> from tenuo_core import Wildcard, Exact
    ///     >>> w = Wildcard()
    ///     >>> w.validate_attenuation(Exact("specific"))  # OK
    fn validate_attenuation(&self, child: &Bound<'_, PyAny>) -> PyResult<()> {
        // Convert Python constraint to Rust
        let child_constraint = py_to_constraint(child)?;

        // Wildcard can attenuate to anything - the Rust core validates this
        Constraint::Wildcard(self.inner.clone())
            .validate_attenuation(&child_constraint)
            .map_err(to_py_err)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    /// Wildcard always returns True.
    fn satisfies(&self, _value: &Bound<'_, PyAny>) -> PyResult<bool> {
        Ok(true)
    }

    fn __repr__(&self) -> String {
        "Wildcard()".to_string()
    }
}

/// Secure path containment constraint.
///
/// Validates that paths are safely contained within a root directory,
/// preventing path traversal attacks. This is a lexical check only -
/// it normalizes `.` and `..` components but does NOT access the filesystem.
///
/// Example (Python):
///
/// ```text
/// subpath = Subpath("/data")
/// subpath.contains("/data/file.txt")  # True
/// subpath.contains("/data/../etc/passwd")  # False (normalized to /etc/passwd)
/// subpath.contains("/etc/passwd")  # False (not under /data)
/// ```
#[pyclass(name = "Subpath")]
#[derive(Clone)]
pub struct PySubpath {
    inner: Subpath,
}

#[pymethods]
impl PySubpath {
    /// Create a new Subpath constraint.
    ///
    /// Args:
    ///     root: The root directory path (must be absolute).
    ///     case_sensitive: Whether to match case-sensitively. Default: True.
    ///         Set to False for Windows paths.
    ///     allow_equal: Whether to allow path == root. Default: True.
    ///         Set to False to require strictly under root.
    ///
    /// Raises:
    ///     ValueError: If root is not an absolute path.
    ///
    /// Example:
    ///     >>> from tenuo import Subpath
    ///     >>> subpath = Subpath("/data")
    ///     >>> subpath.contains("/data/file.txt")
    ///     True
    ///     >>> subpath.contains("/etc/passwd")
    ///     False
    #[new]
    #[pyo3(signature = (root, case_sensitive=true, allow_equal=true))]
    fn new(root: &str, case_sensitive: bool, allow_equal: bool) -> PyResult<Self> {
        Ok(Self {
            inner: Subpath::with_options(root, case_sensitive, allow_equal).map_err(to_py_err)?,
        })
    }

    /// Check if a path is safely contained within root.
    ///
    /// Args:
    ///     path: The path to check.
    ///
    /// Returns:
    ///     True if the path is safely contained, False otherwise.
    ///
    /// The check:
    ///     - Rejects null bytes
    ///     - Rejects relative paths
    ///     - Normalizes `.` and `..` components
    ///     - Checks prefix containment after normalization
    fn contains(&self, path: &str) -> PyResult<bool> {
        self.inner.contains_path(path).map_err(to_py_err)
    }

    /// Alias for contains() for consistency with other constraints.
    ///
    /// Args:
    ///     path: The path to check.
    ///
    /// Returns:
    ///     True if the path is safely contained, False otherwise.
    fn matches(&self, path: &str) -> PyResult<bool> {
        self.contains(path)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        // Python-style repr with quoted string
        if self.inner.case_sensitive && self.inner.allow_equal {
            format!("Subpath('{}')", self.inner.root)
        } else {
            format!(
                "Subpath('{}', case_sensitive={}, allow_equal={})",
                self.inner.root,
                if self.inner.case_sensitive {
                    "True"
                } else {
                    "False"
                },
                if self.inner.allow_equal {
                    "True"
                } else {
                    "False"
                }
            )
        }
    }

    fn __str__(&self) -> String {
        // Include type name for better error messages
        format!("Subpath('{}')", self.inner.root)
    }

    /// The root directory path.
    #[getter]
    fn root(&self) -> String {
        self.inner.root.clone()
    }

    /// Whether matching is case-sensitive.
    #[getter]
    fn case_sensitive(&self) -> bool {
        self.inner.case_sensitive
    }

    /// Whether path == root is allowed.
    #[getter]
    fn allow_equal(&self) -> bool {
        self.inner.allow_equal
    }

    /// Validate that another Subpath is a valid attenuation (narrowing) of this one.
    ///
    /// A child Subpath is valid if its root is contained within this parent's root.
    ///
    /// Args:
    ///     child: The child Subpath to validate.
    ///
    /// Raises:
    ///     MonotonicityError: If child would expand capabilities.
    ///
    /// Example:
    ///     >>> parent = Subpath("/data")
    ///     >>> child = Subpath("/data/reports")
    ///     >>> parent.validate_attenuation(child)  # OK
    ///     >>> parent = Subpath("/data/reports")
    ///     >>> child = Subpath("/data")
    ///     >>> parent.validate_attenuation(child)  # Raises MonotonicityError
    fn validate_attenuation(&self, child: &PySubpath) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }
}

/// SSRF-safe URL constraint.
///
/// Validates URLs to prevent Server-Side Request Forgery attacks by blocking:
/// - Private IP ranges (RFC1918: 10.x, 172.16.x, 192.168.x)
/// - Loopback addresses (127.x, ::1, localhost)
/// - Cloud metadata endpoints (169.254.169.254, etc.)
/// - Dangerous schemes (file://, gopher://, etc.)
/// - IP encoding bypasses (decimal, hex, octal, IPv6-mapped, URL-encoded)
///
/// Example (Python):
///
/// ```text
/// url_safe = UrlSafe()  # Secure defaults
/// url_safe.is_safe("https://api.github.com/repos")  # True
/// url_safe.is_safe("http://169.254.169.254/")  # False (metadata)
/// url_safe.is_safe("http://127.0.0.1/")  # False (loopback)
///
/// # Domain allowlist - only specific domains allowed:
/// url_safe = UrlSafe(allow_domains=["api.github.com", "*.googleapis.com"])
/// ```
#[pyclass(name = "UrlSafe")]
#[derive(Clone)]
pub struct PyUrlSafe {
    inner: UrlSafe,
}

#[pymethods]
impl PyUrlSafe {
    /// Create a new UrlSafe constraint.
    ///
    /// Args:
    ///     allow_schemes: Allowed URL schemes. Default: ["http", "https"]
    ///     allow_domains: If set, only these domains are allowed.
    ///         Supports wildcards: "*.example.com"
    ///     allow_ports: If set, only these ports are allowed.
    ///     block_private: Block RFC1918 private IPs. Default: True.
    ///     block_loopback: Block loopback (127.x, ::1). Default: True.
    ///     block_metadata: Block cloud metadata endpoints. Default: True.
    ///     block_reserved: Block reserved IP ranges. Default: True.
    ///     block_internal_tlds: Block internal TLDs (.internal, .local). Default: False.
    ///
    /// Example:
    ///     >>> from tenuo import UrlSafe
    ///     >>> url_safe = UrlSafe()  # Secure defaults
    ///     >>> url_safe.is_safe("https://api.github.com/repos")
    ///     True
    ///     >>> url_safe.is_safe("http://169.254.169.254/")
    ///     False
    #[new]
    #[pyo3(signature = (
        allow_schemes=None,
        allow_domains=None,
        allow_ports=None,
        block_private=true,
        block_loopback=true,
        block_metadata=true,
        block_reserved=true,
        block_internal_tlds=false
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        allow_schemes: Option<Vec<String>>,
        allow_domains: Option<Vec<String>>,
        allow_ports: Option<Vec<u16>>,
        block_private: bool,
        block_loopback: bool,
        block_metadata: bool,
        block_reserved: bool,
        block_internal_tlds: bool,
    ) -> Self {
        Self {
            inner: UrlSafe {
                schemes: allow_schemes.unwrap_or_else(|| vec!["http".into(), "https".into()]),
                allow_domains,
                allow_ports,
                block_private,
                block_loopback,
                block_metadata,
                block_reserved,
                block_internal_tlds,
            },
        }
    }

    /// Check if a URL is safe to fetch.
    ///
    /// Args:
    ///     url: URL string to check.
    ///
    /// Returns:
    ///     True if the URL passes all SSRF checks, False otherwise.
    fn is_safe(&self, url: &str) -> PyResult<bool> {
        self.inner.is_safe(url).map_err(to_py_err)
    }

    /// Alias for is_safe() for consistency with other constraints.
    ///
    /// Args:
    ///     url: URL string to check.
    ///
    /// Returns:
    ///     True if the URL passes all SSRF checks, False otherwise.
    fn matches(&self, url: &str) -> PyResult<bool> {
        self.is_safe(url)
    }

    /// Unified constraint check - returns True if value satisfies this constraint.
    fn satisfies(&self, value: &Bound<'_, PyAny>) -> PyResult<bool> {
        let cv = py_to_constraint_value(value)?;
        self.inner.matches(&cv).map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        // Python-style repr
        let mut opts = Vec::new();

        let default_schemes = vec!["http".to_string(), "https".to_string()];
        if self.inner.schemes != default_schemes {
            opts.push(format!("allow_schemes={:?}", self.inner.schemes));
        }
        if let Some(ref domains) = self.inner.allow_domains {
            opts.push(format!("allow_domains={:?}", domains));
        }
        if let Some(ref ports) = self.inner.allow_ports {
            opts.push(format!("allow_ports={:?}", ports));
        }
        if !self.inner.block_private {
            opts.push("block_private=False".to_string());
        }
        if !self.inner.block_loopback {
            opts.push("block_loopback=False".to_string());
        }
        if !self.inner.block_metadata {
            opts.push("block_metadata=False".to_string());
        }
        if !self.inner.block_reserved {
            opts.push("block_reserved=False".to_string());
        }
        if self.inner.block_internal_tlds {
            opts.push("block_internal_tlds=True".to_string());
        }

        if opts.is_empty() {
            "UrlSafe()".to_string()
        } else {
            format!("UrlSafe({})", opts.join(", "))
        }
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    /// Allowed URL schemes.
    #[getter]
    fn schemes(&self) -> Vec<String> {
        self.inner.schemes.clone()
    }

    /// Allowed domains (if set).
    #[getter]
    fn allow_domains(&self) -> Option<Vec<String>> {
        self.inner.allow_domains.clone()
    }

    /// Allowed ports (if set).
    #[getter]
    fn allow_ports(&self) -> Option<Vec<u16>> {
        self.inner.allow_ports.clone()
    }

    /// Whether private IPs are blocked.
    #[getter]
    fn block_private(&self) -> bool {
        self.inner.block_private
    }

    /// Whether loopback is blocked.
    #[getter]
    fn block_loopback(&self) -> bool {
        self.inner.block_loopback
    }

    /// Whether metadata endpoints are blocked.
    #[getter]
    fn block_metadata(&self) -> bool {
        self.inner.block_metadata
    }

    /// Whether reserved ranges are blocked.
    #[getter]
    fn block_reserved(&self) -> bool {
        self.inner.block_reserved
    }

    /// Whether internal TLDs are blocked.
    #[getter]
    fn block_internal_tlds(&self) -> bool {
        self.inner.block_internal_tlds
    }

    /// Validate that another UrlSafe is a valid attenuation (narrowing) of this one.
    ///
    /// A child UrlSafe is valid if it is at least as restrictive as this parent:
    /// - Child schemes must be subset of parent schemes
    /// - Child cannot disable blocking flags that parent enables
    /// - If parent has domain allowlist, child must too (and be subset)
    ///
    /// Args:
    ///     child: The child UrlSafe to validate.
    ///
    /// Raises:
    ///     MonotonicityError: If child would expand capabilities.
    ///
    /// Example:
    ///     >>> parent = UrlSafe(allow_domains=["*.example.com"])
    ///     >>> child = UrlSafe(allow_domains=["api.example.com"])
    ///     >>> parent.validate_attenuation(child)  # OK
    fn validate_attenuation(&self, child: &PyUrlSafe) -> PyResult<()> {
        self.inner
            .validate_attenuation(&child.inner)
            .map_err(to_py_err)
    }
}

/// Python wrapper for SigningKey.
#[pyclass(name = "SigningKey")]
pub struct PySigningKey {
    inner: RustSigningKey,
}

#[pymethods]
impl PySigningKey {
    #[new]
    fn new() -> Self {
        Self {
            inner: RustSigningKey::generate(),
        }
    }

    #[staticmethod]
    fn generate() -> Self {
        Self {
            inner: RustSigningKey::generate(),
        }
    }

    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("secret key must be exactly 32 bytes"))?;
        Ok(Self {
            inner: RustSigningKey::from_bytes(&arr),
        })
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().to_bytes().to_vec()
    }

    /// Get the secret key bytes.
    ///
    /// # Security Warning
    ///
    /// This method creates a copy of the secret key in Python's managed memory.
    /// Python's garbage collector does not guarantee secure erasure of secrets.
    /// The secret key may persist in memory until garbage collection occurs.
    ///
    /// **Recommendations:**
    /// - Only call this method when absolutely necessary (e.g., for key backup/export)
    /// - Minimize the lifetime of SigningKey objects
    /// - Avoid storing the returned bytes in long-lived variables
    /// - Consider using Rust directly for production key management
    ///
    /// For most use cases, you should not need to access the secret key bytes directly.
    /// Use the SigningKey object for signing operations instead.
    fn secret_key_bytes(&self) -> Vec<u8> {
        self.inner.secret_key_bytes().to_vec()
    }

    /// Get the public key as a PublicKey object.
    #[getter]
    fn public_key(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Create a SigningKey from a PEM string.
    #[staticmethod]
    fn from_pem(pem: &str) -> PyResult<Self> {
        let inner = RustSigningKey::from_pem(pem).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Convert the SigningKey to a PEM string.
    fn to_pem(&self) -> String {
        self.inner.to_pem()
    }
}

/// Convert a Rust Constraint to a Python constraint object.
fn constraint_to_py(py: Python<'_>, constraint: &Constraint) -> PyResult<PyObject> {
    match constraint {
        Constraint::Pattern(p) =>
        {
            #[allow(deprecated)]
            Ok(PyPattern { inner: p.clone() }.into_py(py))
        }
        Constraint::Exact(e) =>
        {
            #[allow(deprecated)]
            Ok(PyExact { inner: e.clone() }.into_py(py))
        }
        Constraint::OneOf(o) =>
        {
            #[allow(deprecated)]
            Ok(PyOneOf { inner: o.clone() }.into_py(py))
        }
        Constraint::NotOneOf(n) =>
        {
            #[allow(deprecated)]
            Ok(PyNotOneOf { inner: n.clone() }.into_py(py))
        }
        Constraint::Unknown { .. } => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Unknown constraint type encountered (not supported in Python bindings)",
        )),
        Constraint::Range(r) =>
        {
            #[allow(deprecated)]
            Ok(PyRange { inner: r.clone() }.into_py(py))
        }
        Constraint::Cidr(c) =>
        {
            #[allow(deprecated)]
            Ok(PyCidr { inner: c.clone() }.into_py(py))
        }
        Constraint::UrlPattern(u) =>
        {
            #[allow(deprecated)]
            Ok(PyUrlPattern { inner: u.clone() }.into_py(py))
        }
        Constraint::Contains(c) =>
        {
            #[allow(deprecated)]
            Ok(PyContains { inner: c.clone() }.into_py(py))
        }
        Constraint::Subset(s) =>
        {
            #[allow(deprecated)]
            Ok(PySubset { inner: s.clone() }.into_py(py))
        }
        Constraint::All(a) => {
            let py_constraints = Python::with_gil(|py| -> PyResult<Vec<PyObject>> {
                let mut vec = Vec::new();
                for c in &a.constraints {
                    vec.push(constraint_to_py(py, c)?);
                }
                Ok(vec)
            })?;
            #[allow(deprecated)]
            Ok(PyAll::new(py_constraints)?.into_py(py))
        }
        Constraint::Any(a) => {
            let py_constraints = Python::with_gil(|py| -> PyResult<Vec<PyObject>> {
                let mut vec = Vec::new();
                for c in &a.constraints {
                    vec.push(constraint_to_py(py, c)?);
                }
                Ok(vec)
            })?;
            #[allow(deprecated)]
            Ok(PyAnyOf::new(py_constraints)?.into_py(py))
        }
        Constraint::Not(n) => {
            let py_constraint = Python::with_gil(|py| -> PyResult<PyObject> {
                constraint_to_py(py, &n.constraint)
            })?;
            #[allow(deprecated)]
            Ok(PyNot::new(py_constraint)?.into_py(py))
        }
        Constraint::Cel(c) =>
        {
            #[allow(deprecated)]
            Ok(PyCel { inner: c.clone() }.into_py(py))
        }
        Constraint::Wildcard(w) =>
        {
            #[allow(deprecated)]
            Ok(PyWildcard { inner: w.clone() }.into_py(py))
        }
        Constraint::Regex(r) =>
        {
            #[allow(deprecated)]
            Ok(PyRegex { inner: r.clone() }.into_py(py))
        }
        Constraint::Subpath(s) =>
        {
            #[allow(deprecated)]
            Ok(PySubpath { inner: s.clone() }.into_py(py))
        }
        Constraint::UrlSafe(u) =>
        {
            #[allow(deprecated)]
            Ok(PyUrlSafe { inner: u.clone() }.into_py(py))
        }
    }
}

/// Convert a Python constraint object to a Rust Constraint.
fn py_to_constraint(obj: &Bound<'_, PyAny>) -> PyResult<Constraint> {
    if let Ok(p) = obj.extract::<PyPattern>() {
        Ok(Constraint::Pattern(p.inner))
    } else if let Ok(e) = obj.extract::<PyExact>() {
        Ok(Constraint::Exact(e.inner))
    } else if let Ok(o) = obj.extract::<PyOneOf>() {
        Ok(Constraint::OneOf(o.inner))
    } else if let Ok(n) = obj.extract::<PyNotOneOf>() {
        Ok(Constraint::NotOneOf(n.inner))
    } else if let Ok(r) = obj.extract::<PyRange>() {
        Ok(Constraint::Range(r.inner))
    } else if let Ok(c) = obj.extract::<PyCidr>() {
        Ok(Constraint::Cidr(c.inner))
    } else if let Ok(u) = obj.extract::<PyUrlPattern>() {
        Ok(Constraint::UrlPattern(u.inner))
    } else if let Ok(c) = obj.extract::<PyContains>() {
        Ok(Constraint::Contains(c.inner))
    } else if let Ok(s) = obj.extract::<PySubset>() {
        Ok(Constraint::Subset(s.inner))
    } else if let Ok(a) = obj.extract::<PyAll>() {
        Ok(Constraint::All(a.inner))
    } else if let Ok(a) = obj.extract::<PyAnyOf>() {
        Ok(Constraint::Any(a.inner))
    } else if let Ok(n) = obj.extract::<PyNot>() {
        Ok(Constraint::Not(n.inner))
    } else if let Ok(c) = obj.extract::<PyCel>() {
        Ok(Constraint::Cel(c.inner))
    } else if let Ok(r) = obj.extract::<PyRegex>() {
        Ok(Constraint::Regex(r.inner))
    } else if let Ok(w) = obj.extract::<PyWildcard>() {
        Ok(Constraint::Wildcard(w.inner))
    } else if let Ok(s) = obj.extract::<PySubpath>() {
        Ok(Constraint::Subpath(s.inner))
    } else if let Ok(u) = obj.extract::<PyUrlSafe>() {
        Ok(Constraint::UrlSafe(u.inner))
    } else {
        Err(PyValueError::new_err(
            "constraint must be Pattern, Exact, OneOf, NotOneOf, Range, Cidr, UrlPattern, Contains, Subset, All, AnyOf, Not, CEL, Regex, Wildcard, Subpath, or UrlSafe",
        ))
    }
}

/// Reserved key for allow_unknown in constraint dicts.
const ALLOW_UNKNOWN_KEY: &str = "_allow_unknown";

/// Build a ConstraintSet from a Python dict.
///
/// Handles the special `_allow_unknown` key to set zero-trust mode.
fn py_dict_to_constraint_set(
    constraints: &Bound<'_, PyDict>,
) -> PyResult<crate::constraints::ConstraintSet> {
    let mut constraint_set = crate::constraints::ConstraintSet::new();

    for (field_key, constraint_val) in constraints.iter() {
        let field: String = field_key.extract()?;

        // Handle special _allow_unknown key
        if field == ALLOW_UNKNOWN_KEY {
            let allow: bool = constraint_val
                .extract()
                .map_err(|_| PyValueError::new_err("_allow_unknown must be a boolean"))?;
            constraint_set.set_allow_unknown(allow);
            continue;
        }

        let constraint = py_to_constraint(&constraint_val)?;
        constraint_set.insert(field, constraint);
    }

    Ok(constraint_set)
}

/// Convert a Python value to a ConstraintValue.
fn py_to_constraint_value(obj: &Bound<'_, PyAny>) -> PyResult<ConstraintValue> {
    if let Ok(s) = obj.extract::<String>() {
        Ok(ConstraintValue::String(s))
    } else if let Ok(i) = obj.extract::<i64>() {
        Ok(ConstraintValue::Integer(i))
    } else if let Ok(f) = obj.extract::<f64>() {
        Ok(ConstraintValue::Float(f))
    } else if let Ok(b) = obj.extract::<bool>() {
        Ok(ConstraintValue::Boolean(b))
    } else if let Ok(l) = obj.extract::<Vec<PyObject>>() {
        // Recursively convert list items
        let py = obj.py();
        let mut values = Vec::new();
        for item in l {
            values.push(py_to_constraint_value(&item.into_bound(py))?);
        }
        Ok(ConstraintValue::List(values))
    } else {
        Err(PyValueError::new_err(
            "value must be str, int, float, bool, or list",
        ))
    }
}

/// Convert a ConstraintValue back to a Python object.
fn constraint_value_to_py(py: Python<'_>, value: &ConstraintValue) -> PyResult<PyObject> {
    match value {
        ConstraintValue::String(s) => Ok(s.to_object(py)),
        ConstraintValue::Integer(i) => Ok(i.to_object(py)),
        ConstraintValue::Float(f) => Ok(f.to_object(py)),
        ConstraintValue::Boolean(b) => Ok(b.to_object(py)),
        ConstraintValue::List(l) => {
            let py_list: Vec<PyObject> = l
                .iter()
                .map(|v| constraint_value_to_py(py, v))
                .collect::<PyResult<Vec<_>>>()?;
            Ok(py_list.to_object(py))
        }
        ConstraintValue::Object(o) => {
            let dict = pyo3::types::PyDict::new(py);
            for (k, v) in o {
                dict.set_item(k, constraint_value_to_py(py, v)?)?;
            }
            Ok(dict.to_object(py))
        }
        ConstraintValue::Null => Ok(py.None()),
    }
}

/// Python enum for WarrantType.
#[pyclass(name = "WarrantType")]
#[derive(Clone, Copy)]
pub struct PyWarrantType {
    inner: WarrantType,
}

#[pymethods]
impl PyWarrantType {
    #[new]
    fn new(warrant_type: &str) -> PyResult<Self> {
        let inner = match warrant_type.to_lowercase().as_str() {
            "execution" => WarrantType::Execution,
            "issuer" => WarrantType::Issuer,
            _ => {
                return Err(PyValueError::new_err(
                    "WarrantType must be 'execution' or 'issuer'",
                ))
            }
        };
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        format!("WarrantType.{:?}", self.inner)
    }

    fn __richcmp__(&self, other: &Self, op: pyo3::basic::CompareOp) -> PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => Ok(self.inner == other.inner),
            pyo3::basic::CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "Comparison not supported",
            )),
        }
    }

    #[classattr]
    #[allow(non_snake_case)]
    fn Execution() -> Self {
        Self {
            inner: WarrantType::Execution,
        }
    }

    #[classattr]
    #[allow(non_snake_case)]
    fn Issuer() -> Self {
        Self {
            inner: WarrantType::Issuer,
        }
    }
}

/// Python class for Clearance.
#[pyclass(name = "Clearance")]
#[derive(Clone, Copy)]
pub struct PyClearance {
    inner: Clearance,
}

#[pymethods]
#[allow(non_snake_case)]
impl PyClearance {
    #[new]
    fn new(value: &Bound<'_, PyAny>) -> PyResult<Self> {
        if let Ok(s) = value.extract::<String>() {
            let inner = s.parse().map_err(|e: String| PyValueError::new_err(e))?;
            Ok(Self { inner })
        } else if let Ok(n) = value.extract::<u8>() {
            Ok(Self {
                inner: Clearance(n),
            })
        } else {
            Err(PyValueError::new_err(
                "Clearance must be initialized with a string name or integer (0-255)",
            ))
        }
    }

    #[classattr]
    fn UNTRUSTED() -> Self {
        Self {
            inner: Clearance::UNTRUSTED,
        }
    }

    #[classattr]
    fn EXTERNAL() -> Self {
        Self {
            inner: Clearance::EXTERNAL,
        }
    }

    #[classattr]
    fn PARTNER() -> Self {
        Self {
            inner: Clearance::PARTNER,
        }
    }

    #[classattr]
    fn INTERNAL() -> Self {
        Self {
            inner: Clearance::INTERNAL,
        }
    }

    #[classattr]
    fn PRIVILEGED() -> Self {
        Self {
            inner: Clearance::PRIVILEGED,
        }
    }

    #[classattr]
    fn SYSTEM() -> Self {
        Self {
            inner: Clearance::SYSTEM,
        }
    }

    /// Get the numeric value of the clearance.
    fn value(&self) -> u8 {
        self.inner.level()
    }

    /// Get the numeric value of the clearance (alias for value()).
    #[getter]
    fn level(&self) -> u8 {
        self.inner.level()
    }

    /// Check if this clearance meets or exceeds the requirement.
    ///
    /// More readable than `>=` for checking clearance requirements.
    ///
    /// Example:
    ///     if warrant.clearance.meets(Clearance.INTERNAL):
    ///         # clearance is INTERNAL or higher
    fn meets(&self, required: &Self) -> bool {
        self.inner.meets(required.inner)
    }

    /// Create a custom clearance level.
    ///
    /// Values 0-50 overlap with standard tiers; 51-255 are fully custom.
    ///
    /// Example:
    ///     CONTRACTOR = Clearance.custom(15)  # Between External (10) and Partner (20)
    #[staticmethod]
    fn custom(level: u8) -> Self {
        Self {
            inner: Clearance::custom(level),
        }
    }

    /// Compare clearance levels numerically.
    fn __ge__(&self, other: &Self) -> bool {
        self.inner >= other.inner
    }

    fn __le__(&self, other: &Self) -> bool {
        self.inner <= other.inner
    }

    fn __gt__(&self, other: &Self) -> bool {
        self.inner > other.inner
    }

    fn __lt__(&self, other: &Self) -> bool {
        self.inner < other.inner
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __repr__(&self) -> String {
        format!("{}", self.inner)
    }
}

/// Python wrapper for ChangeType enum.
#[pyclass(name = "ChangeType")]
#[derive(Clone)]
pub struct PyChangeType {
    inner: RustChangeType,
}

#[pymethods]
#[allow(non_snake_case)]
impl PyChangeType {
    /// Unchanged variant.
    #[classattr]
    fn UNCHANGED() -> Self {
        Self {
            inner: RustChangeType::Unchanged,
        }
    }

    /// Added variant.
    #[classattr]
    fn ADDED() -> Self {
        Self {
            inner: RustChangeType::Added,
        }
    }

    /// Removed variant.
    #[classattr]
    fn REMOVED() -> Self {
        Self {
            inner: RustChangeType::Removed,
        }
    }

    /// Narrowed variant.
    #[classattr]
    fn NARROWED() -> Self {
        Self {
            inner: RustChangeType::Narrowed,
        }
    }

    /// Reduced variant.
    #[classattr]
    fn REDUCED() -> Self {
        Self {
            inner: RustChangeType::Reduced,
        }
    }

    /// Increased variant.
    #[classattr]
    fn INCREASED() -> Self {
        Self {
            inner: RustChangeType::Increased,
        }
    }

    /// Demoted variant.
    #[classattr]
    fn DEMOTED() -> Self {
        Self {
            inner: RustChangeType::Demoted,
        }
    }

    /// Promoted variant.
    #[classattr]
    fn PROMOTED() -> Self {
        Self {
            inner: RustChangeType::Promoted,
        }
    }

    /// Dropped variant.
    #[classattr]
    fn DROPPED() -> Self {
        Self {
            inner: RustChangeType::Dropped,
        }
    }

    /// Get the string value.
    #[getter]
    fn value(&self) -> &'static str {
        self.inner.as_str()
    }

    fn __repr__(&self) -> String {
        format!("ChangeType.{}", self.inner.as_str().to_uppercase())
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.inner.as_str().hash(&mut hasher);
        hasher.finish()
    }
}

/// Python wrapper for ToolsDiff.
#[pyclass(name = "ToolsDiff")]
#[derive(Clone)]
pub struct PyToolsDiff {
    inner: RustToolsDiff,
}

#[pymethods]
impl PyToolsDiff {
    #[getter]
    fn parent_tools(&self) -> Vec<String> {
        self.inner.parent_tools.clone()
    }

    #[getter]
    fn child_tools(&self) -> Vec<String> {
        self.inner.child_tools.clone()
    }

    #[getter]
    fn kept(&self) -> Vec<String> {
        self.inner.kept.clone()
    }

    #[getter]
    fn dropped(&self) -> Vec<String> {
        self.inner.dropped.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "ToolsDiff(kept={:?}, dropped={:?})",
            self.inner.kept, self.inner.dropped
        )
    }
}

/// Python wrapper for ConstraintDiff.
#[pyclass(name = "ConstraintDiff")]
#[derive(Clone)]
pub struct PyConstraintDiff {
    inner: RustConstraintDiff,
}

#[pymethods]
impl PyConstraintDiff {
    #[getter]
    fn field(&self) -> &str {
        &self.inner.field
    }

    #[getter]
    fn parent_constraint(&self, py: Python<'_>) -> PyResult<Option<PyObject>> {
        match &self.inner.parent_constraint {
            Some(c) => Ok(Some(constraint_to_py(py, c)?)),
            None => Ok(None),
        }
    }

    #[getter]
    fn child_constraint(&self, py: Python<'_>) -> PyResult<Option<PyObject>> {
        match &self.inner.child_constraint {
            Some(c) => Ok(Some(constraint_to_py(py, c)?)),
            None => Ok(None),
        }
    }

    #[getter]
    fn change(&self) -> PyChangeType {
        PyChangeType {
            inner: self.inner.change,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "ConstraintDiff(field='{}', change={})",
            self.inner.field,
            self.inner.change.as_str()
        )
    }
}

/// Python wrapper for TtlDiff.
#[pyclass(name = "TtlDiff")]
#[derive(Clone)]
pub struct PyTtlDiff {
    inner: RustTtlDiff,
}

#[pymethods]
impl PyTtlDiff {
    #[getter]
    fn parent_ttl_seconds(&self) -> Option<i64> {
        self.inner.parent_ttl_seconds
    }

    #[getter]
    fn child_ttl_seconds(&self) -> Option<i64> {
        self.inner.child_ttl_seconds
    }

    #[getter]
    fn change(&self) -> PyChangeType {
        PyChangeType {
            inner: self.inner.change,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "TtlDiff(parent={:?}, child={:?}, change={})",
            self.inner.parent_ttl_seconds,
            self.inner.child_ttl_seconds,
            self.inner.change.as_str()
        )
    }
}

/// Python wrapper for ClearanceDiff.
#[pyclass(name = "ClearanceDiff")]
#[derive(Clone)]
pub struct PyClearanceDiff {
    inner: RustClearanceDiff,
}

#[pymethods]
impl PyClearanceDiff {
    #[getter]
    fn parent_clearance(&self) -> Option<PyClearance> {
        self.inner
            .parent_clearance
            .map(|c| PyClearance { inner: c })
    }

    #[getter]
    fn child_clearance(&self) -> Option<PyClearance> {
        self.inner.child_clearance.map(|c| PyClearance { inner: c })
    }

    #[getter]
    fn change(&self) -> PyChangeType {
        PyChangeType {
            inner: self.inner.change,
        }
    }

    fn __repr__(&self) -> String {
        format!("ClearanceDiff(change={})", self.inner.change.as_str())
    }
}

/// Python wrapper for DepthDiff.
#[pyclass(name = "DepthDiff")]
#[derive(Clone)]
pub struct PyDepthDiff {
    inner: RustDepthDiff,
}

#[pymethods]
impl PyDepthDiff {
    #[getter]
    fn parent_depth(&self) -> u32 {
        self.inner.parent_depth
    }

    #[getter]
    fn child_depth(&self) -> u32 {
        self.inner.child_depth
    }

    #[getter]
    fn is_terminal(&self) -> bool {
        self.inner.is_terminal
    }

    fn __repr__(&self) -> String {
        format!(
            "DepthDiff(parent={}, child={}, terminal={})",
            self.inner.parent_depth, self.inner.child_depth, self.inner.is_terminal
        )
    }
}

/// Python wrapper for DelegationDiff.
#[pyclass(name = "DelegationDiff")]
#[derive(Clone)]
pub struct PyDelegationDiff {
    inner: RustDelegationDiff,
}

#[pymethods]
impl PyDelegationDiff {
    #[getter]
    fn parent_warrant_id(&self) -> &str {
        &self.inner.parent_warrant_id
    }

    #[getter]
    fn child_warrant_id(&self) -> Option<&str> {
        self.inner.child_warrant_id.as_deref()
    }

    #[getter]
    fn timestamp(&self) -> String {
        self.inner.timestamp.to_rfc3339()
    }

    #[getter]
    fn tools(&self) -> PyToolsDiff {
        PyToolsDiff {
            inner: self.inner.tools.clone(),
        }
    }

    #[getter]
    fn capabilities<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (tool, tool_diffs) in &self.inner.capabilities {
            let tool_dict = PyDict::new(py);
            for (field, diff) in tool_diffs {
                let py_diff = PyConstraintDiff {
                    inner: diff.clone(),
                };
                tool_dict.set_item(field, py_diff.into_pyobject(py)?)?;
            }
            dict.set_item(tool, tool_dict)?;
        }
        Ok(dict)
    }

    #[getter]
    fn ttl(&self) -> PyTtlDiff {
        PyTtlDiff {
            inner: self.inner.ttl.clone(),
        }
    }

    #[getter]
    fn clearance(&self) -> PyClearanceDiff {
        PyClearanceDiff {
            inner: self.inner.clearance.clone(),
        }
    }

    #[getter]
    fn depth(&self) -> PyDepthDiff {
        PyDepthDiff {
            inner: self.inner.depth.clone(),
        }
    }

    #[getter]
    fn intent(&self) -> Option<&str> {
        self.inner.intent.as_deref()
    }

    /// Convert to JSON string.
    fn to_json(&self) -> PyResult<String> {
        self.inner
            .to_json()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Get human-readable diff output.
    fn to_human(&self) -> String {
        self.inner.to_human()
    }

    /// Get SIEM-compatible JSON output.
    fn to_siem_json(&self) -> PyResult<String> {
        self.inner
            .to_siem_json()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    fn __repr__(&self) -> String {
        format!(
            "DelegationDiff(parent='{}', child={:?})",
            self.inner.parent_warrant_id, self.inner.child_warrant_id
        )
    }
}

/// Python wrapper for DelegationReceipt.
#[pyclass(name = "DelegationReceipt")]
#[derive(Clone)]
pub struct PyDelegationReceipt {
    inner: RustDelegationReceipt,
}

#[pymethods]
impl PyDelegationReceipt {
    /// Create a receipt from a diff.
    #[staticmethod]
    fn from_diff(
        diff: &PyDelegationDiff,
        child_warrant_id: &str,
        delegator_fingerprint: &str,
        delegatee_fingerprint: &str,
    ) -> Self {
        Self {
            inner: RustDelegationReceipt::from_diff(
                diff.inner.clone(),
                child_warrant_id.to_string(),
                delegator_fingerprint.to_string(),
                delegatee_fingerprint.to_string(),
            ),
        }
    }

    #[getter]
    fn parent_warrant_id(&self) -> &str {
        &self.inner.parent_warrant_id
    }

    #[getter]
    fn child_warrant_id(&self) -> &str {
        &self.inner.child_warrant_id
    }

    #[getter]
    fn timestamp(&self) -> String {
        self.inner.timestamp.to_rfc3339()
    }

    #[getter]
    fn tools(&self) -> PyToolsDiff {
        PyToolsDiff {
            inner: self.inner.tools.clone(),
        }
    }

    #[getter]
    fn capabilities<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (tool, tool_diffs) in &self.inner.capabilities {
            let tool_dict = PyDict::new(py);
            for (field, diff) in tool_diffs {
                let py_diff = PyConstraintDiff {
                    inner: diff.clone(),
                };
                tool_dict.set_item(field, py_diff.into_pyobject(py)?)?;
            }
            dict.set_item(tool, tool_dict)?;
        }
        Ok(dict)
    }

    #[getter]
    fn ttl(&self) -> PyTtlDiff {
        PyTtlDiff {
            inner: self.inner.ttl.clone(),
        }
    }

    #[getter]
    fn clearance(&self) -> PyClearanceDiff {
        PyClearanceDiff {
            inner: self.inner.clearance.clone(),
        }
    }

    #[getter]
    fn depth(&self) -> PyDepthDiff {
        PyDepthDiff {
            inner: self.inner.depth.clone(),
        }
    }

    #[getter]
    fn delegator_fingerprint(&self) -> &str {
        &self.inner.delegator_fingerprint
    }

    #[getter]
    fn delegatee_fingerprint(&self) -> &str {
        &self.inner.delegatee_fingerprint
    }

    #[getter]
    fn intent(&self) -> Option<&str> {
        self.inner.intent.as_deref()
    }

    #[getter]
    fn used_pass_through(&self) -> bool {
        self.inner.used_pass_through
    }

    #[getter]
    fn pass_through_reason(&self) -> Option<&str> {
        self.inner.pass_through_reason.as_deref()
    }

    /// Convert to JSON string.
    fn to_json(&self) -> PyResult<String> {
        self.inner
            .to_json()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Get SIEM-compatible JSON output.
    fn to_siem_json(&self) -> PyResult<String> {
        self.inner
            .to_siem_json()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    fn __repr__(&self) -> String {
        format!(
            "DelegationReceipt(parent='{}', child='{}')",
            self.inner.parent_warrant_id, self.inner.child_warrant_id
        )
    }
}

/// Python wrapper for AttenuationBuilder (owned, no lifetime issues).
///
/// Provides a fluent API for configuring attenuated warrants with
/// diff preview capabilities.
#[pyclass(name = "AttenuationBuilder")]
pub struct PyAttenuationBuilder {
    inner: OwnedAttenuationBuilder,
}

#[pymethods]
impl PyAttenuationBuilder {
    /// Add a capability (tool + constraints) to the warrant.
    ///
    /// **POLA**: You must explicitly add each capability you want. Only tools
    /// specified via this method will be in the child warrant.
    ///
    /// **Zero-Trust Mode**: If any constraint is defined, unknown fields are
    /// rejected by default. Use `_allow_unknown=True` to opt out:
    ///
    /// ```text
    /// builder.with_capability("fetch", {
    ///     "url": Pattern("https://*"),
    ///     "_allow_unknown": True,  # Allow other fields
    /// })
    /// ```
    fn with_capability(&mut self, tool: &str, constraints: &Bound<'_, PyDict>) -> PyResult<()> {
        let constraint_set = py_dict_to_constraint_set(constraints)?;
        self.inner.set_capability(tool, constraint_set);
        Ok(())
    }

    /// Inherit all capabilities from the parent warrant.
    ///
    /// This is an **explicit opt-in** to full inheritance. Use this when you
    /// want to start with all parent capabilities and then narrow specific ones.
    ///
    /// Without this, the builder follows POLA (Principle of Least Authority)
    /// and starts with NO capabilities.
    fn inherit_all(&mut self) {
        self.inner.inherit_all();
    }

    /// Set a shorter TTL in seconds.
    fn with_ttl(&mut self, seconds: u64) {
        self.inner.set_ttl(Duration::from_secs(seconds));
    }

    /// Set the authorized holder for the child warrant.
    fn with_holder(&mut self, holder: &PyPublicKey) {
        self.inner.set_holder(holder.inner.clone());
    }

    /// Set the trust level for the child warrant.
    fn with_clearance(&mut self, level: &PyClearance) {
        self.inner.set_clearance(level.inner);
    }

    /// Set the intent/purpose for this delegation (for audit trails).
    fn with_intent(&mut self, intent: &str) {
        self.inner.set_intent(intent);
    }

    /// Narrow execution warrant tools to a single tool.
    ///
    /// The tool must be in the parent warrant's tools.
    /// This is for EXECUTION warrants. For ISSUER warrants, use `with_issuable_tool()`.
    fn with_tool(&mut self, tool: &str) {
        self.inner.retain_capability(tool);
    }

    /// Narrow execution warrant tools to a subset.
    ///
    /// All tools must be in the parent warrant's tools.
    fn with_tools(&mut self, tools: Vec<String>) {
        self.inner.retain_capabilities(&tools);
    }

    /// Set a single tool for issuable_tools (for issuer warrants).
    ///
    /// This replaces the entire issuable_tools list with a single tool.
    /// For multiple tools, use `with_issuable_tools()` instead.
    fn with_issuable_tool(&mut self, tool: &str) {
        self.inner.set_issuable_tool(tool);
    }

    /// Set multiple tools for issuable_tools (for issuer warrants).
    ///
    /// This replaces the entire issuable_tools list.
    fn with_issuable_tools(&mut self, tools: Vec<String>) {
        self.inner.set_issuable_tools(tools);
    }

    /// Drop tools from issuable_tools (for issuer warrants).
    fn drop_tools(&mut self, tools: Vec<String>) {
        self.inner.drop_issuable_tools(tools);
    }

    /// Make this warrant terminal (cannot be delegated further).
    fn terminal(&mut self) {
        self.inner.set_terminal();
    }

    /// Get the parent warrant.
    #[getter]
    fn parent(&self) -> PyWarrant {
        PyWarrant {
            inner: self.inner.parent().clone(),
        }
    }

    /// Get the configured capabilities.
    #[getter]
    fn capabilities<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (tool, constraints) in self.inner.tools().iter() {
            let constraint_dict = PyDict::new(py);
            for (field, constraint) in constraints.iter() {
                let py_constraint = constraint_to_py(py, constraint)?;
                constraint_dict.set_item(field, py_constraint)?;
            }
            dict.set_item(tool, constraint_dict)?;
        }
        Ok(dict)
    }

    /// Get the configured TTL in seconds (if set).
    #[getter]
    fn ttl_seconds(&self) -> Option<u64> {
        self.inner.ttl_seconds()
    }

    /// Get the configured holder (if set).
    #[getter]
    fn holder(&self) -> Option<PyPublicKey> {
        self.inner
            .get_holder()
            .map(|pk| PyPublicKey { inner: pk.clone() })
    }

    /// Get the configured clearance.
    #[getter]
    fn clearance(&self) -> Option<PyClearance> {
        self.inner.clearance().map(|tl| PyClearance { inner: tl })
    }

    /// Get the configured intent.
    #[getter]
    fn intent(&self) -> Option<String> {
        self.inner.intent().map(|s| s.to_string())
    }

    /// Get human-readable diff preview.
    fn diff(&self) -> String {
        self.inner.diff().to_human()
    }

    /// Get structured diff for programmatic use.
    fn diff_structured(&self) -> PyDelegationDiff {
        PyDelegationDiff {
            inner: self.inner.diff(),
        }
    }

    /// Build and sign the attenuated warrant.
    ///
    /// The signing key must belong to the holder of the parent warrant (the delegator).
    /// This enforces the delegation authority rule: you can only delegate what you hold.
    ///
    /// # Arguments
    ///
    /// * `signing_key` - The keypair of the parent warrant's holder
    ///
    /// # Errors
    ///
    /// Returns `DelegationAuthorityError` if the signing key doesn't match
    /// the parent warrant's holder.
    #[pyo3(name = "delegate")]
    fn delegate(&self, signing_key: &PySigningKey) -> PyResult<PyWarrant> {
        let warrant = self
            .inner
            .clone()
            .build(&signing_key.inner)
            .map_err(to_py_err)?;
        Ok(PyWarrant { inner: warrant })
    }

    /// Build and return both warrant and receipt.
    ///
    /// This is a convenience method for workflows that need the receipt immediately.
    /// The signing key must belong to the holder of the parent warrant.
    #[pyo3(name = "delegate_with_receipt")]
    fn delegate_with_receipt(
        &self,
        signing_key: &PySigningKey,
    ) -> PyResult<(PyWarrant, PyDelegationReceipt)> {
        let (warrant, receipt) = self
            .inner
            .clone()
            .build_with_receipt(&signing_key.inner)
            .map_err(to_py_err)?;
        Ok((
            PyWarrant { inner: warrant },
            PyDelegationReceipt { inner: receipt },
        ))
    }

    fn __repr__(&self) -> String {
        format!(
            "AttenuationBuilder(parent={}, ttl={:?}, holder={:?})",
            self.inner.parent().id(),
            self.inner.ttl_seconds(),
            self.inner.get_holder().is_some()
        )
    }
}

/// Python wrapper for IssuanceBuilder (owned, no lifetime issues).
///
/// Provides a fluent API for issuing execution warrants from issuer warrants.
#[pyclass(name = "IssuanceBuilder")]
pub struct PyIssuanceBuilder {
    inner: OwnedIssuanceBuilder,
}

#[pymethods]
impl PyIssuanceBuilder {
    /// Add a capability (tool + constraints) to the execution warrant.
    ///
    /// **Zero-Trust Mode**: If any constraint is defined, unknown fields are
    /// rejected by default. Use `_allow_unknown=True` to opt out.
    fn with_capability(&mut self, tool: &str, constraints: &Bound<'_, PyDict>) -> PyResult<()> {
        let constraint_set = py_dict_to_constraint_set(constraints)?;
        self.inner.set_capability(tool, constraint_set);
        Ok(())
    }

    /// Set the clearance for the execution warrant.
    fn with_clearance(&mut self, level: &PyClearance) {
        self.inner.set_clearance(level.inner);
    }

    /// Set TTL in seconds.
    fn with_ttl(&mut self, seconds: u64) {
        self.inner.set_ttl(Duration::from_secs(seconds));
    }

    /// Set the maximum delegation depth.
    fn with_max_depth(&mut self, max_depth: u32) {
        self.inner.set_max_depth(max_depth);
    }

    /// Set the session ID.
    fn with_session_id(&mut self, session_id: &str) {
        self.inner.set_session_id(session_id);
    }

    /// Set the agent ID.
    fn with_agent_id(&mut self, agent_id: &str) {
        self.inner.set_agent_id(agent_id);
    }

    /// Set the authorized holder for the execution warrant.
    fn with_holder(&mut self, holder: &PyPublicKey) {
        self.inner.set_holder(holder.inner.clone());
    }

    /// Set required approvers.
    fn with_required_approvers(&mut self, approvers: &Bound<'_, PyAny>) -> PyResult<()> {
        let py_list = approvers.downcast::<pyo3::types::PyList>()?;
        let mut rust_approvers = Vec::new();
        for item in py_list.iter() {
            let pk: PyPublicKey = item.extract()?;
            rust_approvers.push(pk.inner);
        }
        self.inner.set_required_approvers(rust_approvers);
        Ok(())
    }

    /// Set minimum approvals.
    fn with_min_approvals(&mut self, min: u32) {
        self.inner.set_min_approvals(min);
    }

    /// Set the intent/purpose for this issuance.
    fn with_intent(&mut self, intent: &str) {
        self.inner.set_intent(intent);
    }

    /// Make this warrant terminal (cannot be delegated further).
    fn terminal(&mut self) {
        self.inner.set_terminal();
    }

    /// Add a tool (with empty constraints) or merge.
    fn with_tool(&mut self, tool: &str) {
        let empty = crate::constraints::ConstraintSet::new();
        self.inner.set_capability(tool, empty);
    }

    /// Get the issuer warrant.
    #[getter]
    fn issuer(&self) -> PyWarrant {
        PyWarrant {
            inner: self.inner.issuer().clone(),
        }
    }

    /// Get the configured tools (if set).
    #[getter]
    fn tools(&self) -> Option<Vec<String>> {
        let caps = self.inner.tools();
        if caps.is_empty() {
            None
        } else {
            let mut keys: Vec<String> = caps.keys().cloned().collect();
            keys.sort();
            Some(keys)
        }
    }

    /// Get the configured TTL in seconds (if set).
    #[getter]
    fn ttl_seconds(&self) -> Option<u64> {
        self.inner.ttl_seconds()
    }

    /// Get the configured holder (if set).
    #[getter]
    fn holder(&self) -> Option<PyPublicKey> {
        self.inner
            .holder()
            .map(|pk| PyPublicKey { inner: pk.clone() })
    }

    /// Get the configured clearance.
    #[getter]
    fn clearance(&self) -> Option<PyClearance> {
        self.inner.clearance().map(|tl| PyClearance { inner: tl })
    }

    /// Get the configured intent.
    #[getter]
    fn intent(&self) -> Option<String> {
        self.inner.intent().map(|s| s.to_string())
    }

    /// Build and sign the execution warrant.
    ///
    /// The signing key must belong to the holder of the issuer warrant.
    /// This enforces the delegation authority rule: you can only delegate what you hold.
    ///
    /// # Arguments
    ///
    /// * `signing_key` - The keypair of the issuer warrant's holder
    fn build(&self, signing_key: &PySigningKey) -> PyResult<PyWarrant> {
        let warrant = self
            .inner
            .clone()
            .build(&signing_key.inner)
            .map_err(to_py_err)?;
        Ok(PyWarrant { inner: warrant })
    }

    fn __repr__(&self) -> String {
        format!(
            "IssuanceBuilder(issuer={}, tools={:?}, holder={:?})",
            self.inner.issuer().id(),
            self.inner.tools().keys().collect::<Vec<_>>(),
            self.inner.get_holder().is_some()
        )
    }
}

/// Python wrapper for Warrant.
#[pyclass(name = "Warrant", subclass)]
pub struct PyWarrant {
    inner: RustWarrant,
}

#[pymethods]
impl PyWarrant {
    /// Create a Warrant from a base64 string.
    ///
    /// To issue a new warrant, use `Warrant.issue()`.
    #[new]
    fn new(token: String) -> PyResult<Self> {
        let inner = crate::wire::decode_base64(&token).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    fn __str__(&self) -> PyResult<String> {
        crate::wire::encode_base64(&self.inner).map_err(to_py_err)
    }

    /// Issue a new warrant.
    #[staticmethod]
    #[pyo3(signature = (keypair, capabilities=None, ttl_seconds=3600, holder=None, session_id=None, clearance=None, required_approvers=None, min_approvals=None))]
    #[allow(clippy::too_many_arguments)]
    fn issue(
        keypair: &PySigningKey,
        capabilities: Option<&Bound<'_, PyDict>>,
        ttl_seconds: u64,
        holder: Option<&PyPublicKey>,
        session_id: Option<&str>,
        clearance: Option<&PyClearance>,
        required_approvers: Option<Vec<PyPublicKey>>,
        min_approvals: Option<u32>,
    ) -> PyResult<Self> {
        let mut builder = RustWarrant::builder().ttl(Duration::from_secs(ttl_seconds));

        // Capabilities: dict[tool_name, dict[field, constraint]]
        // Supports _allow_unknown key for zero-trust mode opt-out
        if let Some(caps_dict) = capabilities {
            for (tool_key, constraints_val) in caps_dict.iter() {
                let tool_name: String = tool_key.extract()?;

                let constraints_dict: &Bound<'_, PyDict> = constraints_val
                    .downcast()
                    .map_err(|_| PyValueError::new_err("capabilities values must be dicts"))?;

                let constraint_set = py_dict_to_constraint_set(constraints_dict)?;
                builder = builder.capability(tool_name, constraint_set);
            }
        }

        // Set clearance if provided
        if let Some(tl) = clearance {
            builder = builder.clearance(tl.inner);
        }

        // If holder is provided, use it. Otherwise, default to the issuer (self-signed).
        if let Some(h) = holder {
            builder = builder.holder(h.inner.clone());
        } else {
            builder = builder.holder(keypair.inner.public_key());
        }

        if let Some(sid) = session_id {
            builder = builder.session_id(sid);
        }

        // Multi-sig: set required approvers if provided
        if let Some(approvers) = required_approvers {
            let rust_approvers: Vec<crate::crypto::PublicKey> =
                approvers.into_iter().map(|pk| pk.inner).collect();
            builder = builder.required_approvers(rust_approvers);
        }

        // Multi-sig: set minimum approvals if provided
        if let Some(min) = min_approvals {
            builder = builder.min_approvals(min);
        }

        let warrant = builder.build(&keypair.inner).map_err(to_py_err)?;
        Ok(Self { inner: warrant })
    }

    /// Issue a new issuer warrant.
    ///
    /// Issuer warrants can issue execution warrants but cannot execute tools themselves.
    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (issuable_tools, keypair, constraint_bounds=None, max_issue_depth=None, ttl_seconds=3600, holder=None, session_id=None, clearance=None))]
    fn issue_issuer(
        issuable_tools: Vec<String>,
        keypair: &PySigningKey,
        constraint_bounds: Option<&Bound<'_, PyDict>>,
        max_issue_depth: Option<u32>,
        ttl_seconds: u64,
        holder: Option<&PyPublicKey>,
        session_id: Option<&str>,
        clearance: Option<&PyClearance>,
    ) -> PyResult<Self> {
        let mut builder = RustWarrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(issuable_tools)
            .ttl(Duration::from_secs(ttl_seconds));

        if let Some(depth) = max_issue_depth {
            builder = builder.max_issue_depth(depth);
        }

        // Set clearance if provided
        if let Some(tl) = clearance {
            builder = builder.clearance(tl.inner);
        }

        // If holder is provided, use it. Otherwise, default to the issuer (self-signed).
        if let Some(h) = holder {
            builder = builder.holder(h.inner.clone());
        } else {
            builder = builder.holder(keypair.inner.public_key());
        }

        if let Some(sid) = session_id {
            builder = builder.session_id(sid);
        }

        if let Some(bounds_dict) = constraint_bounds {
            for (key, value) in bounds_dict.iter() {
                let field: String = key.extract()?;
                let constraint = py_to_constraint(&value)?;
                builder = builder.constraint_bound(field, constraint);
            }
        }

        let warrant = builder.build(&keypair.inner).map_err(to_py_err)?;
        Ok(Self { inner: warrant })
    }

    /// Create an IssuanceBuilder for issuing execution warrants from this issuer warrant.
    ///
    /// This method can only be called on issuer warrants. It returns a builder that
    /// validates the issued execution warrant complies with the issuer's constraints.
    ///
    /// Returns:
    ///     IssuanceBuilder for fluent API
    ///
    /// Raises:
    ///     ValidationError: If this is not an issuer warrant
    fn issue_execution(&self) -> PyResult<PyIssuanceBuilder> {
        // Validate this is an issuer warrant
        if self.inner.r#type() != WarrantType::Issuer {
            return Err(PyValueError::new_err(
                "can only issue execution warrants from issuer warrants",
            ));
        }

        Ok(PyIssuanceBuilder {
            inner: OwnedIssuanceBuilder::new(self.inner.clone()),
        })
    }

    /// Get the warrant type.
    #[getter]
    fn warrant_type(&self) -> PyWarrantType {
        let wt = self.inner.r#type();
        PyWarrantType { inner: wt }
    }

    /// Get the warrant ID.
    #[getter]
    fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Get the tool names.
    #[getter]
    fn tools(&self) -> Option<Vec<String>> {
        self.inner.capabilities().map(|caps| {
            let mut keys: Vec<String> = caps.keys().cloned().collect();
            keys.sort();
            keys
        })
    }

    /// Get issuable tools (Issuer warrants only).
    #[getter]
    fn issuable_tools(&self) -> Option<Vec<String>> {
        self.inner.issuable_tools().map(|t| t.to_vec())
    }

    /// Get max issue depth (Issuer warrants only).
    #[getter]
    fn max_issue_depth(&self) -> Option<u32> {
        self.inner.max_issue_depth()
    }

    /// Get the delegation depth.
    #[getter]
    fn depth(&self) -> u32 {
        self.inner.depth()
    }

    /// Get the maximum delegation depth for this warrant chain.
    #[getter]
    fn max_depth(&self) -> Option<u32> {
        self.inner.max_depth()
    }

    /// Get remaining TTL in seconds.
    ///
    /// Returns the number of seconds until expiration, or 0 if already expired.
    fn ttl_seconds(&self) -> u64 {
        let now = chrono::Utc::now().timestamp() as u64;
        let expires = self.inner.expires_at().timestamp() as u64;
        expires.saturating_sub(now)
    }

    /// Get the parent warrant hash.
    #[getter]
    fn parent_hash(&self) -> Option<String> {
        self.inner.parent_hash().map(hex::encode)
    }

    /// Get the session ID.
    #[getter]
    fn session_id(&self) -> Option<&str> {
        self.inner.session_id()
    }

    /// Get the authorized holder's public key.
    #[getter]
    fn authorized_holder(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.authorized_holder().clone(),
        }
    }

    /// Get the raw payload bytes.
    #[getter]
    fn payload_bytes(&self) -> Vec<u8> {
        self.inner.payload_bytes().to_vec()
    }

    /// Get the issuer's public key (who signed this warrant).
    ///
    /// For root warrants, this is the control plane's key.
    /// For delegated warrants, this is the delegator's key.
    #[getter]
    fn issuer(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.issuer().clone(),
        }
    }

    /// Get the trust level (optional, for audit/classification).
    #[getter]
    fn clearance(&self) -> Option<PyClearance> {
        self.inner.clearance().map(|tl| PyClearance { inner: tl })
    }

    /// Check if the warrant has expired.
    fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    /// Check if this warrant is terminal (cannot delegate further).
    ///
    /// A warrant is terminal when its depth equals or exceeds its max_depth.
    /// Terminal warrants can still execute tools but cannot attenuate/delegate.
    fn is_terminal(&self) -> bool {
        self.inner.is_terminal()
    }

    /// Get the expiration time (RFC3339 string).
    fn expires_at(&self) -> String {
        self.inner.expires_at().to_rfc3339()
    }

    /// Get capabilities as a Python dict (tool -> dict[field, constraint]).
    ///
    /// Returns None if this is an issuer warrant.
    #[getter]
    fn capabilities<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>> {
        if let Some(caps) = self.inner.capabilities() {
            let dict = PyDict::new(py);
            for (tool, constraints) in caps.iter() {
                let constraint_dict = PyDict::new(py);
                for (field, constraint) in constraints.iter() {
                    let py_constraint = constraint_to_py(py, constraint)?;
                    constraint_dict.set_item(field, py_constraint)?;
                }
                dict.set_item(tool, constraint_dict)?;
            }
            Ok(Some(dict))
        } else {
            Ok(None)
        }
    }

    /// Get constraint bounds as a Python dict (Issuer warrants only).
    fn constraint_bounds_dict<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>> {
        if let Some(bounds) = self.inner.constraint_bounds() {
            let dict = PyDict::new(py);
            for (field, constraint) in bounds.iter() {
                let py_constraint = constraint_to_py(py, constraint)?;
                dict.set_item(field, py_constraint)?;
            }
            Ok(Some(dict))
        } else {
            Ok(None)
        }
    }

    /// Create an attenuation builder for this warrant.
    ///
    /// Returns an `AttenuationBuilder` that can be configured with constraints,
    /// TTL, holder, etc. before calling `delegate()` to create the child warrant.
    ///
    /// # Example
    ///
    /// ```text
    /// builder = parent.grant_builder()
    /// builder.with_constraint("path", Exact("/data/q3.pdf"))
    /// builder.with_ttl(60)
    /// builder.with_holder(worker_key)
    /// child = builder.delegate(parent_keypair)  # Parent signs
    /// ```
    fn attenuate_builder(&self) -> PyAttenuationBuilder {
        PyAttenuationBuilder {
            inner: OwnedAttenuationBuilder::new(self.inner.clone()),
        }
    }

    /// Attenuate the warrant (create a child with narrower scope).
    ///
    /// The signing_key must be the holder of THIS warrant. The new warrant's
    /// holder defaults to the same key, but can be set with holder=.
    #[pyo3(signature = (capabilities, signing_key, ttl_seconds=None, holder=None, clearance=None))]
    fn attenuate(
        &self,
        capabilities: &Bound<'_, PyDict>,
        signing_key: &PySigningKey,
        ttl_seconds: Option<u64>,
        holder: Option<&PyPublicKey>,
        clearance: Option<&PyClearance>,
    ) -> PyResult<PyWarrant> {
        let mut builder = self.inner.attenuate();

        if let Some(ttl) = ttl_seconds {
            builder = builder.ttl(Duration::from_secs(ttl));
        }

        if let Some(h) = holder {
            builder = builder.holder(h.inner.clone());
        }

        // Capabilities: dict[tool_name, dict[field, constraint]]
        // Supports _allow_unknown key for zero-trust mode opt-out
        for (tool_key, constraints_val) in capabilities.iter() {
            let tool_name: String = tool_key.extract()?;

            let constraints_dict: &Bound<'_, PyDict> = constraints_val
                .downcast()
                .map_err(|_| PyValueError::new_err("capabilities values must be dicts"))?;

            let constraint_set = py_dict_to_constraint_set(constraints_dict)?;
            builder = builder.capability(tool_name, constraint_set);
        }

        // Note: Clearance on AttenuationBuilder requires mutable access
        if let Some(c) = clearance {
            builder = builder.clearance(c.inner);
        }

        let warrant = builder.build(&signing_key.inner).map_err(to_py_err)?;
        Ok(PyWarrant { inner: warrant })
    }

    // ========================================================================
    // AUTHORIZATION METHODS
    // Use these for actual authorization decisions in production code.
    // ========================================================================

    /// Authorize an action against this warrant (PRODUCTION USE).
    ///
    /// This is the primary authorization method. It performs all security checks:
    /// - Warrant expiration
    /// - Tool permission
    /// - Proof-of-Possession signature verification
    /// - Constraint satisfaction
    ///
    /// Use this method when you need to make an actual authorization decision.
    /// For debugging why authorization failed, use `check_constraints()` or `why_denied()`.
    ///
    /// Args:
    ///     tool: Tool name to authorize
    ///     args: Dictionary of argument name -> value
    ///     signature: PoP signature bytes (64 bytes) - REQUIRED for security
    ///
    /// Returns:
    ///     True if fully authorized, False otherwise
    ///
    /// Note:
    ///     Returns False for BOTH constraint failures AND missing/invalid PoP.
    ///     This is intentional - in production, you should not distinguish these.
    ///     For debugging, use `check_constraints()` instead.
    #[pyo3(signature = (tool, args, signature=None))]
    fn authorize(
        &self,
        tool: &str,
        args: &Bound<'_, PyDict>,
        signature: Option<&[u8]>,
    ) -> PyResult<bool> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        // Convert signature bytes to Signature if provided
        let sig = match signature {
            Some(bytes) => {
                let arr: [u8; 64] = bytes
                    .try_into()
                    .map_err(|_| PyValueError::new_err("signature must be exactly 64 bytes"))?;
                Some(crate::crypto::Signature::from_bytes(&arr).map_err(to_py_err)?)
            }
            None => None,
        };

        match self.inner.authorize(tool, &rust_args, sig.as_ref()) {
            Ok(()) => Ok(true),
            Err(crate::error::Error::ConstraintNotSatisfied { .. }) => Ok(false),
            Err(crate::error::Error::MissingSignature(_)) => Ok(false),
            Err(crate::error::Error::SignatureInvalid(_)) => Ok(false),
            Err(e) => Err(to_py_err(e)),
        }
    }

    // ========================================================================
    // DIAGNOSTIC METHODS
    // Use these for debugging, logging, and understanding authorization failures.
    // DO NOT use these for authorization decisions - they skip security checks.
    // ========================================================================

    /// Check if constraints are satisfied (DIAGNOSTIC USE ONLY).
    ///
    /// This method checks ONLY constraint satisfaction, skipping:
    /// - PoP signature verification
    /// - Expiration checks
    ///
    /// Use this to understand WHY a request would be denied due to constraints.
    /// DO NOT use this for actual authorization - use `authorize()` instead.
    ///
    /// Args:
    ///     tool: Tool name to check
    ///     args: Dictionary of argument name -> value
    ///
    /// Returns:
    ///     None if constraints are satisfied, or a string describing the failure
    ///
    /// Example:
    ///     ```text
    ///     result = warrant.check_constraints("read_file", {"path": "/etc/passwd"})
    ///     if result:
    ///         print(f"Would be denied: {result}")
    ///     ```
    fn check_constraints(&self, tool: &str, args: &Bound<'_, PyDict>) -> PyResult<Option<String>> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        match self.inner.check_constraints(tool, &rust_args) {
            Ok(()) => Ok(None),
            Err(crate::error::Error::ConstraintNotSatisfied { field, reason }) => Ok(Some(
                format!("Constraint '{}' not satisfied: {}", field, reason),
            )),
            Err(e) => Ok(Some(format!("{}", e))),
        }
    }

    /// Check constraints with structured result (DIAGNOSTIC USE ONLY).
    ///
    /// Like check_constraints, but returns structured data instead of a string.
    ///
    /// Returns:
    ///     None if constraints are satisfied, or a tuple (field, reason) on failure
    fn check_constraints_detailed(
        &self,
        tool: &str,
        args: &Bound<'_, PyDict>,
    ) -> PyResult<Option<(String, String)>> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        match self.inner.check_constraints(tool, &rust_args) {
            Ok(()) => Ok(None),
            Err(crate::error::Error::ConstraintNotSatisfied { field, reason }) => {
                Ok(Some((field, reason)))
            }
            Err(e) => Ok(Some(("_error".to_string(), format!("{}", e)))),
        }
    }

    // ========================================================================
    // INTROSPECTION METHODS
    // Use these to inspect warrant metadata. Safe for any use.
    // ========================================================================

    /// Get the agent ID if set on this warrant.
    fn agent_id(&self) -> Option<String> {
        self.inner.agent_id().map(|s| s.to_string())
    }

    /// Check if this warrant requires multi-signature approval.
    fn requires_multisig(&self) -> bool {
        self.inner.requires_multisig()
    }

    /// Get the required approvers for multi-signature (if any).
    fn required_approvers(&self) -> Option<Vec<PyPublicKey>> {
        self.inner.required_approvers().map(|approvers| {
            approvers
                .iter()
                .map(|pk| PyPublicKey { inner: pk.clone() })
                .collect()
        })
    }

    /// Get the minimum number of approvals required (if multisig).
    fn min_approvals(&self) -> Option<u32> {
        self.inner.min_approvals()
    }

    /// Get the effective approval threshold.
    ///
    /// Returns min_approvals if set, otherwise the number of required_approvers.
    fn approval_threshold(&self) -> u32 {
        self.inner.approval_threshold()
    }

    /// Get all custom extensions as a dict of name -> bytes.
    fn extensions<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (key, value) in self.inner.extensions().iter() {
            dict.set_item(key, value.as_slice())?;
        }
        Ok(dict)
    }

    /// Get a specific extension by name.
    fn extension(&self, key: &str) -> Option<Vec<u8>> {
        self.inner.extension(key).cloned()
    }

    /// Validate the warrant structure and constraints (DIAGNOSTIC USE).
    ///
    /// Checks structural validity of the warrant (not authorization).
    /// Use this to detect malformed or potentially malicious warrants.
    ///
    /// Returns:
    ///     Empty list if valid, or list of validation error messages.
    fn validate_warrant(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if let Err(e) = self.inner.validate() {
            errors.push(format!("{}", e));
        }
        if let Err(e) = self.inner.validate_constraint_depth() {
            errors.push(format!("{}", e));
        }
        errors
    }

    // ========================================================================
    // CRYPTOGRAPHIC METHODS
    // Use these for signature verification and PoP signing.
    // ========================================================================

    /// Verify the warrant's issuer signature.
    ///
    /// Checks that the warrant was signed by the expected issuer.
    /// This is part of chain-of-trust verification.
    fn verify(&self, public_key_bytes: &[u8]) -> PyResult<bool> {
        let arr: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("public key must be exactly 32 bytes"))?;
        let pk = crate::crypto::PublicKey::from_bytes(&arr).map_err(to_py_err)?;

        match self.inner.verify(&pk) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Create a Proof-of-Possession signature.
    ///
    /// Use this when making a request with a warrant that requires PoP.
    /// The keypair should match the authorized_holder on the warrant.
    ///
    /// Args:
    ///     keypair: The PySigningKey to sign with
    ///     tool: Tool name being called
    ///     args: Dictionary of argument name -> value
    ///
    /// Returns:
    ///     64-byte signature as bytes
    fn sign(
        &self,
        keypair: &PySigningKey,
        tool: &str,
        args: &Bound<'_, PyDict>,
    ) -> PyResult<Vec<u8>> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        let sig = self
            .inner
            .sign(&keypair.inner, tool, &rust_args)
            .map_err(to_py_err)?;
        Ok(sig.to_bytes().to_vec())
    }

    /// Generate a deduplication key for replay protection.
    ///
    /// Use this as a cache key to prevent replay attacks. Store with TTL
    /// of `dedup_ttl_secs()` (120 seconds by default).
    ///
    /// Args:
    ///     tool: Tool name being called
    ///     args: Dictionary of argument name -> value
    ///
    /// Returns:
    ///     Hex string suitable for use as cache key
    fn dedup_key(&self, tool: &str, args: &Bound<'_, PyDict>) -> PyResult<String> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        Ok(self.inner.dedup_key(tool, &rust_args))
    }

    /// Get the recommended TTL for deduplication cache entries.
    ///
    /// Returns 120 seconds by default (matches PoP validity window).
    #[staticmethod]
    fn dedup_ttl_secs() -> i64 {
        crate::warrant::Warrant::dedup_ttl_secs()
    }

    /// Encode the warrant to base64 (for HTTP headers).
    fn to_base64(&self) -> PyResult<String> {
        wire::encode_base64(&self.inner).map_err(to_py_err)
    }

    /// Encode the warrant to PEM format (for config files).
    fn to_pem(&self) -> PyResult<String> {
        wire::encode_pem(&self.inner).map_err(to_py_err)
    }

    /// Decode a warrant from base64.
    #[staticmethod]
    fn from_base64(s: &str) -> PyResult<Self> {
        let inner = wire::decode_base64(s).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        format!(
            "Warrant(id='{}', type={:?}, tool={}, depth={})",
            self.inner.id(),
            self.inner.r#type(),
            if self.inner.payload.tools.is_empty() {
                "None".to_string()
            } else {
                format!("{:?}", self.inner.payload.tools.keys())
            },
            self.inner.depth()
        )
    }
}

/// Python wrapper for McpConfig.
#[pyclass(name = "McpConfig")]
pub struct PyMcpConfig {
    inner: McpConfig,
}

#[pymethods]
impl PyMcpConfig {
    #[staticmethod]
    fn from_file(path: &str) -> PyResult<Self> {
        let config = McpConfig::from_file(path).map_err(config_err_to_py)?;
        Ok(Self { inner: config })
    }
}

/// Python wrapper for CompiledMcpConfig.
#[pyclass(name = "CompiledMcpConfig")]
pub struct PyCompiledMcpConfig {
    inner: Arc<CompiledMcpConfig>,
}

#[pymethods]
impl PyCompiledMcpConfig {
    #[staticmethod]
    fn compile(config: &PyMcpConfig) -> PyResult<Self> {
        let compiled = CompiledMcpConfig::compile(config.inner.clone()).map_err(to_py_err)?;
        Ok(Self {
            inner: Arc::new(compiled),
        })
    }

    /// Validate the configuration.
    fn validate(&self) -> Vec<String> {
        self.inner.validate()
    }

    /// Extract constraints from an MCP tool call.
    ///
    /// Args:
    ///     tool_name: The name of the tool being called
    ///     arguments: The arguments dictionary from the MCP request
    ///
    /// Returns:
    ///     ExtractionResult object with .constraints and .tool attributes
    fn extract_constraints(
        &self,
        tool_name: &str,
        arguments: &Bound<'_, PyDict>,
    ) -> PyResult<PyExtractionResult> {
        // Convert Python dict to serde_json::Value
        let py = arguments.py();
        let json_str = {
            let json_mod = py.import("json")?;
            let dumps = json_mod.getattr("dumps")?;
            dumps.call1((arguments,))?.extract::<String>()?
        };

        let args_value: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| PyValueError::new_err(format!("Invalid JSON arguments: {}", e)))?;

        // Extract
        let result = self
            .inner
            .extract_constraints(tool_name, &args_value)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        // Convert extracted constraints to Python dict
        let dict = PyDict::new(py);
        for (key, value) in result.constraints {
            let py_val = constraint_value_to_py(py, &value)?;
            dict.set_item(key, py_val)?;
        }

        Ok(PyExtractionResult {
            constraints: dict.into(),
            tool: result.tool,
            warrant_base64: result.warrant_base64,
            signature_base64: result.signature_base64,
        })
    }
}

/// Python wrapper for ExtractionResult.
#[pyclass(name = "ExtractionResult")]
pub struct PyExtractionResult {
    #[pyo3(get)]
    constraints: PyObject,
    #[pyo3(get)]
    tool: String,
    #[pyo3(get)]
    warrant_base64: Option<String>,
    #[pyo3(get)]
    signature_base64: Option<String>,
}

#[pymethods]
impl PyExtractionResult {
    fn __repr__(&self) -> String {
        let auth_info = if self.warrant_base64.is_some() {
            " +auth"
        } else {
            " "
        };
        format!(
            "ExtractionResult(tool='{}', constraints={{...}}{})",
            self.tool, auth_info
        )
    }
}

/// Python wrapper for PublicKey.
#[pyclass(name = "PublicKey")]
#[derive(Clone)]
pub struct PyPublicKey {
    inner: RustPublicKey,
}

#[pymethods]
impl PyPublicKey {
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("public key must be exactly 32 bytes"))?;
        let inner = RustPublicKey::from_bytes(&arr).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    fn __richcmp__(&self, other: &Self, op: pyo3::basic::CompareOp) -> PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => Ok(self.inner == other.inner),
            pyo3::basic::CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "Comparison not supported",
            )),
        }
    }

    fn __repr__(&self) -> String {
        let bytes = self.inner.to_bytes();
        format!(
            "PublicKey({:02x}{:02x}{:02x}{:02x}...)",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }

    /// Create a PublicKey from a PEM string.
    #[staticmethod]
    fn from_pem(pem: &str) -> PyResult<Self> {
        let inner = RustPublicKey::from_pem(pem).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Convert the PublicKey to a PEM string.
    fn to_pem(&self) -> String {
        self.inner.to_pem()
    }
}

/// Python wrapper for Signature.
#[pyclass(name = "Signature")]
pub struct PySignature {
    inner: RustSignature,
}

#[pymethods]
impl PySignature {
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("signature must be exactly 64 bytes"))?;
        let inner = RustSignature::from_bytes(&arr).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    fn __repr__(&self) -> String {
        let bytes = self.inner.to_bytes();
        format!("Signature({:02x}{:02x}...)", bytes[0], bytes[1])
    }
}

/// Python wrapper for ChainStep.
#[pyclass(name = "ChainStep")]
#[derive(Clone)]
pub struct PyChainStep {
    inner: RustChainStep,
}

#[pymethods]
impl PyChainStep {
    /// The warrant ID at this step.
    #[getter]
    fn warrant_id(&self) -> String {
        self.inner.warrant_id.clone()
    }

    /// Delegation depth at this step.
    #[getter]
    fn depth(&self) -> u32 {
        self.inner.depth
    }

    /// Public key of the issuer at this step (32 bytes).
    #[getter]
    fn issuer(&self) -> Vec<u8> {
        self.inner.issuer.to_vec()
    }

    fn __repr__(&self) -> String {
        format!(
            "ChainStep(warrant_id='{}', depth={}, issuer={:02x}...)",
            self.inner.warrant_id, self.inner.depth, self.inner.issuer[0]
        )
    }
}

/// Python wrapper for ChainVerificationResult.
#[pyclass(name = "ChainVerificationResult")]
#[derive(Clone)]
pub struct PyChainVerificationResult {
    inner: RustChainVerificationResult,
}

#[pymethods]
impl PyChainVerificationResult {
    /// Public key of the root issuer (trusted authority), or None.
    #[getter]
    fn root_issuer(&self) -> Option<Vec<u8>> {
        self.inner.root_issuer.map(|arr| arr.to_vec())
    }

    /// Total length of the verified chain.
    #[getter]
    fn chain_length(&self) -> usize {
        self.inner.chain_length
    }

    /// Depth of the leaf warrant.
    #[getter]
    fn leaf_depth(&self) -> u32 {
        self.inner.leaf_depth
    }

    /// Details of each verified step.
    #[getter]
    fn verified_steps(&self) -> Vec<PyChainStep> {
        self.inner
            .verified_steps
            .iter()
            .map(|step| PyChainStep {
                inner: step.clone(),
            })
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "ChainVerificationResult(chain_length={}, leaf_depth={}, steps={})",
            self.inner.chain_length,
            self.inner.leaf_depth,
            self.inner.verified_steps.len()
        )
    }
}

// ============================================================================
// Approval (Multi-Sig Support)
// ============================================================================

/// A cryptographically signed approval from a human or external system.
///
/// Approvals are used for multi-sig authorization where warrants require
/// multiple parties to approve an action before it can be executed.
///
/// Example:
/// ```text
///     # Create an approval for a specific action
///     approval = Approval.create(
///         warrant=warrant,
///         tool="delete_database",
///         args={"database": "production"},
///         keypair=approver_key,
///         external_id="admin@company.com",
///         provider="okta",
///         ttl_secs=300,
///     )
///     
///     # Use the approval with authorize
///     authorizer.authorize(warrant, tool, args, signature, approvals=[approval])
/// ```
#[pyclass(name = "Approval")]
pub struct PyApproval {
    inner: RustApproval,
}

#[pymethods]
impl PyApproval {
    /// Create a new approval.
    ///
    /// Args:
    ///     warrant: The warrant being approved for
    ///     tool: Tool name
    ///     args: Arguments dictionary
    ///     keypair: The approver's signing key
    ///     external_id: External identity (e.g., "admin@company.com")
    ///     provider: Identity provider (e.g., "okta", "aws-iam")
    ///     ttl_secs: Time-to-live in seconds (default: 300)
    ///     reason: Optional approval reason/justification
    ///
    /// Returns:
    ///     A signed Approval object
    #[staticmethod]
    #[pyo3(signature = (warrant, tool, args, keypair, external_id, provider, ttl_secs=300, reason=None))]
    #[allow(clippy::too_many_arguments)]
    fn create(
        warrant: &PyWarrant,
        tool: &str,
        args: &Bound<'_, PyDict>,
        keypair: &PySigningKey,
        external_id: &str,
        provider: &str,
        ttl_secs: i64,
        reason: Option<String>,
    ) -> PyResult<Self> {
        use chrono::{Duration, Utc};

        // Convert args
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        // Compute request hash (binds approval to specific request)
        let warrant_id = warrant.inner.id().to_string();
        let request_hash = compute_request_hash(
            &warrant_id,
            tool,
            &rust_args,
            Some(warrant.inner.authorized_holder()),
        );

        // Create timestamps
        let approved_at = Utc::now();
        let expires_at = approved_at + Duration::seconds(ttl_secs);

        // Generate random nonce for replay protection
        let nonce: [u8; 16] = rand::random();

        // Create signable payload with domain separation
        // Uses centralized constant from domain.rs
        use crate::domain::APPROVAL_CONTEXT;
        let mut signable = Vec::new();
        signable.extend_from_slice(APPROVAL_CONTEXT);
        signable.extend_from_slice(&nonce);
        signable.extend_from_slice(&request_hash);
        signable.extend_from_slice(external_id.as_bytes());
        signable.extend_from_slice(&approved_at.timestamp().to_le_bytes());
        signable.extend_from_slice(&expires_at.timestamp().to_le_bytes());

        // Sign
        let signature = keypair.inner.sign(&signable);

        Ok(PyApproval {
            inner: RustApproval {
                request_hash,
                nonce,
                approver_key: keypair.inner.public_key(),
                external_id: external_id.to_string(),
                provider: provider.to_string(),
                approved_at,
                expires_at,
                reason,
                signature,
            },
        })
    }

    /// Verify the approval signature and check expiration.
    ///
    /// Returns:
    ///     None on success, raises exception on failure
    fn verify(&self) -> PyResult<()> {
        self.inner.verify().map_err(to_py_err)
    }

    /// Get the approver's public key.
    #[getter]
    fn approver_key(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.approver_key.clone(),
        }
    }

    /// Get the nonce (for replay protection).
    #[getter]
    fn nonce(&self) -> Vec<u8> {
        self.inner.nonce.to_vec()
    }

    /// Get the external identity.
    #[getter]
    fn external_id(&self) -> &str {
        &self.inner.external_id
    }

    /// Get the provider name.
    #[getter]
    fn provider(&self) -> &str {
        &self.inner.provider
    }

    /// Get the approval reason (if any).
    #[getter]
    fn reason(&self) -> Option<&str> {
        self.inner.reason.as_deref()
    }

    /// Get when the approval was created (ISO format).
    #[getter]
    fn approved_at(&self) -> String {
        self.inner.approved_at.to_rfc3339()
    }

    /// Get when the approval expires (ISO format).
    #[getter]
    fn expires_at(&self) -> String {
        self.inner.expires_at.to_rfc3339()
    }

    /// Check if the approval has expired.
    fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.inner.expires_at
    }

    // =========================================================================
    // Serialization Methods
    // =========================================================================

    /// Serialize the approval to bytes (CBOR format).
    ///
    /// Returns:
    ///     bytes: The serialized approval
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(&self.inner, &mut buf)
            .map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e)))?;
        Ok(buf)
    }

    /// Deserialize an approval from bytes (CBOR format).
    ///
    /// Args:
    ///     data: The serialized approval bytes
    ///
    /// Returns:
    ///     Approval: The deserialized approval
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner: RustApproval = ciborium::from_reader(data)
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))?;
        Ok(Self { inner })
    }

    /// Serialize the approval to JSON string.
    ///
    /// Returns:
    ///     str: The JSON representation
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("JSON serialization failed: {}", e)))
    }

    /// Serialize the approval to pretty JSON string.
    ///
    /// Returns:
    ///     str: The pretty-printed JSON representation
    fn to_json_pretty(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("JSON serialization failed: {}", e)))
    }

    /// Deserialize an approval from JSON string.
    ///
    /// Args:
    ///     json_str: The JSON string
    ///
    /// Returns:
    ///     Approval: The deserialized approval
    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let inner: RustApproval = serde_json::from_str(json_str)
            .map_err(|e| PyValueError::new_err(format!("JSON deserialization failed: {}", e)))?;
        Ok(Self { inner })
    }

    /// Get the request hash this approval is bound to (hex string).
    #[getter]
    fn request_hash_hex(&self) -> String {
        hex::encode(self.inner.request_hash)
    }

    /// Get the request hash this approval is bound to (raw bytes).
    #[getter]
    fn request_hash(&self) -> [u8; 32] {
        self.inner.request_hash
    }

    fn __repr__(&self) -> String {
        format!(
            "Approval(approver={}, provider={}, external_id={})",
            self.inner.approver_key.fingerprint(),
            self.inner.provider,
            self.inner.external_id
        )
    }
}

/// Compute the request hash for an approval.
///
/// This is a helper function to compute the hash that binds an approval
/// to a specific (warrant, tool, args) tuple.
///
/// Args:
///     warrant: The warrant
///     tool: Tool name
///     args: Arguments dictionary
///
/// Returns:
///     32-byte hash as bytes
#[pyfunction(name = "compute_approval_hash")]
fn py_compute_approval_hash(
    warrant: &PyWarrant,
    tool: &str,
    args: &Bound<'_, PyDict>,
) -> PyResult<[u8; 32]> {
    let mut rust_args = HashMap::new();
    for (key, value) in args.iter() {
        let field: String = key.extract()?;
        let cv = py_to_constraint_value(&value)?;
        rust_args.insert(field, cv);
    }

    let warrant_id = warrant.inner.id().to_string();
    Ok(compute_request_hash(
        &warrant_id,
        tool,
        &rust_args,
        Some(warrant.inner.authorized_holder()),
    ))
}

// ============================================================================
// Authorizer
// ============================================================================

/// Python wrapper for Authorizer.
///
/// Example:
/// ```text
///     # Create with explicit trusted roots
///     authorizer = Authorizer(trusted_roots=[key1, key2])
///     
///     # Create with all options
///     authorizer = Authorizer(
///         trusted_roots=[control_plane_key],
///         clock_tolerance_secs=60,
///         pop_window_secs=15,
///         pop_max_windows=4,
///     )
/// ```
#[pyclass(name = "Authorizer")]
pub struct PyAuthorizer {
    inner: RustAuthorizer,
}

#[pymethods]
impl PyAuthorizer {
    /// Create a new authorizer.
    ///
    /// Args:
    ///     trusted_roots: List of trusted root public keys. At least one required.
    ///     clock_tolerance_secs: Clock tolerance in seconds (default: 30)
    ///     pop_window_secs: PoP window size in seconds (default: 30)
    ///     pop_max_windows: Number of PoP windows to accept (default: 4)
    ///
    /// Example:
    /// ```text
    ///     authorizer = Authorizer(trusted_roots=[control_plane_key])
    ///     
    ///     # With custom settings
    ///     authorizer = Authorizer(
    ///         trusted_roots=[key1, key2],
    ///         clock_tolerance_secs=60,
    ///         pop_window_secs=15,
    ///         pop_max_windows=4,
    ///     )
    /// ```
    #[new]
    #[pyo3(signature = (trusted_roots=None, clock_tolerance_secs=30, pop_window_secs=30, pop_max_windows=4))]
    fn new(
        trusted_roots: Option<Vec<PyRef<PyPublicKey>>>,
        clock_tolerance_secs: i64,
        pop_window_secs: i64,
        pop_max_windows: u32,
    ) -> PyResult<Self> {
        let mut authorizer = RustAuthorizer::new()
            .with_clock_tolerance(chrono::Duration::seconds(clock_tolerance_secs))
            .with_pop_window(pop_window_secs, pop_max_windows);

        if let Some(roots) = trusted_roots {
            for key in roots {
                authorizer = authorizer.with_trusted_root(key.inner.clone());
            }
        }

        Ok(Self { inner: authorizer })
    }

    // =========================================================================
    // Mutable setters (for adding after construction)
    // =========================================================================

    /// Add a trusted root public key.
    ///
    /// Args:
    ///     key: The public key to trust
    fn add_trusted_root(&mut self, key: &PyPublicKey) {
        self.inner.add_trusted_root(key.inner.clone());
    }

    /// Set the clock tolerance for expiration checks.
    ///
    /// Args:
    ///     seconds: Clock tolerance in seconds
    fn set_clock_tolerance(&mut self, seconds: i64) {
        self.inner
            .set_clock_tolerance(chrono::Duration::seconds(seconds));
    }

    /// Set the PoP window configuration.
    ///
    /// Args:
    ///     window_secs: Size of each time window
    ///     max_windows: Number of windows to accept
    fn set_pop_window(&mut self, window_secs: i64, max_windows: u32) {
        self.inner.set_pop_window(window_secs, max_windows);
    }

    /// Set minimum clearance required for a tool.
    ///
    /// This is **gateway-level policy** for defense in depth. Even if a warrant
    /// has the tool in its capabilities, authorization will fail if the warrant's
    /// clearance is below the requirement.
    ///
    /// Args:
    ///     tool_pattern: Tool name or pattern. Supports:
    ///         - Exact match: "delete_database"
    ///         - Prefix pattern: "admin_*" (matches admin_users, admin_config)
    ///         - Default: "*" (applies to all tools without specific rules)
    ///     level: Minimum Clearance required
    ///
    /// Raises:
    ///     ValueError: If the pattern is invalid (e.g., "**", "*admin*")
    ///
    /// Example:
    ///     ```text
    ///     authorizer = Authorizer(trusted_roots=[root_key])
    ///     authorizer.require_clearance("*", Clearance.EXTERNAL)  # Default baseline
    ///     authorizer.require_clearance("delete_*", Clearance.PRIVILEGED)
    ///     authorizer.require_clearance("admin_reset", Clearance.SYSTEM)
    ///     ```
    fn require_clearance(&mut self, tool: String, level: &PyClearance) -> PyResult<()> {
        self.inner
            .require_clearance(&tool, level.inner)
            .map_err(to_py_err)
    }

    /// Get the required clearance for a tool.
    ///
    /// Args:
    ///     tool: Tool name to check
    ///
    /// Returns:
    ///     Clearance if a requirement is configured, None otherwise
    ///
    /// Lookup precedence: Exact match → Glob pattern → Default "*" → None
    fn get_required_clearance(&self, tool: String) -> Option<PyClearance> {
        self.inner
            .get_required_clearance(&tool)
            .map(|tl| PyClearance { inner: tl })
    }

    // =========================================================================
    // Getters
    // =========================================================================

    /// Get the current PoP window configuration.
    ///
    /// Returns:
    ///     Tuple of (window_secs, max_windows)
    fn pop_window_config(&self) -> (i64, u32) {
        self.inner.pop_window_config()
    }

    /// Get the total PoP validity duration in seconds.
    fn pop_validity_secs(&self) -> i64 {
        self.inner.pop_validity_secs()
    }

    /// Get the number of trusted roots.
    fn trusted_root_count(&self) -> usize {
        self.inner.trusted_root_count()
    }

    /// Verify a warrant (checks signature, expiration, revocation).
    fn verify(&self, warrant: &PyWarrant) -> PyResult<()> {
        self.inner.verify(&warrant.inner).map_err(to_py_err)
    }

    /// Authorize an action against a warrant.
    ///
    /// Args:
    ///     warrant: The warrant to check
    ///     tool: Tool name being invoked
    ///     args: Dictionary of argument name -> value
    ///     signature: Optional PoP signature bytes (64 bytes)
    ///     approvals: Optional list of Approval objects (for multi-sig warrants)
    ///
    /// Returns:
    ///     None on success, raises exception on failure
    ///
    /// Example (Python):
    /// - Simple: `authorizer.authorize(warrant, "search", {"query": "test"}, signature)`
    /// - With multi-sig: `authorizer.authorize(warrant, tool, args, signature, [approval1, approval2])`
    #[pyo3(signature = (warrant, tool, args, signature=None, approvals=None))]
    fn authorize(
        &self,
        warrant: &PyWarrant,
        tool: &str,
        args: &Bound<'_, PyDict>,
        signature: Option<&[u8]>,
        approvals: Option<Vec<PyRef<PyApproval>>>,
    ) -> PyResult<()> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        let sig = match signature {
            Some(bytes) => {
                let arr: [u8; 64] = bytes
                    .try_into()
                    .map_err(|_| PyValueError::new_err("signature must be exactly 64 bytes"))?;
                Some(RustSignature::from_bytes(&arr).map_err(to_py_err)?)
            }
            None => None,
        };

        // Convert approvals
        let rust_approvals: Vec<RustApproval> = approvals
            .unwrap_or_default()
            .iter()
            .map(|a| a.inner.clone())
            .collect();

        self.inner
            .authorize(
                &warrant.inner,
                tool,
                &rust_args,
                sig.as_ref(),
                &rust_approvals,
            )
            .map_err(to_py_err)
    }

    /// Convenience: verify warrant and authorize in one call.
    ///
    /// Args:
    ///     warrant: The warrant to check
    ///     tool: Tool name being invoked
    ///     args: Dictionary of argument name -> value
    ///     signature: Optional PoP signature bytes (64 bytes)
    ///     approvals: Optional list of Approval objects (for multi-sig warrants)
    #[pyo3(signature = (warrant, tool, args, signature=None, approvals=None))]
    fn check(
        &self,
        warrant: &PyWarrant,
        tool: &str,
        args: &Bound<'_, PyDict>,
        signature: Option<&[u8]>,
        approvals: Option<Vec<PyRef<PyApproval>>>,
    ) -> PyResult<()> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        let sig = match signature {
            Some(bytes) => {
                let arr: [u8; 64] = bytes
                    .try_into()
                    .map_err(|_| PyValueError::new_err("signature must be exactly 64 bytes"))?;
                Some(RustSignature::from_bytes(&arr).map_err(to_py_err)?)
            }
            None => None,
        };

        // Convert approvals
        let rust_approvals: Vec<RustApproval> = approvals
            .unwrap_or_default()
            .iter()
            .map(|a| a.inner.clone())
            .collect();

        self.inner
            .check(
                &warrant.inner,
                tool,
                &rust_args,
                sig.as_ref(),
                &rust_approvals,
            )
            .map_err(to_py_err)
    }

    /// Verify a complete delegation chain.
    ///
    /// This is the most thorough verification method, validating the entire
    /// path from a trusted root to the leaf warrant.
    ///
    /// Args:
    ///     chain: Ordered list of warrants from root (index 0) to leaf (last)
    ///
    /// Returns:
    ///     ChainVerificationResult on success, raises exception on failure
    ///
    /// Chain Invariants Verified:
    ///     1. Root Trust: chain[0] must be signed by a trusted issuer
    ///     2. Linkage: chain[i+1].parent_id == chain[i].id
    ///     3. Depth: chain[i+1].depth == chain[i].depth + 1
    ///     4. Expiration: chain[i+1].expires_at <= chain[i].expires_at
    ///     5. Monotonicity: chain[i+1].constraints ⊆ chain[i].constraints
    ///     6. Signatures: Each warrant has a valid signature
    ///     7. No Cycles: Each warrant ID appears exactly once
    fn verify_chain(&self, chain: &Bound<'_, PySequence>) -> PyResult<PyChainVerificationResult> {
        let len = chain.len()?;
        if len == 0 {
            return Err(PyValueError::new_err("chain cannot be empty"));
        }

        let mut warrants = Vec::with_capacity(len);
        for i in 0..len {
            let item = chain.get_item(i)?;
            let warrant_bound = item.downcast::<PyWarrant>()?;
            let warrant = warrant_bound.borrow();
            warrants.push(warrant.inner.clone());
        }

        let result = self.inner.verify_chain(&warrants).map_err(to_py_err)?;
        Ok(PyChainVerificationResult { inner: result })
    }

    /// Verify chain and authorize an action.
    ///
    /// Convenience method combining chain verification and authorization
    /// against the leaf warrant.
    ///
    /// Args:
    ///     chain: Ordered list of warrants from root to leaf
    ///     tool: Tool name being invoked
    ///     args: Dictionary of argument name -> value
    ///     signature: Optional PoP signature bytes (64 bytes)
    ///
    /// Returns:
    ///     ChainVerificationResult on success, raises exception on failure
    #[pyo3(signature = (chain, tool, args, signature=None))]
    fn check_chain(
        &self,
        chain: &Bound<'_, PySequence>,
        tool: &str,
        args: &Bound<'_, PyDict>,
        signature: Option<&[u8]>,
    ) -> PyResult<PyChainVerificationResult> {
        let len = chain.len()?;
        if len == 0 {
            return Err(PyValueError::new_err("chain cannot be empty"));
        }

        let mut warrants = Vec::with_capacity(len);
        for i in 0..len {
            let item = chain.get_item(i)?;
            let warrant_bound = item.downcast::<PyWarrant>()?;
            let warrant = warrant_bound.borrow();
            warrants.push(warrant.inner.clone());
        }

        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        let sig = match signature {
            Some(bytes) => {
                let arr: [u8; 64] = bytes
                    .try_into()
                    .map_err(|_| PyValueError::new_err("signature must be exactly 64 bytes"))?;
                Some(RustSignature::from_bytes(&arr).map_err(to_py_err)?)
            }
            None => None,
        };

        let result = self
            .inner
            .check_chain(&warrants, tool, &rust_args, sig.as_ref(), &[])
            .map_err(to_py_err)?;
        Ok(PyChainVerificationResult { inner: result })
    }
}

// ============================================================================
// Revocation System Python Bindings
// ============================================================================

/// Python wrapper for RevocationRequest.
///
/// A signed request to revoke a warrant. Can be submitted to Control Plane.
///
/// Example:
///     request = RevocationRequest.new(
///         warrant_id="tnu_wrt_...",
///         reason="Key compromise detected",
///         requestor_keypair=keypair,
///     )
///     # Submit to Control Plane
///     bytes = request.to_bytes()
#[pyclass(name = "RevocationRequest")]
#[derive(Clone)]
pub struct PyRevocationRequest {
    inner: crate::revocation::RevocationRequest,
}

#[pymethods]
impl PyRevocationRequest {
    /// Create a new revocation request.
    ///
    /// Args:
    ///     warrant_id: The ID of the warrant to revoke
    ///     reason: Human-readable reason for revocation
    ///     requestor_keypair: Keypair to sign the request
    ///
    /// Returns:
    ///     A signed RevocationRequest
    #[staticmethod]
    fn new(warrant_id: &str, reason: &str, requestor_keypair: &PySigningKey) -> PyResult<Self> {
        let inner =
            crate::revocation::RevocationRequest::new(warrant_id, reason, &requestor_keypair.inner)
                .map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Verify the request signature.
    fn verify_signature(&self) -> PyResult<()> {
        self.inner.verify_signature().map_err(to_py_err)
    }

    /// The warrant ID being revoked.
    #[getter]
    fn warrant_id(&self) -> &str {
        &self.inner.warrant_id
    }

    /// The reason for revocation.
    #[getter]
    fn reason(&self) -> &str {
        &self.inner.reason
    }

    /// The public key of the requestor.
    #[getter]
    fn requestor(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.requestor.clone(),
        }
    }

    /// When the request was created (ISO 8601).
    #[getter]
    fn requested_at(&self) -> String {
        self.inner.requested_at.to_rfc3339()
    }

    /// Serialize to bytes (CBOR).
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    /// Deserialize from bytes.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let inner = crate::revocation::RevocationRequest::from_bytes(bytes).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        format!(
            "RevocationRequest(warrant_id='{}', reason='{}', requestor={})",
            self.inner.warrant_id,
            self.inner.reason,
            hex::encode(self.inner.requestor.to_bytes())
        )
    }
}

/// Python wrapper for SignedRevocationList (SRL).
///
/// A cryptographically signed list of revoked warrant IDs.
///
/// Example (Python):
/// ```text
///     # Build a new SRL
///     srl = SignedRevocationList.builder() \
///         .revoke("tnu_wrt_compromised_123") \
///         .revoke("tnu_wrt_expired_456") \
///         .version(42) \
///         .build(control_plane_keypair)
///
///     # Verify before use
///     srl.verify(control_plane_pubkey)
///
///     # Check if a warrant is revoked
///     if srl.is_revoked(warrant.id):
///         raise WarrantRevokedError()
/// ```
#[pyclass(name = "SignedRevocationList")]
#[derive(Clone)]
pub struct PySignedRevocationList {
    inner: crate::revocation::SignedRevocationList,
}

#[pymethods]
impl PySignedRevocationList {
    /// Create a builder for constructing an SRL.
    #[staticmethod]
    fn builder() -> PySrlBuilder {
        PySrlBuilder {
            inner: crate::revocation::SignedRevocationList::builder(),
        }
    }

    /// Create an empty SRL (for initialization).
    #[staticmethod]
    fn empty(keypair: &PySigningKey) -> PyResult<Self> {
        let inner =
            crate::revocation::SignedRevocationList::empty(&keypair.inner).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Verify this SRL was signed by the expected issuer.
    fn verify(&self, expected_issuer: &PyPublicKey) -> PyResult<()> {
        self.inner.verify(&expected_issuer.inner).map_err(to_py_err)
    }

    /// Check if a warrant ID is in this revocation list.
    fn is_revoked(&self, warrant_id: &str) -> bool {
        self.inner.is_revoked(warrant_id)
    }

    /// Get the version number.
    #[getter]
    fn version(&self) -> u64 {
        self.inner.version()
    }

    /// When this list was issued (ISO 8601).
    #[getter]
    fn issued_at(&self) -> String {
        self.inner.issued_at().to_rfc3339()
    }

    /// The issuer's public key.
    #[getter]
    fn issuer(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.issuer().clone(),
        }
    }

    /// List of revoked warrant IDs.
    #[getter]
    fn revoked_ids(&self) -> Vec<String> {
        self.inner.revoked_ids().to_vec()
    }

    /// Number of revoked warrants.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Serialize to bytes (CBOR).
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    /// Deserialize from bytes.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let inner =
            crate::revocation::SignedRevocationList::from_bytes(bytes).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        format!(
            "SignedRevocationList(version={}, count={}, issuer={})",
            self.inner.version(),
            self.inner.len(),
            hex::encode(self.inner.issuer().to_bytes())
        )
    }
}

/// Builder for creating SignedRevocationLists.
#[pyclass(name = "SrlBuilder")]
pub struct PySrlBuilder {
    inner: crate::revocation::SrlBuilder,
}

#[pymethods]
impl PySrlBuilder {
    /// Add a warrant ID to revoke.
    ///
    /// Returns self for chaining.
    fn revoke(&mut self, warrant_id: &str) {
        self.inner = std::mem::take(&mut self.inner).revoke(warrant_id);
    }

    /// Add multiple warrant IDs to revoke.
    ///
    /// Returns self for chaining.
    fn revoke_all(&mut self, ids: Vec<String>) {
        self.inner = std::mem::take(&mut self.inner).revoke_all(ids);
    }

    /// Set the version number (must be monotonically increasing).
    ///
    /// Returns self for chaining.
    fn version(&mut self, version: u64) {
        self.inner = std::mem::take(&mut self.inner).version(version);
    }

    /// Import entries from an existing SRL.
    ///
    /// Returns self for chaining.
    #[allow(clippy::wrong_self_convention)]
    fn from_existing(&mut self, existing: &PySignedRevocationList) {
        self.inner = std::mem::take(&mut self.inner).from_existing(&existing.inner);
    }

    /// Build and sign the revocation list.
    fn build(&mut self, keypair: &PySigningKey) -> PyResult<PySignedRevocationList> {
        let builder = std::mem::take(&mut self.inner);
        let inner = builder.build(&keypair.inner).map_err(to_py_err)?;
        Ok(PySignedRevocationList { inner })
    }
}

/// Tenuo Python module.
///
/// This function is public so it can be called from tenuo-python package.
pub fn tenuo_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyWarrantType>()?;
    m.add_class::<PyClearance>()?;
    m.add_class::<PyPattern>()?;
    m.add_class::<PyExact>()?;
    m.add_class::<PyOneOf>()?;
    m.add_class::<PyRange>()?;
    m.add_class::<PyCidr>()?;
    m.add_class::<PyUrlPattern>()?;
    m.add_class::<PyRegex>()?;
    m.add_class::<PyWildcard>()?;
    m.add_class::<PySubpath>()?;
    m.add_class::<PyUrlSafe>()?;
    m.add_class::<PyCel>()?;
    m.add_class::<PyNotOneOf>()?;
    m.add_class::<PyContains>()?;
    m.add_class::<PySubset>()?;
    m.add_class::<PyAll>()?;
    m.add_class::<PyAnyOf>()?;
    m.add_class::<PyNot>()?;
    // Core types
    m.add_class::<PySigningKey>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PySignature>()?;
    m.add_class::<PyWarrant>()?;
    m.add_class::<PyAttenuationBuilder>()?;
    m.add_class::<PyIssuanceBuilder>()?;
    // Diff types
    m.add_class::<PyChangeType>()?;
    m.add_class::<PyToolsDiff>()?;
    m.add_class::<PyConstraintDiff>()?;
    m.add_class::<PyTtlDiff>()?;
    m.add_class::<PyClearanceDiff>()?;
    m.add_class::<PyDepthDiff>()?;
    m.add_class::<PyDelegationDiff>()?;
    m.add_class::<PyDelegationReceipt>()?;
    m.add_class::<PyWarrantType>()?;
    m.add_class::<PyMcpConfig>()?;
    m.add_class::<PyCompiledMcpConfig>()?;
    m.add_class::<PyAuthorizer>()?;
    m.add_class::<PyChainStep>()?;
    m.add_class::<PyChainVerificationResult>()?;
    m.add_class::<PyExtractionResult>()?;
    // Multi-sig
    m.add_class::<PyApproval>()?;
    // Revocation
    m.add_class::<PyRevocationRequest>()?;
    m.add_class::<PySignedRevocationList>()?;
    m.add_class::<PySrlBuilder>()?;

    // Constants
    m.add("MAX_DELEGATION_DEPTH", crate::MAX_DELEGATION_DEPTH)?;
    m.add("MAX_WARRANT_SIZE", crate::MAX_WARRANT_SIZE)?;
    m.add("MAX_WARRANT_TTL_SECS", crate::MAX_WARRANT_TTL_SECS)?;
    m.add("DEFAULT_WARRANT_TTL_SECS", crate::DEFAULT_WARRANT_TTL_SECS)?;
    m.add("WIRE_VERSION", crate::WIRE_VERSION)?;
    m.add("WARRANT_HEADER", wire::WARRANT_HEADER)?;

    // Functions
    m.add_function(wrap_pyfunction!(py_compute_diff, m)?)?;
    m.add_function(wrap_pyfunction!(py_decode_warrant_stack_base64, m)?)?;
    m.add_function(wrap_pyfunction!(py_compute_approval_hash, m)?)?;

    Ok(())
}

/// Decode a warrant stack from base64 or PEM format.
///
/// Returns a list of warrants in the stack (from root to leaf).
#[pyfunction(name = "decode_warrant_stack_base64")]
fn py_decode_warrant_stack_base64(s: &str) -> PyResult<Vec<PyWarrant>> {
    use crate::wire;
    let stack = wire::decode_pem_chain(s).map_err(to_py_err)?;
    Ok(stack
        .0
        .into_iter()
        .map(|w| PyWarrant { inner: w })
        .collect())
}

/// Compute diff between two warrants.
#[pyfunction(name = "compute_diff")]
fn py_compute_diff(parent: &PyWarrant, child: &PyWarrant) -> PyDelegationDiff {
    PyDelegationDiff {
        inner: crate::diff::compute_diff(&parent.inner, &child.inner),
    }
}
