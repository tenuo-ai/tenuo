//! Python bindings for Tenuo via PyO3.
//!
//! This module provides Python-friendly wrappers around the core Rust types.

// PyO3 macros generate code that triggers false positive clippy warnings
#![allow(clippy::useless_conversion)]

use crate::constraints::{
    All, Any, CelConstraint, Constraint, ConstraintValue, Contains, Exact, Not, NotOneOf, OneOf,
    Pattern, Range, RegexConstraint, Subset, Wildcard,
};
use crate::crypto::{
    Keypair as RustKeypair, PublicKey as RustPublicKey, Signature as RustSignature,
};
use crate::diff::{
    ChangeType as RustChangeType, ConstraintDiff as RustConstraintDiff,
    DelegationDiff as RustDelegationDiff, DelegationReceipt as RustDelegationReceipt,
    DepthDiff as RustDepthDiff, ToolsDiff as RustToolsDiff, TrustDiff as RustTrustDiff,
    TtlDiff as RustTtlDiff,
};
use crate::mcp::{CompiledMcpConfig, McpConfig};
use crate::planes::{
    Authorizer as RustAuthorizer, ChainStep as RustChainStep,
    ChainVerificationResult as RustChainVerificationResult,
};
use crate::warrant::{
    OwnedAttenuationBuilder, OwnedIssuanceBuilder, TrustLevel, Warrant as RustWarrant, WarrantType,
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
    fn new(min: Option<f64>, max: Option<f64>) -> Self {
        Self {
            inner: Range::new(min, max),
        }
    }

    #[staticmethod]
    fn max_value(max: f64) -> Self {
        Self {
            inner: Range::max(max),
        }
    }

    #[staticmethod]
    fn min_value(min: f64) -> Self {
        Self {
            inner: Range::min(min),
        }
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

    fn __repr__(&self) -> String {
        format!("CEL('{}')", self.inner.expression)
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

    fn __repr__(&self) -> String {
        format!("Regex('{}')", self.inner.pattern)
    }

    #[getter]
    fn pattern(&self) -> String {
        self.inner.pattern.clone()
    }
}

/// Python wrapper for Wildcard constraint.
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

    fn __repr__(&self) -> String {
        "Wildcard()".to_string()
    }
}

/// Python wrapper for Keypair.
#[pyclass(name = "Keypair")]
pub struct PyKeypair {
    inner: RustKeypair,
}

#[pymethods]
impl PyKeypair {
    #[new]
    fn new() -> Self {
        Self {
            inner: RustKeypair::generate(),
        }
    }

    #[staticmethod]
    fn generate() -> Self {
        Self {
            inner: RustKeypair::generate(),
        }
    }

    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("secret key must be exactly 32 bytes"))?;
        Ok(Self {
            inner: RustKeypair::from_bytes(&arr),
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
    /// - Minimize the lifetime of Keypair objects
    /// - Avoid storing the returned bytes in long-lived variables
    /// - Consider using Rust directly for production key management
    ///
    /// For most use cases, you should not need to access the secret key bytes directly.
    /// Use the Keypair object for signing operations instead.
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

    /// Create a Keypair from a PEM string.
    #[staticmethod]
    fn from_pem(pem: &str) -> PyResult<Self> {
        let inner = RustKeypair::from_pem(pem).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Convert the Keypair to a PEM string.
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
        Constraint::Range(r) =>
        {
            #[allow(deprecated)]
            Ok(PyRange { inner: r.clone() }.into_py(py))
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
    } else {
        Err(PyValueError::new_err(
            "constraint must be Pattern, Exact, OneOf, NotOneOf, Range, Contains, Subset, All, AnyOf, Not, CEL, Regex, or Wildcard",
        ))
    }
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
}

/// Python enum for TrustLevel.
#[pyclass(name = "TrustLevel")]
#[derive(Clone, Copy)]
pub struct PyTrustLevel {
    inner: TrustLevel,
}

#[pymethods]
impl PyTrustLevel {
    #[new]
    fn new(level: &str) -> PyResult<Self> {
        let inner = level
            .parse()
            .map_err(|e: String| PyValueError::new_err(e))?;
        Ok(Self { inner })
    }

    #[classattr]
    #[allow(non_snake_case)]
    fn Untrusted() -> Self {
        Self {
            inner: TrustLevel::Untrusted,
        }
    }

    #[classattr]
    #[allow(non_snake_case)]
    fn External() -> Self {
        Self {
            inner: TrustLevel::External,
        }
    }

    #[classattr]
    #[allow(non_snake_case)]
    fn Partner() -> Self {
        Self {
            inner: TrustLevel::Partner,
        }
    }

    #[classattr]
    #[allow(non_snake_case)]
    fn Internal() -> Self {
        Self {
            inner: TrustLevel::Internal,
        }
    }

    #[classattr]
    #[allow(non_snake_case)]
    fn Privileged() -> Self {
        Self {
            inner: TrustLevel::Privileged,
        }
    }

    #[classattr]
    #[allow(non_snake_case)]
    fn System() -> Self {
        Self {
            inner: TrustLevel::System,
        }
    }

    /// Get the numeric value of the trust level.
    fn value(&self) -> u8 {
        self.inner as u8
    }

    /// Compare trust levels numerically.
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
        format!("TrustLevel.{:?}", self.inner)
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

/// Python wrapper for TrustDiff.
#[pyclass(name = "TrustDiff")]
#[derive(Clone)]
pub struct PyTrustDiff {
    inner: RustTrustDiff,
}

#[pymethods]
impl PyTrustDiff {
    #[getter]
    fn parent_trust(&self) -> Option<PyTrustLevel> {
        self.inner.parent_trust.map(|t| PyTrustLevel { inner: t })
    }

    #[getter]
    fn child_trust(&self) -> Option<PyTrustLevel> {
        self.inner.child_trust.map(|t| PyTrustLevel { inner: t })
    }

    #[getter]
    fn change(&self) -> PyChangeType {
        PyChangeType {
            inner: self.inner.change,
        }
    }

    fn __repr__(&self) -> String {
        format!("TrustDiff(change={})", self.inner.change.as_str())
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
    fn constraints<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (field, diff) in &self.inner.constraints {
            let py_diff = PyConstraintDiff {
                inner: diff.clone(),
            };
            dict.set_item(field, py_diff.into_pyobject(py)?)?;
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
    fn trust(&self) -> PyTrustDiff {
        PyTrustDiff {
            inner: self.inner.trust.clone(),
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
    fn constraints<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (field, diff) in &self.inner.constraints {
            let py_diff = PyConstraintDiff {
                inner: diff.clone(),
            };
            dict.set_item(field, py_diff.into_pyobject(py)?)?;
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
    fn trust(&self) -> PyTrustDiff {
        PyTrustDiff {
            inner: self.inner.trust.clone(),
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
    /// Add or override a constraint.
    fn with_constraint(&mut self, field: &str, constraint: &Bound<'_, PyAny>) -> PyResult<()> {
        let constraint = py_to_constraint(constraint)?;
        self.inner.set_constraint(field, constraint);
        Ok(())
    }

    /// Set a shorter TTL in seconds.
    fn with_ttl(&mut self, seconds: u64) {
        self.inner.set_ttl(Duration::from_secs(seconds));
    }

    /// Set the authorized holder for the child warrant.
    fn with_holder(&mut self, holder: &PyPublicKey) {
        self.inner.set_authorized_holder(holder.inner.clone());
    }

    /// Set the trust level for the child warrant.
    fn with_trust_level(&mut self, level: &PyTrustLevel) {
        self.inner.set_trust_level(level.inner);
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
        self.inner.set_exec_tool(tool);
    }

    /// Narrow execution warrant tools to a subset.
    ///
    /// All tools must be in the parent warrant's tools.
    fn with_tools(&mut self, tools: Vec<String>) {
        self.inner.set_exec_tools(tools);
    }

    /// Set a single tool for issuable_tools (for issuer warrants).
    ///
    /// This replaces the entire issuable_tools list with a single tool.
    /// For multiple tools, use `with_issuable_tools()` instead.
    fn with_issuable_tool(&mut self, tool: &str) {
        self.inner.set_tool(tool);
    }

    /// Set multiple tools for issuable_tools (for issuer warrants).
    ///
    /// This replaces the entire issuable_tools list.
    fn with_issuable_tools(&mut self, tools: Vec<String>) {
        self.inner.set_tools(tools);
    }

    /// Drop tools from issuable_tools (for issuer warrants).
    fn drop_tools(&mut self, tools: Vec<String>) {
        self.inner.drop_tools(tools);
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

    /// Get the configured trust level.
    #[getter]
    fn trust_level(&self) -> Option<PyTrustLevel> {
        self.inner
            .trust_level()
            .map(|tl| PyTrustLevel { inner: tl })
    }

    /// Get the configured intent.
    #[getter]
    fn intent(&self) -> Option<String> {
        self.inner.intent().map(|s| s.to_string())
    }

    /// Get the constraints being configured as a Python dict.
    fn constraints_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (field, constraint) in self.inner.constraints().iter() {
            let py_constraint = constraint_to_py(py, constraint)?;
            dict.set_item(field, py_constraint)?;
        }
        Ok(dict)
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
    /// # Arguments
    ///
    /// * `keypair` - The keypair of the delegator
    /// * `parent_keypair` - The keypair that signed the parent warrant
    fn delegate_to(&self, keypair: &PyKeypair, parent_keypair: &PyKeypair) -> PyResult<PyWarrant> {
        let warrant = self
            .inner
            .clone()
            .build(&keypair.inner, &parent_keypair.inner)
            .map_err(to_py_err)?;
        Ok(PyWarrant { inner: warrant })
    }

    /// Build and return both warrant and receipt.
    ///
    /// This is a convenience method for workflows that need the receipt immediately.
    fn delegate_to_with_receipt(
        &self,
        keypair: &PyKeypair,
        parent_keypair: &PyKeypair,
    ) -> PyResult<(PyWarrant, PyDelegationReceipt)> {
        let (warrant, receipt) = self
            .inner
            .clone()
            .build_with_receipt(&keypair.inner, &parent_keypair.inner)
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
            self.inner.holder().is_some()
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
    /// Set the tool name for the execution warrant.
    fn with_tool(&mut self, tool: &str) {
        self.inner.set_tool(tool);
    }

    /// Set multiple tools for the execution warrant.
    fn with_tools(&mut self, tools: Vec<String>) {
        self.inner.set_tools(tools);
    }

    /// Add or override a constraint.
    fn with_constraint(&mut self, field: &str, constraint: &Bound<'_, PyAny>) -> PyResult<()> {
        let constraint = py_to_constraint(constraint)?;
        self.inner.set_constraint(field, constraint);
        Ok(())
    }

    /// Set the trust level for the execution warrant.
    fn with_trust_level(&mut self, level: &PyTrustLevel) {
        self.inner.set_trust_level(level.inner);
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
        self.inner.set_authorized_holder(holder.inner.clone());
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
        self.inner.tools().map(|t| t.to_vec())
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

    /// Get the configured trust level.
    #[getter]
    fn trust_level(&self) -> Option<PyTrustLevel> {
        self.inner
            .trust_level()
            .map(|tl| PyTrustLevel { inner: tl })
    }

    /// Get the configured intent.
    #[getter]
    fn intent(&self) -> Option<String> {
        self.inner.intent().map(|s| s.to_string())
    }

    /// Get the constraints being configured as a Python dict.
    fn constraints_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (field, constraint) in self.inner.constraints().iter() {
            let py_constraint = constraint_to_py(py, constraint)?;
            dict.set_item(field, py_constraint)?;
        }
        Ok(dict)
    }

    /// Build and sign the execution warrant.
    ///
    /// # Arguments
    ///
    /// * `keypair` - The keypair of the issuer warrant holder
    /// * `issuer_keypair` - The keypair that signed the issuer warrant
    fn build(&self, keypair: &PyKeypair, issuer_keypair: &PyKeypair) -> PyResult<PyWarrant> {
        let warrant = self
            .inner
            .clone()
            .build(&keypair.inner, &issuer_keypair.inner)
            .map_err(to_py_err)?;
        Ok(PyWarrant { inner: warrant })
    }

    fn __repr__(&self) -> String {
        format!(
            "IssuanceBuilder(issuer={}, tools={:?}, holder={:?})",
            self.inner.issuer().id(),
            self.inner.tools(),
            self.inner.holder().is_some()
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
    /// Issue a new warrant.
    #[staticmethod]
    #[pyo3(signature = (tools, keypair, constraints=None, ttl_seconds=3600, holder=None, session_id=None, trust_level=None))]
    fn issue(
        tools: &Bound<'_, PyAny>,
        keypair: &PyKeypair,
        constraints: Option<&Bound<'_, PyDict>>,
        ttl_seconds: u64,
        holder: Option<&PyPublicKey>,
        session_id: Option<&str>,
        trust_level: Option<&PyTrustLevel>,
    ) -> PyResult<Self> {
        let mut builder = RustWarrant::builder().ttl(Duration::from_secs(ttl_seconds));

        if let Ok(tool_str) = tools.extract::<String>() {
            builder = builder.tool(tool_str);
        } else if let Ok(tools_list) = tools.extract::<Vec<String>>() {
            builder = builder.tools(tools_list);
        } else {
            return Err(PyValueError::new_err(
                "tools must be a string or list of strings",
            ));
        }

        // Set trust level if provided
        if let Some(tl) = trust_level {
            builder = builder.trust_level(tl.inner);
        }

        // If holder is provided, use it. Otherwise, default to the issuer (self-signed).
        if let Some(h) = holder {
            builder = builder.authorized_holder(h.inner.clone());
        } else {
            builder = builder.authorized_holder(keypair.inner.public_key());
        }

        if let Some(sid) = session_id {
            builder = builder.session_id(sid);
        }

        if let Some(constraints_dict) = constraints {
            for (key, value) in constraints_dict.iter() {
                let field: String = key.extract()?;
                let constraint = py_to_constraint(&value)?;
                builder = builder.constraint(field, constraint);
            }
        }

        let warrant = builder.build(&keypair.inner).map_err(to_py_err)?;
        Ok(Self { inner: warrant })
    }

    /// Issue a new issuer warrant.
    ///
    /// Issuer warrants can issue execution warrants but cannot execute tools themselves.
    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (issuable_tools, trust_ceiling, keypair, constraint_bounds=None, max_issue_depth=None, ttl_seconds=3600, holder=None, session_id=None, trust_level=None))]
    fn issue_issuer(
        issuable_tools: Vec<String>,
        trust_ceiling: &PyTrustLevel,
        keypair: &PyKeypair,
        constraint_bounds: Option<&Bound<'_, PyDict>>,
        max_issue_depth: Option<u32>,
        ttl_seconds: u64,
        holder: Option<&PyPublicKey>,
        session_id: Option<&str>,
        trust_level: Option<&PyTrustLevel>,
    ) -> PyResult<Self> {
        let mut builder = RustWarrant::builder()
            .r#type(WarrantType::Issuer)
            .issuable_tools(issuable_tools)
            .trust_ceiling(trust_ceiling.inner)
            .ttl(Duration::from_secs(ttl_seconds));

        if let Some(depth) = max_issue_depth {
            builder = builder.max_issue_depth(depth);
        }

        // Set trust level if provided
        if let Some(tl) = trust_level {
            builder = builder.trust_level(tl.inner);
        }

        // If holder is provided, use it. Otherwise, default to the issuer (self-signed).
        if let Some(h) = holder {
            builder = builder.authorized_holder(h.inner.clone());
        } else {
            builder = builder.authorized_holder(keypair.inner.public_key());
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

    /// Get the warrant ID.
    #[getter]
    fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Get the tool names.
    #[getter]
    fn tools(&self) -> Option<Vec<String>> {
        self.inner.tools().map(|t| t.to_vec())
    }

    /// Get issuable tools (Issuer warrants only).
    #[getter]
    fn issuable_tools(&self) -> Option<Vec<String>> {
        self.inner.issuable_tools().map(|t| t.to_vec())
    }

    /// Get trust ceiling (Issuer warrants only).
    #[getter]
    fn trust_ceiling(&self) -> Option<PyTrustLevel> {
        self.inner
            .trust_ceiling()
            .map(|t| PyTrustLevel { inner: t })
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

    /// Get the parent warrant ID.
    #[getter]
    fn parent_id(&self) -> Option<String> {
        self.inner.parent_id().map(|id| id.to_string())
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
    fn trust_level(&self) -> Option<PyTrustLevel> {
        self.inner
            .trust_level()
            .map(|tl| PyTrustLevel { inner: tl })
    }

    /// Get the embedded issuer chain (for self-contained verification).
    fn issuer_chain(&self) -> Vec<PyObject> {
        // Return empty list for now - issuer_chain is complex to expose
        // Chain reconstruction can use parent_id to trace back
        Vec::new()
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

    /// Get constraints as a Python dict.
    ///
    /// Returns None if this is an issuer warrant (which uses constraint_bounds instead).
    fn constraints_dict<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>> {
        if let Some(constraints) = self.inner.constraints() {
            let dict = PyDict::new(py);
            for (field, constraint) in constraints.iter() {
                let py_constraint = constraint_to_py(py, constraint)?;
                dict.set_item(field, py_constraint)?;
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
    /// TTL, holder, etc. before calling `delegate_to()` to create the child warrant.
    ///
    /// # Example
    ///
    /// ```python
    /// builder = parent.attenuate_builder()
    /// builder.with_constraint("path", Exact("/data/q3.pdf"))
    /// builder.with_ttl(60)
    /// builder.with_holder(worker_key)
    /// child = builder.delegate_to(keypair, parent_keypair)
    /// ```
    fn attenuate_builder(&self) -> PyAttenuationBuilder {
        PyAttenuationBuilder {
            inner: OwnedAttenuationBuilder::new(self.inner.clone()),
        }
    }

    /// Attenuate the warrant (create a child with narrower scope).
    #[pyo3(signature = (constraints, keypair, parent_keypair, ttl_seconds=None, holder=None, trust_level=None))]
    fn attenuate(
        &self,
        constraints: &Bound<'_, PyDict>,
        keypair: &PyKeypair,
        parent_keypair: &PyKeypair,
        ttl_seconds: Option<u64>,
        holder: Option<&PyPublicKey>,
        trust_level: Option<&PyTrustLevel>,
    ) -> PyResult<PyWarrant> {
        let mut builder = self.inner.attenuate();

        if let Some(ttl) = ttl_seconds {
            builder = builder.ttl(Duration::from_secs(ttl));
        }

        if let Some(h) = holder {
            builder = builder.authorized_holder(h.inner.clone());
        }

        // Note: TrustLevel on AttenuationBuilder requires mutable access
        // For the Owned version, we need to use the set_ method
        if trust_level.is_some() {
            // Trust level setting is done via OwnedAttenuationBuilder
            // The reference-based builder doesn't support it directly
            // Users should use attenuate_builder() for trust level changes
        }

        for (field, constraint) in constraints.iter() {
            let field: String = field.extract()?;
            let constraint = py_to_constraint(&constraint)?;
            builder = builder.constraint(field, constraint);
        }

        let warrant = builder
            .build(&keypair.inner, &parent_keypair.inner)
            .map_err(to_py_err)?;
        Ok(PyWarrant { inner: warrant })
    }

    /// Authorize an action against this warrant.
    ///
    /// Args:
    ///     tool: Tool name to authorize
    ///     args: Dictionary of argument name -> value
    ///     signature: Optional signature bytes for Proof-of-Possession (64 bytes)
    ///
    /// Returns:
    ///     True if authorized, False if constraint not satisfied
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

    /// Verify the warrant signature.
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
    ///     keypair: The PyKeypair to sign with
    ///     tool: Tool name being called
    ///     args: Dictionary of argument name -> value
    ///
    /// Returns:
    ///     64-byte signature as bytes
    fn create_pop_signature(
        &self,
        keypair: &PyKeypair,
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
            .create_pop_signature(&keypair.inner, tool, &rust_args)
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
            self.inner
                .tools()
                .map(|t| format!("{:?}", t))
                .unwrap_or_else(|| "None".to_string()),
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
    fn compile(config: &PyMcpConfig) -> Self {
        let compiled = CompiledMcpConfig::compile(config.inner.clone());
        Self {
            inner: Arc::new(compiled),
        }
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
}

#[pymethods]
impl PyExtractionResult {
    fn __repr__(&self) -> String {
        format!(
            "ExtractionResult(tool='{}', constraints={{...}})",
            self.tool
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

/// Python wrapper for Authorizer.
///
/// Example:
/// ```python
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
    /// ```python
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
    ///
    /// Returns:
    ///     None on success, raises exception on failure
    #[pyo3(signature = (warrant, tool, args, signature=None))]
    fn authorize(
        &self,
        warrant: &PyWarrant,
        tool: &str,
        args: &Bound<'_, PyDict>,
        signature: Option<&[u8]>,
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

        self.inner
            .authorize(&warrant.inner, tool, &rust_args, sig.as_ref(), &[])
            .map_err(to_py_err)
    }

    /// Convenience: verify warrant and authorize in one call.
    #[pyo3(signature = (warrant, tool, args, signature=None))]
    fn check(
        &self,
        warrant: &PyWarrant,
        tool: &str,
        args: &Bound<'_, PyDict>,
        signature: Option<&[u8]>,
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

        self.inner
            .check(&warrant.inner, tool, &rust_args, sig.as_ref(), &[])
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

/// Helper to convert ConstraintValue to Python object
fn constraint_value_to_py(py: Python<'_>, cv: &ConstraintValue) -> PyResult<PyObject> {
    #[allow(deprecated)]
    match cv {
        ConstraintValue::String(s) => Ok(s.to_object(py)),
        ConstraintValue::Integer(i) => Ok(i.to_object(py)),
        ConstraintValue::Float(f) => Ok(f.to_object(py)),
        ConstraintValue::Boolean(b) => Ok(b.to_object(py)),
        ConstraintValue::Null => Ok(py.None()),
        ConstraintValue::List(l) => {
            let list = pyo3::types::PyList::empty(py);
            for item in l {
                list.append(constraint_value_to_py(py, item)?)?;
            }
            Ok(list.into())
        }
        ConstraintValue::Object(m) => {
            let dict = PyDict::new(py);
            for (k, v) in m {
                dict.set_item(k, constraint_value_to_py(py, v)?)?;
            }
            Ok(dict.into())
        }
    }
}

/// Tenuo Python module.
///
/// This function is public so it can be called from tenuo-python package.
pub fn tenuo_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyWarrantType>()?;
    m.add_class::<PyTrustLevel>()?;
    m.add_class::<PyPattern>()?;
    m.add_class::<PyExact>()?;
    m.add_class::<PyOneOf>()?;
    m.add_class::<PyRange>()?;
    m.add_class::<PyRegex>()?;
    m.add_class::<PyWildcard>()?;
    m.add_class::<PyCel>()?;
    m.add_class::<PyNotOneOf>()?;
    m.add_class::<PyContains>()?;
    m.add_class::<PySubset>()?;
    m.add_class::<PyAll>()?;
    m.add_class::<PyAnyOf>()?;
    m.add_class::<PyNot>()?;
    // Core types
    m.add_class::<PyKeypair>()?;
    // Add SigningKey as an alias for Keypair
    m.add("SigningKey", m.getattr("Keypair")?)?;
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
    m.add_class::<PyTrustDiff>()?;
    m.add_class::<PyDepthDiff>()?;
    m.add_class::<PyDelegationDiff>()?;
    m.add_class::<PyDelegationReceipt>()?;
    m.add_class::<PyWarrantType>()?;
    m.add_class::<PyTrustLevel>()?;
    m.add_class::<PyMcpConfig>()?;
    m.add_class::<PyCompiledMcpConfig>()?;
    m.add_class::<PyAuthorizer>()?;
    m.add_class::<PyChainStep>()?;
    m.add_class::<PyChainVerificationResult>()?;
    m.add_class::<PyExtractionResult>()?;

    // Constants
    m.add("MAX_DELEGATION_DEPTH", crate::MAX_DELEGATION_DEPTH)?;
    m.add("MAX_ISSUER_CHAIN_LENGTH", crate::MAX_ISSUER_CHAIN_LENGTH)?;
    m.add("MAX_WARRANT_SIZE", crate::MAX_WARRANT_SIZE)?;
    m.add("WIRE_VERSION", crate::WIRE_VERSION)?;
    m.add("WARRANT_HEADER", wire::WARRANT_HEADER)?;

    // Functions
    m.add_function(wrap_pyfunction!(py_compute_diff, m)?)?;

    Ok(())
}

/// Compute diff between two warrants.
#[pyfunction(name = "compute_diff")]
fn py_compute_diff(parent: &PyWarrant, child: &PyWarrant) -> PyDelegationDiff {
    PyDelegationDiff {
        inner: crate::diff::compute_diff(&parent.inner, &child.inner),
    }
}
