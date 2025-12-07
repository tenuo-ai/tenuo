//! Python bindings for Tenuo via PyO3.
//!
//! This module provides Python-friendly wrappers around the core Rust types.

// PyO3 macros generate code that triggers false positive clippy warnings
#![allow(clippy::useless_conversion)]

use crate::constraints::{
    CelConstraint, Constraint, ConstraintValue, Exact, OneOf, Pattern, Range,
};
use crate::crypto::{Keypair as RustKeypair, PublicKey as RustPublicKey, Signature as RustSignature};
use crate::warrant::Warrant as RustWarrant;
use crate::wire;
use crate::mcp::{McpConfig, CompiledMcpConfig};
use crate::planes::Authorizer as RustAuthorizer;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Convert a Tenuo error to a Python exception.
fn to_py_err(e: crate::error::Error) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// Convert a ConfigError to a Python exception.
fn config_err_to_py(e: crate::gateway_config::ConfigError) -> PyErr {
    PyValueError::new_err(e.to_string())
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
    fn public_key(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.public_key(),
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
    } else if let Ok(r) = obj.extract::<PyRange>() {
        Ok(Constraint::Range(r.inner))
    } else if let Ok(c) = obj.extract::<PyCel>() {
        Ok(Constraint::Cel(c.inner))
    } else {
        Err(PyValueError::new_err(
            "constraint must be Pattern, Exact, OneOf, Range, or CEL",
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
    } else {
        Err(PyValueError::new_err("value must be str, int, float, or bool"))
    }
}

/// Python wrapper for Warrant.
#[pyclass(name = "Warrant")]
pub struct PyWarrant {
    inner: RustWarrant,
}

#[pymethods]
impl PyWarrant {
    /// Create a new warrant builder.
    #[staticmethod]
    #[pyo3(signature = (tool, constraints, ttl_seconds, keypair, session_id=None))]
    fn create(
        tool: &str,
        constraints: &Bound<'_, PyDict>,
        ttl_seconds: u64,
        keypair: &PyKeypair,
        session_id: Option<&str>,
    ) -> PyResult<Self> {
        let mut builder = RustWarrant::builder()
            .tool(tool)
            .ttl(Duration::from_secs(ttl_seconds));

        if let Some(sid) = session_id {
            builder = builder.session_id(sid);
        }

        for (key, value) in constraints.iter() {
            let field: String = key.extract()?;
            let constraint = py_to_constraint(&value)?;
            builder = builder.constraint(field, constraint);
        }

        let warrant = builder.build(&keypair.inner).map_err(to_py_err)?;
        Ok(Self { inner: warrant })
    }

    /// Get the warrant ID.
    #[getter]
    fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Get the tool name.
    #[getter]
    fn tool(&self) -> &str {
        self.inner.tool()
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

    /// Check if the warrant has expired.
    fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    /// Attenuate this warrant with additional constraints.
    ///
    /// Note: session_id is immutable and inherited from the parent warrant.
    #[pyo3(signature = (constraints, keypair, ttl_seconds=None))]
    fn attenuate(
        &self,
        constraints: &Bound<'_, PyDict>,
        keypair: &PyKeypair,
        ttl_seconds: Option<u64>,
    ) -> PyResult<PyWarrant> {
        let mut builder = self.inner.attenuate();

        if let Some(ttl) = ttl_seconds {
            builder = builder.ttl(Duration::from_secs(ttl));
        }

        for (key, value) in constraints.iter() {
            let field: String = key.extract()?;
            let constraint = py_to_constraint(&value)?;
            builder = builder.constraint(field, constraint);
        }

        let warrant = builder.build(&keypair.inner).map_err(to_py_err)?;
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
    fn authorize(&self, tool: &str, args: &Bound<'_, PyDict>, signature: Option<&[u8]>) -> PyResult<bool> {
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
    fn create_pop_signature(&self, keypair: &PyKeypair, tool: &str, args: &Bound<'_, PyDict>) -> PyResult<Vec<u8>> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        let sig = self.inner.create_pop_signature(&keypair.inner, tool, &rust_args)
            .map_err(to_py_err)?;
        Ok(sig.to_bytes().to_vec())
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
            "Warrant(id='{}', tool='{}', depth={})",
            self.inner.id(),
            self.inner.tool(),
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
    fn extract_constraints(&self, tool_name: &str, arguments: &Bound<'_, PyDict>) -> PyResult<PyExtractionResult> {
        // Convert Python dict to serde_json::Value
        let py = arguments.py();
        let json_str = {
            let json_mod = py.import_bound("json")?;
            let dumps = json_mod.getattr("dumps")?;
            dumps.call1((arguments,))?.extract::<String>()?
        };
        
        let args_value: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| PyValueError::new_err(format!("Invalid JSON arguments: {}", e)))?;

        // Extract
        let result = self.inner.extract_constraints(tool_name, &args_value)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        // Convert extracted constraints to Python dict
        let dict = PyDict::new_bound(py);
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
        format!("ExtractionResult(tool='{}', constraints={{...}})", self.tool)
    }
}

/// Python wrapper for PublicKey.
#[pyclass(name = "PublicKey")]
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
        format!("PublicKey({:02x}{:02x}{:02x}{:02x}...)", 
                bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// Python wrapper for Authorizer.
#[pyclass(name = "Authorizer")]
pub struct PyAuthorizer {
    inner: RustAuthorizer,
}

#[pymethods]
impl PyAuthorizer {
    #[staticmethod]
    fn new(public_key: &PyPublicKey) -> Self {
        Self {
            inner: RustAuthorizer::new(public_key.inner.clone()),
        }
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

        self.inner.authorize(&warrant.inner, tool, &rust_args, sig.as_ref(), &[])
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

        self.inner.check(&warrant.inner, tool, &rust_args, sig.as_ref(), &[])
            .map_err(to_py_err)
    }
}

/// Helper to convert ConstraintValue to Python object
fn constraint_value_to_py(py: Python<'_>, cv: &ConstraintValue) -> PyResult<PyObject> {
    match cv {
        ConstraintValue::String(s) => Ok(s.into_py(py)),
        ConstraintValue::Integer(i) => Ok(i.into_py(py)),
        ConstraintValue::Float(f) => Ok(f.into_py(py)),
        ConstraintValue::Boolean(b) => Ok(b.into_py(py)),
        ConstraintValue::Null => Ok(py.None()),
        ConstraintValue::List(l) => {
            let list = pyo3::types::PyList::empty_bound(py);
            for item in l {
                list.append(constraint_value_to_py(py, item)?)?;
            }
            Ok(list.into())
        }
        ConstraintValue::Object(m) => {
            let dict = PyDict::new_bound(py);
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
#[pymodule]
pub fn tenuo_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPattern>()?;
    m.add_class::<PyExact>()?;
    m.add_class::<PyOneOf>()?;
    m.add_class::<PyRange>()?;
    m.add_class::<PyCel>()?;
    m.add_class::<PyKeypair>()?;
    m.add_class::<PyWarrant>()?;
    m.add_class::<PyMcpConfig>()?;
    m.add_class::<PyCompiledMcpConfig>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PyAuthorizer>()?;
    m.add_class::<PyExtractionResult>()?;

    // Constants
    m.add("MAX_DELEGATION_DEPTH", crate::MAX_DELEGATION_DEPTH)?;
    m.add("WIRE_VERSION", crate::WIRE_VERSION)?;
    m.add("WARRANT_HEADER", wire::WARRANT_HEADER)?;

    Ok(())
}
