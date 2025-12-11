//! Python bindings for Tenuo via PyO3.
//!
//! This module provides Python-friendly wrappers around the core Rust types.

// PyO3 macros generate code that triggers false positive clippy warnings
#![allow(clippy::useless_conversion)]

use crate::constraints::{
    CelConstraint, Constraint, ConstraintValue, Exact, OneOf, Pattern, Range,
    Wildcard, NotOneOf, RegexConstraint, Contains, Subset, All, Any, Not,
};
use crate::crypto::{Keypair as RustKeypair, PublicKey as RustPublicKey, Signature as RustSignature};
use crate::warrant::Warrant as RustWarrant;
use crate::wire;
use crate::mcp::{McpConfig, CompiledMcpConfig};
use crate::planes::Authorizer as RustAuthorizer;
use crate::approval::{Approval as RustApproval, compute_request_hash};
use crate::revocation::{SignedRevocationList as RustSrl, SrlBuilder as RustSrlBuilder};
use crate::planes::{ChainVerificationResult as RustChainResult, ChainStep as RustChainStep};
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

/// Python wrapper for Wildcard constraint.
/// 
/// Wildcard matches any value. This is the universal superset constraint
/// that can be attenuated to any other constraint type.
/// 
/// Example:
///     # Root warrant: allow any cluster
///     warrant = Warrant.create(
///         tool="manage",
///         constraints={"cluster": Wildcard()},
///         ...
///     )
///     # Child can narrow to specific pattern
///     child = warrant.attenuate(
///         constraints={"cluster": Pattern("staging-*")},
///         ...
///     )
#[pyclass(name = "Wildcard")]
#[derive(Clone)]
pub struct PyWildcard {
    inner: Wildcard,
}

#[pymethods]
impl PyWildcard {
    #[new]
    fn new() -> Self {
        Self {
            inner: Wildcard::new(),
        }
    }

    fn __repr__(&self) -> String {
        "Wildcard()".to_string()
    }
}

/// Python wrapper for NotOneOf constraint (exclusion / "carving holes").
/// 
/// Value must NOT be in the excluded set. Use this to "carve holes" from
/// a broader allowlist defined in a parent warrant.
/// 
/// SECURITY: Never start with negation! Always start with a positive allowlist
/// (Pattern, OneOf, Wildcard) and use NotOneOf in child warrants to exclude.
/// 
/// Example:
///     # Parent: allow all staging clusters
///     parent = Warrant.create(constraints={"cluster": Pattern("staging-*")}, ...)
///     # Child: exclude the database cluster
///     child = parent.attenuate(constraints={"cluster": NotOneOf(["staging-db"])}, ...)
#[pyclass(name = "NotOneOf")]
#[derive(Clone)]
pub struct PyNotOneOf {
    inner: NotOneOf,
}

#[pymethods]
impl PyNotOneOf {
    #[new]
    fn new(excluded: Vec<String>) -> Self {
        Self {
            inner: NotOneOf::new(excluded),
        }
    }

    fn __repr__(&self) -> String {
        format!("NotOneOf({:?})", self.inner.excluded)
    }
}

/// Python wrapper for Regex constraint.
/// 
/// Regular expression matching for string values.
/// 
/// Example:
///     Regex(r"^prod-[a-z]+$")  # Matches prod-web, prod-api, etc.
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
}

/// Python wrapper for Contains constraint.
/// 
/// A list value must contain all specified required values.
/// 
/// Example:
///     # Roles list must include "admin"
///     Contains(["admin"])
#[pyclass(name = "Contains")]
#[derive(Clone)]
pub struct PyContains {
    inner: Contains,
}

#[pymethods]
impl PyContains {
    #[new]
    fn new(required: Vec<String>) -> Self {
        Self {
            inner: Contains::new(required),
        }
    }

    fn __repr__(&self) -> String {
        format!("Contains({:?})", self.inner.required)
    }
}

/// Python wrapper for Subset constraint.
/// 
/// A list value must be a subset of the allowed values.
/// 
/// Example:
///     # Requested permissions must be subset of allowed
///     Subset(["read", "write", "admin"])
#[pyclass(name = "Subset")]
#[derive(Clone)]
pub struct PySubset {
    inner: Subset,
}

#[pymethods]
impl PySubset {
    #[new]
    fn new(allowed: Vec<String>) -> Self {
        Self {
            inner: Subset::new(allowed),
        }
    }

    fn __repr__(&self) -> String {
        format!("Subset({:?})", self.inner.allowed)
    }
}

/// Python wrapper for All constraint (AND).
/// 
/// All nested constraints must match.
/// 
/// Example:
///     All([Range.min_value(0), Range.max_value(100)])  # 0 <= value <= 100
#[pyclass(name = "All")]
#[derive(Clone)]
pub struct PyAll {
    inner: All,
}

#[pymethods]
impl PyAll {
    #[new]
    fn new(py: Python<'_>, constraints: Vec<PyObject>) -> PyResult<Self> {
        let mut rust_constraints = Vec::new();
        for obj in constraints {
            let bound = obj.bind(py);
            let constraint = py_to_constraint(bound)?;
            rust_constraints.push(constraint);
        }
        Ok(Self {
            inner: All::new(rust_constraints),
        })
    }

    fn __repr__(&self) -> String {
        format!("All([{} constraints])", self.inner.constraints.len())
    }
}

/// Python wrapper for Any constraint (OR).
/// 
/// At least one nested constraint must match.
/// 
/// Example:
///     Any([Exact("admin"), Exact("superuser")])  # Either admin or superuser
#[pyclass(name = "Any")]
#[derive(Clone)]
pub struct PyAny {
    inner: Any,
}

#[pymethods]
impl PyAny {
    #[new]
    fn new(py: Python<'_>, constraints: Vec<PyObject>) -> PyResult<Self> {
        let mut rust_constraints = Vec::new();
        for obj in constraints {
            let bound = obj.bind(py);
            let constraint = py_to_constraint(bound)?;
            rust_constraints.push(constraint);
        }
        Ok(Self {
            inner: Any::new(rust_constraints),
        })
    }

    fn __repr__(&self) -> String {
        format!("Any([{} constraints])", self.inner.constraints.len())
    }
}

/// Python wrapper for Not constraint (negation).
/// 
/// The inner constraint must NOT match.
/// 
/// WARNING: Use NotOneOf instead when possible. Negation can be dangerous
/// for security if not used carefully (blacklisting vs allowlisting).
/// 
/// Example:
///     Not(Exact("blocked"))  # Any value except "blocked"
#[pyclass(name = "Not")]
#[derive(Clone)]
pub struct PyNot {
    inner: Not,
}

#[pymethods]
impl PyNot {
    #[new]
    fn new(py: Python<'_>, constraint: PyObject) -> PyResult<Self> {
        let bound = constraint.bind(py);
        let inner_constraint = py_to_constraint(bound)?;
        Ok(Self {
            inner: Not::new(inner_constraint),
        })
    }

    fn __repr__(&self) -> String {
        "Not(...)".to_string()
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

    /// Sign a message with this keypair.
    /// 
    /// Args:
    ///     message: The message bytes to sign
    /// 
    /// Returns:
    ///     A Signature object
    fn sign(&self, message: &[u8]) -> PySignature {
        PySignature {
            inner: self.inner.sign(message),
        }
    }
}

/// Convert a Python constraint object to a Rust Constraint.
fn py_to_constraint(obj: &Bound<'_, PyAny>) -> PyResult<Constraint> {
    // Try each constraint type in order
    if let Ok(w) = obj.extract::<PyWildcard>() {
        Ok(Constraint::Wildcard(w.inner))
    } else if let Ok(p) = obj.extract::<PyPattern>() {
        Ok(Constraint::Pattern(p.inner))
    } else if let Ok(r) = obj.extract::<PyRegex>() {
        Ok(Constraint::Regex(r.inner))
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
    } else if let Ok(a) = obj.extract::<PyAny>() {
        Ok(Constraint::Any(a.inner))
    } else if let Ok(n) = obj.extract::<PyNot>() {
        Ok(Constraint::Not(n.inner))
    } else if let Ok(c) = obj.extract::<PyCel>() {
        Ok(Constraint::Cel(c.inner))
    } else {
        Err(PyValueError::new_err(
            "constraint must be one of: Wildcard, Pattern, Regex, Exact, OneOf, NotOneOf, Range, Contains, Subset, All, Any, Not, CEL",
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
    /// Create a new warrant.
    /// 
    /// Args:
    ///     tool: Tool name this warrant authorizes
    ///     constraints: Dictionary of constraint_name -> Constraint object
    ///     ttl_seconds: Time-to-live in seconds
    ///     keypair: Keypair to sign the warrant
    ///     session_id: Optional session identifier
    ///     authorized_holder: Optional public key - if set, holder must prove possession (PoP)
    ///     required_approvers: Optional list of public keys that must approve actions
    ///     min_approvals: Optional minimum number of approvals required (M-of-N)
    #[staticmethod]
    #[pyo3(signature = (tool, constraints, ttl_seconds, keypair, session_id=None, authorized_holder=None, required_approvers=None, min_approvals=None))]
    fn create(
        tool: &str,
        constraints: &Bound<'_, PyDict>,
        ttl_seconds: u64,
        keypair: &PyKeypair,
        session_id: Option<&str>,
        authorized_holder: Option<&PyPublicKey>,
        required_approvers: Option<Vec<PyPublicKey>>,
        min_approvals: Option<u32>,
    ) -> PyResult<Self> {
        let mut builder = RustWarrant::builder()
            .tool(tool)
            .ttl(Duration::from_secs(ttl_seconds));

        if let Some(sid) = session_id {
            builder = builder.session_id(sid);
        }

        if let Some(holder) = authorized_holder {
            builder = builder.authorized_holder(holder.inner.clone());
        }

        if let Some(approvers) = required_approvers {
            let rust_approvers: Vec<RustPublicKey> = approvers.into_iter().map(|p| p.inner).collect();
            builder = builder.required_approvers(rust_approvers);
        }

        if let Some(min) = min_approvals {
            builder = builder.min_approvals(min);
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

    /// Get the issuer's public key.
    #[getter]
    fn issuer(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.issuer().clone(),
        }
    }

    /// Get the authorized holder's public key (if set).
    /// 
    /// When set, the holder must prove possession of the corresponding
    /// private key to use this warrant (Proof-of-Possession).
    #[getter]
    fn authorized_holder(&self) -> Option<PyPublicKey> {
        self.inner.authorized_holder().map(|pk| PyPublicKey {
            inner: pk.clone(),
        })
    }

    /// Check if this warrant requires Proof-of-Possession.
    #[getter]
    fn requires_pop(&self) -> bool {
        self.inner.requires_pop()
    }

    /// Get the expiration time as an RFC3339 string.
    #[getter]
    fn expires_at(&self) -> String {
        self.inner.expires_at().to_rfc3339()
    }

    /// Attenuate this warrant with additional constraints.
    ///
    /// Args:
    ///     constraints: Dictionary of constraint_name -> Constraint object
    ///     keypair: Keypair to sign the attenuated warrant
    ///     ttl_seconds: Optional TTL (must be <= parent's remaining TTL)
    ///     authorized_holder: Optional public key - if set, holder must prove possession (PoP)
    ///     add_approvers: Optional list of public keys to add as required approvers
    ///     raise_min_approvals: Optional new minimum approvals count (must be >= parent's)
    ///
    /// Note: session_id is immutable and inherited from the parent warrant.
    #[pyo3(signature = (constraints, keypair, ttl_seconds=None, authorized_holder=None, add_approvers=None, raise_min_approvals=None))]
    fn attenuate(
        &self,
        constraints: &Bound<'_, PyDict>,
        keypair: &PyKeypair,
        ttl_seconds: Option<u64>,
        authorized_holder: Option<&PyPublicKey>,
        add_approvers: Option<Vec<PyPublicKey>>,
        raise_min_approvals: Option<u32>,
    ) -> PyResult<PyWarrant> {
        let mut builder = self.inner.attenuate();

        if let Some(ttl) = ttl_seconds {
            builder = builder.ttl(Duration::from_secs(ttl));
        }

        if let Some(holder) = authorized_holder {
            builder = builder.authorized_holder(holder.inner.clone());
        }

        if let Some(approvers) = add_approvers {
            let rust_approvers: Vec<RustPublicKey> = approvers.into_iter().map(|p| p.inner).collect();
            builder = builder.add_approvers(rust_approvers);
        }

        if let Some(min) = raise_min_approvals {
            builder = builder.raise_min_approvals(min);
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
    ///     signature: Optional Signature object for Proof-of-Possession
    /// 
    /// Returns:
    ///     True if authorized, False if constraint not satisfied, PoP missing, or PoP invalid
    #[pyo3(signature = (tool, args, signature=None))]
    fn authorize(&self, tool: &str, args: &Bound<'_, PyDict>, signature: Option<&PySignature>) -> PyResult<bool> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        match self.inner.authorize(tool, &rust_args, signature.map(|s| &s.inner)) {
            Ok(()) => Ok(true),
            Err(crate::error::Error::ConstraintNotSatisfied { .. }) => Ok(false),
            Err(crate::error::Error::MissingSignature(_)) => Ok(false),
            Err(crate::error::Error::SignatureInvalid(_)) => Ok(false),
            Err(e) => Err(to_py_err(e)),
        }
    }

    /// Verify the warrant signature against an issuer's public key.
    /// 
    /// Args:
    ///     public_key: The expected issuer's PublicKey object
    /// 
    /// Returns:
    ///     True if signature is valid, False otherwise
    fn verify(&self, public_key: &PyPublicKey) -> PyResult<bool> {
        match self.inner.verify(&public_key.inner) {
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
    ///     keypair: The Keypair to sign with (must match authorized_holder)
    ///     tool: Tool name being called
    ///     args: Dictionary of argument name -> value
    /// 
    /// Returns:
    ///     A Signature object to pass to authorize()
    fn create_pop_signature(&self, keypair: &PyKeypair, tool: &str, args: &Bound<'_, PyDict>) -> PyResult<PySignature> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        let sig = self.inner.create_pop_signature(&keypair.inner, tool, &rust_args)
            .map_err(to_py_err)?;
        Ok(PySignature { inner: sig })
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
        format!("PublicKey({:02x}{:02x}{:02x}{:02x}...)", 
                bytes[0], bytes[1], bytes[2], bytes[3])
    }

    fn __eq__(&self, other: &PyPublicKey) -> bool {
        self.inner.to_bytes() == other.inner.to_bytes()
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.inner.to_bytes().hash(&mut hasher);
        hasher.finish()
    }

    /// Verify a signature against a message.
    /// 
    /// Args:
    ///     message: The message bytes that were signed
    ///     signature: The Signature object to verify
    /// 
    /// Returns:
    ///     True if signature is valid, False otherwise
    fn verify(&self, message: &[u8], signature: &PySignature) -> bool {
        self.inner.verify(message, &signature.inner).is_ok()
    }
}

/// Python wrapper for Signature.
#[pyclass(name = "Signature")]
#[derive(Clone)]
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
        format!("Signature({:02x}{:02x}{:02x}{:02x}...)", 
                bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// Python wrapper for Approval.
#[pyclass(name = "Approval")]
#[derive(Clone)]
pub struct PyApproval {
    inner: RustApproval,
}

#[pymethods]
impl PyApproval {
    /// Create a new approval.
    ///
    /// Args:
    ///     warrant_id: The ID of the warrant being used
    ///     tool: The tool name being authorized
    ///     args: Dictionary of argument name -> value
    ///     approver_key: Keypair of the approver
    ///     external_id: Identity string of the approver (e.g. "admin@corp.com")
    ///     provider: Identity provider name (e.g. "okta")
    ///     ttl_seconds: How long the approval is valid for (default 300s)
    ///     reason: Optional reason for approval
    ///     authorized_holder: Optional public key of the agent using the warrant
    #[staticmethod]
    #[pyo3(signature = (warrant_id, tool, args, approver_key, external_id, provider, ttl_seconds=300, reason=None, authorized_holder=None))]
    fn create(
        warrant_id: &str,
        tool: &str,
        args: &Bound<'_, PyDict>,
        approver_key: &PyKeypair,
        external_id: &str,
        provider: &str,
        ttl_seconds: i64,
        reason: Option<String>,
        authorized_holder: Option<&PyPublicKey>,
    ) -> PyResult<Self> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        let holder_inner = authorized_holder.map(|h| &h.inner);
        let request_hash = compute_request_hash(warrant_id, tool, &rust_args, holder_inner);
        
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl_seconds);

        // Manually construct Approval since we don't have a builder exposed yet
        // Ideally we'd use a builder, but constructing struct directly is fine for internal crate usage
        let mut payload_bytes = Vec::new();
        payload_bytes.extend_from_slice(&request_hash);
        payload_bytes.extend_from_slice(external_id.as_bytes());
        payload_bytes.extend_from_slice(&now.timestamp().to_le_bytes());
        payload_bytes.extend_from_slice(&expires_at.timestamp().to_le_bytes());

        let signature = approver_key.inner.sign(&payload_bytes);

        let inner = RustApproval {
            request_hash,
            approver_key: approver_key.inner.public_key(),
            external_id: external_id.to_string(),
            provider: provider.to_string(),
            approved_at: now,
            expires_at,
            reason,
            signature,
        };

        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        format!("Approval(approver='{}', provider='{}')", self.inner.external_id, self.inner.provider)
    }
}

// ============================================================================
// REVOCATION SYSTEM
// ============================================================================

/// Python wrapper for SignedRevocationList.
/// 
/// A cryptographically signed list of revoked warrant IDs.
/// Use SrlBuilder to create new revocation lists.
/// 
/// Example:
///     # Create a revocation list
///     srl = SrlBuilder() \
///         .revoke("tnu_wrt_compromised_123") \
///         .revoke("tnu_wrt_stolen_456") \
///         .version(1) \
///         .build(control_plane_keypair)
///     
///     # Set on authorizer
///     authorizer.set_revocation_list(srl, control_plane_keypair.public_key())
#[pyclass(name = "SignedRevocationList")]
#[derive(Clone)]
pub struct PySignedRevocationList {
    inner: RustSrl,
}

#[pymethods]
impl PySignedRevocationList {
    /// Check if a warrant ID is revoked.
    fn is_revoked(&self, warrant_id: &str) -> bool {
        self.inner.is_revoked(warrant_id)
    }

    /// Get the version number.
    #[getter]
    fn version(&self) -> u64 {
        self.inner.version()
    }

    /// Get the list of revoked warrant IDs.
    fn revoked_ids(&self) -> Vec<String> {
        self.inner.revoked_ids().iter().cloned().collect()
    }

    /// Get the number of revoked warrants.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Serialize to bytes (CBOR).
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    /// Deserialize from bytes (CBOR).
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let inner = RustSrl::from_bytes(bytes).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Verify this list was signed by the expected issuer.
    fn verify(&self, expected_issuer: &PyPublicKey) -> PyResult<bool> {
        match self.inner.verify(&expected_issuer.inner) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "SignedRevocationList(version={}, count={})",
            self.inner.version(),
            self.inner.len()
        )
    }
}

/// Builder for creating SignedRevocationLists.
/// 
/// Example:
///     srl = SrlBuilder() \
///         .revoke("tnu_wrt_compromised_123") \
///         .version(42) \
///         .build(keypair)
#[pyclass(name = "SrlBuilder")]
pub struct PySrlBuilder {
    revoked_ids: Vec<String>,
    version: u64,
}

#[pymethods]
impl PySrlBuilder {
    #[new]
    fn new() -> Self {
        Self {
            revoked_ids: Vec::new(),
            version: 1,
        }
    }

    /// Add a warrant ID to revoke.
    fn revoke(mut slf: PyRefMut<'_, Self>, warrant_id: &str) -> PyRefMut<'_, Self> {
        slf.revoked_ids.push(warrant_id.to_string());
        slf
    }

    /// Add multiple warrant IDs to revoke.
    fn revoke_all(mut slf: PyRefMut<'_, Self>, warrant_ids: Vec<String>) -> PyRefMut<'_, Self> {
        slf.revoked_ids.extend(warrant_ids);
        slf
    }

    /// Set the version number.
    /// 
    /// Version must be monotonically increasing. Authorizers should reject
    /// lists with version < their current version (anti-rollback).
    fn version(mut slf: PyRefMut<'_, Self>, version: u64) -> PyRefMut<'_, Self> {
        slf.version = version;
        slf
    }

    /// Build and sign the revocation list.
    fn build(&self, keypair: &PyKeypair) -> PyResult<PySignedRevocationList> {
        let mut builder = RustSrlBuilder::new().version(self.version);
        for id in &self.revoked_ids {
            builder = builder.revoke(id);
        }
        let inner = builder.build(&keypair.inner).map_err(to_py_err)?;
        Ok(PySignedRevocationList { inner })
    }

    /// Create an empty signed revocation list.
    #[staticmethod]
    fn empty(keypair: &PyKeypair) -> PyResult<PySignedRevocationList> {
        let inner = RustSrl::empty(&keypair.inner).map_err(to_py_err)?;
        Ok(PySignedRevocationList { inner })
    }

    fn __repr__(&self) -> String {
        format!(
            "SrlBuilder(version={}, pending={})",
            self.version,
            self.revoked_ids.len()
        )
    }
}

// ============================================================================
// CHAIN VERIFICATION
// ============================================================================

/// A single step in a verified delegation chain.
#[pyclass(name = "ChainStep")]
#[derive(Clone)]
pub struct PyChainStep {
    /// The warrant ID at this step.
    #[pyo3(get)]
    warrant_id: String,
    /// Delegation depth at this step.
    #[pyo3(get)]
    depth: u32,
    /// Public key bytes of the issuer at this step (hex-encoded).
    #[pyo3(get)]
    issuer_hex: String,
}

#[pymethods]
impl PyChainStep {
    fn __repr__(&self) -> String {
        format!(
            "ChainStep(warrant_id='{}', depth={}, issuer='{:.16}...')",
            self.warrant_id, self.depth, self.issuer_hex
        )
    }
}

impl From<&RustChainStep> for PyChainStep {
    fn from(step: &RustChainStep) -> Self {
        Self {
            warrant_id: step.warrant_id.clone(),
            depth: step.depth,
            issuer_hex: hex::encode(step.issuer),
        }
    }
}

/// Result of a successful chain verification.
/// 
/// Contains metadata about the verified delegation chain.
#[pyclass(name = "ChainVerificationResult")]
#[derive(Clone)]
pub struct PyChainVerificationResult {
    /// Public key bytes of the root issuer (hex-encoded).
    #[pyo3(get)]
    root_issuer_hex: Option<String>,
    /// Total length of the verified chain.
    #[pyo3(get)]
    chain_length: usize,
    /// Depth of the leaf warrant.
    #[pyo3(get)]
    leaf_depth: u32,
    /// Details of each verified step.
    verified_steps: Vec<PyChainStep>,
}

#[pymethods]
impl PyChainVerificationResult {
    /// Get the verified steps in the chain.
    #[getter]
    fn steps(&self) -> Vec<PyChainStep> {
        self.verified_steps.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "ChainVerificationResult(chain_length={}, leaf_depth={})",
            self.chain_length, self.leaf_depth
        )
    }
}

impl From<RustChainResult> for PyChainVerificationResult {
    fn from(result: RustChainResult) -> Self {
        Self {
            root_issuer_hex: result.root_issuer.map(|b| hex::encode(b)),
            chain_length: result.chain_length,
            leaf_depth: result.leaf_depth,
            verified_steps: result.verified_steps.iter().map(PyChainStep::from).collect(),
        }
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

    /// Set a signed revocation list.
    /// 
    /// Verifies the signature before accepting. Returns error if verification fails.
    /// 
    /// Args:
    ///     srl: The signed revocation list
    ///     expected_issuer: The Control Plane's public key (must match SRL issuer)
    /// 
    /// Example:
    ///     srl = SrlBuilder().revoke("tnu_wrt_compromised").version(1).build(cp_keypair)
    ///     authorizer.set_revocation_list(srl, cp_keypair.public_key())
    fn set_revocation_list(
        &mut self,
        srl: &PySignedRevocationList,
        expected_issuer: &PyPublicKey,
    ) -> PyResult<()> {
        self.inner
            .set_revocation_list(srl.inner.clone(), &expected_issuer.inner)
            .map_err(to_py_err)
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
    ///     signature: Optional PoP Signature object
    ///     approvals: Optional list of Approval objects (for multi-sig)
    /// 
    /// Returns:
    ///     None on success, raises exception on failure
    #[pyo3(signature = (warrant, tool, args, signature=None, approvals=None))]
    fn authorize(
        &self,
        warrant: &PyWarrant,
        tool: &str,
        args: &Bound<'_, PyDict>,
        signature: Option<&PySignature>,
        approvals: Option<Vec<PyApproval>>,
    ) -> PyResult<()> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        let rust_approvals: Vec<RustApproval> = approvals
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.inner)
            .collect();

        self.inner.authorize(
            &warrant.inner, 
            tool, 
            &rust_args, 
            signature.map(|s| &s.inner), 
            &rust_approvals
        ).map_err(to_py_err)
    }

    /// Convenience: verify warrant and authorize in one call.
    /// 
    /// Args:
    ///     warrant: The warrant to check
    ///     tool: Tool name being invoked
    ///     args: Dictionary of argument name -> value
    ///     signature: Optional PoP Signature object
    ///     approvals: Optional list of Approval objects (for multi-sig)
    /// 
    /// Returns:
    ///     None on success, raises exception on failure
    #[pyo3(signature = (warrant, tool, args, signature=None, approvals=None))]
    fn check(
        &self,
        warrant: &PyWarrant,
        tool: &str,
        args: &Bound<'_, PyDict>,
        signature: Option<&PySignature>,
        approvals: Option<Vec<PyApproval>>,
    ) -> PyResult<()> {
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        let rust_approvals: Vec<RustApproval> = approvals
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.inner)
            .collect();

        self.inner.check(
            &warrant.inner, 
            tool, 
            &rust_args, 
            signature.map(|s| &s.inner), 
            &rust_approvals
        ).map_err(to_py_err)
    }

    /// Verify a complete delegation chain.
    /// 
    /// This is the most thorough verification method, validating the entire
    /// path from a trusted root to the leaf warrant.
    /// 
    /// Args:
    ///     chain: List of warrants from root (index 0) to leaf (last)
    /// 
    /// Chain Invariants Verified:
    ///     1. Root Trust: chain[0] must be signed by a trusted issuer
    ///     2. Linkage: chain[i+1].parent_id == chain[i].id
    ///     3. Depth: chain[i+1].depth == chain[i].depth + 1
    ///     4. Expiration: chain[i+1].expires_at <= chain[i].expires_at
    ///     5. Monotonicity: chain[i+1].constraints ⊆ chain[i].constraints
    ///     6. Signatures: Each warrant has a valid signature
    ///     7. Revocation: No warrant in the chain is revoked (cascading)
    /// 
    /// Returns:
    ///     ChainVerificationResult on success
    /// 
    /// Raises:
    ///     RuntimeError on verification failure
    /// 
    /// Example:
    ///     # Verify full delegation: control_plane -> orchestrator -> worker
    ///     result = authorizer.verify_chain([root_warrant, orch_warrant, worker_warrant])
    ///     print(f"Chain verified: {result.chain_length} warrants, depth {result.leaf_depth}")
    fn verify_chain(&self, chain: Vec<PyWarrant>) -> PyResult<PyChainVerificationResult> {
        let rust_chain: Vec<RustWarrant> = chain.into_iter().map(|w| w.inner).collect();
        let result = self.inner.verify_chain(&rust_chain).map_err(to_py_err)?;
        Ok(PyChainVerificationResult::from(result))
    }

    /// Verify chain and authorize an action.
    /// 
    /// Convenience method that verifies the full chain and then authorizes
    /// the action against the leaf warrant (last in chain).
    /// 
    /// Args:
    ///     chain: List of warrants from root to leaf
    ///     tool: Tool name being invoked
    ///     args: Dictionary of argument name -> value
    ///     signature: Optional PoP Signature object
    ///     approvals: Optional list of Approval objects (for multi-sig)
    /// 
    /// Returns:
    ///     ChainVerificationResult on success
    /// 
    /// Raises:
    ///     RuntimeError on verification or authorization failure
    #[pyo3(signature = (chain, tool, args, signature=None, approvals=None))]
    fn check_chain(
        &self,
        chain: Vec<PyWarrant>,
        tool: &str,
        args: &Bound<'_, PyDict>,
        signature: Option<&PySignature>,
        approvals: Option<Vec<PyApproval>>,
    ) -> PyResult<PyChainVerificationResult> {
        let rust_chain: Vec<RustWarrant> = chain.into_iter().map(|w| w.inner).collect();
        
        let mut rust_args = HashMap::new();
        for (key, value) in args.iter() {
            let field: String = key.extract()?;
            let cv = py_to_constraint_value(&value)?;
            rust_args.insert(field, cv);
        }

        let rust_approvals: Vec<RustApproval> = approvals
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.inner)
            .collect();

        let result = self.inner.check_chain(
            &rust_chain,
            tool,
            &rust_args,
            signature.map(|s| &s.inner),
            &rust_approvals
        ).map_err(to_py_err)?;
        
        Ok(PyChainVerificationResult::from(result))
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
    // Constraints - Basic
    m.add_class::<PyWildcard>()?;
    m.add_class::<PyPattern>()?;
    m.add_class::<PyRegex>()?;
    m.add_class::<PyExact>()?;
    m.add_class::<PyOneOf>()?;
    m.add_class::<PyNotOneOf>()?;
    m.add_class::<PyRange>()?;
    
    // Constraints - List operations
    m.add_class::<PyContains>()?;
    m.add_class::<PySubset>()?;
    
    // Constraints - Composite
    m.add_class::<PyAll>()?;
    m.add_class::<PyAny>()?;
    m.add_class::<PyNot>()?;
    m.add_class::<PyCel>()?;
    
    // Crypto
    m.add_class::<PyKeypair>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PySignature>()?;
    
    // Core
    m.add_class::<PyWarrant>()?;
    m.add_class::<PyAuthorizer>()?;
    m.add_class::<PyApproval>()?;
    
    // Revocation
    m.add_class::<PySignedRevocationList>()?;
    m.add_class::<PySrlBuilder>()?;
    
    // Chain Verification
    m.add_class::<PyChainStep>()?;
    m.add_class::<PyChainVerificationResult>()?;
    
    // MCP
    m.add_class::<PyMcpConfig>()?;
    m.add_class::<PyCompiledMcpConfig>()?;
    m.add_class::<PyExtractionResult>()?;

    // Constants
    m.add("MAX_DELEGATION_DEPTH", crate::MAX_DELEGATION_DEPTH)?;
    m.add("MAX_CONSTRAINT_DEPTH", crate::MAX_CONSTRAINT_DEPTH)?;
    m.add("WIRE_VERSION", crate::WIRE_VERSION)?;
    m.add("WARRANT_HEADER", wire::WARRANT_HEADER)?;

    Ok(())
}
