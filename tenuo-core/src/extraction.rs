//! Constraint Extraction System
//!
//! Extracts runtime values from HTTP requests and maps them to Tenuo constraints.
//!
//! # Extraction Sources
//!
//! Values can be extracted from:
//! - **Path parameters**: `/api/v1/clusters/{cluster}` → `cluster`
//! - **Query parameters**: `?namespace=default` → `namespace`
//! - **Headers**: `X-Tenant-Id: acme` → `tenant_id`
//! - **JSON body with dot notation**: `spec.replicas`, `metadata.cost`
//!
//! # JSONPath Syntax
//!
//! Supports dot notation for nested access:
//! - `field` - Top-level field
//! - `parent.child` - Nested object field
//! - `items.0.name` - Array index access
//! - `items.*.id` - Wildcard (all items)
//!
//! # Type Preservation
//!
//! Integer types are preserved for precision with large IDs (snowflakes, etc.).
//! Only explicitly fractional numbers become floats.
//!
//! # Wildcard Extraction
//!
//! Wildcard paths (`items.*.field`) produce `List` values.
//! Ensure your Warrant Constraints are compatible with Lists:
//! - Use `OneOf` or `NotOneOf` for membership checks
//! - Use `Cel` for complex list operations:
//!   - All items: `items.all(x, x.cost < 100)`
//!   - Any item: `items.exists(x, x.approved)`
//!   - Sum: `items.map(x, x.cost).sum() < 1000`
//!
//! Scalar constraints (`Exact`, `Range`, `Pattern`) will NOT match
//! List values and will return false (request blocked).
//!
//! # Performance
//!
//! For best performance, use [`CompiledPath`] and [`CompiledExtractionRule`]
//! which pre-parse paths at configuration load time.

use crate::constraints::ConstraintValue;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use smallvec::SmallVec;
use std::collections::{HashMap, BTreeMap};
use std::sync::Arc;

// ============================================================================
// Compiled Path (Pre-parsed for performance)
// ============================================================================

/// A pre-parsed path segment for fast extraction.
///
/// Segments are parsed once at config load time, avoiding repeated
/// string splitting and parsing during request handling.
#[derive(Debug, Clone, PartialEq)]
pub enum PathSegment {
    /// Object field access: `"fieldName"`
    Field(Arc<str>),
    /// Array index access: `items.0.name` → index 0
    Index(usize),
    /// Wildcard: `items.*.id` → all items
    Wildcard,
}

/// A pre-compiled JSON path for fast extraction.
///
/// Paths are parsed once when loading configuration, avoiding the cost
/// of string splitting and parsing on every request.
///
/// Uses `SmallVec` to avoid heap allocation for paths with ≤4 segments
/// (covers most common cases like `spec.replicas` or `metadata.cost`).
#[derive(Debug, Clone)]
pub struct CompiledPath {
    /// Original path string (for debugging)
    pub original: Arc<str>,
    /// Pre-parsed segments
    pub segments: SmallVec<[PathSegment; 4]>,
    /// Whether this path contains a wildcard
    pub has_wildcard: bool,
}

impl CompiledPath {
    /// Compile a path string into a `CompiledPath`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tenuo_core::extraction::CompiledPath;
    ///
    /// let path = CompiledPath::compile("spec.replicas");
    /// assert_eq!(path.segments.len(), 2);
    /// assert!(!path.has_wildcard);
    ///
    /// let wildcard_path = CompiledPath::compile("items.*.id");
    /// assert!(wildcard_path.has_wildcard);
    /// ```
    pub fn compile(path: &str) -> Self {
        let mut segments = SmallVec::new();
        let mut has_wildcard = false;

        for segment in path.split('.') {
            if segment == "*" {
                segments.push(PathSegment::Wildcard);
                has_wildcard = true;
            } else if let Ok(idx) = segment.parse::<usize>() {
                segments.push(PathSegment::Index(idx));
            } else {
                segments.push(PathSegment::Field(Arc::from(segment)));
            }
        }

        Self {
            original: Arc::from(path),
            segments,
            has_wildcard,
        }
    }

    /// Extract a value from JSON using the pre-compiled path.
    ///
    /// This is faster than [`extract_json_path`] because the path
    /// has already been parsed into segments.
    pub fn extract(&self, body: &Value) -> Option<ConstraintValue> {
        extract_compiled_recursive(body, &self.segments)
    }
}

fn extract_compiled_recursive(value: &Value, segments: &[PathSegment]) -> Option<ConstraintValue> {
    if segments.is_empty() {
        return json_to_constraint_value(value);
    }

    let segment = &segments[0];
    let rest = &segments[1..];

    match segment {
        PathSegment::Wildcard => {
            if let Some(arr) = value.as_array() {
                let values: Vec<ConstraintValue> = arr
                    .iter()
                    .filter_map(|item| extract_compiled_recursive(item, rest))
                    .collect();
                if values.is_empty() {
                    return None;
                }
                return Some(ConstraintValue::List(values));
            }
            None
        }
        PathSegment::Index(idx) => {
            let item = value.get(*idx)?;
            extract_compiled_recursive(item, rest)
        }
        PathSegment::Field(name) => {
            let child = value.get(name.as_ref())?;
            extract_compiled_recursive(child, rest)
        }
    }
}

// ============================================================================
// Compiled Extraction Rule
// ============================================================================

/// A pre-compiled extraction rule for fast extraction.
///
/// This is the compiled version of [`ExtractionRule`], with paths
/// pre-parsed and header keys pre-lowercased.
#[derive(Debug, Clone)]
pub struct CompiledExtractionRule {
    /// Original rule (for debugging and defaults)
    pub rule: ExtractionRule,
    /// Pre-compiled body path (only for Body source)
    pub compiled_path: Option<CompiledPath>,
    /// Pre-lowercased header key (only for Header source)
    pub lowercase_key: Option<Arc<str>>,
}

impl CompiledExtractionRule {
    /// Compile an extraction rule for fast extraction.
    pub fn compile(rule: ExtractionRule) -> Self {
        let compiled_path = if rule.from == ExtractionSource::Body {
            Some(CompiledPath::compile(&rule.path))
        } else {
            None
        };

        let lowercase_key = if rule.from == ExtractionSource::Header {
            Some(Arc::from(rule.path.to_lowercase()))
        } else {
            None
        };

        Self {
            rule,
            compiled_path,
            lowercase_key,
        }
    }

    /// Extract a value using the compiled rule.
    ///
    /// Faster than [`extract_by_rule`] because paths are pre-parsed.
    pub fn extract(&self, ctx: &RequestContext) -> Option<ConstraintValue> {
        match &self.rule.from {
            ExtractionSource::Path => {
                ctx.path_params.get(&self.rule.path).map(|s| ConstraintValue::String(s.clone()))
            }
            ExtractionSource::Query => {
                ctx.query_params.get(&self.rule.path).map(|s| ConstraintValue::String(s.clone()))
            }
            ExtractionSource::Header => {
                let key = self.lowercase_key.as_ref()?;
                ctx.headers.get(key.as_ref()).map(|s| ConstraintValue::String(s.clone()))
            }
            ExtractionSource::Body => {
                let path = self.compiled_path.as_ref()?;
                path.extract(&ctx.body)
            }
            ExtractionSource::Literal => {
                self.rule.default.as_ref().and_then(json_to_constraint_value)
            }
        }
    }
}

/// A set of compiled extraction rules keyed by field name.
#[derive(Debug, Clone, Default)]
pub struct CompiledExtractionRules {
    /// Field name → compiled rule
    pub rules: HashMap<String, CompiledExtractionRule>,
}

impl CompiledExtractionRules {
    /// Compile a set of extraction rules.
    pub fn compile(rules: HashMap<String, ExtractionRule>) -> Self {
        let compiled = rules
            .into_iter()
            .map(|(name, rule)| (name, CompiledExtractionRule::compile(rule)))
            .collect();
        Self { rules: compiled }
    }

    /// Extract all constraints using compiled rules.
    ///
    /// Faster than [`extract_all`] because paths are pre-parsed.
    pub fn extract_all(
        &self,
        ctx: &RequestContext,
    ) -> Result<(HashMap<String, ConstraintValue>, Vec<ExtractionTrace>), ExtractionError> {
        let mut constraints = HashMap::new();
        let mut traces = Vec::new();

        for (name, compiled) in &self.rules {
            let value = compiled.extract(ctx);

            let trace = ExtractionTrace {
                field: name.clone(),
                source: compiled.rule.from.clone(),
                path: compiled.rule.path.clone(),
                result: value.clone(),
                required: compiled.rule.required,
                hint: if value.is_none() {
                    Some(generate_hint(&compiled.rule, ctx))
                } else {
                    None
                },
            };
            traces.push(trace);

            match value {
                Some(v) => {
                    constraints.insert(name.clone(), v);
                }
                None if compiled.rule.required => {
                    return Err(ExtractionError {
                        field: name.clone(),
                        source: compiled.rule.from.clone(),
                        path: compiled.rule.path.clone(),
                        hint: generate_hint(&compiled.rule, ctx),
                        required: true,
                    });
                }
                None => {
                    // Apply default if present
                    if let Some(ref default) = compiled.rule.default {
                        if let Some(v) = json_to_constraint_value(default) {
                            constraints.insert(name.clone(), v);
                        }
                    }
                }
            }
        }

        Ok((constraints, traces))
    }
}


/// Extraction source specifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ExtractionSource {
    /// Extract from URL path parameter: `/api/{cluster}/action`
    Path,
    /// Extract from query string: `?namespace=default`
    Query,
    /// Extract from HTTP header: `X-Tenant-Id`
    Header,
    /// Extract from JSON body using dot notation: `spec.replicas`
    Body,
    /// Use a literal default value
    Literal,
}

/// Configuration for extracting a single constraint field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionRule {
    /// Where to extract the value from
    pub from: ExtractionSource,
    /// Path or key to extract (dot notation for body)
    pub path: String,
    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,
    /// Whether this field is required
    #[serde(default)]
    pub required: bool,
    /// Default value if not found
    #[serde(default)]
    pub default: Option<Value>,
    /// Expected type hint (integer, float, boolean, string, list)
    #[serde(rename = "type", default)]
    pub value_type: Option<String>,
    /// Allowed values for validation
    #[serde(default)]
    pub allowed_values: Option<Vec<String>>,
}

/// Request context containing all extractable data.
#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    /// Path parameters extracted from URL pattern
    pub path_params: HashMap<String, String>,
    /// Query string parameters
    pub query_params: HashMap<String, String>,
    /// HTTP headers (lowercase keys)
    pub headers: HashMap<String, String>,
    /// JSON body (or Value::Null if not JSON)
    pub body: Value,
}

impl RequestContext {
    /// Create a new empty request context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create context with a JSON body.
    pub fn with_body(body: Value) -> Self {
        Self {
            body,
            ..Default::default()
        }
    }

    /// Add a path parameter.
    pub fn path_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.path_params.insert(key.into(), value.into());
        self
    }

    /// Add a query parameter.
    pub fn query_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_params.insert(key.into(), value.into());
        self
    }

    /// Add a header.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into().to_lowercase(), value.into());
        self
    }
}

/// Result of an extraction attempt with debugging info.
#[derive(Debug, Clone)]
pub struct ExtractionTrace {
    /// Field name being extracted
    pub field: String,
    /// Source type
    pub source: ExtractionSource,
    /// Path within source
    pub path: String,
    /// Extracted value (if successful)
    pub result: Option<ConstraintValue>,
    /// Whether field was required
    pub required: bool,
    /// Error hint if extraction failed
    pub hint: Option<String>,
}

/// Extraction error with debugging information.
#[derive(Debug, Clone)]
pub struct ExtractionError {
    /// Field that failed to extract
    pub field: String,
    /// Source that was searched
    pub source: ExtractionSource,
    /// Path that was not found
    pub path: String,
    /// Human-readable hint for debugging
    pub hint: String,
    /// Whether this was a required field
    pub required: bool,
}

impl std::fmt::Display for ExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Missing required field '{}' (from {:?}, path: {}). {}",
            self.field, self.source, self.path, self.hint
        )
    }
}

impl std::error::Error for ExtractionError {}

/// Extract a value from JSON using dot notation.
///
/// # Supported Paths
///
/// - `field` - Top-level field
/// - `parent.child.grandchild` - Nested objects
/// - `items.0.name` - Array index
/// - `items.*.id` - Wildcard (returns List)
///
/// # Examples
///
/// ```
/// use tenuo_core::{extraction::extract_json_path, constraints::ConstraintValue};
/// use serde_json::json;
///
/// let body = json!({
///     "spec": { "replicas": 5 },
///     "items": [
///         { "id": "a", "cost": 10 },
///         { "id": "b", "cost": 20 }
///     ]
/// });
///
/// // Nested access
/// assert_eq!(
///     extract_json_path(&body, "spec.replicas"),
///     Some(ConstraintValue::Integer(5))
/// );
///
/// // Array index
/// assert_eq!(
///     extract_json_path(&body, "items.0.id"),
///     Some(ConstraintValue::String("a".into()))
/// );
///
/// // Wildcard
/// assert_eq!(
///     extract_json_path(&body, "items.*.id"),
///     Some(ConstraintValue::List(vec![
///         ConstraintValue::String("a".into()),
///         ConstraintValue::String("b".into()),
///     ]))
/// );
/// ```
pub fn extract_json_path(body: &Value, path: &str) -> Option<ConstraintValue> {
    let segments: Vec<&str> = path.split('.').collect();
    extract_recursive(body, &segments)
}

fn extract_recursive(value: &Value, segments: &[&str]) -> Option<ConstraintValue> {
    if segments.is_empty() {
        return json_to_constraint_value(value);
    }

    let segment = segments[0];
    let rest = &segments[1..];

    // Wildcard handling
    if segment == "*" {
        if let Some(arr) = value.as_array() {
            let values: Vec<ConstraintValue> = arr
                .iter()
                .filter_map(|item| extract_recursive(item, rest))
                .collect();
            if values.is_empty() {
                return None;
            }
            return Some(ConstraintValue::List(values));
        }
        return None;
    }

    // Array index access
    if let Ok(idx) = segment.parse::<usize>() {
        let item = value.get(idx)?;
        return extract_recursive(item, rest);
    }

    // Object field access
    let child = value.get(segment)?;
    extract_recursive(child, rest)
}

/// Convert JSON value to ConstraintValue, preserving integer precision.
fn json_to_constraint_value(value: &Value) -> Option<ConstraintValue> {
    match value {
        Value::String(s) => Some(ConstraintValue::String(s.clone())),
        Value::Bool(b) => Some(ConstraintValue::Boolean(*b)),
        Value::Number(n) => {
            // Prioritize i64 for integers to preserve precision
            if let Some(i) = n.as_i64() {
                Some(ConstraintValue::Integer(i))
            } else if let Some(u) = n.as_u64() {
                // Large unsigned integers that don't fit in i64
                // Store as string to preserve precision
                if u > i64::MAX as u64 {
                    Some(ConstraintValue::String(u.to_string()))
                } else {
                    Some(ConstraintValue::Integer(u as i64))
                }
            } else if let Some(f) = n.as_f64() {
                Some(ConstraintValue::Float(f))
            } else {
                None
            }
        }
        Value::Array(arr) => {
            let values: Vec<ConstraintValue> = arr
                .iter()
                .filter_map(json_to_constraint_value)
                .collect();
            Some(ConstraintValue::List(values))
        }
        Value::Null => Some(ConstraintValue::Null),
        Value::Object(map) => {
            let mut result = BTreeMap::new();
            for (k, v) in map {
                if let Some(cv) = json_to_constraint_value(v) {
                    result.insert(k.clone(), cv);
                }
            }
            Some(ConstraintValue::Object(result))
        }
    }
}

/// Extract a value according to an extraction rule.
pub fn extract_by_rule(rule: &ExtractionRule, ctx: &RequestContext) -> Option<ConstraintValue> {
    match &rule.from {
        ExtractionSource::Path => {
            ctx.path_params.get(&rule.path).map(|s| ConstraintValue::String(s.clone()))
        }
        ExtractionSource::Query => {
            ctx.query_params.get(&rule.path).map(|s| ConstraintValue::String(s.clone()))
        }
        ExtractionSource::Header => {
            let key = rule.path.to_lowercase();
            ctx.headers.get(&key).map(|s| ConstraintValue::String(s.clone()))
        }
        ExtractionSource::Body => extract_json_path(&ctx.body, &rule.path),
        ExtractionSource::Literal => {
            rule.default.as_ref().and_then(json_to_constraint_value)
        }
    }
}

/// Generate a helpful hint for debugging extraction failures.
pub fn generate_hint(rule: &ExtractionRule, ctx: &RequestContext) -> String {
    match &rule.from {
        ExtractionSource::Body => {
            let available = list_available_paths(&ctx.body, 3);
            if available.is_empty() {
                "Body is empty or not valid JSON".to_string()
            } else {
                format!(
                    "Path '{}' not found. Available paths: {}",
                    rule.path,
                    available.join(", ")
                )
            }
        }
        ExtractionSource::Header => {
            let available: Vec<_> = ctx.headers.keys().take(5).cloned().collect();
            format!(
                "Header '{}' not found. Available: {}",
                rule.path,
                if available.is_empty() {
                    "(none)".to_string()
                } else {
                    available.join(", ")
                }
            )
        }
        ExtractionSource::Path => {
            format!(
                "Path param '{}' not matched. Check route pattern.",
                rule.path
            )
        }
        ExtractionSource::Query => {
            let available: Vec<_> = ctx.query_params.keys().take(5).cloned().collect();
            format!(
                "Query param '{}' not found. Available: {}",
                rule.path,
                if available.is_empty() {
                    "(none)".to_string()
                } else {
                    available.join(", ")
                }
            )
        }
        ExtractionSource::Literal => "Literal has no default value".to_string(),
    }
}

/// List available JSON paths for debugging.
fn list_available_paths(value: &Value, max_depth: usize) -> Vec<String> {
    let mut paths = Vec::new();
    collect_paths(value, String::new(), max_depth, &mut paths);
    paths
}

fn collect_paths(value: &Value, prefix: String, depth: usize, paths: &mut Vec<String>) {
    if depth == 0 {
        return;
    }

    match value {
        Value::Object(map) => {
            for (key, val) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", prefix, key)
                };
                paths.push(path.clone());
                collect_paths(val, path, depth - 1, paths);
            }
        }
        Value::Array(arr) if !arr.is_empty() => {
            paths.push(format!("{}.*", prefix));
            let path = format!("{}.0", prefix);
            collect_paths(&arr[0], path, depth - 1, paths);
        }
        _ => {}
    }
}

/// Extract multiple constraints according to a rule map.
///
/// Returns both successful extractions and traces for debugging.
pub fn extract_all(
    rules: &HashMap<String, ExtractionRule>,
    ctx: &RequestContext,
) -> Result<(HashMap<String, ConstraintValue>, Vec<ExtractionTrace>), ExtractionError> {
    let mut constraints = HashMap::new();
    let mut traces = Vec::new();

    for (name, rule) in rules {
        let value = extract_by_rule(rule, ctx);

        let trace = ExtractionTrace {
            field: name.clone(),
            source: rule.from.clone(),
            path: rule.path.clone(),
            result: value.clone(),
            required: rule.required,
            hint: if value.is_none() {
                Some(generate_hint(rule, ctx))
            } else {
                None
            },
        };
        traces.push(trace);

        match value {
            Some(v) => {
                constraints.insert(name.clone(), v);
            }
            None if rule.required => {
                return Err(ExtractionError {
                    field: name.clone(),
                    source: rule.from.clone(),
                    path: rule.path.clone(),
                    hint: generate_hint(rule, ctx),
                    required: true,
                });
            }
            None => {
                // Apply default if present
                if let Some(ref default) = rule.default {
                    if let Some(v) = json_to_constraint_value(default) {
                        constraints.insert(name.clone(), v);
                    }
                }
            }
        }
    }

    Ok((constraints, traces))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_simple_extraction() {
        let body = json!({ "name": "test", "count": 42 });
        
        assert_eq!(
            extract_json_path(&body, "name"),
            Some(ConstraintValue::String("test".into()))
        );
        assert_eq!(
            extract_json_path(&body, "count"),
            Some(ConstraintValue::Integer(42))
        );
    }

    #[test]
    fn test_nested_extraction() {
        let body = json!({
            "spec": {
                "replicas": 5,
                "container": {
                    "image": "nginx:latest"
                }
            }
        });

        assert_eq!(
            extract_json_path(&body, "spec.replicas"),
            Some(ConstraintValue::Integer(5))
        );
        assert_eq!(
            extract_json_path(&body, "spec.container.image"),
            Some(ConstraintValue::String("nginx:latest".into()))
        );
    }

    #[test]
    fn test_array_index() {
        let body = json!({
            "items": [
                { "id": "first" },
                { "id": "second" }
            ]
        });

        assert_eq!(
            extract_json_path(&body, "items.0.id"),
            Some(ConstraintValue::String("first".into()))
        );
        assert_eq!(
            extract_json_path(&body, "items.1.id"),
            Some(ConstraintValue::String("second".into()))
        );
    }

    #[test]
    fn test_wildcard_extraction() {
        let body = json!({
            "transfers": [
                { "amount": 100, "recipient": "alice" },
                { "amount": 200, "recipient": "bob" }
            ]
        });

        assert_eq!(
            extract_json_path(&body, "transfers.*.amount"),
            Some(ConstraintValue::List(vec![
                ConstraintValue::Integer(100),
                ConstraintValue::Integer(200),
            ]))
        );
    }

    #[test]
    fn test_integer_preservation() {
        // Large snowflake ID
        let body = json!({ "id": 9007199254740993_i64 });
        
        if let Some(ConstraintValue::Integer(i)) = extract_json_path(&body, "id") {
            assert_eq!(i, 9007199254740993);
        } else {
            panic!("Expected integer");
        }
    }

    #[test]
    fn test_float_extraction() {
        let body = json!({ "price": 19.99 });
        
        assert_eq!(
            extract_json_path(&body, "price"),
            Some(ConstraintValue::Float(19.99))
        );
    }

    #[test]
    fn test_request_context() {
        let ctx = RequestContext::new()
            .path_param("cluster", "staging-web")
            .query_param("namespace", "default")
            .header("X-Tenant-Id", "acme");

        let rule = ExtractionRule {
            from: ExtractionSource::Path,
            path: "cluster".into(),
            description: None,
            required: true,
            default: None,
            value_type: None,
            allowed_values: None,
        };

        assert_eq!(
            extract_by_rule(&rule, &ctx),
            Some(ConstraintValue::String("staging-web".into()))
        );
    }

    #[test]
    fn test_extract_all_with_defaults() {
        let mut rules = HashMap::new();
        rules.insert("cluster".into(), ExtractionRule {
            from: ExtractionSource::Path,
            path: "cluster".into(),
            description: None,
            required: true,
            default: None,
            value_type: None,
            allowed_values: None,
        });
        rules.insert("namespace".into(), ExtractionRule {
            from: ExtractionSource::Query,
            path: "namespace".into(),
            description: None,
            required: false,
            default: Some(json!("default")),
            value_type: None,
            allowed_values: None,
        });

        let ctx = RequestContext::new()
            .path_param("cluster", "prod");

        let (constraints, _traces) = extract_all(&rules, &ctx).unwrap();
        
        assert_eq!(
            constraints.get("cluster"),
            Some(&ConstraintValue::String("prod".into()))
        );
        assert_eq!(
            constraints.get("namespace"),
            Some(&ConstraintValue::String("default".into()))
        );
    }

    #[test]
    fn test_missing_required_field() {
        let mut rules = HashMap::new();
        rules.insert("cluster".into(), ExtractionRule {
            from: ExtractionSource::Path,
            path: "cluster".into(),
            description: None,
            required: true,
            default: None,
            value_type: None,
            allowed_values: None,
        });

        let ctx = RequestContext::new(); // No path params

        let result = extract_all(&rules, &ctx);
        assert!(result.is_err());
        
        let err = result.unwrap_err();
        assert_eq!(err.field, "cluster");
        assert!(err.required);
    }

    // ========================================================================
    // Compiled Path Tests
    // ========================================================================

    #[test]
    fn test_compiled_path_simple() {
        let path = CompiledPath::compile("name");
        assert_eq!(path.segments.len(), 1);
        assert!(!path.has_wildcard);
        
        let body = json!({ "name": "test" });
        assert_eq!(path.extract(&body), Some(ConstraintValue::String("test".into())));
    }

    #[test]
    fn test_compiled_path_nested() {
        let path = CompiledPath::compile("spec.replicas");
        assert_eq!(path.segments.len(), 2);
        assert!(!path.has_wildcard);
        
        let body = json!({ "spec": { "replicas": 5 } });
        assert_eq!(path.extract(&body), Some(ConstraintValue::Integer(5)));
    }

    #[test]
    fn test_compiled_path_array_index() {
        let path = CompiledPath::compile("items.0.id");
        assert_eq!(path.segments.len(), 3);
        
        let body = json!({ "items": [{ "id": "first" }, { "id": "second" }] });
        assert_eq!(path.extract(&body), Some(ConstraintValue::String("first".into())));
    }

    #[test]
    fn test_compiled_path_wildcard() {
        let path = CompiledPath::compile("items.*.id");
        assert!(path.has_wildcard);
        
        let body = json!({ "items": [{ "id": "a" }, { "id": "b" }] });
        assert_eq!(
            path.extract(&body),
            Some(ConstraintValue::List(vec![
                ConstraintValue::String("a".into()),
                ConstraintValue::String("b".into()),
            ]))
        );
    }

    #[test]
    fn test_compiled_extraction_rule() {
        let rule = ExtractionRule {
            from: ExtractionSource::Body,
            path: "metadata.cost".into(),
            description: None,
            required: true,
            default: None,
            value_type: None,
            allowed_values: None,
        };
        
        let compiled = CompiledExtractionRule::compile(rule);
        assert!(compiled.compiled_path.is_some());
        
        let ctx = RequestContext::with_body(json!({ "metadata": { "cost": 150.0 } }));
        assert_eq!(compiled.extract(&ctx), Some(ConstraintValue::Float(150.0)));
    }

    #[test]
    fn test_compiled_extraction_rules() {
        let mut rules = HashMap::new();
        rules.insert("cluster".into(), ExtractionRule {
            from: ExtractionSource::Path,
            path: "cluster".into(),
            description: None,
            required: true,
            default: None,
            value_type: None,
            allowed_values: None,
        });
        rules.insert("cost".into(), ExtractionRule {
            from: ExtractionSource::Body,
            path: "metadata.cost".into(),
            description: None,
            required: false,
            default: None,
            value_type: None,
            allowed_values: None,
        });
        
        let compiled = CompiledExtractionRules::compile(rules);
        
        let ctx = RequestContext::with_body(json!({ "metadata": { "cost": 100.0 } }))
            .path_param("cluster", "prod");
        
        let (constraints, _traces) = compiled.extract_all(&ctx).unwrap();
        
        assert_eq!(
            constraints.get("cluster"),
            Some(&ConstraintValue::String("prod".into()))
        );
        assert_eq!(
            constraints.get("cost"),
            Some(&ConstraintValue::Float(100.0))
        );
    }

    #[test]
    fn test_object_extraction() {
        let body = json!({
            "meta": {
                "cost": 100,
                "owner": "admin"
            }
        });

        if let Some(ConstraintValue::Object(map)) = extract_json_path(&body, "meta") {
             assert_eq!(map.get("cost"), Some(&ConstraintValue::Integer(100)));
             assert_eq!(map.get("owner"), Some(&ConstraintValue::String("admin".to_string())));
        } else {
             panic!("Failed to extract object");
        }
    }
}

