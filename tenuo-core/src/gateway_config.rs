//! Gateway Configuration Parser
//!
//! Parses YAML configuration files for Tenuo gateway/sidecar deployments.
//!
//! # Configuration File Format
//!
//! ```yaml
//! version: "1"
//!
//! settings:
//!   warrant_header: "X-Tenuo-Warrant"
//!   pop_header: "X-Tenuo-PoP"
//!   clock_tolerance_secs: 30
//!   trusted_roots:
//!     - "f32e74b5..."
//!
//! tools:
//!   manage_infrastructure:
//!     description: "Kubernetes operations"
//!     constraints:
//!       cluster:
//!         from: path
//!         path: "cluster"
//!         required: true
//!       cost:
//!         from: body
//!         path: "metadata.estimatedCost"
//!         type: float
//!
//! routes:
//!   - pattern: "/api/v1/clusters/{cluster}/{action}"
//!     method: ["POST", "PUT"]
//!     tool: "manage_infrastructure"
//! ```
//!
//! # Performance
//!
//! For production use, compile the configuration using [`CompiledGatewayConfig`]:
//!
//! ```ignore
//! let config = GatewayConfig::from_file("gateway.yaml")?;
//! let compiled = CompiledGatewayConfig::compile(config)?;
//!
//! // Fast route matching using radix tree
//! if let Some(result) = compiled.match_route("POST", "/api/v1/clusters/prod/scale") {
//!     let constraints = compiled.extract_constraints(&result, &ctx)?;
//! }
//! ```

use crate::constraints::ConstraintValue;
use crate::extraction::{
    extract_all, CompiledExtractionRules, ExtractionError, ExtractionRule, ExtractionSource,
    ExtractionTrace, RequestContext,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Gateway configuration parsed from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Configuration version
    pub version: String,
    /// Global settings
    pub settings: GatewaySettings,
    /// Tool definitions with extraction rules
    pub tools: HashMap<String, ToolConfig>,
    /// Route matching configuration
    pub routes: Vec<RouteConfig>,
}

/// Global gateway settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewaySettings {
    /// Header containing the warrant (base64)
    #[serde(default = "default_warrant_header", alias = "chain_header")]
    pub warrant_header: String,
    /// Header containing the PoP signature
    #[serde(default = "default_pop_header")]
    pub pop_header: String,
    /// Clock tolerance for expiration checks (seconds)
    #[serde(default = "default_clock_tolerance")]
    pub clock_tolerance_secs: u64,
    /// Trusted root public keys (hex)
    #[serde(default, alias = "trusted_issuers")]
    pub trusted_roots: Vec<String>,
}

fn default_warrant_header() -> String {
    "X-Tenuo-Warrant".into()
}

fn default_pop_header() -> String {
    "X-Tenuo-PoP".into()
}

fn default_clock_tolerance() -> u64 {
    30
}

impl Default for GatewaySettings {
    fn default() -> Self {
        Self {
            warrant_header: default_warrant_header(),
            pop_header: default_pop_header(),
            clock_tolerance_secs: default_clock_tolerance(),
            trusted_roots: Vec::new(),
        }
    }
}

/// Tool configuration with extraction rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    /// Human-readable description
    pub description: String,
    /// Constraint extraction rules
    pub constraints: HashMap<String, ExtractionRule>,
}

/// Route matching configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// URL pattern with placeholders: `/api/{cluster}/{action}`
    pub pattern: String,
    /// Allowed HTTP methods (empty = all)
    #[serde(default)]
    pub method: Vec<String>,
    /// Tool name to use for this route
    pub tool: String,
    /// Additional constraints from headers/query (merged with tool constraints)
    #[serde(default)]
    pub extra_constraints: HashMap<String, ExtractionRule>,
}

/// Result of constraint extraction.
#[derive(Debug)]
pub struct ExtractionResult {
    /// Extracted constraint values
    pub constraints: HashMap<String, ConstraintValue>,
    /// Debug traces for all extraction attempts
    pub traces: Vec<ExtractionTrace>,
    /// Matched tool name
    pub tool: String,
}

impl GatewayConfig {
    /// Parse configuration from YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, ConfigError> {
        serde_yaml::from_str(yaml).map_err(ConfigError::YamlParse)
    }

    /// Load configuration from a file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::FileRead(path.as_ref().display().to_string(), e))?;
        Self::from_yaml(&content)
    }

    /// Find a matching route for a request.
    pub fn match_route(
        &self,
        method: &str,
        path: &str,
    ) -> Option<(&RouteConfig, HashMap<String, String>)> {
        for route in &self.routes {
            // Check method
            if !route.method.is_empty()
                && !route.method.iter().any(|m| m.eq_ignore_ascii_case(method))
            {
                continue;
            }

            // Try to match pattern
            if let Some(params) = match_pattern(&route.pattern, path) {
                return Some((route, params));
            }
        }
        None
    }

    /// Extract constraints for a matched route.
    pub fn extract_constraints(
        &self,
        route: &RouteConfig,
        ctx: &RequestContext,
    ) -> Result<ExtractionResult, ExtractionError> {
        let tool_config = self.tools.get(&route.tool).ok_or_else(|| ExtractionError {
            field: route.tool.clone(),
            source: ExtractionSource::Literal,
            path: String::new(),
            hint: format!("Tool '{}' not defined in configuration", route.tool),
            required: true,
        })?;

        // Merge tool constraints with route-specific extras
        let mut all_rules = tool_config.constraints.clone();
        for (name, rule) in &route.extra_constraints {
            all_rules.insert(name.clone(), rule.clone());
        }

        let (constraints, traces) = extract_all(&all_rules, ctx)?;

        Ok(ExtractionResult {
            constraints,
            traces,
            tool: route.tool.clone(),
        })
    }

    /// Validate the configuration for common errors.
    pub fn validate(&self) -> Result<(), Vec<ConfigValidationError>> {
        let mut errors = Vec::new();

        // Check that all routes reference defined tools
        for (i, route) in self.routes.iter().enumerate() {
            if !self.tools.contains_key(&route.tool) {
                errors.push(ConfigValidationError {
                    location: format!("routes[{}]", i),
                    message: format!("Tool '{}' is not defined", route.tool),
                });
            }

            // Validate pattern syntax
            if let Err(msg) = validate_pattern(&route.pattern) {
                errors.push(ConfigValidationError {
                    location: format!("routes[{}].pattern", i),
                    message: msg,
                });
            }
        }

        // Check extraction rules
        for (tool_name, tool_config) in &self.tools {
            for (field_name, rule) in &tool_config.constraints {
                // Validate body paths
                if rule.from == ExtractionSource::Body && rule.path.is_empty() {
                    errors.push(ConfigValidationError {
                        location: format!("tools.{}.constraints.{}", tool_name, field_name),
                        message: "Body extraction requires a path".into(),
                    });
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Match a URL pattern and extract path parameters.
///
/// Pattern: `/api/v1/clusters/{cluster}/{action}`
/// Path: `/api/v1/clusters/staging-web/scale`
/// Returns: `{"cluster": "staging-web", "action": "scale"}`
fn match_pattern(pattern: &str, path: &str) -> Option<HashMap<String, String>> {
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();

    // Quick length check (allow trailing slash difference)
    let pattern_len = pattern_parts.len();
    let path_len = path_parts.len();

    if pattern_len != path_len {
        // Handle trailing slash
        if !(pattern_len == path_len + 1 && pattern_parts.last() == Some(&"")
            || path_len == pattern_len + 1 && path_parts.last() == Some(&""))
        {
            return None;
        }
    }

    let mut params = HashMap::new();

    for (pattern_part, path_part) in pattern_parts.iter().zip(path_parts.iter()) {
        if pattern_part.starts_with('{') && pattern_part.ends_with('}') {
            // Extract parameter name
            let name = &pattern_part[1..pattern_part.len() - 1];
            params.insert(name.to_string(), path_part.to_string());
        } else if pattern_part != path_part {
            return None;
        }
    }

    Some(params)
}

/// Validate pattern syntax.
fn validate_pattern(pattern: &str) -> Result<(), String> {
    let mut in_brace = false;
    let mut brace_content = String::new();

    for c in pattern.chars() {
        match c {
            '{' => {
                if in_brace {
                    return Err("Nested braces not allowed".into());
                }
                in_brace = true;
                brace_content.clear();
            }
            '}' => {
                if !in_brace {
                    return Err("Unmatched closing brace".into());
                }
                if brace_content.is_empty() {
                    return Err("Empty parameter name".into());
                }
                in_brace = false;
            }
            _ if in_brace => {
                brace_content.push(c);
            }
            _ => {}
        }
    }

    if in_brace {
        return Err("Unclosed brace".into());
    }

    Ok(())
}

/// Configuration parsing error.
#[derive(Debug)]
pub enum ConfigError {
    /// YAML parsing error
    YamlParse(serde_yaml::Error),
    /// File reading error
    FileRead(String, std::io::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::YamlParse(e) => write!(f, "YAML parse error: {}", e),
            ConfigError::FileRead(path, e) => write!(f, "Failed to read {}: {}", path, e),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Configuration validation error.
#[derive(Debug)]
pub struct ConfigValidationError {
    /// Location in config (e.g., "routes[0].tool")
    pub location: String,
    /// Error message
    pub message: String,
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

// ============================================================================
// Compiled Gateway Configuration (Optimized for Production)
// ============================================================================

/// HTTP method matching with support for standard and custom methods.
///
/// Uses bitflags for standard methods (GET, POST, etc.) for O(1) matching,
/// with a HashSet fallback for custom methods (PURGE, PROPFIND, etc.).
#[derive(Debug, Clone)]
pub struct MethodMask {
    /// Bitmask for standard methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
    standard: u8,
    /// Set of custom method names (uppercase) for non-standard methods
    custom: std::collections::HashSet<String>,
    /// If true, matches all methods
    all: bool,
}

impl MethodMask {
    const GET: u8 = 1 << 0;
    const POST: u8 = 1 << 1;
    const PUT: u8 = 1 << 2;
    const DELETE: u8 = 1 << 3;
    const PATCH: u8 = 1 << 4;
    const HEAD: u8 = 1 << 5;
    const OPTIONS: u8 = 1 << 6;

    /// Create a method mask that matches all methods.
    pub fn all() -> Self {
        Self {
            standard: 0,
            custom: std::collections::HashSet::new(),
            all: true,
        }
    }

    /// Create a method mask from a list of method strings.
    pub fn from_methods(methods: &[String]) -> Self {
        if methods.is_empty() {
            return Self::all();
        }

        let mut standard_mask = 0u8;
        let mut custom_set = std::collections::HashSet::new();

        for method in methods {
            let method_upper = method.to_uppercase();
            let bit = Self::method_bit(&method_upper);
            if bit != 0 {
                standard_mask |= bit;
            } else {
                // Custom method
                custom_set.insert(method_upper);
            }
        }

        Self {
            standard: standard_mask,
            custom: custom_set,
            all: false,
        }
    }

    fn method_bit(method: &str) -> u8 {
        match method {
            "GET" => Self::GET,
            "POST" => Self::POST,
            "PUT" => Self::PUT,
            "DELETE" => Self::DELETE,
            "PATCH" => Self::PATCH,
            "HEAD" => Self::HEAD,
            "OPTIONS" => Self::OPTIONS,
            _ => 0,
        }
    }

    /// Check if this mask matches the given method.
    ///
    /// # Performance
    ///
    /// - Standard methods (GET, POST, etc.): O(1) bitwise check
    /// - Custom methods (PURGE, PROPFIND, etc.): O(1) HashSet lookup
    #[inline]
    pub fn matches(&self, method: &str) -> bool {
        if self.all {
            return true;
        }

        let method_upper = method.to_uppercase();
        let bit = Self::method_bit(&method_upper);

        if bit != 0 {
            // Standard method - check bitmask
            (self.standard & bit) != 0
        } else {
            // Custom method - check HashSet
            self.custom.contains(&method_upper)
        }
    }
}

impl Default for MethodMask {
    fn default() -> Self {
        Self::all()
    }
}

/// A compiled route with pre-parsed extraction rules.
#[derive(Debug, Clone)]
pub struct CompiledRoute {
    /// Original route configuration
    pub config: RouteConfig,
    /// Pre-compiled method mask
    pub method_mask: MethodMask,
    /// Pre-compiled extraction rules (tool + extra merged)
    pub extraction_rules: CompiledExtractionRules,
    /// Tool name
    pub tool: Arc<str>,
}

/// Result of a route match.
#[derive(Debug)]
pub struct RouteMatch<'a> {
    /// Matched route
    pub route: &'a CompiledRoute,
    /// Extracted path parameters
    pub path_params: HashMap<String, String>,
}

/// A compiled gateway configuration optimized for production use.
///
/// Provides significant performance improvements:
/// - **Route matching**: Uses radix tree (matchit) for O(log n) matching
/// - **Method matching**: Uses bitmask for O(1) comparison
/// - **Path extraction**: Pre-compiled paths avoid string parsing
/// - **Header matching**: Pre-lowercased keys avoid case conversion
///
/// # Thread Safety
///
/// This structure is **not** `Clone` and should be wrapped in `Arc` for sharing
/// across Tokio tasks. The authorizer HTTP server does this automatically.
///
/// # Example
///
/// ```ignore
/// let config = GatewayConfig::from_file("gateway.yaml")?;
/// let compiled = CompiledGatewayConfig::compile(config)?;
///
/// // Wrap in Arc for sharing across threads
/// let compiled = Arc::new(compiled);
///
/// // Fast matching on every request
/// if let Some(m) = compiled.match_route("POST", "/api/v1/clusters/prod/scale") {
///     let result = compiled.extract_constraints(&m, &ctx)?;
/// }
/// ```
pub struct CompiledGatewayConfig {
    /// Original settings
    pub settings: GatewaySettings,
    /// Radix-tree router for fast path matching
    router: matchit::Router<usize>,
    /// Compiled routes indexed by router value
    routes: Vec<CompiledRoute>,
}

/// Error when compiling gateway configuration.
#[derive(Debug)]
pub enum CompileError {
    /// Route pattern is invalid
    InvalidPattern {
        route_index: usize,
        pattern: String,
        error: String,
    },
    /// Tool referenced by route is not defined
    UndefinedTool { route_index: usize, tool: String },
    /// Router conflict (duplicate patterns)
    RouterConflict {
        route_index: usize,
        pattern: String,
        error: String,
    },
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::InvalidPattern {
                route_index,
                pattern,
                error,
            } => {
                write!(
                    f,
                    "Route {}: Invalid pattern '{}': {}",
                    route_index, pattern, error
                )
            }
            CompileError::UndefinedTool { route_index, tool } => {
                write!(f, "Route {}: Tool '{}' is not defined", route_index, tool)
            }
            CompileError::RouterConflict {
                route_index,
                pattern,
                error,
            } => {
                write!(
                    f,
                    "Route {}: Pattern '{}' conflicts: {}",
                    route_index, pattern, error
                )
            }
        }
    }
}

impl std::error::Error for CompileError {}

impl CompiledGatewayConfig {
    /// Compile a gateway configuration for optimized production use.
    ///
    /// This pre-parses all patterns, paths, and rules for fast matching.
    pub fn compile(config: GatewayConfig) -> Result<Self, CompileError> {
        let mut router = matchit::Router::new();
        let mut routes = Vec::with_capacity(config.routes.len());

        for (i, route) in config.routes.into_iter().enumerate() {
            // Validate tool exists
            let tool_config =
                config
                    .tools
                    .get(&route.tool)
                    .ok_or_else(|| CompileError::UndefinedTool {
                        route_index: i,
                        tool: route.tool.clone(),
                    })?;

            // Convert pattern from {param} to :param for matchit
            let matchit_pattern = convert_pattern_to_matchit(&route.pattern);

            // Add to router
            router
                .insert(matchit_pattern, i)
                .map_err(|e| CompileError::RouterConflict {
                    route_index: i,
                    pattern: route.pattern.clone(),
                    error: e.to_string(),
                })?;

            // Merge and compile extraction rules
            let mut all_rules = tool_config.constraints.clone();
            for (name, rule) in &route.extra_constraints {
                all_rules.insert(name.clone(), rule.clone());
            }
            let extraction_rules = CompiledExtractionRules::compile(all_rules);

            let compiled = CompiledRoute {
                method_mask: MethodMask::from_methods(&route.method),
                tool: Arc::from(route.tool.as_str()),
                extraction_rules,
                config: route,
            };

            routes.push(compiled);
        }

        Ok(Self {
            settings: config.settings,
            router,
            routes,
        })
    }

    /// Match a request path and method against the compiled routes.
    ///
    /// Uses radix tree for O(log n) path matching and bitmask for O(1) method check.
    ///
    /// # Returns
    ///
    /// `Some(RouteMatch)` if a matching route is found, `None` otherwise.
    pub fn match_route(&self, method: &str, path: &str) -> Option<RouteMatch<'_>> {
        // Strip query string if present
        let clean_path = path.split('?').next().unwrap_or(path);

        // Try to match with matchit router
        let matched = self.router.at(clean_path).ok()?;
        let route_idx = *matched.value;
        let route = &self.routes[route_idx];

        // Check method
        if !route.method_mask.matches(method) {
            return None;
        }

        // Convert matchit params to HashMap
        let mut path_params = HashMap::new();
        for (key, value) in matched.params.iter() {
            path_params.insert(key.to_string(), value.to_string());
        }

        Some(RouteMatch { route, path_params })
    }

    /// Extract constraints for a matched route.
    ///
    /// Uses pre-compiled extraction rules for fast extraction.
    pub fn extract_constraints(
        &self,
        route_match: &RouteMatch<'_>,
        ctx: &RequestContext,
    ) -> Result<ExtractionResult, ExtractionError> {
        // Create context with path params from match
        let mut full_ctx = ctx.clone();
        full_ctx.path_params = route_match.path_params.clone();

        let (constraints, traces) = route_match.route.extraction_rules.extract_all(&full_ctx)?;

        Ok(ExtractionResult {
            constraints,
            traces,
            tool: route_match.route.tool.to_string(),
        })
    }
}

/// Convert a pattern from `{param}` format to `:param` format for matchit.
fn convert_pattern_to_matchit(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len());
    let mut in_brace = false;

    for c in pattern.chars() {
        match c {
            '{' => {
                in_brace = true;
                result.push(':');
            }
            '}' => {
                in_brace = false;
            }
            _ => {
                if in_brace || c != '{' {
                    result.push(c);
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SAMPLE_CONFIG: &str = r#"
version: "1"

settings:
  warrant_header: "X-Tenuo-Warrant"
  pop_header: "X-Tenuo-PoP"
  clock_tolerance_secs: 30
  trusted_roots:
    - "f32e74b5b8569dc288db0109b7ec0d8eb3b4e5be7b07c647171d53fd31e7391f"

tools:
  manage_infrastructure:
    description: "Kubernetes cluster management"
    constraints:
      cluster:
        from: path
        path: "cluster"
        required: true
      action:
        from: path
        path: "action"
        required: true
      replicas:
        from: body
        path: "spec.replicas"
        type: integer
      cost:
        from: body
        path: "metadata.estimatedCost"
        type: float

routes:
  - pattern: "/api/v1/clusters/{cluster}/{action}"
    method: ["POST", "PUT"]
    tool: "manage_infrastructure"
"#;

    #[test]
    fn test_parse_config() {
        let config = GatewayConfig::from_yaml(SAMPLE_CONFIG).unwrap();

        assert_eq!(config.version, "1");
        assert_eq!(config.settings.warrant_header, "X-Tenuo-Warrant");
        assert!(config.tools.contains_key("manage_infrastructure"));
        assert_eq!(config.routes.len(), 1);
    }

    #[test]
    fn test_route_matching() {
        let config = GatewayConfig::from_yaml(SAMPLE_CONFIG).unwrap();

        let result = config.match_route("POST", "/api/v1/clusters/staging-web/scale");
        assert!(result.is_some());

        let (route, params) = result.unwrap();
        assert_eq!(route.tool, "manage_infrastructure");
        assert_eq!(params.get("cluster"), Some(&"staging-web".to_string()));
        assert_eq!(params.get("action"), Some(&"scale".to_string()));
    }

    #[test]
    fn test_route_method_mismatch() {
        let config = GatewayConfig::from_yaml(SAMPLE_CONFIG).unwrap();

        // GET is not allowed
        let result = config.match_route("GET", "/api/v1/clusters/staging-web/scale");
        assert!(result.is_none());
    }

    #[test]
    fn test_constraint_extraction() {
        let config = GatewayConfig::from_yaml(SAMPLE_CONFIG).unwrap();

        let (route, path_params) = config
            .match_route("POST", "/api/v1/clusters/staging-web/scale")
            .unwrap();

        let mut ctx = RequestContext::with_body(json!({
            "spec": { "replicas": 5 },
            "metadata": { "estimatedCost": 150.0 }
        }));
        ctx.path_params = path_params;

        let result = config.extract_constraints(route, &ctx).unwrap();

        assert_eq!(
            result.constraints.get("cluster"),
            Some(&ConstraintValue::String("staging-web".into()))
        );
        assert_eq!(
            result.constraints.get("replicas"),
            Some(&ConstraintValue::Integer(5))
        );
        assert_eq!(
            result.constraints.get("cost"),
            Some(&ConstraintValue::Float(150.0))
        );
    }

    #[test]
    fn test_pattern_matching() {
        assert!(match_pattern("/api/{id}", "/api/123").is_some());
        assert!(match_pattern("/api/{a}/{b}", "/api/x/y").is_some());
        assert!(match_pattern("/api/static", "/api/static").is_some());
        assert!(match_pattern("/api/{id}", "/api/123/extra").is_none());
        assert!(match_pattern("/api/{id}", "/different/123").is_none());
    }

    #[test]
    fn test_config_validation() {
        let bad_config = r#"
version: "1"
settings: {}
tools: {}
routes:
  - pattern: "/api/{}"
    tool: "undefined_tool"
"#;
        let config = GatewayConfig::from_yaml(bad_config).unwrap();
        let errors = config.validate().unwrap_err();

        assert!(errors.iter().any(|e| e.message.contains("undefined_tool")));
        assert!(errors.iter().any(|e| e.message.contains("Empty parameter")));
    }

    // ========================================================================
    // Compiled Config Tests
    // ========================================================================

    #[test]
    fn test_compiled_route_matching() {
        let config = GatewayConfig::from_yaml(SAMPLE_CONFIG).unwrap();
        let compiled = CompiledGatewayConfig::compile(config).unwrap();

        let result = compiled.match_route("POST", "/api/v1/clusters/staging-web/scale");
        assert!(result.is_some());

        let route_match = result.unwrap();
        assert_eq!(route_match.route.tool.as_ref(), "manage_infrastructure");
        assert_eq!(
            route_match.path_params.get("cluster"),
            Some(&"staging-web".to_string())
        );
        assert_eq!(
            route_match.path_params.get("action"),
            Some(&"scale".to_string())
        );
    }

    #[test]
    fn test_compiled_method_mask() {
        let mask = MethodMask::from_methods(&["POST".to_string(), "PUT".to_string()]);
        assert!(mask.matches("POST"));
        assert!(mask.matches("PUT"));
        assert!(mask.matches("post")); // Case insensitive
        assert!(!mask.matches("GET"));
        assert!(!mask.matches("DELETE"));

        let all_mask = MethodMask::all();
        assert!(all_mask.matches("GET"));
        assert!(all_mask.matches("POST"));
        assert!(all_mask.matches("DELETE"));
    }

    #[test]
    fn test_custom_http_methods() {
        // Test custom methods (PURGE, PROPFIND, etc.)
        let mask = MethodMask::from_methods(&[
            "POST".to_string(),
            "PURGE".to_string(),
            "PROPFIND".to_string(),
        ]);

        // Standard method
        assert!(mask.matches("POST"));
        assert!(!mask.matches("GET"));

        // Custom methods
        assert!(mask.matches("PURGE"));
        assert!(mask.matches("purge")); // Case insensitive
        assert!(mask.matches("PROPFIND"));
        assert!(mask.matches("propfind"));

        // Not in mask
        assert!(!mask.matches("PATCH"));
        assert!(!mask.matches("CUSTOM_METHOD"));
    }

    #[test]
    fn test_method_mask_all() {
        let all_mask = MethodMask::all();

        // Standard methods
        assert!(all_mask.matches("GET"));
        assert!(all_mask.matches("POST"));
        assert!(all_mask.matches("PUT"));
        assert!(all_mask.matches("DELETE"));
        assert!(all_mask.matches("PATCH"));
        assert!(all_mask.matches("HEAD"));
        assert!(all_mask.matches("OPTIONS"));

        // Custom methods
        assert!(all_mask.matches("PURGE"));
        assert!(all_mask.matches("PROPFIND"));
        assert!(all_mask.matches("CUSTOM_METHOD"));
    }

    #[test]
    fn test_compiled_constraint_extraction() {
        let config = GatewayConfig::from_yaml(SAMPLE_CONFIG).unwrap();
        let compiled = CompiledGatewayConfig::compile(config).unwrap();

        let route_match = compiled
            .match_route("POST", "/api/v1/clusters/staging-web/scale")
            .unwrap();

        let ctx = RequestContext::with_body(json!({
            "spec": { "replicas": 5 },
            "metadata": { "estimatedCost": 150.0 }
        }));

        let result = compiled.extract_constraints(&route_match, &ctx).unwrap();

        assert_eq!(
            result.constraints.get("cluster"),
            Some(&ConstraintValue::String("staging-web".into()))
        );
        assert_eq!(
            result.constraints.get("replicas"),
            Some(&ConstraintValue::Integer(5))
        );
        assert_eq!(
            result.constraints.get("cost"),
            Some(&ConstraintValue::Float(150.0))
        );
    }

    #[test]
    fn test_compiled_method_mismatch() {
        let config = GatewayConfig::from_yaml(SAMPLE_CONFIG).unwrap();
        let compiled = CompiledGatewayConfig::compile(config).unwrap();

        // GET is not allowed
        let result = compiled.match_route("GET", "/api/v1/clusters/staging-web/scale");
        assert!(result.is_none());
    }

    #[test]
    fn test_compiled_path_with_query() {
        let config = GatewayConfig::from_yaml(SAMPLE_CONFIG).unwrap();
        let compiled = CompiledGatewayConfig::compile(config).unwrap();

        // Should match even with query string
        let result = compiled.match_route("POST", "/api/v1/clusters/staging-web/scale?foo=bar");
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().path_params.get("cluster"),
            Some(&"staging-web".to_string())
        );
    }

    #[test]
    fn test_pattern_to_matchit_conversion() {
        assert_eq!(convert_pattern_to_matchit("/api/{id}"), "/api/:id");
        assert_eq!(
            convert_pattern_to_matchit("/api/{cluster}/{action}"),
            "/api/:cluster/:action"
        );
        assert_eq!(convert_pattern_to_matchit("/static/path"), "/static/path");
    }

    #[test]
    fn test_matchit_directly() {
        let mut router: matchit::Router<usize> = matchit::Router::new();

        // Test param matching
        router.insert("/api/:cluster/:action", 0).unwrap();
        let matched = router.at("/api/staging-web/scale");
        assert!(matched.is_ok());

        let m = matched.unwrap();
        assert_eq!(*m.value, 0);
        assert_eq!(m.params.get("cluster"), Some("staging-web"));
        assert_eq!(m.params.get("action"), Some("scale"));
    }
}
