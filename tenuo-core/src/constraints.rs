//! Constraint types for Tenuo warrants.
//!
//! Constraints restrict what argument values are allowed when a tool is invoked.
//! The key invariant is **monotonicity**: child constraints can only be stricter
//! than parent constraints, never looser.
//!
//! ## Constraint Types
//!
//! | Type | Description | Example |
//! |------|-------------|---------|
//! | `Pattern` | Glob matching | `staging-*` |
//! | `Regex` | Regular expression | `^prod-[a-z]+$` |
//! | `Exact` | Exact value | `"staging-web"` or `42` |
//! | `OneOf` | Value in set | `["a", "b", "c"]` |
//! | `Range` | Numeric/date bounds | `0..10000` |
//! | `Contains` | List contains value | `["admin"] ⊆ roles` |
//! | `Subset` | List is subset | `requested ⊆ allowed` |
//! | `All` | All constraints must match | `AND(a, b, c)` |
//! | `Any` | At least one must match | `OR(a, b, c)` |
//! | `Not` | Negation | `NOT(pattern)` |
//! | `Cel` | CEL expression | `amount < 10000` |

use crate::error::{Error, Result};
use glob::Pattern as GlobPattern;
use regex::Regex as RegexPattern;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A constraint on an argument value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum Constraint {
    /// Glob-style pattern matching (e.g., "staging-*").
    Pattern(Pattern),
    
    /// Regular expression matching.
    Regex(RegexConstraint),
    
    /// Exact value match (works for strings, numbers, bools).
    Exact(Exact),
    
    /// One of a set of allowed values.
    OneOf(OneOf),
    
    /// Numeric range constraint.
    Range(Range),
    
    /// List must contain specified values.
    Contains(Contains),
    
    /// List must be a subset of allowed values.
    Subset(Subset),
    
    /// All nested constraints must match (AND).
    All(All),
    
    /// At least one nested constraint must match (OR).
    Any(Any),
    
    /// Negation of a constraint.
    Not(Not),
    
    /// CEL expression for complex logic.
    Cel(CelConstraint),
}

impl Constraint {
    /// Check if this constraint is satisfied by the given value.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        match self {
            Constraint::Pattern(p) => p.matches(value),
            Constraint::Regex(r) => r.matches(value),
            Constraint::Exact(e) => e.matches(value),
            Constraint::OneOf(o) => o.matches(value),
            Constraint::Range(r) => r.matches(value),
            Constraint::Contains(c) => c.matches(value),
            Constraint::Subset(s) => s.matches(value),
            Constraint::All(a) => a.matches(value),
            Constraint::Any(a) => a.matches(value),
            Constraint::Not(n) => n.matches(value),
            Constraint::Cel(c) => c.matches(value),
        }
    }

    /// Check if `child` is a valid attenuation of `self` (parent).
    ///
    /// Returns `Ok(())` if the child is strictly narrower or equal.
    /// Returns `Err` if the child would expand capabilities.
    pub fn validate_attenuation(&self, child: &Constraint) -> Result<()> {
        match (self, child) {
            // Pattern can narrow to Pattern or Exact
            (Constraint::Pattern(parent), Constraint::Pattern(child_pat)) => {
                parent.validate_attenuation(child_pat)
            }
            (Constraint::Pattern(parent), Constraint::Exact(child_exact)) => {
                if parent.matches(&child_exact.value)? {
                    Ok(())
                } else {
                    Err(Error::MonotonicityViolation(format!(
                        "exact value '{:?}' does not match parent pattern '{}'",
                        child_exact.value, parent.pattern
                    )))
                }
            }
            
            // Regex can narrow to Regex or Exact
            (Constraint::Regex(parent), Constraint::Regex(child_regex)) => {
                parent.validate_attenuation(child_regex)
            }
            (Constraint::Regex(parent), Constraint::Exact(child_exact)) => {
                if parent.matches(&child_exact.value)? {
                    Ok(())
                } else {
                    Err(Error::MonotonicityViolation(format!(
                        "exact value '{:?}' does not match parent regex '{}'",
                        child_exact.value, parent.pattern
                    )))
                }
            }
            
            // Exact can only stay Exact with same value
            (Constraint::Exact(parent), Constraint::Exact(child)) => {
                if parent.value == child.value {
                    Ok(())
                } else {
                    Err(Error::MonotonicityViolation(format!(
                        "exact value '{:?}' differs from parent '{:?}'",
                        child.value, parent.value
                    )))
                }
            }
            
            // OneOf can narrow to smaller OneOf or Exact
            (Constraint::OneOf(parent), Constraint::OneOf(child)) => {
                parent.validate_attenuation(child)
            }
            (Constraint::OneOf(parent), Constraint::Exact(child)) => {
                if parent.contains(&child.value) {
                    Ok(())
                } else {
                    Err(Error::MonotonicityViolation(format!(
                        "exact value '{:?}' not in parent set",
                        child.value
                    )))
                }
            }
            
            // Range can narrow to smaller Range
            (Constraint::Range(parent), Constraint::Range(child)) => {
                parent.validate_attenuation(child)
            }
            
            // Contains can add more required values
            (Constraint::Contains(parent), Constraint::Contains(child)) => {
                parent.validate_attenuation(child)
            }
            
            // Subset can narrow the allowed set
            (Constraint::Subset(parent), Constraint::Subset(child)) => {
                parent.validate_attenuation(child)
            }
            
            // All can add more constraints
            (Constraint::All(parent), Constraint::All(child)) => {
                parent.validate_attenuation(child)
            }
            
            // CEL follows conjunction rule
            (Constraint::Cel(parent), Constraint::Cel(child)) => {
                parent.validate_attenuation(child)
            }
            
            // Any other combination is invalid
            _ => Err(Error::MonotonicityViolation(format!(
                "incompatible constraint types for attenuation: {:?} -> {:?}",
                std::mem::discriminant(self),
                std::mem::discriminant(child)
            ))),
        }
    }
}

// ============================================================================
// Constraint Values
// ============================================================================

/// Value that can be matched against constraints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ConstraintValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    List(Vec<ConstraintValue>),
    Object(HashMap<String, ConstraintValue>),
    Null,
}

impl ConstraintValue {
    /// Get as string if this is a String variant.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ConstraintValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as number (f64) if this is numeric.
    pub fn as_number(&self) -> Option<f64> {
        match self {
            ConstraintValue::Integer(i) => Some(*i as f64),
            ConstraintValue::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Get as list if this is a List variant.
    pub fn as_list(&self) -> Option<&Vec<ConstraintValue>> {
        match self {
            ConstraintValue::List(l) => Some(l),
            _ => None,
        }
    }
}

impl From<&str> for ConstraintValue {
    fn from(s: &str) -> Self {
        ConstraintValue::String(s.to_string())
    }
}

impl From<String> for ConstraintValue {
    fn from(s: String) -> Self {
        ConstraintValue::String(s)
    }
}

impl From<i64> for ConstraintValue {
    fn from(n: i64) -> Self {
        ConstraintValue::Integer(n)
    }
}

impl From<i32> for ConstraintValue {
    fn from(n: i32) -> Self {
        ConstraintValue::Integer(n as i64)
    }
}

impl From<f64> for ConstraintValue {
    fn from(n: f64) -> Self {
        ConstraintValue::Float(n)
    }
}

impl From<bool> for ConstraintValue {
    fn from(b: bool) -> Self {
        ConstraintValue::Boolean(b)
    }
}

impl<T: Into<ConstraintValue>> From<Vec<T>> for ConstraintValue {
    fn from(v: Vec<T>) -> Self {
        ConstraintValue::List(v.into_iter().map(Into::into).collect())
    }
}

impl std::fmt::Display for ConstraintValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConstraintValue::String(s) => write!(f, "{}", s),
            ConstraintValue::Integer(i) => write!(f, "{}", i),
            ConstraintValue::Float(n) => write!(f, "{}", n),
            ConstraintValue::Boolean(b) => write!(f, "{}", b),
            ConstraintValue::Null => write!(f, "null"),
            ConstraintValue::List(l) => {
                write!(f, "[")?;
                for (i, v) in l.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", v)?;
                }
                write!(f, "]")
            }
            ConstraintValue::Object(m) => {
                write!(f, "{{")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", k, v)?;
                }
                write!(f, "}}")
            }
        }
    }
}

// ============================================================================
// Pattern Constraint (Glob)
// ============================================================================

/// Glob-style pattern constraint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pattern {
    pub pattern: String,
    #[serde(skip)]
    compiled: Option<GlobPattern>,
}

impl Pattern {
    /// Create a new pattern constraint.
    pub fn new(pattern: &str) -> Result<Self> {
        let compiled = GlobPattern::new(pattern)
            .map_err(|e| Error::InvalidPattern(e.to_string()))?;
        Ok(Self {
            pattern: pattern.to_string(),
            compiled: Some(compiled),
        })
    }

    /// Get the pattern string.
    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    fn get_compiled(&self) -> Result<GlobPattern> {
        if let Some(ref compiled) = self.compiled {
            Ok(compiled.clone())
        } else {
            GlobPattern::new(&self.pattern)
                .map_err(|e| Error::InvalidPattern(e.to_string()))
        }
    }

    /// Check if a value matches this pattern.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        let compiled = self.get_compiled()?;
        match value {
            ConstraintValue::String(s) => Ok(compiled.matches(s)),
            _ => Ok(false),
        }
    }

    /// Validate that `child` is a valid attenuation of this pattern.
    pub fn validate_attenuation(&self, child: &Pattern) -> Result<()> {
        // Simple case: if patterns are equal, it's valid
        if self.pattern == child.pattern {
            return Ok(());
        }

        // Extract the prefix before the first wildcard
        let parent_parts: Vec<&str> = self.pattern.split('*').collect();
        let child_parts: Vec<&str> = child.pattern.split('*').collect();

        // Child must start with parent's prefix
        if !parent_parts.is_empty()
            && !child_parts.is_empty()
            && !child_parts[0].starts_with(parent_parts[0])
        {
            return Err(Error::MonotonicityViolation(format!(
                "pattern '{}' is not a subset of '{}'",
                child.pattern, self.pattern
            )));
        }

        // Child should have same or fewer wildcards
        if child.pattern.matches('*').count() > self.pattern.matches('*').count() {
            return Err(Error::MonotonicityViolation(format!(
                "pattern '{}' has more wildcards than parent '{}'",
                child.pattern, self.pattern
            )));
        }

        Ok(())
    }
}

impl From<Pattern> for Constraint {
    fn from(p: Pattern) -> Self {
        Constraint::Pattern(p)
    }
}

// ============================================================================
// Regex Constraint
// ============================================================================

/// Regular expression constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexConstraint {
    pub pattern: String,
    #[serde(skip)]
    compiled: Option<RegexPattern>,
}

impl PartialEq for RegexConstraint {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl RegexConstraint {
    /// Create a new regex constraint.
    pub fn new(pattern: &str) -> Result<Self> {
        let compiled = RegexPattern::new(pattern)
            .map_err(|e| Error::InvalidPattern(format!("invalid regex: {}", e)))?;
        Ok(Self {
            pattern: pattern.to_string(),
            compiled: Some(compiled),
        })
    }

    fn get_compiled(&self) -> Result<RegexPattern> {
        if let Some(ref compiled) = self.compiled {
            Ok(compiled.clone())
        } else {
            RegexPattern::new(&self.pattern)
                .map_err(|e| Error::InvalidPattern(format!("invalid regex: {}", e)))
        }
    }

    /// Check if a value matches this regex.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        let compiled = self.get_compiled()?;
        match value {
            ConstraintValue::String(s) => Ok(compiled.is_match(s)),
            _ => Ok(false),
        }
    }

    /// Validate attenuation (conservative: patterns must be equal or child more specific).
    pub fn validate_attenuation(&self, child: &RegexConstraint) -> Result<()> {
        // For regex, we can only safely allow equal patterns
        // (regex subset checking is undecidable in general)
        if self.pattern == child.pattern {
            return Ok(());
        }

        // Conservative: reject different patterns
        // In practice, users should switch to Exact for attenuation
        Err(Error::MonotonicityViolation(
            "regex attenuation requires pattern match; use Exact for specific values".to_string()
        ))
    }
}

impl From<RegexConstraint> for Constraint {
    fn from(r: RegexConstraint) -> Self {
        Constraint::Regex(r)
    }
}

// ============================================================================
// Exact Constraint
// ============================================================================

/// Exact value constraint (works for any value type).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Exact {
    pub value: ConstraintValue,
}

impl Exact {
    /// Create a new exact value constraint.
    pub fn new(value: impl Into<ConstraintValue>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Check if a value matches exactly.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        Ok(&self.value == value)
    }
}

impl From<Exact> for Constraint {
    fn from(e: Exact) -> Self {
        Constraint::Exact(e)
    }
}

// ============================================================================
// OneOf Constraint
// ============================================================================

/// One-of constraint (value must be in allowed set).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OneOf {
    pub values: Vec<ConstraintValue>,
}

impl OneOf {
    /// Create a new one-of constraint from strings.
    pub fn new<S: Into<String>>(values: impl IntoIterator<Item = S>) -> Self {
        Self {
            values: values.into_iter().map(|s| ConstraintValue::String(s.into())).collect(),
        }
    }

    /// Create a one-of constraint from any values.
    pub fn from_values(values: impl IntoIterator<Item = impl Into<ConstraintValue>>) -> Self {
        Self {
            values: values.into_iter().map(Into::into).collect(),
        }
    }

    /// Check if this set contains a value.
    pub fn contains(&self, value: &ConstraintValue) -> bool {
        self.values.contains(value)
    }

    /// Check if a value is in the allowed set.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        Ok(self.contains(value))
    }

    /// Validate that `child` is a valid attenuation (subset of parent values).
    pub fn validate_attenuation(&self, child: &OneOf) -> Result<()> {
        for v in &child.values {
            if !self.contains(v) {
                return Err(Error::MonotonicityViolation(format!(
                    "value '{:?}' in child is not in parent set",
                    v
                )));
            }
        }
        Ok(())
    }
}

impl From<OneOf> for Constraint {
    fn from(o: OneOf) -> Self {
        Constraint::OneOf(o)
    }
}

// ============================================================================
// Range Constraint
// ============================================================================

/// Numeric range constraint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Range {
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub min_inclusive: bool,
    pub max_inclusive: bool,
}

impl Range {
    /// Create a new range constraint with inclusive bounds.
    pub fn new(min: Option<f64>, max: Option<f64>) -> Self {
        Self {
            min,
            max,
            min_inclusive: true,
            max_inclusive: true,
        }
    }

    /// Create a range with only a maximum value.
    pub fn max(max: f64) -> Self {
        Self::new(None, Some(max))
    }

    /// Create a range with only a minimum value.
    pub fn min(min: f64) -> Self {
        Self::new(Some(min), None)
    }

    /// Create a range between min and max.
    pub fn between(min: f64, max: f64) -> Self {
        Self::new(Some(min), Some(max))
    }

    /// Set whether the minimum bound is inclusive.
    pub fn min_exclusive(mut self) -> Self {
        self.min_inclusive = false;
        self
    }

    /// Set whether the maximum bound is inclusive.
    pub fn max_exclusive(mut self) -> Self {
        self.max_inclusive = false;
        self
    }

    /// Check if a value is within the range.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        let n = match value.as_number() {
            Some(n) => n,
            None => return Ok(false),
        };

        let min_ok = match self.min {
            None => true,
            Some(min) if self.min_inclusive => n >= min,
            Some(min) => n > min,
        };

        let max_ok = match self.max {
            None => true,
            Some(max) if self.max_inclusive => n <= max,
            Some(max) => n < max,
        };

        Ok(min_ok && max_ok)
    }

    /// Validate that `child` is a valid attenuation (subset of parent range).
    pub fn validate_attenuation(&self, child: &Range) -> Result<()> {
        // Child min must be >= parent min
        match (self.min, child.min) {
            (Some(parent_min), Some(child_min)) if child_min < parent_min => {
                return Err(Error::MonotonicityViolation(format!(
                    "child min {} is less than parent min {}",
                    child_min, parent_min
                )));
            }
            (Some(parent_min), None) => {
                return Err(Error::MonotonicityViolation(format!(
                    "child has no min but parent requires >= {}",
                    parent_min
                )));
            }
            _ => {}
        }

        // Child max must be <= parent max
        match (self.max, child.max) {
            (Some(parent_max), Some(child_max)) if child_max > parent_max => {
                return Err(Error::MonotonicityViolation(format!(
                    "child max {} is greater than parent max {}",
                    child_max, parent_max
                )));
            }
            (Some(parent_max), None) => {
                return Err(Error::MonotonicityViolation(format!(
                    "child has no max but parent requires <= {}",
                    parent_max
                )));
            }
            _ => {}
        }

        Ok(())
    }
}

impl From<Range> for Constraint {
    fn from(r: Range) -> Self {
        Constraint::Range(r)
    }
}

// ============================================================================
// Contains Constraint (List must contain specified values)
// ============================================================================

/// Constraint that a list value must contain specified values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Contains {
    /// Values that must be present in the list.
    pub required: Vec<ConstraintValue>,
}

impl Contains {
    /// Create a new contains constraint.
    pub fn new(required: impl IntoIterator<Item = impl Into<ConstraintValue>>) -> Self {
        Self {
            required: required.into_iter().map(Into::into).collect(),
        }
    }

    /// Check if a list value contains all required values.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        let list = match value.as_list() {
            Some(l) => l,
            None => return Ok(false),
        };

        Ok(self.required.iter().all(|r| list.contains(r)))
    }

    /// Validate attenuation: child can require MORE values (stricter).
    pub fn validate_attenuation(&self, child: &Contains) -> Result<()> {
        // Child must contain all parent's required values (can add more)
        for v in &self.required {
            if !child.required.contains(v) {
                return Err(Error::MonotonicityViolation(format!(
                    "child must still require {:?}",
                    v
                )));
            }
        }
        Ok(())
    }
}

impl From<Contains> for Constraint {
    fn from(c: Contains) -> Self {
        Constraint::Contains(c)
    }
}

// ============================================================================
// Subset Constraint (List must be subset of allowed values)
// ============================================================================

/// Constraint that a list value must be a subset of allowed values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Subset {
    /// Allowed values (superset).
    pub allowed: Vec<ConstraintValue>,
}

impl Subset {
    /// Create a new subset constraint.
    pub fn new(allowed: impl IntoIterator<Item = impl Into<ConstraintValue>>) -> Self {
        Self {
            allowed: allowed.into_iter().map(Into::into).collect(),
        }
    }

    /// Check if a list value is a subset of allowed values.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        let list = match value.as_list() {
            Some(l) => l,
            None => return Ok(false),
        };

        Ok(list.iter().all(|v| self.allowed.contains(v)))
    }

    /// Validate attenuation: child's allowed set must be ⊆ parent's allowed set.
    pub fn validate_attenuation(&self, child: &Subset) -> Result<()> {
        for v in &child.allowed {
            if !self.allowed.contains(v) {
                return Err(Error::MonotonicityViolation(format!(
                    "child allows {:?} which parent does not allow",
                    v
                )));
            }
        }
        Ok(())
    }
}

impl From<Subset> for Constraint {
    fn from(s: Subset) -> Self {
        Constraint::Subset(s)
    }
}

// ============================================================================
// Composite Constraints: All, Any, Not
// ============================================================================

/// All constraints must match (AND).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct All {
    pub constraints: Vec<Constraint>,
}

impl All {
    /// Create a new All constraint.
    pub fn new(constraints: impl IntoIterator<Item = Constraint>) -> Self {
        Self {
            constraints: constraints.into_iter().collect(),
        }
    }

    /// Check if all constraints match.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        for c in &self.constraints {
            if !c.matches(value)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Validate attenuation: child must have all parent constraints plus optionally more.
    pub fn validate_attenuation(&self, child: &All) -> Result<()> {
        // Every parent constraint must appear in child
        for parent_c in &self.constraints {
            let found = child.constraints.iter().any(|child_c| {
                parent_c.validate_attenuation(child_c).is_ok()
            });
            if !found {
                return Err(Error::MonotonicityViolation(
                    "child All must include all parent constraints".to_string()
                ));
            }
        }
        Ok(())
    }
}

impl From<All> for Constraint {
    fn from(a: All) -> Self {
        Constraint::All(a)
    }
}

/// At least one constraint must match (OR).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Any {
    pub constraints: Vec<Constraint>,
}

impl Any {
    /// Create a new Any constraint.
    pub fn new(constraints: impl IntoIterator<Item = Constraint>) -> Self {
        Self {
            constraints: constraints.into_iter().collect(),
        }
    }

    /// Check if any constraint matches.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        for c in &self.constraints {
            if c.matches(value)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl From<Any> for Constraint {
    fn from(a: Any) -> Self {
        Constraint::Any(a)
    }
}

/// Negation of a constraint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Not {
    pub constraint: Box<Constraint>,
}

impl Not {
    /// Create a new Not constraint.
    pub fn new(constraint: Constraint) -> Self {
        Self {
            constraint: Box::new(constraint),
        }
    }

    /// Check if the inner constraint does NOT match.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        Ok(!self.constraint.matches(value)?)
    }
}

impl From<Not> for Constraint {
    fn from(n: Not) -> Self {
        Constraint::Not(n)
    }
}

// ============================================================================
// CEL Expression Constraint
// ============================================================================

/// CEL (Common Expression Language) constraint.
///
/// CEL allows complex, composable expressions for authorization logic.
/// Expressions are compiled and cached for performance.
///
/// # Example
///
/// ```rust,ignore
/// // Simple comparison
/// CelConstraint::new("amount < 10000")
///
/// // Complex logic with approval
/// CelConstraint::new("amount < 10000 || (amount < 100000 && approver != '')")
///
/// // List membership
/// CelConstraint::new("'admin' in roles")
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CelConstraint {
    /// The CEL expression as a string.
    pub expression: String,
    /// Optional parent expression for attenuation tracking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_expression: Option<String>,
}

impl CelConstraint {
    /// Create a new CEL constraint.
    ///
    /// The expression will be compiled and validated on first use.
    pub fn new(expression: impl Into<String>) -> Self {
        Self {
            expression: expression.into(),
            parent_expression: None,
        }
    }

    /// Create an attenuated CEL constraint from a parent.
    ///
    /// The child expression is automatically formatted as:
    /// `(parent_expression) && new_predicate`
    pub fn attenuate(parent: &CelConstraint, additional_predicate: &str) -> Self {
        Self {
            expression: format!("({}) && {}", parent.expression, additional_predicate),
            parent_expression: Some(parent.expression.clone()),
        }
    }

    /// Validate the CEL expression syntax.
    ///
    /// This compiles the expression without evaluating it.
    pub fn validate(&self) -> Result<()> {
        crate::cel::compile(&self.expression)?;
        Ok(())
    }

    /// Check if a value satisfies the CEL expression.
    ///
    /// For object values, each field becomes a top-level variable.
    /// For primitive values, the value is available as `value`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // For object: {"amount": 5000, "currency": "USD"}
    /// // Expression can use: amount < 10000 && currency == "USD"
    ///
    /// // For primitive: 5000
    /// // Expression can use: value < 10000
    /// ```
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        crate::cel::evaluate_with_value_context(&self.expression, value)
    }

    /// Evaluate with additional context variables.
    pub fn matches_with_context(
        &self,
        value: &ConstraintValue,
        context: &HashMap<String, ConstraintValue>,
    ) -> Result<bool> {
        crate::cel::evaluate(&self.expression, value, context)
    }

    /// Validate that `child` is a valid attenuation.
    ///
    /// Child CEL constraints must take the form: `(parent_expression) && new_predicate`
    ///
    /// This ensures monotonicity: the child can only add restrictions, not remove them.
    pub fn validate_attenuation(&self, child: &CelConstraint) -> Result<()> {
        // Same expression is always valid
        if child.expression == self.expression {
            return Ok(());
        }

        // Child must be a conjunction with parent
        let expected_prefix = format!("({}) && ", self.expression);
        
        if !child.expression.starts_with(&expected_prefix) {
            return Err(Error::MonotonicityViolation(format!(
                "child CEL must be '({}) && <predicate>', got '{}'",
                self.expression, child.expression
            )));
        }

        // Validate the child expression compiles
        child.validate()?;

        Ok(())
    }
}

impl From<CelConstraint> for Constraint {
    fn from(c: CelConstraint) -> Self {
        Constraint::Cel(c)
    }
}

// ============================================================================
// Constraint Set
// ============================================================================

/// A set of constraints keyed by field name.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ConstraintSet {
    constraints: HashMap<String, Constraint>,
}

impl ConstraintSet {
    /// Create a new empty constraint set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a constraint for a field.
    pub fn insert(&mut self, field: impl Into<String>, constraint: impl Into<Constraint>) {
        self.constraints.insert(field.into(), constraint.into());
    }

    /// Get a constraint for a field.
    pub fn get(&self, field: &str) -> Option<&Constraint> {
        self.constraints.get(field)
    }

    /// Check if all constraints are satisfied by the given arguments.
    pub fn matches(&self, args: &HashMap<String, ConstraintValue>) -> Result<()> {
        for (field, constraint) in &self.constraints {
            let value = args.get(field).ok_or_else(|| Error::ConstraintNotSatisfied {
                field: field.clone(),
                reason: "missing required argument".to_string(),
            })?;

            if !constraint.matches(value)? {
                return Err(Error::ConstraintNotSatisfied {
                    field: field.clone(),
                    reason: "value does not match constraint".to_string(),
                });
            }
        }
        Ok(())
    }

    /// Validate that `child` is a valid attenuation of this constraint set.
    pub fn validate_attenuation(&self, child: &ConstraintSet) -> Result<()> {
        // Check each parent constraint has a valid child constraint
        for (field, parent_constraint) in &self.constraints {
            let child_constraint = child.constraints.get(field).ok_or_else(|| {
                Error::MonotonicityViolation(format!(
                    "child is missing constraint for field '{}' that parent has",
                    field
                ))
            })?;

            parent_constraint.validate_attenuation(child_constraint)?;
        }

        // Child can have additional constraints (that's more restrictive)
        Ok(())
    }

    /// Iterate over all constraints.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Constraint)> {
        self.constraints.iter()
    }

    /// Check if the constraint set is empty.
    pub fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }

    /// Get the number of constraints.
    pub fn len(&self) -> usize {
        self.constraints.len()
    }
}

impl FromIterator<(String, Constraint)> for ConstraintSet {
    fn from_iter<T: IntoIterator<Item = (String, Constraint)>>(iter: T) -> Self {
        Self {
            constraints: iter.into_iter().collect(),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matches() {
        let pattern = Pattern::new("staging-*").unwrap();
        assert!(pattern.matches(&"staging-web".into()).unwrap());
        assert!(pattern.matches(&"staging-api".into()).unwrap());
        assert!(!pattern.matches(&"prod-web".into()).unwrap());
    }

    #[test]
    fn test_regex_matches() {
        let regex = RegexConstraint::new(r"^prod-[a-z]+$").unwrap();
        assert!(regex.matches(&"prod-web".into()).unwrap());
        assert!(regex.matches(&"prod-api".into()).unwrap());
        assert!(!regex.matches(&"prod-123".into()).unwrap());
        assert!(!regex.matches(&"staging-web".into()).unwrap());
    }

    #[test]
    fn test_exact_matches_various_types() {
        // String
        let exact = Exact::new("hello");
        assert!(exact.matches(&"hello".into()).unwrap());
        assert!(!exact.matches(&"world".into()).unwrap());

        // Number
        let exact = Exact::new(42i64);
        assert!(exact.matches(&42i64.into()).unwrap());
        assert!(!exact.matches(&43i64.into()).unwrap());

        // Boolean
        let exact = Exact::new(true);
        assert!(exact.matches(&true.into()).unwrap());
        assert!(!exact.matches(&false.into()).unwrap());
    }

    #[test]
    fn test_range_matches() {
        let range = Range::between(10.0, 100.0);
        assert!(range.matches(&50i64.into()).unwrap());
        assert!(range.matches(&10i64.into()).unwrap());
        assert!(range.matches(&100i64.into()).unwrap());
        assert!(!range.matches(&5i64.into()).unwrap());
        assert!(!range.matches(&150i64.into()).unwrap());
    }

    #[test]
    fn test_contains_constraint() {
        let contains = Contains::new(["admin", "write"]);
        
        let has_both: ConstraintValue = vec!["admin", "write", "read"]
            .into_iter()
            .map(|s| ConstraintValue::String(s.to_string()))
            .collect::<Vec<_>>()
            .into();
        assert!(contains.matches(&has_both).unwrap());

        let missing_one: ConstraintValue = vec!["admin", "read"]
            .into_iter()
            .map(|s| ConstraintValue::String(s.to_string()))
            .collect::<Vec<_>>()
            .into();
        assert!(!contains.matches(&missing_one).unwrap());
    }

    #[test]
    fn test_subset_constraint() {
        let subset = Subset::new(["read", "write", "admin"]);
        
        let valid: ConstraintValue = vec!["read", "write"]
            .into_iter()
            .map(|s| ConstraintValue::String(s.to_string()))
            .collect::<Vec<_>>()
            .into();
        assert!(subset.matches(&valid).unwrap());

        let invalid: ConstraintValue = vec!["read", "delete"]
            .into_iter()
            .map(|s| ConstraintValue::String(s.to_string()))
            .collect::<Vec<_>>()
            .into();
        assert!(!subset.matches(&invalid).unwrap());
    }

    #[test]
    fn test_all_constraint() {
        let all = All::new([
            Range::min(0.0).into(),
            Range::max(100.0).into(),
        ]);

        assert!(all.matches(&50i64.into()).unwrap());
        assert!(!all.matches(&(-10i64).into()).unwrap());
        assert!(!all.matches(&150i64.into()).unwrap());
    }

    #[test]
    fn test_any_constraint() {
        let any = Any::new([
            Exact::new("admin").into(),
            Exact::new("superuser").into(),
        ]);

        assert!(any.matches(&"admin".into()).unwrap());
        assert!(any.matches(&"superuser".into()).unwrap());
        assert!(!any.matches(&"user".into()).unwrap());
    }

    #[test]
    fn test_not_constraint() {
        let not = Not::new(Exact::new("blocked").into());

        assert!(not.matches(&"allowed".into()).unwrap());
        assert!(!not.matches(&"blocked".into()).unwrap());
    }

    #[test]
    fn test_pattern_attenuation() {
        let parent = Pattern::new("staging-*").unwrap();
        let valid_child = Pattern::new("staging-web").unwrap();
        assert!(parent.validate_attenuation(&valid_child).is_ok());

        let invalid_child = Pattern::new("prod-*").unwrap();
        assert!(parent.validate_attenuation(&invalid_child).is_err());
    }

    #[test]
    fn test_range_attenuation() {
        let parent = Range::max(10000.0);
        let valid_child = Range::max(5000.0);
        assert!(parent.validate_attenuation(&valid_child).is_ok());

        let invalid_child = Range::max(15000.0);
        assert!(parent.validate_attenuation(&invalid_child).is_err());
    }

    #[test]
    fn test_subset_attenuation() {
        let parent = Subset::new(["a", "b", "c"]);
        let valid_child = Subset::new(["a", "b"]);  // Smaller allowed set
        assert!(parent.validate_attenuation(&valid_child).is_ok());

        let invalid_child = Subset::new(["a", "d"]);  // 'd' not in parent
        assert!(parent.validate_attenuation(&invalid_child).is_err());
    }

    #[test]
    fn test_constraint_set_validation() {
        let mut parent = ConstraintSet::new();
        parent.insert("cluster", Pattern::new("staging-*").unwrap());
        parent.insert("version", Pattern::new("1.28.*").unwrap());

        let mut child = ConstraintSet::new();
        child.insert("cluster", Exact::new("staging-web"));
        child.insert("version", Pattern::new("1.28.5").unwrap());

        assert!(parent.validate_attenuation(&child).is_ok());
    }
}
