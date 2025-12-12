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
//! | `Wildcard` | Matches anything | `*` (unconstrained) |
//! | `Pattern` | Glob matching | `staging-*` |
//! | `Regex` | Regular expression | `^prod-[a-z]+$` |
//! | `Exact` | Exact value | `"staging-web"` or `42` |
//! | `OneOf` | Value in set | `["a", "b", "c"]` |
//! | `NotOneOf` | Value NOT in set | `!["prod", "secure"]` |
//! | `Range` | Numeric/date bounds | `0..10000` |
//! | `Contains` | List contains value | `["admin"] ⊆ roles` |
//! | `Subset` | List is subset | `requested ⊆ allowed` |
//! | `All` | All constraints must match | `AND(a, b, c)` |
//! | `Any` | At least one must match | `OR(a, b, c)` |
//! | `Not` | Negation (unsafe) | `NOT(pattern)` - avoid |
//! | `Cel` | CEL expression | `amount < 10000` |
//!
//! ## Security: Constraint Depth Limit
//!
//! Recursive constraint types (`All`, `Any`, `Not`) are limited to a maximum
//! nesting depth of [`MAX_CONSTRAINT_DEPTH`] (16) to prevent stack overflow
//! attacks from maliciously crafted warrants.

use crate::error::{Error, Result};

/// Maximum allowed nesting depth for recursive constraints (All, Any, Not).
/// 
/// This prevents stack overflow attacks from deeply nested constraints like
/// `Not(Not(Not(...)))` or `All([All([All([...])])])`.
/// 
/// Depth 16 allows for complex real-world policies while preventing abuse.
pub const MAX_CONSTRAINT_DEPTH: u32 = 16;
use glob::Pattern as GlobPattern;
use regex::Regex as RegexPattern;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::cell::Cell;

thread_local! {
    static DESERIALIZATION_DEPTH: Cell<usize> = const { Cell::new(0) };
}

struct DepthGuard;

impl DepthGuard {
    fn new<E: serde::de::Error>() -> std::result::Result<Self, E> {
        DESERIALIZATION_DEPTH.with(|depth| {
            let d = depth.get();
            if d > MAX_CONSTRAINT_DEPTH as usize {
                return Err(E::custom(format!(
                    "constraint recursion depth exceeded maximum of {}", 
                    MAX_CONSTRAINT_DEPTH
                )));
            }
            depth.set(d + 1);
            Ok(DepthGuard)
        })
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        DESERIALIZATION_DEPTH.with(|depth| {
            depth.set(depth.get() - 1);
        });
    }
}

/// A constraint on an argument value.
/// 
/// **Security**: Custom deserialization validates nesting depth to prevent
/// stack overflow attacks from maliciously nested constraints like `Not(Not(Not(...)))`.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum Constraint {
    /// Wildcard - matches anything. The universal superset.
    /// Can be attenuated to any other constraint type.
    Wildcard(Wildcard),
    
    /// Glob-style pattern matching (e.g., "staging-*").
    Pattern(Pattern),
    
    /// Regular expression matching.
    Regex(RegexConstraint),
    
    /// Exact value match (works for strings, numbers, bools).
    Exact(Exact),
    
    /// One of a set of allowed values.
    OneOf(OneOf),
    
    /// Value must NOT be in the excluded set ("carving holes").
    /// 
    /// Use this to exclude specific values from a broader allowlist.
    /// Must be combined with a positive constraint (Wildcard, Pattern, etc.)
    /// in a parent warrant.
    /// 
    /// **Security Rule**: Never start with negation! Always start with
    /// a positive allowlist and use NotOneOf to "carve holes" in children.
    NotOneOf(NotOneOf),
    
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

// Custom Deserialize to enforce constraint depth validation
impl<'de> serde::Deserialize<'de> for Constraint {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let _guard = DepthGuard::new::<D::Error>()?;

        // Helper enum for raw deserialization (same structure, no validation)
        #[derive(serde::Deserialize)]
        #[serde(tag = "type", content = "value")]
        enum ConstraintRaw {
            Wildcard(Wildcard),
            Pattern(Pattern),
            Regex(RegexConstraint),
            Exact(Exact),
            OneOf(OneOf),
            NotOneOf(NotOneOf),
            Range(Range),
            Contains(Contains),
            Subset(Subset),
            All(AllRaw),
            Any(AnyRaw),
            Not(NotRaw),
            Cel(CelConstraint),
        }

        // Raw versions of recursive types that deserialize to Constraint
        #[derive(serde::Deserialize)]
        struct AllRaw { constraints: Vec<Constraint> }
        #[derive(serde::Deserialize)]
        struct AnyRaw { constraints: Vec<Constraint> }
        #[derive(serde::Deserialize)]
        struct NotRaw { constraint: Box<Constraint> }

        let raw = ConstraintRaw::deserialize(deserializer)?;

        let constraint = match raw {
            ConstraintRaw::Wildcard(v) => Constraint::Wildcard(v),
            ConstraintRaw::Pattern(v) => Constraint::Pattern(v),
            ConstraintRaw::Regex(v) => Constraint::Regex(v),
            ConstraintRaw::Exact(v) => Constraint::Exact(v),
            ConstraintRaw::OneOf(v) => Constraint::OneOf(v),
            ConstraintRaw::NotOneOf(v) => Constraint::NotOneOf(v),
            ConstraintRaw::Range(v) => Constraint::Range(v),
            ConstraintRaw::Contains(v) => Constraint::Contains(v),
            ConstraintRaw::Subset(v) => Constraint::Subset(v),
            ConstraintRaw::All(v) => Constraint::All(All { constraints: v.constraints }),
            ConstraintRaw::Any(v) => Constraint::Any(Any { constraints: v.constraints }),
            ConstraintRaw::Not(v) => Constraint::Not(Not { constraint: v.constraint }),
            ConstraintRaw::Cel(v) => Constraint::Cel(v),
        };

        // Validate depth after full deserialization
        constraint.validate_depth().map_err(serde::de::Error::custom)?;

        Ok(constraint)
    }
}

impl Constraint {
    /// Calculate the maximum nesting depth of this constraint.
    /// 
    /// Non-recursive constraints have depth 0.
    /// `All`, `Any`, and `Not` add 1 to their children's depth.
    /// 
    /// This is used to prevent stack overflow attacks from deeply nested
    /// constraints like `Not(Not(Not(...)))`.
    pub fn depth(&self) -> u32 {
        match self {
            // Non-recursive types have depth 0
            Constraint::Wildcard(_)
            | Constraint::Pattern(_)
            | Constraint::Regex(_)
            | Constraint::Exact(_)
            | Constraint::OneOf(_)
            | Constraint::NotOneOf(_)
            | Constraint::Range(_)
            | Constraint::Contains(_)
            | Constraint::Subset(_)
            | Constraint::Cel(_) => 0,
            
            // Recursive types: 1 + max child depth
            Constraint::All(all) => {
                1 + all.constraints.iter().map(|c| c.depth()).max().unwrap_or(0)
            }
            Constraint::Any(any) => {
                1 + any.constraints.iter().map(|c| c.depth()).max().unwrap_or(0)
            }
            Constraint::Not(not) => {
                1 + not.constraint.depth()
            }
        }
    }
    
    /// Validate that this constraint's nesting depth doesn't exceed the limit.
    /// 
    /// Returns `Ok(())` if depth <= `MAX_CONSTRAINT_DEPTH`.
    /// Returns `Err(ConstraintDepthExceeded)` if depth exceeds the limit.
    /// 
    /// Call this after deserializing or before using untrusted constraints.
    pub fn validate_depth(&self) -> Result<()> {
        let depth = self.depth();
        if depth > MAX_CONSTRAINT_DEPTH {
            Err(Error::ConstraintDepthExceeded {
                depth,
                max: MAX_CONSTRAINT_DEPTH,
            })
        } else {
            Ok(())
        }
    }
    
    /// Check if this constraint is satisfied by the given value.
    /// 
    /// **Note**: This method does not check depth limits. Call `validate_depth()`
    /// first on untrusted constraints to prevent stack overflow.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        match self {
            Constraint::Wildcard(_) => Ok(true), // Wildcard matches everything
            Constraint::Pattern(p) => p.matches(value),
            Constraint::Regex(r) => r.matches(value),
            Constraint::Exact(e) => e.matches(value),
            Constraint::OneOf(o) => o.matches(value),
            Constraint::NotOneOf(n) => n.matches(value),
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
            // Wildcard can attenuate to ANYTHING (it's the universal superset)
            (Constraint::Wildcard(_), _) => Ok(()),
            
            // Nothing can attenuate TO Wildcard (would expand permissions)
            (_, Constraint::Wildcard(_)) => Err(Error::WildcardExpansion {
                parent_type: self.type_name().to_string(),
            }),
            
            // Pattern can narrow to Pattern or Exact
            (Constraint::Pattern(parent), Constraint::Pattern(child_pat)) => {
                parent.validate_attenuation(child_pat)
            }
            (Constraint::Pattern(parent), Constraint::Exact(child_exact)) => {
                if parent.matches(&child_exact.value)? {
                    Ok(())
                } else {
                    Err(Error::ValueNotInParentSet {
                        value: format!("{:?}", child_exact.value),
                    })
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
                    Err(Error::ValueNotInParentSet {
                        value: format!("{:?}", child_exact.value),
                    })
                }
            }
            
            // Exact can only stay Exact with same value
            (Constraint::Exact(parent), Constraint::Exact(child)) => {
                if parent.value == child.value {
                    Ok(())
                } else {
                    Err(Error::ExactValueMismatch {
                        parent: format!("{:?}", parent.value),
                        child: format!("{:?}", child.value),
                    })
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
                    Err(Error::ValueNotInParentSet {
                        value: format!("{:?}", child.value),
                    })
                }
            }
            // OneOf can narrow to NotOneOf (carving holes from the allowed set)
            (Constraint::OneOf(parent), Constraint::NotOneOf(child)) => {
                // Warn if this would result in an empty set (paradox)
                let remaining: Vec<_> = parent.values.iter()
                    .filter(|v| !child.excluded.contains(v))
                    .collect();
                if remaining.is_empty() {
                    return Err(Error::EmptyResultSet {
                        parent_type: "OneOf".to_string(),
                        count: parent.values.len(),
                    });
                }
                Ok(())
            }
            
            // NotOneOf can add more exclusions (carving more holes)
            (Constraint::NotOneOf(parent), Constraint::NotOneOf(child)) => {
                parent.validate_attenuation(child)
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
            _ => Err(Error::IncompatibleConstraintTypes {
                parent_type: self.type_name().to_string(),
                child_type: child.type_name().to_string(),
            }),
        }
    }
    
    /// Get the type name of this constraint for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Constraint::Wildcard(_) => "Wildcard",
            Constraint::Pattern(_) => "Pattern",
            Constraint::Regex(_) => "Regex",
            Constraint::Exact(_) => "Exact",
            Constraint::OneOf(_) => "OneOf",
            Constraint::NotOneOf(_) => "NotOneOf",
            Constraint::Range(_) => "Range",
            Constraint::Contains(_) => "Contains",
            Constraint::Subset(_) => "Subset",
            Constraint::All(_) => "All",
            Constraint::Any(_) => "Any",
            Constraint::Not(_) => "Not",
            Constraint::Cel(_) => "Cel",
        }
    }
}

// ============================================================================
// Constraint Values
// ============================================================================

/// Value that can be matched against constraints.
/// 
/// Note: Object uses BTreeMap for deterministic serialization order.
/// This ensures canonical CBOR encoding for consistent warrant IDs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ConstraintValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    List(Vec<ConstraintValue>),
    Object(BTreeMap<String, ConstraintValue>),
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
// Wildcard Constraint (Universal Superset)
// ============================================================================

/// Wildcard constraint - matches any value.
///
/// This is the universal superset. It can be attenuated to ANY other
/// constraint type, making it ideal for root warrants where you want
/// to leave a field unconstrained but allow children to restrict it.
///
/// # Example
///
/// ```rust,ignore
/// // Root warrant: allow any action
/// .constraint("action", Wildcard)
///
/// // Child warrant: narrow to specific actions
/// .constraint("action", OneOf::new(vec!["upgrade", "restart"]))
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Wildcard;

impl Wildcard {
    /// Create a new wildcard constraint.
    pub fn new() -> Self {
        Self
    }

    /// Wildcard matches any value.
    pub fn matches(&self, _value: &ConstraintValue) -> Result<bool> {
        Ok(true)
    }
}

impl From<Wildcard> for Constraint {
    fn from(w: Wildcard) -> Self {
        Constraint::Wildcard(w)
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
    ///
    /// Tenuo supports **single-wildcard patterns** only:
    /// - **Prefix patterns**: `"staging-*"` (wildcard at end)
    /// - **Suffix patterns**: `"*-safe"` (wildcard at start)
    /// - **Exact patterns**: `"staging-web"` (no wildcard)
    ///
    /// For attenuation to be valid, child must match a **subset** of parent:
    /// - `"staging-*"` → `"staging-web-*"` ✓ (prefix extended)
    /// - `"staging-*"` → `"staging-web"` ✓ (wildcard removed)
    /// - `"*-safe"` → `"*-extra-safe"` ✓ (suffix extended)
    /// - `"*-safe"` → `"image-safe"` ✓ (wildcard removed)
    /// - `"*-safe"` → `"*"` ✗ (suffix removed, expands match set)
    ///
    /// Patterns with wildcard in the middle or multiple wildcards require
    /// exact equality (conservative for security).
    pub fn validate_attenuation(&self, child: &Pattern) -> Result<()> {
        // Equal patterns always valid
        if self.pattern == child.pattern {
            return Ok(());
        }

        let parent_type = self.pattern_type();
        let child_type = child.pattern_type();

        match (parent_type, child_type) {
            // Exact parent: child must be equal (already checked above)
            (PatternType::Exact, _) => {
                Err(Error::PatternExpanded {
                    parent: self.pattern.clone(),
                    child: child.pattern.clone(),
                })
            }

            // Prefix pattern: "staging-*"
            (PatternType::Prefix(parent_prefix), PatternType::Prefix(child_prefix)) => {
                // Child prefix must extend parent prefix
                if child_prefix.starts_with(parent_prefix) {
                    Ok(())
                } else {
                    Err(Error::PatternExpanded {
                        parent: self.pattern.clone(),
                        child: child.pattern.clone(),
                    })
                }
            }
            (PatternType::Prefix(parent_prefix), PatternType::Exact) => {
                // Child is exact, must match parent's prefix
                if child.pattern.starts_with(parent_prefix) {
                    Ok(())
                } else {
                    Err(Error::PatternExpanded {
                        parent: self.pattern.clone(),
                        child: child.pattern.clone(),
                    })
                }
            }

            // Suffix pattern: "*-safe"
            (PatternType::Suffix(parent_suffix), PatternType::Suffix(child_suffix)) => {
                // Child suffix must extend parent suffix
                if child_suffix.ends_with(parent_suffix) {
                    Ok(())
                } else {
                    Err(Error::PatternExpanded {
                        parent: self.pattern.clone(),
                        child: child.pattern.clone(),
                    })
                }
            }
            (PatternType::Suffix(parent_suffix), PatternType::Exact) => {
                // Child is exact, must match parent's suffix
                if child.pattern.ends_with(parent_suffix) {
                    Ok(())
                } else {
                    Err(Error::PatternExpanded {
                        parent: self.pattern.clone(),
                        child: child.pattern.clone(),
                    })
                }
            }

            // Complex patterns (infix, multiple wildcards): require equality
            (PatternType::Complex, _) | (_, PatternType::Complex) => {
                Err(Error::PatternExpanded {
                    parent: self.pattern.clone(),
                    child: child.pattern.clone(),
                })
            }

            // Prefix cannot attenuate to suffix or vice versa
            _ => {
                Err(Error::PatternExpanded {
                    parent: self.pattern.clone(),
                    child: child.pattern.clone(),
                })
            }
        }
    }

    /// Classify the pattern type for attenuation validation.
    fn pattern_type(&self) -> PatternType<'_> {
        let star_count = self.pattern.matches('*').count();

        match star_count {
            0 => PatternType::Exact,
            1 => {
                if self.pattern.ends_with('*') {
                    // "prefix-*" → Prefix pattern
                    PatternType::Prefix(&self.pattern[..self.pattern.len() - 1])
                } else if self.pattern.starts_with('*') {
                    // "*-suffix" → Suffix pattern
                    PatternType::Suffix(&self.pattern[1..])
                } else {
                    // "pre-*-suf" → Complex (not supported for attenuation)
                    PatternType::Complex
                }
            }
            _ => PatternType::Complex,
        }
    }
}

/// Pattern classification for attenuation validation.
#[derive(Debug)]
enum PatternType<'a> {
    /// No wildcards: exact match only
    Exact,
    /// Single `*` at end: `"staging-*"`
    Prefix(&'a str),
    /// Single `*` at start: `"*-safe"`
    Suffix(&'a str),
    /// Wildcard in middle or multiple wildcards
    Complex,
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
                return Err(Error::ValueNotInParentSet {
                    value: format!("{:?}", v),
                });
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
// NotOneOf Constraint (Exclusion / "Carving Holes")
// ============================================================================

/// Exclusion constraint - value must NOT be in the excluded set.
///
/// This is the safe way to do negation. Use it to "carve holes" from a
/// broader allowlist defined in a parent warrant.
///
/// # Security Rule: Never Start with Negation
///
/// **Bad (Blacklisting)**:
/// ```rust,ignore
/// // Root: Exclude prod-db
/// .constraint("cluster", NotOneOf::new(vec!["prod-db"]))
/// // Risk: New cluster "secure-vault" is automatically allowed!
/// ```
///
/// **Good (Whitelisting with Exceptions)**:
/// ```rust,ignore
/// // Root: Allow all staging clusters
/// .constraint("cluster", Pattern::new("staging-*")?)
///
/// // Child: Exclude the DB cluster
/// .constraint("cluster", NotOneOf::new(vec!["staging-db"]))
/// // Safety: Only staging clusters are ever considered
/// ```
///
/// # Attenuation
///
/// Child can exclude MORE values (grow the exclusion set).
/// This shrinks the effective allowed set, maintaining monotonicity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotOneOf {
    /// Values to exclude.
    pub excluded: Vec<ConstraintValue>,
}

impl NotOneOf {
    /// Create a new exclusion constraint.
    pub fn new(excluded: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            excluded: excluded.into_iter()
                .map(|s| ConstraintValue::String(s.into()))
                .collect(),
        }
    }

    /// Create from any constraint values.
    pub fn from_values(excluded: impl IntoIterator<Item = impl Into<ConstraintValue>>) -> Self {
        Self {
            excluded: excluded.into_iter().map(Into::into).collect(),
        }
    }

    /// Check if a value is excluded.
    pub fn is_excluded(&self, value: &ConstraintValue) -> bool {
        self.excluded.contains(value)
    }

    /// Check if a value passes (is NOT excluded).
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        Ok(!self.is_excluded(value))
    }

    /// Validate attenuation: child can exclude MORE values.
    ///
    /// More exclusions = smaller allowed set = valid attenuation.
    pub fn validate_attenuation(&self, child: &NotOneOf) -> Result<()> {
        // Child must exclude everything parent excludes (can add more)
        for v in &self.excluded {
            if !child.excluded.contains(v) {
                return Err(Error::ExclusionRemoved {
                    value: format!("{:?}", v),
                });
            }
        }
        Ok(())
    }
}

impl From<NotOneOf> for Constraint {
    fn from(n: NotOneOf) -> Self {
        Constraint::NotOneOf(n)
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
    /// 
    /// # Panics
    /// Panics if min or max is NaN (NaN causes non-deterministic serialization).
    pub fn new(min: Option<f64>, max: Option<f64>) -> Self {
        // NaN values cause non-deterministic serialization and comparison issues
        if let Some(m) = min {
            assert!(!m.is_nan(), "Range min cannot be NaN");
        }
        if let Some(m) = max {
            assert!(!m.is_nan(), "Range max cannot be NaN");
        }
        Self {
            min,
            max,
            min_inclusive: true,
            max_inclusive: true,
        }
    }

    /// Create a range with only a maximum value.
    /// 
    /// # Panics
    /// Panics if max is NaN.
    pub fn max(max: f64) -> Self {
        Self::new(None, Some(max))
    }

    /// Create a range with only a minimum value.
    /// 
    /// # Panics
    /// Panics if min is NaN.
    pub fn min(min: f64) -> Self {
        Self::new(Some(min), None)
    }

    /// Create a range between min and max.
    /// 
    /// # Panics
    /// Panics if min or max is NaN.
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
    ///
    /// Returns `Ok(false)` for non-numeric values or NaN.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        let n = match value.as_number() {
            Some(n) => n,
            None => return Ok(false),
        };

        // NaN never matches any range (NaN comparisons always return false)
        if n.is_nan() {
            return Ok(false);
        }

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
                return Err(Error::RangeExpanded {
                    bound: "min".to_string(),
                    parent_value: parent_min,
                    child_value: child_min,
                });
            }
            (Some(parent_min), None) => {
                return Err(Error::RangeExpanded {
                    bound: "min".to_string(),
                    parent_value: parent_min,
                    child_value: f64::NEG_INFINITY,
                });
            }
            _ => {}
        }

        // Child max must be <= parent max
        match (self.max, child.max) {
            (Some(parent_max), Some(child_max)) if child_max > parent_max => {
                return Err(Error::RangeExpanded {
                    bound: "max".to_string(),
                    parent_value: parent_max,
                    child_value: child_max,
                });
            }
            (Some(parent_max), None) => {
                return Err(Error::RangeExpanded {
                    bound: "max".to_string(),
                    parent_value: parent_max,
                    child_value: f64::INFINITY,
                });
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
                return Err(Error::RequiredValueRemoved {
                    value: format!("{:?}", v),
                });
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
    /// let cel = CelConstraint::new("amount < 10000");
    /// let value = ConstraintValue::Object(/* {"amount": 5000} */);
    /// assert!(cel.matches(&value)?);
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
    /// Whitespace variations are allowed (e.g., `&&` vs ` && `).
    ///
    /// # Security Note on Monotonicity
    /// Tenuo currently enforces **Syntactic Monotonicity** for CEL, not Semantic Monotonicity.
    ///
    /// - **Allowed**: `parent && new_check` (Syntactically stricter)
    /// - **Rejected**: `stricter_check` (Semantically stricter but not syntactically derived)
    ///
    /// Example:
    /// - Parent: `net.in_cidr(ip, '10.0.0.0/8')`
    /// - Child: `net.in_cidr(ip, '10.1.0.0/16')` -> **REJECTED** (cannot prove subset relation easily)
    /// - Child: `(net.in_cidr(ip, '10.0.0.0/8')) && net.in_cidr(ip, '10.1.0.0/16')` -> **ALLOWED**
    pub fn validate_attenuation(&self, child: &CelConstraint) -> Result<()> {
        // Same expression is always valid (after normalizing whitespace)
        if normalize_cel_whitespace(&child.expression) == normalize_cel_whitespace(&self.expression) {
            return Ok(());
        }

        // Child must be a conjunction with parent
        // Normalize both to handle whitespace variations
        let child_normalized = normalize_cel_whitespace(&child.expression);
        let expected_prefix = format!("({})&&", normalize_cel_whitespace(&self.expression));
        
        if !child_normalized.starts_with(&expected_prefix) {
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

/// Normalize CEL expression whitespace for comparison.
/// Removes spaces around operators to allow flexible formatting.
fn normalize_cel_whitespace(expr: &str) -> String {
    expr.split_whitespace().collect::<Vec<_>>().join("")
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
/// 
/// Uses BTreeMap for deterministic serialization order (canonical CBOR).
/// This ensures consistent warrant IDs regardless of insertion order.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ConstraintSet {
    constraints: BTreeMap<String, Constraint>,
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

    /// Validate that all constraints in this set have acceptable nesting depth.
    /// 
    /// Call this after deserialization to prevent stack overflow attacks
    /// from deeply nested constraints.
    pub fn validate_depth(&self) -> Result<()> {
        for constraint in self.constraints.values() {
            constraint.validate_depth()?;
        }
        Ok(())
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

    #[test]
    fn test_cross_type_attenuation_pattern_to_exact() {
        // Valid: Pattern can narrow to Exact if value matches
        let parent = Constraint::Pattern(Pattern::new("staging-*").unwrap());
        let child = Constraint::Exact(Exact::new("staging-web"));
        assert!(parent.validate_attenuation(&child).is_ok());

        // Invalid: Exact value doesn't match pattern
        let invalid_child = Constraint::Exact(Exact::new("prod-web"));
        assert!(parent.validate_attenuation(&invalid_child).is_err());
    }

    #[test]
    fn test_cross_type_attenuation_oneof_to_exact() {
        // Valid: OneOf can narrow to Exact if value is in set
        let parent = Constraint::OneOf(OneOf::new(vec!["upgrade", "restart", "scale"]));
        let child = Constraint::Exact(Exact::new("upgrade"));
        assert!(parent.validate_attenuation(&child).is_ok());

        // Invalid: Exact value not in OneOf set
        let invalid_child = Constraint::Exact(Exact::new("delete"));
        assert!(parent.validate_attenuation(&invalid_child).is_err());
    }

    #[test]
    fn test_cross_type_attenuation_incompatible_types() {
        // Pattern cannot narrow to OneOf (different types)
        let parent = Constraint::Pattern(Pattern::new("*").unwrap());
        let child = Constraint::OneOf(OneOf::new(vec!["upgrade", "restart"]));
        let result = parent.validate_attenuation(&child);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("incompatible constraint types"));

        // Range cannot narrow to Pattern
        let parent = Constraint::Range(Range::max(1000.0));
        let child = Constraint::Pattern(Pattern::new("*").unwrap());
        let result = parent.validate_attenuation(&child);
        assert!(result.is_err());
    }

    #[test]
    fn test_adding_new_constraint_to_unconstrained_field() {
        // When parent doesn't have a field, child can add any constraint
        let mut parent = ConstraintSet::new();
        parent.insert("cluster", Pattern::new("staging-*").unwrap());
        // parent has no "action" constraint

        let mut child = ConstraintSet::new();
        child.insert("cluster", Exact::new("staging-web"));
        child.insert("action", OneOf::new(vec!["upgrade", "restart"])); // NEW field

        // This should work - child can add new constraints
        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_wildcard_matches_everything() {
        let wildcard = Wildcard::new();
        
        assert!(wildcard.matches(&ConstraintValue::String("anything".to_string())).unwrap());
        assert!(wildcard.matches(&ConstraintValue::Integer(42)).unwrap());
        assert!(wildcard.matches(&ConstraintValue::Float(3.5)).unwrap());
        assert!(wildcard.matches(&ConstraintValue::Boolean(true)).unwrap());
        assert!(wildcard.matches(&ConstraintValue::List(vec![])).unwrap());
    }

    #[test]
    fn test_wildcard_can_attenuate_to_anything() {
        let parent = Constraint::Wildcard(Wildcard::new());
        
        // Wildcard -> Pattern
        let child = Constraint::Pattern(Pattern::new("staging-*").unwrap());
        assert!(parent.validate_attenuation(&child).is_ok());
        
        // Wildcard -> OneOf
        let child = Constraint::OneOf(OneOf::new(vec!["upgrade", "restart"]));
        assert!(parent.validate_attenuation(&child).is_ok());
        
        // Wildcard -> Range
        let child = Constraint::Range(Range::max(1000.0));
        assert!(parent.validate_attenuation(&child).is_ok());
        
        // Wildcard -> Exact
        let child = Constraint::Exact(Exact::new("specific"));
        assert!(parent.validate_attenuation(&child).is_ok());
        
        // Wildcard -> Contains
        let child = Constraint::Contains(Contains::new(vec!["admin"]));
        assert!(parent.validate_attenuation(&child).is_ok());
        
        // Wildcard -> Wildcard (same, OK)
        let child = Constraint::Wildcard(Wildcard::new());
        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_cannot_attenuate_to_wildcard() {
        // Nothing can attenuate TO Wildcard (would expand permissions)
        
        let parent = Constraint::Pattern(Pattern::new("staging-*").unwrap());
        let child = Constraint::Wildcard(Wildcard::new());
        let result = parent.validate_attenuation(&child);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot attenuate to Wildcard"));
        
        let parent = Constraint::OneOf(OneOf::new(vec!["a", "b"]));
        let child = Constraint::Wildcard(Wildcard::new());
        assert!(parent.validate_attenuation(&child).is_err());
    }

    #[test]
    fn test_wildcard_in_constraint_set() {
        // Parent has Wildcard for action
        let mut parent = ConstraintSet::new();
        parent.insert("cluster", Pattern::new("staging-*").unwrap());
        parent.insert("action", Wildcard::new());

        // Child narrows Wildcard -> OneOf (should work!)
        let mut child = ConstraintSet::new();
        child.insert("cluster", Exact::new("staging-web"));
        child.insert("action", OneOf::new(vec!["upgrade", "restart"]));

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    // =========================================================================
    // NotOneOf Tests
    // =========================================================================

    #[test]
    fn test_notoneof_matches() {
        let constraint = NotOneOf::new(vec!["prod", "secure"]);
        
        // Values NOT in the excluded set should match
        assert!(constraint.matches(&ConstraintValue::String("staging".to_string())).unwrap());
        assert!(constraint.matches(&ConstraintValue::String("dev".to_string())).unwrap());
        
        // Values IN the excluded set should NOT match
        assert!(!constraint.matches(&ConstraintValue::String("prod".to_string())).unwrap());
        assert!(!constraint.matches(&ConstraintValue::String("secure".to_string())).unwrap());
    }

    #[test]
    fn test_notoneof_attenuation_can_add_exclusions() {
        // Child can exclude MORE values (stricter)
        let parent = NotOneOf::new(vec!["prod"]);
        let child = NotOneOf::new(vec!["prod", "secure"]); // Excludes more
        
        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_notoneof_attenuation_cannot_remove_exclusions() {
        // Child cannot exclude FEWER values (would be more permissive)
        let parent = NotOneOf::new(vec!["prod", "secure"]);
        let child = NotOneOf::new(vec!["prod"]); // Missing "secure"
        
        let result = parent.validate_attenuation(&child);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must still exclude"));
    }

    #[test]
    fn test_oneof_to_notoneof_carving_holes() {
        // Parent allows: [a, b, c, d]
        // Child excludes: [b] -> effectively allows [a, c, d]
        let parent = Constraint::OneOf(OneOf::new(vec!["a", "b", "c", "d"]));
        let child = Constraint::NotOneOf(NotOneOf::new(vec!["b"]));
        
        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_oneof_to_notoneof_paradox_detection() {
        // Parent allows: [a, b]
        // Child excludes: [a, b] -> empty set (paradox!)
        let parent = Constraint::OneOf(OneOf::new(vec!["a", "b"]));
        let child = Constraint::NotOneOf(NotOneOf::new(vec!["a", "b"]));
        
        let result = parent.validate_attenuation(&child);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::EmptyResultSet { parent_type, count } => {
                assert_eq!(parent_type, "OneOf");
                assert_eq!(count, 2);
            }
            e => panic!("Expected EmptyResultSet, got {:?}", e),
        }
    }

    #[test]
    fn test_wildcard_to_notoneof() {
        // Wildcard can attenuate to NotOneOf (carving holes from everything)
        let parent = Constraint::Wildcard(Wildcard::new());
        let child = Constraint::NotOneOf(NotOneOf::new(vec!["prod", "secure"]));
        
        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_notoneof_to_notoneof() {
        // NotOneOf -> NotOneOf works if child excludes more
        let parent = Constraint::NotOneOf(NotOneOf::new(vec!["prod"]));
        let child = Constraint::NotOneOf(NotOneOf::new(vec!["prod", "secure"]));
        
        assert!(parent.validate_attenuation(&child).is_ok());
    }
}
