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
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// Maximum allowed nesting depth for recursive constraints (All, Any, Not).
///
/// This prevents stack overflow attacks from deeply nested constraints like
/// `Not(Not(Not(...)))` or `All([All([All([...])])])`.
///
/// Depth 32 allows for complex real-world policies (especially machine-generated) while preventing abuse.
pub const MAX_CONSTRAINT_DEPTH: u32 = 32;
use glob::Pattern as GlobPattern;
use regex::Regex as RegexPattern;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};

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

/// Wire format type IDs for constraints (per wire-format-spec.md §6).
///
/// These IDs are used for compact CBOR serialization as `[type_id, value]`.
pub mod constraint_type_id {
    pub const EXACT: u8 = 1;
    pub const PATTERN: u8 = 2;
    /// Range constraint with f64 bounds. Note: i64 values > 2^53 lose precision.
    pub const RANGE: u8 = 3;
    pub const ONE_OF: u8 = 4;
    pub const REGEX: u8 = 5;
    /// Reserved for future IntRange with i64 bounds (not implemented).
    pub const RESERVED_INT_RANGE: u8 = 6;
    pub const NOT_ONE_OF: u8 = 7;
    pub const CIDR: u8 = 8;
    pub const URL_PATTERN: u8 = 9;
    pub const CONTAINS: u8 = 10;
    pub const SUBSET: u8 = 11;
    pub const ALL: u8 = 12;
    pub const ANY: u8 = 13;
    pub const NOT: u8 = 14;
    pub const CEL: u8 = 15;
    pub const WILDCARD: u8 = 16;
    /// Secure path containment (prevents path traversal attacks).
    /// Wire format: `[17, { "root": string, "case_sensitive": bool }]`
    pub const SUBPATH: u8 = 17;
    /// SSRF-safe URL validation (blocks private IPs, metadata endpoints, etc.).
    /// Wire format: `[18, { "schemes": [string], "block_private": bool, ... }]`
    pub const URL_SAFE: u8 = 18;
    // 19-127: Future standard types
    // 128-255: Experimental / private use
}

/// A constraint on an argument value.
///
/// **Wire format**: Serialized as CBOR array `[type_id, value]` for compactness.
///
/// **Security**: Custom deserialization validates nesting depth to prevent
/// stack overflow attacks from maliciously nested constraints like `Not(Not(Not(...)))`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Constraint {
    /// Wildcard - matches anything. The universal superset.
    /// Can be attenuated to any other constraint type.
    /// Wire type ID: 16
    Wildcard(Wildcard),

    /// Glob-style pattern matching (e.g., "staging-*").
    /// Wire type ID: 2
    Pattern(Pattern),

    /// Regular expression matching.
    /// Wire type ID: 5
    Regex(RegexConstraint),

    /// Exact value match (works for strings, numbers, bools).
    /// Wire type ID: 1
    Exact(Exact),

    /// One of a set of allowed values.
    /// Wire type ID: 4
    OneOf(OneOf),

    /// Value must NOT be in the excluded set ("carving holes").
    ///
    /// Use this to exclude specific values from a broader allowlist.
    /// Must be combined with a positive constraint (Wildcard, Pattern, etc.)
    /// in a parent warrant.
    ///
    /// **Security Rule**: Never start with negation! Always start with
    /// a positive allowlist and use NotOneOf to "carve holes" in children.
    /// Wire type ID: 7
    NotOneOf(NotOneOf),

    /// Numeric range constraint.
    /// Wire type ID: 3
    Range(Range),

    /// CIDR network constraint (IP address must be in network).
    /// Wire type ID: 8
    Cidr(Cidr),

    /// URL pattern constraint (validates URL scheme, host, port, path).
    /// Wire type ID: 9
    UrlPattern(UrlPattern),

    /// List must contain specified values.
    /// Wire type ID: 10
    Contains(Contains),

    /// List must be a subset of allowed values.
    /// Wire type ID: 11
    Subset(Subset),

    /// All nested constraints must match (AND).
    /// Wire type ID: 12
    All(All),

    /// At least one nested constraint must match (OR).
    /// Wire type ID: 13
    Any(Any),

    /// Negation of a constraint.
    /// Wire type ID: 14
    Not(Not),

    /// CEL expression for complex logic.
    /// Wire type ID: 15
    Cel(CelConstraint),

    /// Secure path containment constraint.
    /// Validates that paths are safely contained within a root directory.
    /// Wire type ID: 17
    Subpath(Subpath),

    /// SSRF-safe URL constraint.
    /// Validates URLs to prevent Server-Side Request Forgery attacks.
    /// Wire type ID: 18
    UrlSafe(UrlSafe),

    /// Unknown constraint type (deserialized but not understood).
    /// Used for forward compatibility. Always fails authorization.
    Unknown { type_id: u8, payload: Vec<u8> },
}

// Custom Serialize: outputs [type_id, value] array
impl Serialize for Constraint {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use constraint_type_id::*;
        use serde::ser::SerializeTuple;

        let mut tup = serializer.serialize_tuple(2)?;

        match self {
            Constraint::Exact(v) => {
                tup.serialize_element(&EXACT)?;
                tup.serialize_element(v)?;
            }
            Constraint::Pattern(v) => {
                tup.serialize_element(&PATTERN)?;
                tup.serialize_element(v)?;
            }
            Constraint::Range(v) => {
                tup.serialize_element(&RANGE)?;
                tup.serialize_element(v)?;
            }
            Constraint::OneOf(v) => {
                tup.serialize_element(&ONE_OF)?;
                tup.serialize_element(v)?;
            }
            Constraint::Regex(v) => {
                tup.serialize_element(&REGEX)?;
                tup.serialize_element(v)?;
            }
            Constraint::NotOneOf(v) => {
                tup.serialize_element(&NOT_ONE_OF)?;
                tup.serialize_element(v)?;
            }
            Constraint::Cidr(v) => {
                tup.serialize_element(&CIDR)?;
                tup.serialize_element(v)?;
            }
            Constraint::UrlPattern(v) => {
                tup.serialize_element(&URL_PATTERN)?;
                tup.serialize_element(v)?;
            }
            Constraint::Contains(v) => {
                tup.serialize_element(&CONTAINS)?;
                tup.serialize_element(v)?;
            }
            Constraint::Subset(v) => {
                tup.serialize_element(&SUBSET)?;
                tup.serialize_element(v)?;
            }
            Constraint::All(v) => {
                tup.serialize_element(&ALL)?;
                tup.serialize_element(v)?;
            }
            Constraint::Any(v) => {
                tup.serialize_element(&ANY)?;
                tup.serialize_element(v)?;
            }
            Constraint::Not(v) => {
                tup.serialize_element(&NOT)?;
                tup.serialize_element(v)?;
            }
            Constraint::Cel(v) => {
                tup.serialize_element(&CEL)?;
                tup.serialize_element(v)?;
            }
            Constraint::Wildcard(v) => {
                tup.serialize_element(&WILDCARD)?;
                tup.serialize_element(v)?;
            }
            Constraint::Subpath(v) => {
                tup.serialize_element(&SUBPATH)?;
                tup.serialize_element(v)?;
            }
            Constraint::UrlSafe(v) => {
                tup.serialize_element(&URL_SAFE)?;
                tup.serialize_element(v)?;
            }
            Constraint::Unknown { type_id, payload } => {
                tup.serialize_element(type_id)?;
                tup.serialize_element(&serde_bytes::Bytes::new(payload))?;
            }
        }

        tup.end()
    }
}

// Custom Deserialize: reads [type_id, value] array format
impl<'de> serde::Deserialize<'de> for Constraint {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use constraint_type_id::*;
        use serde::de::{Error as DeError, SeqAccess, Visitor};

        let _guard = DepthGuard::new::<D::Error>()?;

        struct ConstraintVisitor;

        impl<'de> Visitor<'de> for ConstraintVisitor {
            type Value = Constraint;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a constraint array [type_id, value]")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let type_id: u8 = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(0, &self))?;

                let constraint = match type_id {
                    EXACT => {
                        let v: Exact = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::Exact(v)
                    }
                    PATTERN => {
                        let v: Pattern = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::Pattern(v)
                    }
                    RANGE => {
                        let v: Range = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::Range(v)
                    }
                    ONE_OF => {
                        let v: OneOf = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::OneOf(v)
                    }
                    REGEX => {
                        let v: RegexConstraint = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::Regex(v)
                    }
                    NOT_ONE_OF => {
                        let v: NotOneOf = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::NotOneOf(v)
                    }
                    CIDR => {
                        let v: Cidr = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::Cidr(v)
                    }
                    URL_PATTERN => {
                        let v: UrlPattern = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::UrlPattern(v)
                    }
                    CONTAINS => {
                        let v: Contains = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::Contains(v)
                    }
                    SUBSET => {
                        let v: Subset = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::Subset(v)
                    }
                    ALL => {
                        let v: All = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::All(v)
                    }
                    ANY => {
                        let v: Any = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::Any(v)
                    }
                    NOT => {
                        let v: Not = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::Not(v)
                    }
                    CEL => {
                        let v: CelConstraint = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::Cel(v)
                    }
                    WILDCARD => {
                        let v: Wildcard = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::Wildcard(v)
                    }
                    SUBPATH => {
                        let v: Subpath = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::Subpath(v)
                    }
                    URL_SAFE => {
                        let v: UrlSafe = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
                        Constraint::UrlSafe(v)
                    }
                    // Unknown type ID (ID 6 reserved for future IntRange with i64 bounds)
                    _ => {
                        // Try to read value as raw bytes for preservation
                        let payload: Vec<u8> = seq
                            .next_element::<serde_bytes::ByteBuf>()?
                            .map(|b| b.into_vec())
                            .unwrap_or_default();
                        Constraint::Unknown { type_id, payload }
                    }
                };

                Ok(constraint)
            }
        }

        let constraint = deserializer.deserialize_seq(ConstraintVisitor)?;

        // Validate depth after full deserialization
        constraint
            .validate_depth()
            .map_err(serde::de::Error::custom)?;

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
            | Constraint::Cidr(_)
            | Constraint::UrlPattern(_)
            | Constraint::Contains(_)
            | Constraint::Subset(_)
            | Constraint::Cel(_)
            | Constraint::Subpath(_)
            | Constraint::UrlSafe(_)
            | Constraint::Unknown { .. } => 0,

            // Recursive types: 1 + max child depth
            Constraint::All(all) => {
                1 + all.constraints.iter().map(|c| c.depth()).max().unwrap_or(0)
            }
            Constraint::Any(any) => {
                1 + any.constraints.iter().map(|c| c.depth()).max().unwrap_or(0)
            }
            Constraint::Not(not) => 1 + not.constraint.depth(),
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
            Constraint::Cidr(c) => c.matches(value),
            Constraint::UrlPattern(u) => u.matches(value),
            Constraint::Contains(c) => c.matches(value),
            Constraint::Subset(s) => s.matches(value),
            Constraint::All(a) => a.matches(value),
            Constraint::Any(a) => a.matches(value),
            Constraint::Not(n) => n.matches(value),
            Constraint::Cel(c) => c.matches(value),
            Constraint::Subpath(s) => s.matches(value),
            Constraint::UrlSafe(u) => u.matches(value),
            Constraint::Unknown { type_id, .. } => Err(Error::ConstraintNotSatisfied {
                field: "constraint".to_string(),
                reason: format!("unknown constraint type ID {}", type_id),
            }),
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
                let remaining: Vec<_> = parent
                    .values
                    .iter()
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
            // Range can narrow to Exact if value is within range
            (Constraint::Range(parent), Constraint::Exact(child_exact)) => {
                // Get numeric value from Exact
                match child_exact.value.as_number() {
                    Some(n) if parent.contains_value(n) => Ok(()),
                    Some(n) => Err(Error::ValueNotInRange {
                        value: n,
                        min: parent.min,
                        max: parent.max,
                    }),
                    None => Err(Error::IncompatibleConstraintTypes {
                        parent_type: "Range".to_string(),
                        child_type: "Exact (non-numeric)".to_string(),
                    }),
                }
            }

            // Cidr can narrow to smaller Cidr (subnet)
            (Constraint::Cidr(parent), Constraint::Cidr(child)) => {
                parent.validate_attenuation(child)
            }
            // Cidr can narrow to Exact IP address
            (Constraint::Cidr(parent), Constraint::Exact(child_exact)) => {
                match child_exact.value.as_str() {
                    Some(ip_str) => {
                        if parent.contains_ip(ip_str)? {
                            Ok(())
                        } else {
                            Err(Error::IpNotInCidr {
                                ip: ip_str.to_string(),
                                cidr: parent.network.to_string(),
                            })
                        }
                    }
                    None => Err(Error::IncompatibleConstraintTypes {
                        parent_type: "Cidr".to_string(),
                        child_type: "Exact (non-string)".to_string(),
                    }),
                }
            }

            // UrlPattern can narrow to UrlPattern or Exact
            (Constraint::UrlPattern(parent), Constraint::UrlPattern(child)) => {
                parent.validate_attenuation(child)
            }
            (Constraint::UrlPattern(parent), Constraint::Exact(child_exact)) => {
                match child_exact.value.as_str() {
                    Some(url_str) => {
                        if parent.matches_url(url_str)? {
                            Ok(())
                        } else {
                            Err(Error::UrlMismatch {
                                reason: format!(
                                    "URL '{}' does not match pattern '{}'",
                                    url_str, parent
                                ),
                            })
                        }
                    }
                    None => Err(Error::IncompatibleConstraintTypes {
                        parent_type: "UrlPattern".to_string(),
                        child_type: "Exact (non-string)".to_string(),
                    }),
                }
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
            (Constraint::All(parent), Constraint::All(child)) => parent.validate_attenuation(child),

            // CEL follows conjunction rule
            (Constraint::Cel(parent), Constraint::Cel(child)) => parent.validate_attenuation(child),

            // Subpath can narrow to Subpath (narrower root) or Exact
            (Constraint::Subpath(parent), Constraint::Subpath(child)) => {
                parent.validate_attenuation(child)
            }
            (Constraint::Subpath(parent), Constraint::Exact(child_exact)) => {
                match child_exact.value.as_str() {
                    Some(path_str) => {
                        if parent.contains_path(path_str)? {
                            Ok(())
                        } else {
                            Err(Error::PathNotContained {
                                path: path_str.to_string(),
                                root: parent.root.clone(),
                            })
                        }
                    }
                    None => Err(Error::IncompatibleConstraintTypes {
                        parent_type: "Subpath".to_string(),
                        child_type: "Exact (non-string)".to_string(),
                    }),
                }
            }

            // UrlSafe can narrow to UrlSafe (more restrictive) or Exact
            (Constraint::UrlSafe(parent), Constraint::UrlSafe(child)) => {
                parent.validate_attenuation(child)
            }
            (Constraint::UrlSafe(parent), Constraint::Exact(child_exact)) => {
                match child_exact.value.as_str() {
                    Some(url_str) => {
                        if parent.is_safe(url_str)? {
                            Ok(())
                        } else {
                            Err(Error::UrlNotSafe {
                                url: url_str.to_string(),
                                reason: "URL blocked by UrlSafe constraint".to_string(),
                            })
                        }
                    }
                    None => Err(Error::IncompatibleConstraintTypes {
                        parent_type: "UrlSafe".to_string(),
                        child_type: "Exact (non-string)".to_string(),
                    }),
                }
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
            Constraint::Cidr(_) => "Cidr",
            Constraint::UrlPattern(_) => "UrlPattern",
            Constraint::NotOneOf(_) => "NotOneOf",
            Constraint::Range(_) => "Range",
            Constraint::Contains(_) => "Contains",
            Constraint::Subset(_) => "Subset",
            Constraint::All(_) => "All",
            Constraint::Any(_) => "Any",
            Constraint::Not(_) => "Not",
            Constraint::Cel(_) => "Cel",
            Constraint::Subpath(_) => "Subpath",
            Constraint::UrlSafe(_) => "UrlSafe",
            Constraint::Unknown { .. } => "Unknown",
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
    ///
    /// # Precision Note
    ///
    /// Converting `i64` to `f64` can lose precision for integers larger than 2^53
    /// (9,007,199,254,740,992). For very large integers (e.g., snowflake IDs),
    /// consider using the integer directly or converting to string.
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
        let compiled =
            GlobPattern::new(pattern).map_err(|e| Error::InvalidPattern(e.to_string()))?;
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
            GlobPattern::new(&self.pattern).map_err(|e| Error::InvalidPattern(e.to_string()))
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
            (PatternType::Exact, _) => Err(Error::PatternExpanded {
                parent: self.pattern.clone(),
                child: child.pattern.clone(),
            }),

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
            (PatternType::Complex, _) | (_, PatternType::Complex) => Err(Error::PatternExpanded {
                parent: self.pattern.clone(),
                child: child.pattern.clone(),
            }),

            // Prefix cannot attenuate to suffix or vice versa
            _ => Err(Error::PatternExpanded {
                parent: self.pattern.clone(),
                child: child.pattern.clone(),
            }),
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
            "regex attenuation requires pattern match; use Exact for specific values".to_string(),
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
            values: values
                .into_iter()
                .map(|s| ConstraintValue::String(s.into()))
                .collect(),
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
            excluded: excluded
                .into_iter()
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
///
/// **Precision Warning**: Bounds are stored as `f64`. Integers larger than 2^53
/// (9,007,199,254,740,992) will lose precision.
///
/// **For Snowflake IDs or 64-bit integers**: Use String comparison or Exact matching
/// to avoid precision loss. Do NOT use `Range` for IDs > 2^53.
///
/// Wire type ID: 3
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Range {
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub min_inclusive: bool,
    pub max_inclusive: bool,
}

impl Range {
    /// Create a new range constraint with inclusive bounds.
    ///
    /// # Errors
    /// Returns `InvalidRange` if min or max is NaN (NaN causes non-deterministic serialization).
    pub fn new(min: Option<f64>, max: Option<f64>) -> Result<Self> {
        // NaN values cause non-deterministic serialization and comparison issues
        if let Some(m) = min {
            if m.is_nan() {
                return Err(Error::InvalidRange("min cannot be NaN".to_string()));
            }
        }
        if let Some(m) = max {
            if m.is_nan() {
                return Err(Error::InvalidRange("max cannot be NaN".to_string()));
            }
        }
        Ok(Self {
            min,
            max,
            min_inclusive: true,
            max_inclusive: true,
        })
    }

    /// Create a range with only a maximum value.
    ///
    /// # Errors
    /// Returns `InvalidRange` if max is NaN.
    pub fn max(max: f64) -> Result<Self> {
        Self::new(None, Some(max))
    }

    /// Create a range with only a minimum value.
    ///
    /// # Errors
    /// Returns `InvalidRange` if min is NaN.
    pub fn min(min: f64) -> Result<Self> {
        Self::new(Some(min), None)
    }

    /// Create a range between min and max.
    ///
    /// # Errors
    /// Returns `InvalidRange` if min or max is NaN.
    pub fn between(min: f64, max: f64) -> Result<Self> {
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
    ///
    /// Checks both numeric bounds AND inclusivity flags:
    /// - Child min must be >= parent min
    /// - Child max must be <= parent max
    /// - If parent bound is exclusive, child cannot make it inclusive (would widen)
    pub fn validate_attenuation(&self, child: &Range) -> Result<()> {
        // Child min must be >= parent min
        match (self.min, child.min) {
            (Some(parent_min), Some(child_min)) => {
                // Check numeric bound
                if child_min < parent_min {
                    return Err(Error::RangeExpanded {
                        bound: "min".to_string(),
                        parent_value: parent_min,
                        child_value: child_min,
                    });
                }
                // Check inclusivity: if parent is exclusive, child at same value cannot be inclusive
                // (that would include the boundary value parent excluded)
                if child_min == parent_min && !self.min_inclusive && child.min_inclusive {
                    return Err(Error::RangeInclusivityExpanded {
                        bound: "min".to_string(),
                        value: parent_min,
                        parent_inclusive: false,
                        child_inclusive: true,
                    });
                }
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
            (Some(parent_max), Some(child_max)) => {
                // Check numeric bound
                if child_max > parent_max {
                    return Err(Error::RangeExpanded {
                        bound: "max".to_string(),
                        parent_value: parent_max,
                        child_value: child_max,
                    });
                }
                // Check inclusivity: if parent is exclusive, child at same value cannot be inclusive
                if child_max == parent_max && !self.max_inclusive && child.max_inclusive {
                    return Err(Error::RangeInclusivityExpanded {
                        bound: "max".to_string(),
                        value: parent_max,
                        parent_inclusive: false,
                        child_inclusive: true,
                    });
                }
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

    /// Check if an exact value is within the range.
    ///
    /// Used for Range -> Exact attenuation validation.
    pub fn contains_value(&self, value: f64) -> bool {
        if value.is_nan() {
            return false;
        }

        let min_ok = match self.min {
            None => true,
            Some(min) if self.min_inclusive => value >= min,
            Some(min) => value > min,
        };

        let max_ok = match self.max {
            None => true,
            Some(max) if self.max_inclusive => value <= max,
            Some(max) => value < max,
        };

        min_ok && max_ok
    }
}

impl From<Range> for Constraint {
    fn from(r: Range) -> Self {
        Constraint::Range(r)
    }
}

// ============================================================================
// Cidr Constraint (IP address must be in network)
// ============================================================================

/// CIDR network constraint - validates that an IP address is within a network range.
///
/// Supports both IPv4 and IPv6 addresses.
///
/// # Example
///
/// ```rust,ignore
/// use tenuo::Cidr;
///
/// let cidr = Cidr::new("10.0.0.0/8")?;
/// assert!(cidr.contains_ip("10.1.2.3")?);
/// assert!(!cidr.contains_ip("192.168.1.1")?);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Cidr {
    /// The network in CIDR notation (stored as parsed IpNetwork).
    pub network: IpNetwork,
    /// Original string representation for serialization.
    pub cidr_string: String,
}

impl Serialize for Cidr {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.cidr_string.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Cidr::new(&s).map_err(serde::de::Error::custom)
    }
}

impl Cidr {
    /// Create a new CIDR constraint from a string like "10.0.0.0/8" or "2001:db8::/32".
    ///
    /// # Errors
    /// Returns error if the CIDR notation is invalid.
    pub fn new(cidr: &str) -> Result<Self> {
        let network = cidr.parse::<IpNetwork>().map_err(|e| Error::InvalidCidr {
            cidr: cidr.to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self {
            network,
            cidr_string: cidr.to_string(),
        })
    }

    /// Check if an IP address string is within this CIDR network.
    pub fn contains_ip(&self, ip_str: &str) -> Result<bool> {
        let ip = ip_str
            .parse::<IpAddr>()
            .map_err(|e| Error::InvalidIpAddress {
                ip: ip_str.to_string(),
                reason: e.to_string(),
            })?;
        Ok(self.network.contains(ip))
    }

    /// Check if a value satisfies the CIDR constraint.
    ///
    /// The value must be a string containing an IP address.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        match value.as_str() {
            Some(ip_str) => self.contains_ip(ip_str),
            None => Ok(false),
        }
    }

    /// Validate that `child` is a valid attenuation (child network is subnet of parent).
    ///
    /// A child CIDR is valid if it's completely contained within the parent CIDR.
    pub fn validate_attenuation(&self, child: &Cidr) -> Result<()> {
        // Child network must be a subnet of parent
        // This means: child's first IP >= parent's first IP
        //         and child's last IP <= parent's last IP
        let parent_net = self.network;
        let child_net = child.network;

        // Check if child network address is within parent
        if !parent_net.contains(child_net.network()) {
            return Err(Error::CidrNotSubnet {
                parent: self.cidr_string.clone(),
                child: child.cidr_string.clone(),
            });
        }

        // Check if child broadcast address is within parent
        if !parent_net.contains(child_net.broadcast()) {
            return Err(Error::CidrNotSubnet {
                parent: self.cidr_string.clone(),
                child: child.cidr_string.clone(),
            });
        }

        Ok(())
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cidr({})", self.cidr_string)
    }
}

impl From<Cidr> for Constraint {
    fn from(c: Cidr) -> Self {
        Constraint::Cidr(c)
    }
}

// ============================================================================
// URL Pattern Constraint (validates URL scheme, host, port, path)
// ============================================================================

/// URL pattern constraint - validates URLs against scheme, host, port, and path patterns.
///
/// This provides structured URL validation with proper parsing and normalization,
/// safer than using Pattern or Regex for URL matching.
///
/// # Example
///
/// ```rust,ignore
/// use tenuo::UrlPattern;
///
/// // Match any HTTPS URL to api.example.com
/// let pattern = UrlPattern::new("https://api.example.com/*")?;
/// assert!(pattern.matches_url("https://api.example.com/v1/users")?);
/// assert!(!pattern.matches_url("http://api.example.com/v1/users")?);  // Wrong scheme
///
/// // Match any subdomain of example.com
/// let pattern = UrlPattern::new("https://*.example.com/*")?;
/// assert!(pattern.matches_url("https://api.example.com/v1")?);
/// assert!(pattern.matches_url("https://www.example.com/")?);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct UrlPattern {
    /// Original pattern string for display/serialization.
    pub pattern: String,
    /// Allowed schemes (e.g., ["https"]). Empty means any scheme.
    pub schemes: Vec<String>,
    /// Host pattern (supports wildcards like "*.example.com").
    pub host_pattern: Option<String>,
    /// Required port. None means any port (or default for scheme).
    pub port: Option<u16>,
    /// Path pattern (glob-style, e.g., "/api/v1/*").
    pub path_pattern: Option<String>,
}

impl Serialize for UrlPattern {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.pattern.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UrlPattern {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        UrlPattern::new(&s).map_err(serde::de::Error::custom)
    }
}

impl UrlPattern {
    /// Create a new URL pattern from a pattern string.
    ///
    /// Pattern format: `scheme://host[:port][/path]`
    ///
    /// - Scheme: Required. Use `*` for any scheme.
    /// - Host: Required. Supports wildcards (`*.example.com`).
    /// - Port: Optional. Omit for default port.
    /// - Path: Optional. Supports glob patterns (`/api/*`).
    ///
    /// # Examples
    ///
    /// - `https://api.example.com/*` - HTTPS only, specific host, any path
    /// - `*://example.com/api/v1/*` - Any scheme, specific host/path
    /// - `https://*.example.com:8443/api/*` - HTTPS, any subdomain, specific port
    ///
    /// # Errors
    /// Returns error if the pattern is not a valid URL pattern.
    pub fn new(pattern: &str) -> Result<Self> {
        // Internal placeholders for URL parsing
        const HOST_PLACEHOLDER: &str = "__tenuo_host_wildcard__";
        const PATH_PLACEHOLDER: &str = "__tenuo_path_wildcard__";

        // Reject patterns containing our internal placeholders (security: prevent collision attacks)
        if pattern.contains(HOST_PLACEHOLDER) || pattern.contains(PATH_PLACEHOLDER) {
            return Err(Error::InvalidUrl {
                url: pattern.to_string(),
                reason: "pattern contains reserved internal sequence".to_string(),
            });
        }

        // SECURITY: We intentionally do not support bare wildcard hosts (https://*/*)
        // This prevents accidentally creating overly permissive URL constraints that
        // would bypass SSRF protection. Users must explicitly specify trusted domains
        // or use UrlSafe() for SSRF-protected wildcards.

        // Handle wildcard scheme
        let (schemes, url_str) = if pattern.starts_with("*://") {
            (vec![], pattern.replacen("*://", "https://", 1))
        } else {
            // Extract scheme(s)
            let scheme_end = pattern.find("://").ok_or_else(|| Error::InvalidUrl {
                url: pattern.to_string(),
                reason: "missing scheme (expected 'scheme://')".to_string(),
            })?;
            let scheme = &pattern[..scheme_end];
            (vec![scheme.to_lowercase()], pattern.to_string())
        };

        // Parse with url crate (replace wildcards temporarily for parsing)
        let parse_str = url_str
            .replace("*.", &format!("{}.", HOST_PLACEHOLDER))
            .replace("/*", &format!("/{}", PATH_PLACEHOLDER));

        let parsed = url::Url::parse(&parse_str).map_err(|e| Error::InvalidUrl {
            url: pattern.to_string(),
            reason: e.to_string(),
        })?;

        // Extract host pattern (restore wildcards)
        let host_pattern = parsed
            .host_str()
            .map(|h| h.replace(&format!("{}.", HOST_PLACEHOLDER), "*."));

        // Extract port (None means default for scheme)
        let port = parsed.port();

        // Extract path pattern (restore wildcards)
        let path = parsed.path();
        let path_pattern = if path.is_empty() || path == "/" {
            None
        } else {
            Some(path.replace(PATH_PLACEHOLDER, "*"))
        };

        Ok(Self {
            pattern: pattern.to_string(),
            schemes,
            host_pattern,
            port,
            path_pattern,
        })
    }

    /// Check if a URL string matches this pattern.
    pub fn matches_url(&self, url_str: &str) -> Result<bool> {
        let parsed = url::Url::parse(url_str).map_err(|e| Error::InvalidUrl {
            url: url_str.to_string(),
            reason: e.to_string(),
        })?;

        // Check scheme
        if !self.schemes.is_empty() && !self.schemes.contains(&parsed.scheme().to_lowercase()) {
            return Ok(false);
        }

        // Check host
        if let Some(host_pattern) = &self.host_pattern {
            let host = parsed.host_str().unwrap_or("");
            if !Self::matches_host_pattern(host_pattern, host) {
                return Ok(false);
            }
        }

        // Check port
        if let Some(required_port) = self.port {
            let actual_port = parsed.port().unwrap_or_else(|| match parsed.scheme() {
                "https" => 443,
                "http" => 80,
                _ => 0,
            });
            if actual_port != required_port {
                return Ok(false);
            }
        }

        // Check path
        if let Some(path_pattern) = &self.path_pattern {
            let path = parsed.path();
            if !Self::matches_path_pattern(path_pattern, path) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Match host against pattern (supports wildcards).
    fn matches_host_pattern(pattern: &str, host: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Wildcard subdomain: *.example.com matches api.example.com, www.example.com
            host == suffix || host.ends_with(&format!(".{}", suffix))
        } else {
            // Exact match (case-insensitive for domains)
            pattern.eq_ignore_ascii_case(host)
        }
    }

    /// Match path against pattern (glob-style).
    fn matches_path_pattern(pattern: &str, path: &str) -> bool {
        if pattern == "*" || pattern == "/*" {
            return true;
        }

        // Use glob matching
        if let Ok(glob) = GlobPattern::new(pattern) {
            glob.matches(path)
        } else {
            pattern == path
        }
    }

    /// Check if a ConstraintValue matches this URL pattern.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        match value.as_str() {
            Some(url_str) => self.matches_url(url_str),
            None => Ok(false),
        }
    }

    /// Validate that `child` is a valid attenuation (narrower or equal).
    ///
    /// Rules:
    /// - Scheme: Can narrow (any → https) but not widen (https → http)
    /// - Host: Can narrow (*.example.com → api.example.com) but not widen
    /// - Port: Can add restriction but not remove
    /// - Path: Can narrow (/api/* → /api/v1/*) but not widen
    pub fn validate_attenuation(&self, child: &UrlPattern) -> Result<()> {
        // Check scheme narrowing
        if !self.schemes.is_empty() {
            // Parent has scheme restrictions
            for child_scheme in &child.schemes {
                if !self.schemes.contains(child_scheme) {
                    return Err(Error::UrlSchemeExpanded {
                        parent: self.schemes.join(","),
                        child: child_scheme.clone(),
                    });
                }
            }
        }
        // If parent allows any scheme (empty), child can restrict to any

        // Check host narrowing
        if let Some(parent_host) = &self.host_pattern {
            if let Some(child_host) = &child.host_pattern {
                if !Self::is_host_subset(parent_host, child_host) {
                    return Err(Error::UrlHostExpanded {
                        parent: parent_host.clone(),
                        child: child_host.clone(),
                    });
                }
            }
            // Child has no host pattern = allows any, which would expand
            else {
                return Err(Error::UrlHostExpanded {
                    parent: parent_host.clone(),
                    child: "*".to_string(),
                });
            }
        }

        // Check port
        if let Some(parent_port) = self.port {
            match child.port {
                Some(child_port) if child_port != parent_port => {
                    return Err(Error::UrlPortExpanded {
                        parent: Some(parent_port),
                        child: Some(child_port),
                    });
                }
                None => {
                    return Err(Error::UrlPortExpanded {
                        parent: Some(parent_port),
                        child: None,
                    });
                }
                _ => {}
            }
        }

        // Check path narrowing
        if let Some(parent_path) = &self.path_pattern {
            if let Some(child_path) = &child.path_pattern {
                if !Self::is_path_subset(parent_path, child_path) {
                    return Err(Error::UrlPathExpanded {
                        parent: parent_path.clone(),
                        child: child_path.clone(),
                    });
                }
            }
            // Child has no path pattern = allows any path, which would expand
            else {
                return Err(Error::UrlPathExpanded {
                    parent: parent_path.clone(),
                    child: "*".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Check if child_host is a subset of parent_host.
    fn is_host_subset(parent: &str, child: &str) -> bool {
        if parent == "*" {
            return true; // Parent allows any host
        }

        if let Some(parent_suffix) = parent.strip_prefix("*.") {
            // Child must be either:
            // 1. Exact match to the suffix (e.g., "example.com" matches "*.example.com")
            // 2. A subdomain of the suffix (e.g., "api.example.com")
            // 3. A more specific wildcard (e.g., "*.api.example.com")
            if child == parent_suffix {
                return true;
            }
            if child.ends_with(&format!(".{}", parent_suffix)) {
                return true;
            }
            if let Some(child_suffix) = child.strip_prefix("*.") {
                // *.api.example.com is subset of *.example.com
                return child_suffix.ends_with(&format!(".{}", parent_suffix))
                    || child_suffix == parent_suffix;
            }
            false
        } else {
            // Parent is exact: child must match exactly
            parent.eq_ignore_ascii_case(child)
        }
    }

    /// Check if child_path is a subset of parent_path.
    fn is_path_subset(parent: &str, child: &str) -> bool {
        if parent == "*" || parent == "/*" {
            return true; // Parent allows any path
        }

        // If parent ends with /*, child must start with parent's prefix
        if parent.ends_with("/*") {
            let parent_prefix = &parent[..parent.len() - 1]; // Remove trailing *
            if child.starts_with(parent_prefix) {
                return true;
            }
            // Also check if child is more specific wildcard
            if child.ends_with("/*") {
                let child_prefix = &child[..child.len() - 1];
                return child_prefix.starts_with(parent_prefix);
            }
            return false;
        }

        // Exact path match or child is more specific
        if parent == child {
            return true;
        }

        // Child has wildcard under parent's exact path
        if child.starts_with(parent) && child[parent.len()..].starts_with('/') {
            return true;
        }

        false
    }
}

impl std::fmt::Display for UrlPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UrlPattern({})", self.pattern)
    }
}

impl From<UrlPattern> for Constraint {
    fn from(u: UrlPattern) -> Self {
        Constraint::UrlPattern(u)
    }
}

// ============================================================================
// Subpath Constraint (Secure Path Containment)
// ============================================================================

/// Secure path containment constraint.
///
/// Validates that paths are safely contained within a root directory,
/// preventing path traversal attacks. This is a **lexical** check only -
/// it normalizes `.` and `..` components but does NOT access the filesystem.
///
/// # Security Features
///
/// - Normalizes `.` and `..` components (lexically, not via filesystem)
/// - Rejects null bytes (C string terminator attack)
/// - Requires absolute paths
/// - Optional case-sensitive matching (Windows compatibility)
/// - Does NOT follow symlinks (stateless validation)
///
/// # Example
///
/// ```rust,ignore
/// use tenuo::Subpath;
///
/// let constraint = Subpath::new("/data")?;
///
/// // These are allowed:
/// assert!(constraint.contains_path("/data/file.txt")?);
/// assert!(constraint.contains_path("/data/subdir/file.txt")?);
///
/// // These are BLOCKED:
/// assert!(!constraint.contains_path("/data/../etc/passwd")?);  // Normalized to /etc/passwd
/// assert!(!constraint.contains_path("/etc/passwd")?);          // Not under /data
/// ```
///
/// # Design Rationale: Stateless Validation
///
/// This constraint does NOT resolve symlinks or access the filesystem.
/// This is intentional for distributed systems where:
///
/// 1. The file may be on a different machine than the validator
/// 2. The filesystem state may change between validation and access
/// 3. Stateless validation enables caching and parallelization
///
/// For symlink-aware validation, use `path_jail` at the execution layer.
///
/// # Wire Format
///
/// ```text
/// [17, { "root": "/data", "case_sensitive": true }]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Subpath {
    /// Root directory path (must be absolute).
    pub root: String,
    /// Whether to match case-sensitively. Default: true.
    /// Set to false for Windows paths.
    #[serde(default = "default_true")]
    pub case_sensitive: bool,
    /// Whether to allow path == root. Default: true.
    /// Set to false to require strictly under root.
    #[serde(default = "default_true")]
    pub allow_equal: bool,
}

fn default_true() -> bool {
    true
}

impl Subpath {
    /// Create a new Subpath constraint.
    ///
    /// # Arguments
    ///
    /// * `root` - The root directory path (must be absolute)
    ///
    /// # Errors
    ///
    /// Returns error if `root` is not an absolute path.
    pub fn new(root: impl Into<String>) -> Result<Self> {
        let root = root.into();
        if !Self::is_absolute(&root) {
            return Err(Error::InvalidPath {
                path: root,
                reason: "root must be an absolute path".to_string(),
            });
        }
        Ok(Self {
            root: Self::normalize_path(&root),
            case_sensitive: true,
            allow_equal: true,
        })
    }

    /// Create a new Subpath constraint with options.
    pub fn with_options(
        root: impl Into<String>,
        case_sensitive: bool,
        allow_equal: bool,
    ) -> Result<Self> {
        let root = root.into();
        if !Self::is_absolute(&root) {
            return Err(Error::InvalidPath {
                path: root,
                reason: "root must be an absolute path".to_string(),
            });
        }
        let mut normalized = Self::normalize_path(&root);
        if !case_sensitive {
            normalized = normalized.to_lowercase();
        }
        Ok(Self {
            root: normalized,
            case_sensitive,
            allow_equal,
        })
    }

    /// Check if a path is absolute.
    ///
    /// Accepts both Unix-style (`/foo`) and Windows-style (`C:\foo`) paths.
    fn is_absolute(path: &str) -> bool {
        // Unix-style absolute
        if path.starts_with('/') {
            return true;
        }
        // Windows-style absolute (e.g., C:\)
        if path.len() >= 3 {
            let bytes = path.as_bytes();
            if bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && (bytes[2] == b'\\' || bytes[2] == b'/')
            {
                return true;
            }
        }
        false
    }

    /// Normalize a path lexically (resolve . and ..).
    ///
    /// This is a pure string operation - no filesystem access.
    fn normalize_path(path: &str) -> String {
        let mut components: Vec<&str> = Vec::new();

        // Preserve leading slash or drive letter
        let (prefix, rest) = if let Some(stripped) = path.strip_prefix('/') {
            ("/", stripped)
        } else if path.len() >= 2 && path.as_bytes()[1] == b':' {
            // Windows drive letter (e.g., "C:")
            let sep_pos =
                if path.len() > 2 && (path.as_bytes()[2] == b'\\' || path.as_bytes()[2] == b'/') {
                    3
                } else {
                    2
                };
            (&path[..sep_pos], &path[sep_pos..])
        } else {
            ("", path)
        };

        // Process path components
        for component in rest.split(['/', '\\']) {
            match component {
                "" | "." => continue, // Skip empty and current dir
                ".." => {
                    // Go up one level (but don't go above root)
                    components.pop();
                }
                _ => components.push(component),
            }
        }

        // Reconstruct path
        let mut result = prefix.to_string();
        for (i, component) in components.iter().enumerate() {
            if (i > 0 || !prefix.is_empty()) && !result.ends_with('/') && !result.ends_with('\\') {
                result.push('/');
            }
            result.push_str(component);
        }

        // Ensure root paths end correctly
        if result.is_empty() {
            result = prefix.to_string();
        }

        result
    }

    /// Check if a path is safely contained within root.
    ///
    /// # Security
    ///
    /// - Rejects null bytes
    /// - Rejects relative paths
    /// - Normalizes `.` and `..` components
    /// - Checks prefix containment after normalization
    pub fn contains_path(&self, path: &str) -> Result<bool> {
        // Reject null bytes (C string terminator attack)
        if path.contains('\0') {
            return Ok(false);
        }

        // Require absolute paths
        if !Self::is_absolute(path) {
            return Ok(false);
        }

        // Normalize the path
        let mut normalized = Self::normalize_path(path);
        if !self.case_sensitive {
            normalized = normalized.to_lowercase();
        }

        // Check containment
        if self.allow_equal && normalized == self.root {
            return Ok(true);
        }

        // Check if normalized starts with root + separator
        let root_with_sep = format!("{}/", self.root.trim_end_matches('/'));
        Ok(normalized.starts_with(&root_with_sep))
    }

    /// Check if a value satisfies the Subpath constraint.
    ///
    /// The value must be a string containing an absolute path.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        match value.as_str() {
            Some(path_str) => self.contains_path(path_str),
            None => Ok(false),
        }
    }

    /// Validate that `child` is a valid attenuation (child root is under parent root).
    ///
    /// A child Subpath is valid if its root is contained within the parent's root.
    pub fn validate_attenuation(&self, child: &Subpath) -> Result<()> {
        // Child root must be under parent root
        if !self.contains_path(&child.root)? {
            return Err(Error::PathNotContained {
                path: child.root.clone(),
                root: self.root.clone(),
            });
        }

        // Child cannot be less restrictive on case sensitivity
        // (case-insensitive parent can narrow to case-sensitive child, but not vice versa)
        if !self.case_sensitive && child.case_sensitive {
            return Err(Error::MonotonicityViolation(
                "cannot attenuate case-insensitive to case-sensitive".to_string(),
            ));
        }

        // Child cannot allow_equal if parent doesn't
        if !self.allow_equal && child.allow_equal {
            return Err(Error::MonotonicityViolation(
                "cannot attenuate allow_equal=false to allow_equal=true".to_string(),
            ));
        }

        Ok(())
    }
}

impl std::fmt::Display for Subpath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.case_sensitive && self.allow_equal {
            write!(f, "Subpath({})", self.root)
        } else {
            write!(
                f,
                "Subpath({}, case_sensitive={}, allow_equal={})",
                self.root, self.case_sensitive, self.allow_equal
            )
        }
    }
}

impl From<Subpath> for Constraint {
    fn from(s: Subpath) -> Self {
        Constraint::Subpath(s)
    }
}

// ============================================================================
// UrlSafe Constraint (SSRF Protection)
// ============================================================================

/// SSRF-safe URL constraint.
///
/// Validates URLs to prevent Server-Side Request Forgery attacks by blocking:
/// - Private IP ranges (RFC1918: 10.x, 172.16.x, 192.168.x)
/// - Loopback addresses (127.x, ::1, localhost)
/// - Cloud metadata endpoints (169.254.169.254, etc.)
/// - Dangerous schemes (file://, gopher://, etc.)
/// - IP encoding bypasses (decimal, hex, octal, IPv6-mapped, URL-encoded)
///
/// # Security Features
///
/// - Validates URL scheme (default: only http, https)
/// - Blocks private IPs (RFC1918) by default
/// - Blocks loopback (127.x, ::1) by default
/// - Blocks cloud metadata endpoints by default
/// - Normalizes IP representations (catches 0x7f000001, etc.)
/// - Decodes URL-encoded hostnames
/// - Optional domain allowlist for maximum restriction
///
/// # Design Rationale: Stateless Validation
///
/// This constraint does NOT perform DNS resolution. This is intentional:
///
/// 1. DNS resolution is I/O (blocks, can fail, changes over time)
/// 2. Attacker-controlled domains can resolve to internal IPs (DNS rebinding)
/// 3. Stateless validation enables caching and cross-language compatibility
///
/// For DNS-aware validation, use `url_jail` at the execution layer.
///
/// # Example
///
/// ```rust,ignore
/// use tenuo::UrlSafe;
///
/// // Secure defaults - blocks known SSRF vectors
/// let constraint = UrlSafe::new();
/// assert!(constraint.is_safe("https://api.github.com/repos")?);
/// assert!(!constraint.is_safe("http://169.254.169.254/")?);  // Metadata
/// assert!(!constraint.is_safe("http://127.0.0.1/")?);         // Loopback
///
/// // Domain allowlist - only specific domains allowed
/// let constraint = UrlSafe::with_domains(vec!["api.github.com", "*.googleapis.com"]);
/// ```
///
/// # Wire Format
///
/// ```text
/// [18, { "schemes": ["http", "https"], "block_private": true, ... }]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UrlSafe {
    /// Allowed URL schemes. Default: ["http", "https"]
    #[serde(default = "default_schemes")]
    pub schemes: Vec<String>,
    /// If set, only these domains are allowed (supports *.example.com)
    #[serde(default)]
    pub allow_domains: Option<Vec<String>>,
    /// If set, only these ports are allowed
    #[serde(default)]
    pub allow_ports: Option<Vec<u16>>,
    /// Block RFC1918 private IPs (10.x, 172.16.x, 192.168.x). Default: true
    #[serde(default = "default_true")]
    pub block_private: bool,
    /// Block loopback (127.x, ::1, localhost). Default: true
    #[serde(default = "default_true")]
    pub block_loopback: bool,
    /// Block cloud metadata endpoints (169.254.169.254, etc.). Default: true
    #[serde(default = "default_true")]
    pub block_metadata: bool,
    /// Block reserved IP ranges (multicast, broadcast). Default: true
    #[serde(default = "default_true")]
    pub block_reserved: bool,
    /// Block internal TLDs (.internal, .local, .localhost). Default: false
    #[serde(default)]
    pub block_internal_tlds: bool,
}

fn default_schemes() -> Vec<String> {
    vec!["http".to_string(), "https".to_string()]
}

/// Cloud metadata endpoint hostnames.
const METADATA_HOSTS: &[&str] = &[
    "169.254.169.254",          // AWS, Azure, DigitalOcean
    "metadata.google.internal", // GCP
    "metadata.goog",            // GCP alternate
    "100.100.100.200",          // Alibaba Cloud
];

/// Internal TLDs that may indicate private infrastructure.
const INTERNAL_TLDS: &[&str] = &[
    ".internal",
    ".local",
    ".localhost",
    ".lan",
    ".corp",
    ".home",
    ".svc",     // Kubernetes service names (e.g., my-service.namespace.svc)
    ".default", // Kubernetes default namespace (e.g., kubernetes.default)
];

impl UrlSafe {
    /// Create a new UrlSafe constraint with secure defaults.
    ///
    /// Blocks private IPs, loopback, metadata endpoints, and dangerous schemes.
    pub fn new() -> Self {
        Self {
            schemes: default_schemes(),
            allow_domains: None,
            allow_ports: None,
            block_private: true,
            block_loopback: true,
            block_metadata: true,
            block_reserved: true,
            block_internal_tlds: false,
        }
    }

    /// Create a UrlSafe constraint with domain allowlist.
    ///
    /// Only URLs to these domains will be allowed.
    /// Supports wildcard subdomains: `*.example.com`
    pub fn with_domains(domains: Vec<impl Into<String>>) -> Self {
        Self {
            schemes: default_schemes(),
            allow_domains: Some(domains.into_iter().map(Into::into).collect()),
            allow_ports: None,
            block_private: true,
            block_loopback: true,
            block_metadata: true,
            block_reserved: true,
            block_internal_tlds: false,
        }
    }

    /// Check if a URL is safe to fetch.
    ///
    /// Returns `Ok(true)` if the URL passes all SSRF checks.
    /// Returns `Ok(false)` for any security violation or malformed URL.
    pub fn is_safe(&self, url: &str) -> Result<bool> {
        use url::Url;

        // Reject null bytes
        if url.contains('\0') {
            return Ok(false);
        }

        // Parse URL
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return Ok(false),
        };

        // Check scheme
        let scheme = parsed.scheme().to_lowercase();
        if !self.schemes.iter().any(|s| s.to_lowercase() == scheme) {
            return Ok(false);
        }

        // Extract host
        let host = match parsed.host_str() {
            Some(h) if !h.is_empty() => h,
            _ => return Ok(false), // No host or empty host
        };

        // Decode percent-encoded hostname (SSRF bypass prevention)
        let host = urlencoding_decode(host).to_lowercase();

        // Check port
        // Note: url::Url::port() returns None for default ports (80 for http, 443 for https)
        // Use port_or_known_default() to get the actual port
        if let Some(ref allowed_ports) = self.allow_ports {
            if let Some(port) = parsed.port_or_known_default() {
                if !allowed_ports.contains(&port) {
                    return Ok(false);
                }
            }
        }

        // Check for localhost names
        if self.block_loopback && (host == "localhost" || host == "localhost.localdomain") {
            return Ok(false);
        }

        // Check internal TLDs
        if self.block_internal_tlds {
            for tld in INTERNAL_TLDS {
                if host.ends_with(tld) || host == tld[1..] {
                    return Ok(false);
                }
            }
        }

        // Check metadata hosts
        if self.block_metadata && METADATA_HOSTS.contains(&host.as_str()) {
            return Ok(false);
        }

        // Try to parse as IP address
        if let Some(ip) = self.parse_ip(&host) {
            if !self.check_ip_safe(&ip) {
                return Ok(false);
            }
        } else {
            // It's a hostname - additional security checks

            // SECURITY: Block ambiguous IP-like hostnames with leading zeros.
            // Different parsers interpret these inconsistently:
            // - WHATWG (url crate): "010.0.0.1" treated as hostname (needs DNS)
            // - POSIX libc: "010.0.0.1" parsed as octal IP = 8.0.0.1
            // - Some browsers: "010.0.0.1" parsed as decimal IP = 10.0.0.1
            //
            // This inconsistency creates SSRF bypass risk. Fail closed.
            if self.looks_like_ambiguous_ip(&host) {
                return Ok(false);
            }

            // Check domain allowlist
            if let Some(ref domains) = self.allow_domains {
                if !self.check_domain_allowed(&host, domains) {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Parse host as IP address, handling various representations.
    fn parse_ip(&self, host: &str) -> Option<IpAddr> {
        // Strip brackets from IPv6
        let host = host.trim_start_matches('[').trim_end_matches(']');

        // Try standard parsing first
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(ip);
        }

        // Try decimal notation (e.g., 2130706433 = 127.0.0.1)
        if host.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(int_val) = host.parse::<u32>() {
                return Some(IpAddr::V4(std::net::Ipv4Addr::from(int_val)));
            }
        }

        // Try hex notation (e.g., 0x7f000001 = 127.0.0.1)
        if host.to_lowercase().starts_with("0x") {
            if let Ok(int_val) = u32::from_str_radix(&host[2..], 16) {
                return Some(IpAddr::V4(std::net::Ipv4Addr::from(int_val)));
            }
        }

        // SECURITY: Handle ambiguous IP notation with leading zeros.
        // Different parsers interpret "010.0.0.1" inconsistently:
        // - POSIX libc: octal, so 010.0.0.1 = 8.0.0.1
        // - WHATWG (browsers): decimal with leading zeros, so 010.0.0.1 = 10.0.0.1
        // - Some libraries: reject as invalid
        //
        // OLD BEHAVIOR: We used to parse as octal (POSIX style).
        // NEW BEHAVIOR: We return None for ambiguous IPs, causing them to be
        // rejected by the looks_like_ambiguous_ip check in the hostname path.
        //
        // Exception: 0177.0.0.1 is clearly octal notation (digits > 7 would fail),
        // so we handle that case specifically.
        if host.starts_with('0') && host.contains('.') {
            let parts: Vec<&str> = host.split('.').collect();
            if parts.len() == 4 {
                let all_numeric = parts
                    .iter()
                    .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));

                if all_numeric {
                    // Check if any part has leading zeros (ambiguous)
                    let has_leading_zeros = parts.iter().any(|p| p.len() > 1 && p.starts_with('0'));

                    if has_leading_zeros {
                        // Check if it's clearly octal (contains only 0-7)
                        let is_clear_octal = parts
                            .iter()
                            .all(|p| p.chars().all(|c| ('0'..='7').contains(&c)));

                        // Even for clear octals (0177.0.0.1), check if the octal result
                        // is different from decimal - that's a bypass risk
                        if is_clear_octal {
                            let mut octets = [0u8; 4];
                            let mut octal_valid = true;
                            let mut decimal_same = true;

                            for (i, part) in parts.iter().enumerate() {
                                let octal_val = if part.starts_with('0') && part.len() > 1 {
                                    u8::from_str_radix(part, 8).ok()
                                } else {
                                    part.parse::<u8>().ok()
                                };

                                let decimal_val = part.parse::<u8>().ok();

                                if let Some(ov) = octal_val {
                                    octets[i] = ov;
                                    // Check if octal and decimal give different results
                                    if decimal_val != Some(ov) {
                                        decimal_same = false;
                                    }
                                } else {
                                    octal_valid = false;
                                    break;
                                }
                            }

                            if octal_valid {
                                if !decimal_same {
                                    // Results differ - this is ambiguous!
                                    // Example: 010.0.0.1 -> octal 8.0.0.1, decimal 10.0.0.1
                                    // We can't know which interpretation the HTTP client will use.
                                    // Return None to block via ambiguous check.
                                    return None;
                                }
                                // Results are same - safe to return the IP
                                return Some(IpAddr::V4(std::net::Ipv4Addr::from(octets)));
                            }
                        }

                        // Has leading zeros but not valid octal (e.g., 08, 09)
                        // or different interpretations - return None to block via ambiguous check
                        return None;
                    }
                }
            }
        }

        None
    }

    /// Check if IP address is safe to connect to.
    fn check_ip_safe(&self, ip: &IpAddr) -> bool {
        // Handle IPv6 addresses that embed IPv4
        let ip = match ip {
            IpAddr::V6(v6) => {
                // 1. IPv6-mapped IPv4: ::ffff:x.x.x.x
                if let Some(mapped) = v6.to_ipv4_mapped() {
                    IpAddr::V4(mapped)
                }
                // 2. IPv4-compatible IPv6: ::x.x.x.x (deprecated RFC 4291 but still parsed)
                // These have the first 96 bits as zero and last 32 bits as IPv4
                // Example: ::127.0.0.1, ::10.0.0.1, [0:0:0:0:0:0:127.0.0.1]
                else {
                    let segments = v6.segments();
                    // Check if first 6 segments are all zero (IPv4-compatible format)
                    if segments[0..6].iter().all(|&s| s == 0) {
                        // Extract the IPv4 address from the last 32 bits
                        let octets = v6.octets();
                        let ipv4 =
                            std::net::Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                        // Don't convert ::0 or ::1 since those are valid IPv6 addresses
                        // (unspecified and loopback respectively)
                        if ipv4.octets() != [0, 0, 0, 0] && ipv4.octets() != [0, 0, 0, 1] {
                            IpAddr::V4(ipv4)
                        } else {
                            *ip
                        }
                    } else {
                        *ip
                    }
                }
            }
            _ => *ip,
        };

        // Check loopback
        if self.block_loopback && ip.is_loopback() {
            return false;
        }

        // Check private ranges (requires manual check for IPv4)
        if self.block_private {
            if let IpAddr::V4(v4) = ip {
                let octets = v4.octets();
                // 10.0.0.0/8
                if octets[0] == 10 {
                    return false;
                }
                // 172.16.0.0/12
                if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                    return false;
                }
                // 192.168.0.0/16
                if octets[0] == 192 && octets[1] == 168 {
                    return false;
                }
            }
            // IPv6 private ranges
            if let IpAddr::V6(v6) = ip {
                let segments = v6.segments();
                // fc00::/7 (unique local)
                if (segments[0] & 0xfe00) == 0xfc00 {
                    return false;
                }
                // fe80::/10 (link-local)
                if (segments[0] & 0xffc0) == 0xfe80 {
                    return false;
                }
            }
        }

        // Check reserved ranges
        if self.block_reserved {
            if let IpAddr::V4(v4) = ip {
                let octets = v4.octets();
                // 0.0.0.0/8 ("This" network)
                if octets[0] == 0 {
                    return false;
                }
                // 224.0.0.0/4 (Multicast)
                if (224..=239).contains(&octets[0]) {
                    return false;
                }
                // 255.255.255.255 (Broadcast)
                if octets == [255, 255, 255, 255] {
                    return false;
                }
            }
        }

        // Check metadata range (169.254.0.0/16 link-local)
        if self.block_metadata {
            if let IpAddr::V4(v4) = ip {
                let octets = v4.octets();
                if octets[0] == 169 && octets[1] == 254 {
                    return false;
                }
            }
        }

        true
    }

    /// Check if hostname matches domain allowlist.
    fn check_domain_allowed(&self, host: &str, domains: &[String]) -> bool {
        for pattern in domains {
            let pattern = pattern.to_lowercase();
            if pattern.starts_with("*.") {
                // Wildcard subdomain: *.example.com matches sub.example.com
                let suffix = &pattern[1..]; // .example.com
                if host.ends_with(suffix) || host == &pattern[2..] {
                    return true;
                }
            } else if host == pattern {
                return true;
            }
        }
        false
    }

    /// Check if hostname looks like an ambiguous IP address.
    ///
    /// Some hostnames look like IP addresses but have leading zeros that
    /// different parsers interpret inconsistently:
    /// - "010.0.0.1": WHATWG sees hostname, POSIX sees octal 8.0.0.1, browsers see 10.0.0.1
    /// - "00000010.0.0.1": Similar ambiguity
    ///
    /// This function returns true if the hostname looks like an IP with
    /// leading zeros, which we block to fail closed against parser confusion.
    fn looks_like_ambiguous_ip(&self, host: &str) -> bool {
        // Check if it looks like a dotted-decimal IPv4 with leading zeros
        let parts: Vec<&str> = host.split('.').collect();

        // Must have exactly 4 parts to look like IPv4
        if parts.len() != 4 {
            return false;
        }

        // Check if all parts are numeric (could be ambiguous IP)
        let all_numeric = parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));

        if !all_numeric {
            return false;
        }

        // Check for leading zeros in any octet (ambiguous notation)
        for part in &parts {
            if part.len() > 1 && part.starts_with('0') {
                // This is ambiguous: "010" could be octal 8 or decimal 10
                return true;
            }
        }

        false
    }

    /// Check if a value satisfies the UrlSafe constraint.
    ///
    /// The value must be a string containing a URL.
    pub fn matches(&self, value: &ConstraintValue) -> Result<bool> {
        match value.as_str() {
            Some(url_str) => self.is_safe(url_str),
            None => Ok(false),
        }
    }

    /// Validate that `child` is a valid attenuation (child is more restrictive).
    ///
    /// A child UrlSafe is valid if it is at least as restrictive as the parent.
    pub fn validate_attenuation(&self, child: &UrlSafe) -> Result<()> {
        // Child schemes must be subset of parent
        for scheme in &child.schemes {
            if !self
                .schemes
                .iter()
                .any(|s| s.to_lowercase() == scheme.to_lowercase())
            {
                return Err(Error::MonotonicityViolation(format!(
                    "child scheme '{}' not in parent schemes",
                    scheme
                )));
            }
        }

        // Child cannot disable blocking if parent enables it
        if self.block_private && !child.block_private {
            return Err(Error::MonotonicityViolation(
                "cannot disable block_private".to_string(),
            ));
        }
        if self.block_loopback && !child.block_loopback {
            return Err(Error::MonotonicityViolation(
                "cannot disable block_loopback".to_string(),
            ));
        }
        if self.block_metadata && !child.block_metadata {
            return Err(Error::MonotonicityViolation(
                "cannot disable block_metadata".to_string(),
            ));
        }
        if self.block_reserved && !child.block_reserved {
            return Err(Error::MonotonicityViolation(
                "cannot disable block_reserved".to_string(),
            ));
        }
        if self.block_internal_tlds && !child.block_internal_tlds {
            return Err(Error::MonotonicityViolation(
                "cannot disable block_internal_tlds".to_string(),
            ));
        }

        // If parent has domain allowlist, child must have it too (and be subset)
        if let Some(ref parent_domains) = self.allow_domains {
            match &child.allow_domains {
                None => {
                    return Err(Error::MonotonicityViolation(
                        "child must have domain allowlist if parent does".to_string(),
                    ));
                }
                Some(child_domains) => {
                    // Each child domain must be covered by a parent domain pattern
                    for cd in child_domains {
                        if !parent_domains.iter().any(|pd| {
                            let pd = pd.to_lowercase();
                            let cd = cd.to_lowercase();
                            // Exact match
                            if pd == cd {
                                return true;
                            }
                            // Parent wildcard covers child exact
                            if pd.starts_with("*.") && cd.ends_with(&pd[1..]) {
                                return true;
                            }
                            false
                        }) {
                            return Err(Error::MonotonicityViolation(format!(
                                "child domain '{}' not covered by parent allowlist",
                                cd
                            )));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for UrlSafe {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for UrlSafe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut opts = Vec::new();
        if self.schemes != default_schemes() {
            opts.push(format!("schemes={:?}", self.schemes));
        }
        if let Some(ref domains) = self.allow_domains {
            opts.push(format!("allow_domains={:?}", domains));
        }
        if !self.block_private {
            opts.push("block_private=false".to_string());
        }
        if !self.block_loopback {
            opts.push("block_loopback=false".to_string());
        }
        if !self.block_metadata {
            opts.push("block_metadata=false".to_string());
        }
        if self.block_internal_tlds {
            opts.push("block_internal_tlds=true".to_string());
        }

        if opts.is_empty() {
            write!(f, "UrlSafe()")
        } else {
            write!(f, "UrlSafe({})", opts.join(", "))
        }
    }
}

impl From<UrlSafe> for Constraint {
    fn from(u: UrlSafe) -> Self {
        Constraint::UrlSafe(u)
    }
}

/// Simple URL decoding (handles percent-encoded characters).
fn urlencoding_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Try to read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            // Invalid encoding, keep as-is
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }

    result
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
            let found = child
                .constraints
                .iter()
                .any(|child_c| parent_c.validate_attenuation(child_c).is_ok());
            if !found {
                return Err(Error::MonotonicityViolation(
                    "child All must include all parent constraints".to_string(),
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
/// # Optional Feature
///
/// Requires the `cel` feature flag. Without this feature, expressions can be
/// deserialized but will fail verification with `FeatureNotEnabled`.
///
/// ```toml
/// tenuo = { version = "0.1", features = ["cel"] }
/// ```
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
        if normalize_cel_whitespace(&child.expression) == normalize_cel_whitespace(&self.expression)
        {
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

/// Helper for serde skip_serializing_if
fn is_false(b: &bool) -> bool {
    !*b
}

/// A set of constraints keyed by field name.
///
/// Uses BTreeMap for deterministic serialization order (canonical CBOR).
/// This ensures consistent warrant IDs regardless of insertion order.
///
/// # Zero-Trust Unknown Fields
///
/// When any constraint is defined, the constraint set operates in "closed-world"
/// mode by default: arguments not explicitly constrained are rejected.
///
/// - No constraints (empty set) -> OPEN: any arguments allowed
/// - Any constraint defined -> CLOSED: unknown fields rejected
/// - `allow_unknown=true` -> Explicit opt-out from closed-world
///
/// Use `Wildcard` constraint to allow any value for a specific field while
/// still operating in closed-world mode for other fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ConstraintSet {
    constraints: BTreeMap<String, Constraint>,
    /// When true, arguments not listed in constraints are allowed.
    /// When false (default), unknown arguments are rejected if any constraints exist.
    #[serde(default, skip_serializing_if = "is_false")]
    allow_unknown: bool,
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

    /// Check if unknown arguments are allowed.
    ///
    /// When `false` (default) and constraints exist, unknown arguments are rejected.
    /// When `true`, unknown arguments pass through even when constraints exist.
    pub fn allow_unknown(&self) -> bool {
        self.allow_unknown
    }

    /// Set whether unknown arguments are allowed.
    ///
    /// Use this to explicitly opt-out of zero-trust mode when you want to
    /// constrain some fields but allow others to pass through unchecked.
    pub fn set_allow_unknown(&mut self, allow: bool) {
        self.allow_unknown = allow;
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
    ///
    /// # Zero-Trust Behavior
    ///
    /// - If no constraints exist: all arguments are allowed (open-world)
    /// - If any constraint exists and `allow_unknown=false`: unknown arguments rejected
    /// - If any constraint exists and `allow_unknown=true`: unknown arguments allowed
    pub fn matches(&self, args: &HashMap<String, ConstraintValue>) -> Result<()> {
        // Zero-trust: if constraints exist and allow_unknown is false,
        // reject any arguments not explicitly constrained
        if !self.constraints.is_empty() && !self.allow_unknown {
            for key in args.keys() {
                if !self.constraints.contains_key(key) {
                    return Err(Error::ConstraintNotSatisfied {
                        field: key.clone(),
                        reason: "unknown field not allowed (zero-trust mode)".to_string(),
                    });
                }
            }
        }

        // Check all defined constraints are satisfied
        for (field, constraint) in &self.constraints {
            let value = args
                .get(field)
                .ok_or_else(|| Error::ConstraintNotSatisfied {
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
    ///
    /// # Monotonicity Rules
    ///
    /// - Child must have all constraints that parent has (can be narrower)
    /// - Child can add new constraints (that's more restrictive)
    /// - Child cannot enable `allow_unknown` if parent has it disabled
    ///   (that would expand capabilities)
    /// - Child can disable `allow_unknown` even if parent enabled it
    ///   (that's more restrictive)
    pub fn validate_attenuation(&self, child: &ConstraintSet) -> Result<()> {
        // Monotonicity: child cannot be MORE permissive than parent
        // If parent has allow_unknown=false, child cannot enable it
        if !self.allow_unknown && child.allow_unknown {
            return Err(Error::MonotonicityViolation(
                "child cannot enable allow_unknown when parent has it disabled".to_string(),
            ));
        }

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
            allow_unknown: false,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Pattern (Glob) Tests - Comprehensive
    // -------------------------------------------------------------------------

    #[test]
    fn test_pattern_suffix_wildcard() {
        // Suffix wildcard: staging-*
        let pattern = Pattern::new("staging-*").unwrap();
        assert!(pattern.matches(&"staging-web".into()).unwrap());
        assert!(pattern.matches(&"staging-api".into()).unwrap());
        assert!(pattern.matches(&"staging-".into()).unwrap()); // Empty suffix ok
        assert!(!pattern.matches(&"prod-web".into()).unwrap());
        assert!(!pattern.matches(&"Staging-web".into()).unwrap()); // Case sensitive
    }

    #[test]
    fn test_pattern_prefix_wildcard() {
        // Prefix wildcard: *@company.com
        let pattern = Pattern::new("*@company.com").unwrap();
        assert!(pattern.matches(&"cfo@company.com".into()).unwrap());
        assert!(pattern.matches(&"alice@company.com".into()).unwrap());
        assert!(pattern.matches(&"@company.com".into()).unwrap()); // Empty prefix ok
        assert!(!pattern.matches(&"hacker@evil.com".into()).unwrap());
        assert!(!pattern.matches(&"cfo@company.com.evil.com".into()).unwrap());
    }

    #[test]
    fn test_pattern_middle_wildcard() {
        // Middle wildcard: /data/*/file.txt
        let pattern = Pattern::new("/data/*/file.txt").unwrap();
        assert!(pattern.matches(&"/data/reports/file.txt".into()).unwrap());
        assert!(pattern.matches(&"/data/x/file.txt".into()).unwrap());
        assert!(!pattern.matches(&"/data/reports/other.txt".into()).unwrap());
        assert!(!pattern.matches(&"/data/file.txt".into()).unwrap()); // Missing middle segment
    }

    #[test]
    fn test_pattern_multiple_wildcards() {
        // Multiple wildcards: /*/reports/*.pdf
        let pattern = Pattern::new("/*/reports/*.pdf").unwrap();
        assert!(pattern.matches(&"/data/reports/q3.pdf".into()).unwrap());
        assert!(pattern.matches(&"/home/reports/annual.pdf".into()).unwrap());
        assert!(!pattern.matches(&"/data/reports/q3.txt".into()).unwrap());
        assert!(!pattern.matches(&"/data/other/q3.pdf".into()).unwrap());
    }

    #[test]
    fn test_pattern_bidirectional_wildcard() {
        // Bidirectional wildcard: *mid*
        let pattern = Pattern::new("*-prod-*").unwrap();
        assert!(pattern.matches(&"db-prod-primary".into()).unwrap());
        assert!(pattern.matches(&"cache-prod-replica".into()).unwrap());
        assert!(pattern.matches(&"-prod-".into()).unwrap()); // Minimal match
        assert!(!pattern.matches(&"db-staging-primary".into()).unwrap());
        assert!(!pattern.matches(&"prod-only".into()).unwrap()); // Missing prefix wildcard match

        // Another example: *safe*
        let pattern = Pattern::new("*safe*").unwrap();
        assert!(pattern.matches(&"unsafe".into()).unwrap());
        assert!(pattern.matches(&"safeguard".into()).unwrap());
        assert!(pattern.matches(&"is-safe-mode".into()).unwrap());
        assert!(!pattern.matches(&"danger".into()).unwrap());
    }

    #[test]
    fn test_pattern_bidirectional_attenuation() {
        let parent = Pattern::new("*-prod-*").unwrap();

        // Same pattern: OK (equality)
        let child_same = Pattern::new("*-prod-*").unwrap();
        assert!(parent.validate_attenuation(&child_same).is_ok());

        // Different pattern: REJECTED (even if logically narrower)
        // This is conservative behavior - subset checking is undecidable
        let child_prefix = Pattern::new("db-prod-*").unwrap();
        assert!(parent.validate_attenuation(&child_prefix).is_err());

        let child_suffix = Pattern::new("*-prod-primary").unwrap();
        assert!(parent.validate_attenuation(&child_suffix).is_err());

        let child_exact = Pattern::new("db-prod-primary").unwrap();
        assert!(parent.validate_attenuation(&child_exact).is_err());
    }

    #[test]
    fn test_pattern_complex_attenuation() {
        // Test middle wildcard (Complex type)
        let parent = Pattern::new("/data/*/file.txt").unwrap();

        // Same pattern: OK
        let child_same = Pattern::new("/data/*/file.txt").unwrap();
        assert!(parent.validate_attenuation(&child_same).is_ok());

        // Different pattern: REJECTED
        let child_different = Pattern::new("/data/reports/file.txt").unwrap();
        assert!(parent.validate_attenuation(&child_different).is_err());
    }

    #[test]
    fn test_pattern_single_wildcard() {
        // Single wildcard matches anything
        let pattern = Pattern::new("*").unwrap();
        assert!(pattern.matches(&"anything".into()).unwrap());
        assert!(pattern.matches(&"".into()).unwrap());
        assert!(pattern.matches(&"foo/bar/baz".into()).unwrap());
    }

    #[test]
    fn test_pattern_question_mark() {
        // ? matches single character
        let pattern = Pattern::new("file?.txt").unwrap();
        assert!(pattern.matches(&"file1.txt".into()).unwrap());
        assert!(pattern.matches(&"fileA.txt".into()).unwrap());
        assert!(!pattern.matches(&"file12.txt".into()).unwrap());
        assert!(!pattern.matches(&"file.txt".into()).unwrap());
    }

    #[test]
    fn test_pattern_character_class() {
        // Character class [abc]
        let pattern = Pattern::new("env-[psd]*").unwrap(); // prod, staging, dev
        assert!(pattern.matches(&"env-prod".into()).unwrap());
        assert!(pattern.matches(&"env-staging".into()).unwrap());
        assert!(pattern.matches(&"env-dev".into()).unwrap());
        assert!(!pattern.matches(&"env-test".into()).unwrap()); // t not in [psd]
    }

    #[test]
    fn test_pattern_no_wildcard() {
        // No wildcard = exact match
        let pattern = Pattern::new("/data/file.txt").unwrap();
        assert!(pattern.matches(&"/data/file.txt".into()).unwrap());
        assert!(!pattern.matches(&"/data/other.txt".into()).unwrap());
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
        let range = Range::between(10.0, 100.0).unwrap();
        assert!(range.matches(&50i64.into()).unwrap());
        assert!(range.matches(&10i64.into()).unwrap());
        assert!(range.matches(&100i64.into()).unwrap());
        assert!(!range.matches(&5i64.into()).unwrap());
        assert!(!range.matches(&150i64.into()).unwrap());
    }

    #[test]
    fn test_range_rejects_nan() {
        // NaN in min
        let result = Range::min(f64::NAN);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("NaN"));

        // NaN in max
        let result = Range::max(f64::NAN);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("NaN"));

        // NaN in between
        let result = Range::between(f64::NAN, 100.0);
        assert!(result.is_err());

        let result = Range::between(0.0, f64::NAN);
        assert!(result.is_err());

        // Valid values still work
        assert!(Range::max(100.0).is_ok());
        assert!(Range::min(0.0).is_ok());
        assert!(Range::between(0.0, 100.0).is_ok());

        // Infinity is allowed (it's a valid f64)
        assert!(Range::max(f64::INFINITY).is_ok());
        assert!(Range::min(f64::NEG_INFINITY).is_ok());
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
            Range::min(0.0).unwrap().into(),
            Range::max(100.0).unwrap().into(),
        ]);

        assert!(all.matches(&50i64.into()).unwrap());
        assert!(!all.matches(&(-10i64).into()).unwrap());
        assert!(!all.matches(&150i64.into()).unwrap());
    }

    #[test]
    fn test_any_constraint() {
        let any = Any::new([Exact::new("admin").into(), Exact::new("superuser").into()]);

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
    fn test_range_attenuation() {
        let parent = Range::max(10000.0).unwrap();
        let valid_child = Range::max(5000.0).unwrap();
        assert!(parent.validate_attenuation(&valid_child).is_ok());

        let invalid_child = Range::max(15000.0).unwrap();
        assert!(parent.validate_attenuation(&invalid_child).is_err());
    }

    // =========================================================================
    // Security Tests: Range Inclusivity (Finding 1)
    // =========================================================================

    #[test]
    fn test_range_inclusivity_cannot_expand() {
        // Parent: (0, 10) exclusive bounds - values must be > 0 and < 10
        let parent = Range::between(0.0, 10.0)
            .unwrap()
            .min_exclusive()
            .max_exclusive();

        // Child: [0, 10] inclusive bounds - would include 0 and 10
        let child_inclusive = Range::between(0.0, 10.0).unwrap(); // Default is inclusive

        // This MUST fail - child would expand permissions to include boundary values
        let result = parent.validate_attenuation(&child_inclusive);
        assert!(
            result.is_err(),
            "Should reject: exclusive->inclusive at same bound expands permissions"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("inclusivity expanded"));
    }

    #[test]
    fn test_range_inclusivity_can_narrow() {
        // Parent: [0, 10] inclusive bounds
        let parent = Range::between(0.0, 10.0).unwrap();

        // Child: (0, 10) exclusive bounds - more restrictive
        let child_exclusive = Range::between(0.0, 10.0)
            .unwrap()
            .min_exclusive()
            .max_exclusive();

        // This MUST succeed - child is more restrictive
        assert!(
            parent.validate_attenuation(&child_exclusive).is_ok(),
            "Should allow: inclusive->exclusive is valid narrowing"
        );
    }

    #[test]
    fn test_range_inclusivity_stricter_value_ok() {
        // Parent: (0, 10) exclusive - values > 0 and < 10
        let parent = Range::between(0.0, 10.0)
            .unwrap()
            .min_exclusive()
            .max_exclusive();

        // Child: [1, 9] inclusive at DIFFERENT values - doesn't include parent's boundaries
        let child = Range::between(1.0, 9.0).unwrap();

        // This is OK - child's bounds are strictly inside parent's exclusive range
        assert!(
            parent.validate_attenuation(&child).is_ok(),
            "Should allow: child bounds strictly inside parent exclusive range"
        );
    }

    // =========================================================================
    // Security Tests: Range -> Exact (Finding 2)
    // =========================================================================

    #[test]
    fn test_range_to_exact_valid() {
        let parent = Constraint::Range(Range::between(0.0, 100.0).unwrap());

        // Valid: Exact(50) is within [0, 100]
        let child = Constraint::Exact(Exact::new(50));
        assert!(
            parent.validate_attenuation(&child).is_ok(),
            "Should allow: Exact(50) is within Range(0, 100)"
        );

        // Valid: Exact at boundary (inclusive)
        let child_at_min = Constraint::Exact(Exact::new(0));
        assert!(
            parent.validate_attenuation(&child_at_min).is_ok(),
            "Should allow: Exact(0) at inclusive min bound"
        );

        let child_at_max = Constraint::Exact(Exact::new(100));
        assert!(
            parent.validate_attenuation(&child_at_max).is_ok(),
            "Should allow: Exact(100) at inclusive max bound"
        );
    }

    #[test]
    fn test_range_to_exact_invalid() {
        let parent = Constraint::Range(Range::between(0.0, 100.0).unwrap());

        // Invalid: Exact(-1) is below range
        let child_below = Constraint::Exact(Exact::new(-1));
        assert!(
            parent.validate_attenuation(&child_below).is_err(),
            "Should reject: Exact(-1) below Range(0, 100)"
        );

        // Invalid: Exact(150) is above range
        let child_above = Constraint::Exact(Exact::new(150));
        assert!(
            parent.validate_attenuation(&child_above).is_err(),
            "Should reject: Exact(150) above Range(0, 100)"
        );
    }

    #[test]
    fn test_range_exclusive_to_exact_boundary() {
        // Parent: (0, 100) exclusive bounds
        let parent = Constraint::Range(
            Range::between(0.0, 100.0)
                .unwrap()
                .min_exclusive()
                .max_exclusive(),
        );

        // Invalid: Exact(0) at exclusive min bound
        let child_at_min = Constraint::Exact(Exact::new(0));
        assert!(
            parent.validate_attenuation(&child_at_min).is_err(),
            "Should reject: Exact(0) at exclusive min bound"
        );

        // Invalid: Exact(100) at exclusive max bound
        let child_at_max = Constraint::Exact(Exact::new(100));
        assert!(
            parent.validate_attenuation(&child_at_max).is_err(),
            "Should reject: Exact(100) at exclusive max bound"
        );

        // Valid: Exact(50) inside exclusive range
        let child_inside = Constraint::Exact(Exact::new(50));
        assert!(
            parent.validate_attenuation(&child_inside).is_ok(),
            "Should allow: Exact(50) inside exclusive range"
        );
    }

    #[test]
    fn test_subset_attenuation() {
        let parent = Subset::new(["a", "b", "c"]);
        let valid_child = Subset::new(["a", "b"]); // Smaller allowed set
        assert!(parent.validate_attenuation(&valid_child).is_ok());

        let invalid_child = Subset::new(["a", "d"]); // 'd' not in parent
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("incompatible constraint types"));

        // Range cannot narrow to Pattern
        let parent = Constraint::Range(Range::max(1000.0).unwrap());
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

        assert!(wildcard
            .matches(&ConstraintValue::String("anything".to_string()))
            .unwrap());
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
        let child = Constraint::Range(Range::max(1000.0).unwrap());
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot attenuate to Wildcard"));

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
        assert!(constraint
            .matches(&ConstraintValue::String("staging".to_string()))
            .unwrap());
        assert!(constraint
            .matches(&ConstraintValue::String("dev".to_string()))
            .unwrap());

        // Values IN the excluded set should NOT match
        assert!(!constraint
            .matches(&ConstraintValue::String("prod".to_string()))
            .unwrap());
        assert!(!constraint
            .matches(&ConstraintValue::String("secure".to_string()))
            .unwrap());
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must still exclude"));
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

    // =========================================================================
    // CIDR Constraint Tests
    // =========================================================================

    #[test]
    fn test_cidr_creation_ipv4() {
        let cidr = Cidr::new("10.0.0.0/8").unwrap();
        assert_eq!(cidr.cidr_string, "10.0.0.0/8");
    }

    #[test]
    fn test_cidr_creation_ipv6() {
        let cidr = Cidr::new("2001:db8::/32").unwrap();
        assert_eq!(cidr.cidr_string, "2001:db8::/32");
    }

    #[test]
    fn test_cidr_invalid() {
        assert!(Cidr::new("not-a-cidr").is_err());
        assert!(Cidr::new("10.0.0.0/33").is_err()); // Invalid prefix for IPv4
        assert!(Cidr::new("256.0.0.0/8").is_err()); // Invalid IP
    }

    #[test]
    fn test_cidr_contains_ip() {
        let cidr = Cidr::new("10.0.0.0/8").unwrap();

        // IPs within the network
        assert!(cidr.contains_ip("10.0.0.1").unwrap());
        assert!(cidr.contains_ip("10.255.255.255").unwrap());
        assert!(cidr.contains_ip("10.1.2.3").unwrap());

        // IPs outside the network
        assert!(!cidr.contains_ip("192.168.1.1").unwrap());
        assert!(!cidr.contains_ip("11.0.0.1").unwrap());
    }

    #[test]
    fn test_cidr_contains_ip_ipv6() {
        let cidr = Cidr::new("2001:db8::/32").unwrap();

        assert!(cidr.contains_ip("2001:db8::1").unwrap());
        assert!(cidr
            .contains_ip("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
            .unwrap());
        assert!(!cidr.contains_ip("2001:db9::1").unwrap());
    }

    #[test]
    fn test_cidr_matches_constraint_value() {
        let cidr = Cidr::new("192.168.0.0/16").unwrap();

        // String IP that matches
        let value = ConstraintValue::String("192.168.1.100".to_string());
        assert!(cidr.matches(&value).unwrap());

        // String IP that doesn't match
        let value = ConstraintValue::String("10.0.0.1".to_string());
        assert!(!cidr.matches(&value).unwrap());

        // Non-string value
        let value = ConstraintValue::Integer(123);
        assert!(!cidr.matches(&value).unwrap());
    }

    #[test]
    fn test_cidr_attenuation_valid_subnet() {
        // Parent: 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
        // Child: 10.1.0.0/16 (10.1.0.0 - 10.1.255.255) - valid subnet
        let parent = Cidr::new("10.0.0.0/8").unwrap();
        let child = Cidr::new("10.1.0.0/16").unwrap();

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_cidr_attenuation_same_network() {
        let parent = Cidr::new("10.0.0.0/8").unwrap();
        let child = Cidr::new("10.0.0.0/8").unwrap();

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_cidr_attenuation_narrower_prefix() {
        // /24 is narrower than /16
        let parent = Cidr::new("192.168.0.0/16").unwrap();
        let child = Cidr::new("192.168.1.0/24").unwrap();

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_cidr_attenuation_invalid_not_subset() {
        // Child network is outside parent
        let parent = Cidr::new("10.0.0.0/8").unwrap();
        let child = Cidr::new("192.168.0.0/16").unwrap();

        let result = parent.validate_attenuation(&child);
        assert!(result.is_err());
    }

    #[test]
    fn test_cidr_attenuation_invalid_wider() {
        // Child is wider than parent (would expand permissions)
        let parent = Cidr::new("10.1.0.0/16").unwrap();
        let child = Cidr::new("10.0.0.0/8").unwrap();

        let result = parent.validate_attenuation(&child);
        assert!(result.is_err());
    }

    #[test]
    fn test_cidr_constraint_attenuation() {
        let parent = Constraint::Cidr(Cidr::new("10.0.0.0/8").unwrap());
        let child = Constraint::Cidr(Cidr::new("10.1.0.0/16").unwrap());

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_cidr_to_exact_attenuation() {
        // CIDR can attenuate to Exact IP if IP is in network
        let parent = Constraint::Cidr(Cidr::new("10.0.0.0/8").unwrap());
        let child = Constraint::Exact(Exact::new("10.1.2.3"));

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_cidr_to_exact_attenuation_invalid() {
        // CIDR to Exact fails if IP not in network
        let parent = Constraint::Cidr(Cidr::new("10.0.0.0/8").unwrap());
        let child = Constraint::Exact(Exact::new("192.168.1.1"));

        let result = parent.validate_attenuation(&child);
        assert!(result.is_err());
    }

    #[test]
    fn test_wildcard_to_cidr_attenuation() {
        // Wildcard can attenuate to CIDR
        let parent = Constraint::Wildcard(Wildcard::new());
        let child = Constraint::Cidr(Cidr::new("10.0.0.0/8").unwrap());

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_cidr_single_ip_prefix32() {
        // /32 represents a single IP address
        let cidr = Cidr::new("192.168.1.100/32").unwrap();

        assert!(cidr.contains_ip("192.168.1.100").unwrap());
        assert!(!cidr.contains_ip("192.168.1.101").unwrap());
        assert!(!cidr.contains_ip("192.168.1.99").unwrap());
    }

    #[test]
    fn test_cidr_all_ips_prefix0() {
        // /0 represents all IP addresses
        let cidr = Cidr::new("0.0.0.0/0").unwrap();

        assert!(cidr.contains_ip("192.168.1.1").unwrap());
        assert!(cidr.contains_ip("10.0.0.1").unwrap());
        assert!(cidr.contains_ip("255.255.255.255").unwrap());
    }

    #[test]
    fn test_cidr_ipv4_ipv6_mismatch() {
        // IPv4 CIDR should not match IPv6 addresses
        let ipv4_cidr = Cidr::new("10.0.0.0/8").unwrap();
        assert!(!ipv4_cidr.contains_ip("2001:db8::1").unwrap());

        // IPv6 CIDR should not match IPv4 addresses
        let ipv6_cidr = Cidr::new("2001:db8::/32").unwrap();
        assert!(!ipv6_cidr.contains_ip("10.0.0.1").unwrap());
    }

    #[test]
    fn test_cidr_invalid_ip_string() {
        let cidr = Cidr::new("10.0.0.0/8").unwrap();

        // Invalid IP strings should return error
        assert!(cidr.contains_ip("not-an-ip").is_err());
        assert!(cidr.contains_ip("").is_err());
        assert!(cidr.contains_ip("256.0.0.1").is_err());
        assert!(cidr.contains_ip("10.0.0").is_err());
    }

    #[test]
    fn test_cidr_serialization_roundtrip() {
        let original = Cidr::new("192.168.0.0/16").unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"192.168.0.0/16\"");

        // Deserialize back
        let deserialized: Cidr = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.cidr_string, original.cidr_string);

        // Verify functionality preserved
        assert!(deserialized.contains_ip("192.168.1.1").unwrap());
        assert!(!deserialized.contains_ip("10.0.0.1").unwrap());
    }

    #[test]
    fn test_cidr_constraint_serialization() {
        let constraint = Constraint::Cidr(Cidr::new("10.0.0.0/8").unwrap());

        // Serialize as CBOR (wire format: [type_id, value])
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&constraint, &mut cbor_bytes).unwrap();

        // Verify type ID is CIDR (8)
        // CBOR array starts with 0x82 (2-element array), then type_id byte
        assert!(cbor_bytes.len() > 2);
        // The type ID should be 8 (CIDR)
        assert_eq!(cbor_bytes[1], constraint_type_id::CIDR);

        // Deserialize back
        let deserialized: Constraint = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();
        if let Constraint::Cidr(c) = deserialized {
            assert_eq!(c.cidr_string, "10.0.0.0/8");
        } else {
            panic!("Expected Cidr constraint, got {:?}", deserialized);
        }
    }

    /// Comprehensive test for all constraint type IDs in wire format.
    /// Verifies that each constraint type serializes with the correct type ID
    /// and round-trips correctly through CBOR.
    #[test]
    fn test_all_constraint_type_ids_wire_format() {
        use constraint_type_id::*;

        // Helper to test a constraint's wire format
        fn test_constraint(constraint: Constraint, expected_type_id: u8, name: &str) {
            let mut bytes = Vec::new();
            ciborium::ser::into_writer(&constraint, &mut bytes).unwrap();

            // CBOR 2-element array starts with 0x82, then type_id
            assert!(bytes.len() >= 2, "{}: too short", name);
            assert_eq!(bytes[0], 0x82, "{}: not a 2-element array", name);
            assert_eq!(bytes[1], expected_type_id, "{}: wrong type ID", name);

            // Round-trip
            let decoded: Constraint = ciborium::de::from_reader(&bytes[..]).unwrap();
            assert_eq!(
                std::mem::discriminant(&constraint),
                std::mem::discriminant(&decoded),
                "{}: discriminant mismatch after round-trip",
                name
            );
        }

        // Test all standard constraint types
        test_constraint(Constraint::Exact(Exact::new("test")), EXACT, "Exact");
        test_constraint(
            Constraint::Pattern(Pattern::new("test-*").unwrap()),
            PATTERN,
            "Pattern",
        );
        test_constraint(
            Constraint::Range(Range::new(Some(0.0), Some(100.0)).unwrap()),
            RANGE,
            "Range",
        );
        test_constraint(
            Constraint::OneOf(OneOf::new(vec!["a".to_string(), "b".to_string()])),
            ONE_OF,
            "OneOf",
        );
        test_constraint(
            Constraint::Regex(RegexConstraint::new("^test$").unwrap()),
            REGEX,
            "Regex",
        );
        test_constraint(
            Constraint::NotOneOf(NotOneOf::new(vec!["x".to_string()])),
            NOT_ONE_OF,
            "NotOneOf",
        );
        test_constraint(
            Constraint::Cidr(Cidr::new("10.0.0.0/8").unwrap()),
            CIDR,
            "Cidr",
        );
        test_constraint(
            Constraint::UrlPattern(UrlPattern::new("https://example.com/*").unwrap()),
            URL_PATTERN,
            "UrlPattern",
        );
        test_constraint(
            Constraint::Contains(Contains::new(vec!["admin".to_string()])),
            CONTAINS,
            "Contains",
        );
        test_constraint(
            Constraint::Subset(Subset::new(vec!["a".to_string(), "b".to_string()])),
            SUBSET,
            "Subset",
        );
        test_constraint(
            Constraint::All(All {
                constraints: vec![Constraint::Exact(Exact::new("x"))],
            }),
            ALL,
            "All",
        );
        test_constraint(
            Constraint::Any(Any {
                constraints: vec![Constraint::Exact(Exact::new("y"))],
            }),
            ANY,
            "Any",
        );
        test_constraint(
            Constraint::Not(Not {
                constraint: Box::new(Constraint::Exact(Exact::new("z"))),
            }),
            NOT,
            "Not",
        );
        test_constraint(Constraint::Cel(CelConstraint::new("x > 0")), CEL, "Cel");
        test_constraint(Constraint::Wildcard(Wildcard::new()), WILDCARD, "Wildcard");
    }

    /// Test that unknown type IDs deserialize to Unknown variant and fail closed.
    #[test]
    fn test_unknown_constraint_type_id() {
        // Manually construct CBOR for unknown type ID 200
        // [200, <bytes>] - Unknown expects raw bytes as payload
        let payload_bytes: Vec<u8> = vec![1, 2, 3, 4];
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(
            &(200u8, serde_bytes::Bytes::new(&payload_bytes)),
            &mut bytes,
        )
        .unwrap();

        let constraint: Constraint = ciborium::de::from_reader(&bytes[..]).unwrap();

        match constraint {
            Constraint::Unknown { type_id, payload } => {
                assert_eq!(type_id, 200);
                assert_eq!(payload, payload_bytes);
                // Unknown constraints always fail authorization (verified in other tests)
            }
            _ => panic!("Expected Unknown variant, got {:?}", constraint),
        }
    }

    #[test]
    fn test_cidr_attenuation_prefix32_to_prefix32() {
        // /32 can attenuate to same /32
        let parent = Cidr::new("10.1.2.3/32").unwrap();
        let child = Cidr::new("10.1.2.3/32").unwrap();

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_cidr_attenuation_to_single_ip() {
        // /8 can attenuate to /32 (single IP)
        let parent = Cidr::new("10.0.0.0/8").unwrap();
        let child = Cidr::new("10.1.2.3/32").unwrap();

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_cidr_ipv6_attenuation() {
        // IPv6 attenuation works the same way
        let parent = Cidr::new("2001:db8::/32").unwrap();
        let child = Cidr::new("2001:db8:1::/48").unwrap();

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_cidr_boundary_ips() {
        let cidr = Cidr::new("192.168.1.0/24").unwrap();

        // First IP in range (network address)
        assert!(cidr.contains_ip("192.168.1.0").unwrap());
        // Last IP in range (broadcast address)
        assert!(cidr.contains_ip("192.168.1.255").unwrap());
        // Just outside range
        assert!(!cidr.contains_ip("192.168.0.255").unwrap());
        assert!(!cidr.contains_ip("192.168.2.0").unwrap());
    }

    // =========================================================================
    // URL Pattern Constraint Tests
    // =========================================================================

    #[test]
    fn test_url_pattern_creation() {
        let pattern = UrlPattern::new("https://api.example.com/*").unwrap();
        assert_eq!(pattern.schemes, vec!["https"]);
        assert_eq!(pattern.host_pattern, Some("api.example.com".to_string()));
        assert_eq!(pattern.path_pattern, Some("/*".to_string()));
    }

    #[test]
    fn test_url_pattern_wildcard_scheme() {
        let pattern = UrlPattern::new("*://example.com/api/*").unwrap();
        assert!(pattern.schemes.is_empty()); // Empty means any scheme
        assert_eq!(pattern.host_pattern, Some("example.com".to_string()));
    }

    #[test]
    fn test_url_pattern_with_port() {
        let pattern = UrlPattern::new("https://api.example.com:8443/api/*").unwrap();
        assert_eq!(pattern.port, Some(8443));
    }

    #[test]
    fn test_url_pattern_wildcard_host() {
        let pattern = UrlPattern::new("https://*.example.com/*").unwrap();
        assert_eq!(pattern.host_pattern, Some("*.example.com".to_string()));
    }

    #[test]
    #[ignore = "URLP-001: Bare wildcard host not yet supported - see UrlPattern::new() for details"]
    fn test_url_pattern_bare_wildcard_host() {
        // SECURITY: Bare wildcard hosts (https://*/*) are intentionally unsupported.
        // This pattern would match ANY domain, bypassing SSRF protection.
        // Users must use either:
        //   - Explicit domains: UrlPattern("https://*.example.com/*")
        //   - UrlSafe() for SSRF-protected URL matching
        let pattern = UrlPattern::new("https://*/*").unwrap();

        // The parser sets host_pattern incorrectly due to replacement order,
        // but this is actually a security feature - bare wildcard hosts should not match.
        assert!(!pattern.matches_url("https://example.com/path").unwrap());
        assert!(!pattern.matches_url("https://evil.com/attack").unwrap());
    }

    #[test]
    fn test_url_pattern_invalid() {
        assert!(UrlPattern::new("not-a-url").is_err());
        assert!(UrlPattern::new("missing-scheme.com").is_err());
    }

    #[test]
    fn test_url_pattern_matches_basic() {
        let pattern = UrlPattern::new("https://api.example.com/*").unwrap();

        assert!(pattern
            .matches_url("https://api.example.com/v1/users")
            .unwrap());
        assert!(pattern.matches_url("https://api.example.com/").unwrap());

        // Wrong scheme
        assert!(!pattern.matches_url("http://api.example.com/v1").unwrap());
        // Wrong host
        assert!(!pattern.matches_url("https://other.example.com/v1").unwrap());
    }

    #[test]
    fn test_url_pattern_matches_wildcard_scheme() {
        let pattern = UrlPattern::new("*://api.example.com/*").unwrap();

        assert!(pattern.matches_url("https://api.example.com/v1").unwrap());
        assert!(pattern.matches_url("http://api.example.com/v1").unwrap());
    }

    #[test]
    fn test_url_pattern_matches_wildcard_host() {
        let pattern = UrlPattern::new("https://*.example.com/*").unwrap();

        assert!(pattern.matches_url("https://api.example.com/v1").unwrap());
        assert!(pattern.matches_url("https://www.example.com/v1").unwrap());
        assert!(pattern.matches_url("https://example.com/v1").unwrap());

        // Different domain
        assert!(!pattern.matches_url("https://api.other.com/v1").unwrap());
    }

    #[test]
    fn test_url_pattern_matches_port() {
        let pattern = UrlPattern::new("https://api.example.com:8443/*").unwrap();

        assert!(pattern
            .matches_url("https://api.example.com:8443/v1")
            .unwrap());
        // Wrong port
        assert!(!pattern
            .matches_url("https://api.example.com:443/v1")
            .unwrap());
        assert!(!pattern.matches_url("https://api.example.com/v1").unwrap());
    }

    #[test]
    fn test_url_pattern_matches_path() {
        let pattern = UrlPattern::new("https://api.example.com/api/v1/*").unwrap();

        assert!(pattern
            .matches_url("https://api.example.com/api/v1/users")
            .unwrap());
        assert!(pattern
            .matches_url("https://api.example.com/api/v1/")
            .unwrap());

        // Wrong path prefix
        assert!(!pattern
            .matches_url("https://api.example.com/api/v2/users")
            .unwrap());
        assert!(!pattern
            .matches_url("https://api.example.com/other")
            .unwrap());
    }

    #[test]
    fn test_url_pattern_attenuation_same() {
        let parent = UrlPattern::new("https://api.example.com/*").unwrap();
        let child = UrlPattern::new("https://api.example.com/*").unwrap();

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_url_pattern_attenuation_narrower_path() {
        let parent = UrlPattern::new("https://api.example.com/*").unwrap();
        let child = UrlPattern::new("https://api.example.com/api/v1/*").unwrap();

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_url_pattern_attenuation_narrower_host() {
        let parent = UrlPattern::new("https://*.example.com/*").unwrap();
        let child = UrlPattern::new("https://api.example.com/*").unwrap();

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_url_pattern_attenuation_add_scheme() {
        // Parent allows any scheme, child restricts to https
        let parent = UrlPattern::new("*://api.example.com/*").unwrap();
        let child = UrlPattern::new("https://api.example.com/*").unwrap();

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_url_pattern_attenuation_invalid_scheme_expansion() {
        let parent = UrlPattern::new("https://api.example.com/*").unwrap();
        let child = UrlPattern::new("http://api.example.com/*").unwrap();

        assert!(parent.validate_attenuation(&child).is_err());
    }

    #[test]
    fn test_url_pattern_attenuation_invalid_host_expansion() {
        let parent = UrlPattern::new("https://api.example.com/*").unwrap();
        let child = UrlPattern::new("https://*.example.com/*").unwrap();

        assert!(parent.validate_attenuation(&child).is_err());
    }

    #[test]
    fn test_url_pattern_attenuation_invalid_path_expansion() {
        let parent = UrlPattern::new("https://api.example.com/api/v1/*").unwrap();
        let child = UrlPattern::new("https://api.example.com/*").unwrap();

        assert!(parent.validate_attenuation(&child).is_err());
    }

    #[test]
    fn test_url_constraint_attenuation() {
        let parent = Constraint::UrlPattern(UrlPattern::new("https://*.example.com/*").unwrap());
        let child =
            Constraint::UrlPattern(UrlPattern::new("https://api.example.com/v1/*").unwrap());

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_url_to_exact_attenuation() {
        let parent = Constraint::UrlPattern(UrlPattern::new("https://api.example.com/*").unwrap());
        let child = Constraint::Exact(Exact::new("https://api.example.com/v1/users"));

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_url_to_exact_attenuation_invalid() {
        let parent = Constraint::UrlPattern(UrlPattern::new("https://api.example.com/*").unwrap());
        let child = Constraint::Exact(Exact::new("https://other.example.com/v1"));

        assert!(parent.validate_attenuation(&child).is_err());
    }

    #[test]
    fn test_wildcard_to_url_attenuation() {
        let parent = Constraint::Wildcard(Wildcard::new());
        let child = Constraint::UrlPattern(UrlPattern::new("https://api.example.com/*").unwrap());

        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_url_pattern_serialization_roundtrip() {
        let original = UrlPattern::new("https://api.example.com/v1/*").unwrap();

        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("https://api.example.com/v1/*"));

        let deserialized: UrlPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.pattern, original.pattern);
    }

    #[test]
    fn test_url_pattern_placeholder_collision_rejected() {
        // Patterns containing our internal placeholder strings should be rejected
        // to prevent collision attacks
        assert!(UrlPattern::new("https://__tenuo_host_wildcard__.evil.com/*").is_err());
        assert!(UrlPattern::new("https://evil.com/__tenuo_path_wildcard__").is_err());

        // Normal patterns should still work
        assert!(UrlPattern::new("https://api.example.com/*").is_ok());
    }

    #[test]
    fn test_unknown_constraint_behavior() {
        // Note: There is no constraint 055. It is not spherical.
        // We do not validate against it because... what were we talking about?
        let unknown = Constraint::Unknown {
            type_id: 55,
            payload: vec![0, 1, 2, 3],
        };

        // Unknown constraints always fail matching
        assert!(unknown
            .matches(&ConstraintValue::String("test".into()))
            .is_err());

        // Unknown constraints cannot be attenuated (fail closed)
        assert!(unknown.validate_attenuation(&unknown).is_err());
    }

    // =========================================================================
    // Zero-Trust Unknown Fields Tests
    // =========================================================================
    //
    // Design:
    // - No constraints (empty set) → OPEN: allow any arguments
    // - Any constraint defined → CLOSED: reject unknown fields
    // - Wildcard constraint on a field → allows any value for that specific field
    // - allow_unknown=true → explicit opt-out from closed-world
    // - Attenuation: allow_unknown is NOT inherited (child defaults to closed)

    #[test]
    fn test_zero_trust_empty_constraint_set_allows_unknown_fields() {
        // No constraints defined → fully open, any arguments allowed
        let cs = ConstraintSet::new();

        let mut args = HashMap::new();
        args.insert(
            "url".to_string(),
            ConstraintValue::String("https://example.com".into()),
        );
        args.insert("timeout".to_string(), ConstraintValue::Integer(30));
        args.insert(
            "anything".to_string(),
            ConstraintValue::String("whatever".into()),
        );

        // Should pass - empty constraint set is fully open
        assert!(cs.matches(&args).is_ok());
    }

    #[test]
    fn test_zero_trust_one_constraint_rejects_unknown_fields() {
        // One constraint defined → closed world, unknown fields rejected
        let mut cs = ConstraintSet::new();
        cs.insert("url", Pattern::new("https://*").unwrap());

        // Only url provided - should pass
        let mut args = HashMap::new();
        args.insert(
            "url".to_string(),
            ConstraintValue::String("https://example.com".into()),
        );
        assert!(cs.matches(&args).is_ok());

        // url + unknown field - should FAIL (zero trust)
        args.insert("timeout".to_string(), ConstraintValue::Integer(30));
        let result = cs.matches(&args);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("timeout"));
        assert!(err.to_string().contains("unknown") || err.to_string().contains("not allowed"));
    }

    #[test]
    fn test_zero_trust_wildcard_allows_any_value_for_field() {
        // Wildcard constraint on a field means "any value allowed for this field"
        // but other unknown fields are still rejected
        let mut cs = ConstraintSet::new();
        cs.insert("url", Pattern::new("https://*").unwrap());
        cs.insert("timeout", Wildcard::new()); // Any value for timeout

        let mut args = HashMap::new();
        args.insert(
            "url".to_string(),
            ConstraintValue::String("https://example.com".into()),
        );
        args.insert("timeout".to_string(), ConstraintValue::Integer(9999));

        // Should pass - both fields are constrained (even if timeout is wildcard)
        assert!(cs.matches(&args).is_ok());

        // But an unknown field is still rejected
        args.insert("retries".to_string(), ConstraintValue::Integer(3));
        assert!(cs.matches(&args).is_err());
    }

    #[test]
    fn test_zero_trust_allow_unknown_explicit_opt_out() {
        // allow_unknown=true explicitly opts out of closed-world
        let mut cs = ConstraintSet::new();
        cs.insert("url", Pattern::new("https://*").unwrap());
        cs.set_allow_unknown(true);

        let mut args = HashMap::new();
        args.insert(
            "url".to_string(),
            ConstraintValue::String("https://example.com".into()),
        );
        args.insert("timeout".to_string(), ConstraintValue::Integer(30));
        args.insert(
            "anything".to_string(),
            ConstraintValue::String("whatever".into()),
        );

        // Should pass - allow_unknown=true
        assert!(cs.matches(&args).is_ok());
    }

    #[test]
    fn test_zero_trust_allow_unknown_still_enforces_defined_constraints() {
        // Even with allow_unknown=true, defined constraints must be satisfied
        let mut cs = ConstraintSet::new();
        cs.insert("url", Pattern::new("https://*").unwrap());
        cs.set_allow_unknown(true);

        let mut args = HashMap::new();
        args.insert(
            "url".to_string(),
            ConstraintValue::String("http://insecure.com".into()),
        ); // http, not https
        args.insert(
            "anything".to_string(),
            ConstraintValue::String("allowed".into()),
        );

        // Should FAIL - url doesn't match pattern
        assert!(cs.matches(&args).is_err());
    }

    #[test]
    fn test_zero_trust_attenuation_allow_unknown_not_inherited() {
        // Parent has allow_unknown=true, child doesn't specify
        // Child should default to allow_unknown=false (closed world)
        let mut parent = ConstraintSet::new();
        parent.insert("url", Pattern::new("https://*").unwrap());
        parent.set_allow_unknown(true);

        let mut child = ConstraintSet::new();
        child.insert("url", Pattern::new("https://api.example.com/*").unwrap());
        // Child does NOT set allow_unknown - defaults to false

        // Attenuation should be valid (child narrows url)
        assert!(parent.validate_attenuation(&child).is_ok());

        // But child should NOT inherit allow_unknown
        assert!(!child.allow_unknown());

        // Child should reject unknown fields
        let mut args = HashMap::new();
        args.insert(
            "url".to_string(),
            ConstraintValue::String("https://api.example.com/v1".into()),
        );
        args.insert("timeout".to_string(), ConstraintValue::Integer(30));
        assert!(child.matches(&args).is_err()); // Rejected!
    }

    #[test]
    fn test_zero_trust_attenuation_child_cannot_enable_allow_unknown() {
        // Parent has allow_unknown=false (or not set)
        // Child cannot enable allow_unknown (that would expand capabilities)
        let mut parent = ConstraintSet::new();
        parent.insert("url", Pattern::new("https://*").unwrap());
        // parent.allow_unknown defaults to false

        let mut child = ConstraintSet::new();
        child.insert("url", Pattern::new("https://api.example.com/*").unwrap());
        child.set_allow_unknown(true); // Child tries to enable

        // Attenuation should FAIL - child is more permissive
        assert!(parent.validate_attenuation(&child).is_err());
    }

    #[test]
    fn test_zero_trust_attenuation_parent_open_child_can_close() {
        // Parent is fully open (no constraints)
        // Child can add constraints (that's more restrictive)
        let parent = ConstraintSet::new(); // No constraints

        let mut child = ConstraintSet::new();
        child.insert("url", Pattern::new("https://*").unwrap());

        // Should be valid - child is more restrictive
        assert!(parent.validate_attenuation(&child).is_ok());
    }

    #[test]
    fn test_zero_trust_serialization_roundtrip() {
        // allow_unknown should survive serialization
        let mut cs = ConstraintSet::new();
        cs.insert("url", Pattern::new("https://*").unwrap());
        cs.set_allow_unknown(true);

        let json = serde_json::to_string(&cs).unwrap();
        let deserialized: ConstraintSet = serde_json::from_str(&json).unwrap();

        assert!(deserialized.allow_unknown());
        assert!(deserialized.get("url").is_some());
    }

    #[test]
    fn test_zero_trust_default_allow_unknown_is_false() {
        let cs = ConstraintSet::new();
        assert!(!cs.allow_unknown());

        let mut cs_with_constraint = ConstraintSet::new();
        cs_with_constraint.insert("url", Pattern::new("https://*").unwrap());
        assert!(!cs_with_constraint.allow_unknown());
    }

    // -------------------------------------------------------------------------
    // Subpath Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_subpath_basic_containment() {
        let sp = Subpath::new("/data").unwrap();
        assert!(sp.contains_path("/data/file.txt").unwrap());
        assert!(sp.contains_path("/data/subdir/file.txt").unwrap());
        assert!(sp.contains_path("/data").unwrap()); // allow_equal = true by default
        assert!(!sp.contains_path("/etc/passwd").unwrap());
        assert!(!sp.contains_path("/data2/file.txt").unwrap());
    }

    #[test]
    fn test_subpath_traversal_blocking() {
        let sp = Subpath::new("/data").unwrap();
        assert!(!sp.contains_path("/data/../etc/passwd").unwrap());
        assert!(!sp.contains_path("/data/subdir/../../etc/passwd").unwrap());
        assert!(sp.contains_path("/data/subdir/../file.txt").unwrap()); // resolves to /data/file.txt
    }

    #[test]
    fn test_subpath_null_bytes() {
        let sp = Subpath::new("/data").unwrap();
        assert!(!sp.contains_path("/data/file\x00.txt").unwrap());
    }

    #[test]
    fn test_subpath_relative_path_rejected() {
        let sp = Subpath::new("/data").unwrap();
        assert!(!sp.contains_path("data/file.txt").unwrap());
        assert!(!sp.contains_path("./file.txt").unwrap());
    }

    #[test]
    fn test_subpath_matches() {
        let sp = Subpath::new("/data").unwrap();
        assert!(sp.matches(&"/data/file.txt".into()).unwrap());
        assert!(!sp.matches(&"/etc/passwd".into()).unwrap());
        assert!(!sp.matches(&123.into()).unwrap()); // Non-string returns false
    }

    // -------------------------------------------------------------------------
    // UrlSafe Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_url_safe_basic() {
        let us = UrlSafe::new();
        assert!(us.is_safe("https://api.github.com/repos").unwrap());
        assert!(us.is_safe("http://example.com/path").unwrap());
    }

    #[test]
    fn test_url_safe_blocks_loopback() {
        let us = UrlSafe::new();
        assert!(!us.is_safe("http://127.0.0.1/").unwrap());
        assert!(!us.is_safe("http://localhost/").unwrap());
        assert!(!us.is_safe("http://[::1]/").unwrap());
    }

    #[test]
    fn test_url_safe_blocks_private_ips() {
        let us = UrlSafe::new();
        assert!(!us.is_safe("http://10.0.0.1/admin").unwrap());
        assert!(!us.is_safe("http://172.16.0.1/").unwrap());
        assert!(!us.is_safe("http://192.168.1.1/admin").unwrap());
    }

    #[test]
    fn test_url_safe_blocks_metadata() {
        let us = UrlSafe::new();
        assert!(!us
            .is_safe("http://169.254.169.254/latest/meta-data/")
            .unwrap());
        assert!(!us.is_safe("http://metadata.google.internal/").unwrap());
    }

    #[test]
    fn test_url_safe_blocks_decimal_ip() {
        let us = UrlSafe::new();
        // 2130706433 = 127.0.0.1 in decimal
        assert!(!us.is_safe("http://2130706433/").unwrap());
    }

    #[test]
    fn test_url_safe_blocks_hex_ip() {
        let us = UrlSafe::new();
        // 0x7f000001 = 127.0.0.1 in hex
        assert!(!us.is_safe("http://0x7f000001/").unwrap());
    }

    #[test]
    fn test_url_safe_empty_host() {
        let us = UrlSafe::new();

        // Note: The Rust `url` crate (WHATWG spec) parses "https:///path" as "https://path/"
        // where "path" becomes the hostname. This is technically correct per spec.
        // So "https:///path" is valid (host = "path"), but "http://" is invalid (no host).

        // This is actually valid - parsed as https://path/
        assert!(us.is_safe("https:///path").unwrap());

        // But "http://" with no path truly has no host
        assert!(!us.is_safe("http://").unwrap());

        // Invalid URL (parse error)
        assert!(!us.is_safe("not-a-url").unwrap());
    }

    #[test]
    fn test_url_safe_null_bytes() {
        let us = UrlSafe::new();
        assert!(!us.is_safe("https://evil.com\x00.trusted.com/").unwrap());
    }

    #[test]
    fn test_url_safe_scheme_blocking() {
        let us = UrlSafe::new();
        assert!(!us.is_safe("file:///etc/passwd").unwrap());
        assert!(!us.is_safe("gopher://evil.com/").unwrap());
        assert!(!us.is_safe("ftp://example.com/").unwrap());
    }

    #[test]
    fn test_url_safe_domain_allowlist() {
        let us = UrlSafe::with_domains(vec!["api.github.com", "*.example.com"]);
        assert!(us.is_safe("https://api.github.com/repos").unwrap());
        assert!(us.is_safe("https://sub.example.com/path").unwrap());
        assert!(!us.is_safe("https://other.com/").unwrap());
    }

    #[test]
    fn test_url_safe_port_restriction() {
        let us = UrlSafe {
            allow_ports: Some(vec![443, 8443]),
            ..UrlSafe::new()
        };
        assert!(us.is_safe("https://example.com:443/").unwrap());
        assert!(us.is_safe("https://example.com:8443/").unwrap());
        assert!(!us.is_safe("http://example.com:80/").unwrap());
        assert!(!us.is_safe("https://example.com:8080/").unwrap());
    }

    #[test]
    fn test_url_safe_matches() {
        let us = UrlSafe::new();
        assert!(us.matches(&"https://api.github.com/".into()).unwrap());
        assert!(!us.matches(&"http://127.0.0.1/".into()).unwrap());
        assert!(!us.matches(&123.into()).unwrap()); // Non-string returns false
    }

    #[test]
    fn test_url_safe_blocks_ipv4_compatible_ipv6() {
        // IPv4-compatible IPv6 addresses (::x.x.x.x) are deprecated (RFC 4291)
        // but still parsed by many URL libraries. Must block these to prevent bypass.
        let us = UrlSafe::new();

        // Loopback via IPv4-compatible format
        assert!(!us.is_safe("http://[::127.0.0.1]/").unwrap());
        assert!(!us.is_safe("http://[0:0:0:0:0:0:127.0.0.1]/").unwrap());

        // Private IPs via IPv4-compatible format
        assert!(!us.is_safe("http://[::10.0.0.1]/").unwrap());
        assert!(!us.is_safe("http://[::172.16.0.1]/").unwrap());
        assert!(!us.is_safe("http://[::192.168.1.1]/").unwrap());

        // Metadata IP via IPv4-compatible format
        assert!(!us.is_safe("http://[::169.254.169.254]/").unwrap());

        // Verify IPv6-mapped still works too
        assert!(!us.is_safe("http://[::ffff:127.0.0.1]/").unwrap());
        assert!(!us.is_safe("http://[::ffff:10.0.0.1]/").unwrap());

        // But ::1 (IPv6 loopback) is still handled correctly
        assert!(!us.is_safe("http://[::1]/").unwrap());
    }

    #[test]
    fn test_url_safe_octal_ip_normalization() {
        // NOTE: The Rust `url` crate (WHATWG URL Standard) automatically normalizes
        // octal-notation IPs when parsing the URL. By the time we see the host,
        // it's already been converted:
        //
        // - "http://010.0.0.1/" → host_str = "8.0.0.1" (octal 010 = decimal 8)
        // - "http://0177.0.0.1/" → host_str = "127.0.0.1" (octal 0177 = decimal 127)
        //
        // This is consistent with POSIX libc interpretation but may differ from
        // some browsers that treat leading zeros as decimal.
        //
        // SECURITY IMPLICATION:
        // - If an attacker uses "010.0.0.1" hoping to access 10.0.0.1 (private),
        //   the url crate converts it to 8.0.0.1 (public), so the attack fails.
        // - If they use "0177.0.0.1" (127.0.0.1 in octal), it correctly maps to
        //   loopback and is blocked.
        //
        // This is not perfect (relies on url crate behavior), but provides
        // defense in depth. For stricter control, use domain allowlists.

        let us = UrlSafe::new();

        // Octal notation is converted by url crate:
        // 010.0.0.1 → 8.0.0.1 (public, allowed)
        // This is NOT ideal but is the url crate's behavior
        assert!(us.is_safe("http://010.0.0.1/").unwrap()); // → 8.0.0.1 (public)

        // 0177.0.0.1 → 127.0.0.1 (loopback, blocked)
        assert!(!us.is_safe("http://0177.0.0.1/").unwrap()); // → 127.0.0.1 (loopback)

        // 012.0.0.1 → 10.0.0.1 (private, blocked)
        assert!(!us.is_safe("http://012.0.0.1/").unwrap()); // → 10.0.0.1 (private)

        // Valid IPs without leading zeros
        assert!(!us.is_safe("http://10.0.0.1/").unwrap()); // Private IP (blocked)
        assert!(us.is_safe("http://8.0.0.1/").unwrap()); // Public IP (allowed)

        // Regular hostnames still work
        assert!(us.is_safe("https://example.com/").unwrap());
        assert!(us.is_safe("https://10example.com/").unwrap()); // Not an IP pattern
    }
}
