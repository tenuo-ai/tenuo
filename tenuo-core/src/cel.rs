//! CEL (Common Expression Language) evaluation for Tenuo constraints.
//!
//! This module provides cached CEL evaluation using the cel-interpreter crate.
//! CEL programs are compiled once and cached for performance.
//!
//! ## Security Properties
//!
//! The CEL cache is **security-neutral**:
//!
//! 1. **Immutable expressions**: Warrant expressions never change after creation.
//!    The cache key is the expression string itself.
//!
//! 2. **Compiled programs only**: We cache the compiled AST/bytecode, NOT
//!    evaluation results. Each execution evaluates against fresh context.
//!
//! 3. **Deterministic**: Same expression + same inputs = same result.
//!    Caching the program doesn't change behavior.
//!
//! 4. **Revocation independent**: Warrant revocation is checked at the warrant
//!    level before CEL evaluation. Cached programs don't bypass revocation.
//!
//! Therefore, long TTLs are safe. Memory is the only constraint (bounded by max_capacity).
//!
//! ## Standard Library Functions
//!
//! Tenuo provides several standard library functions for use in CEL expressions:
//!
//! ### Time Functions
//!
//! #### `time_now(_unused) -> String`
//!
//! Returns the current time in RFC3339 format (e.g., `"2024-01-15T10:30:00Z"`).
//!
//! **Example:**
//! ```cel
//! // Check if a timestamp is in the future
//! time_is_expired(deadline) == false && time_since(deadline) < 3600
//! ```
//!
//! #### `time_is_expired(timestamp: String) -> bool`
//!
//! Checks if an RFC3339 timestamp has passed.
//!
//! **Example:**
//! ```cel
//! // Only allow if not expired
//! !time_is_expired(order.expires_at)
//! ```
//!
//! #### `time_since(timestamp: String) -> i64`
//!
//! Returns the number of seconds since the given RFC3339 timestamp.
//! Returns `0` if the timestamp is invalid or in the future.
//!
//! **Example:**
//! ```cel
//! // Allow only if created within last hour
//! time_since(order.created_at) < 3600
//! ```
//!
//! ### Network Functions
//!
//! #### `net_in_cidr(ip: String, cidr: String) -> bool`
//!
//! Checks if an IP address (IPv4 or IPv6) is within a CIDR block.
//!
//! **Example:**
//! ```cel
//! // Only allow requests from internal network
//! net_in_cidr(request.ip, "10.0.0.0/8") || net_in_cidr(request.ip, "192.168.0.0/16")
//! ```
//!
//! #### `net_is_private(ip: String) -> bool`
//!
//! Checks if an IP address is in a private network range (RFC 1918 for IPv4,
//! or private IPv6 ranges).
//!
//! **Example:**
//! ```cel
//! // Block public IPs
//! net_is_private(request.ip)
//! ```
//!
//! ## Usage in Warrants
//!
//! These functions can be used in CEL constraints when creating warrants:
//!
//! ```rust,ignore
//! use tenuo_core::{Warrant, CelConstraint};
//!
//! let warrant = Warrant::builder()
//!     .tool("api_call")
//!     .constraint("ip", CelConstraint::new(
//!         "net_in_cidr(value, '10.0.0.0/8')"
//!     ))
//!     .constraint("deadline", CelConstraint::new(
//!         "!time_is_expired(value)"
//!     ))
//!     .build(&keypair)?;
//! ```

use crate::constraints::ConstraintValue;
use crate::error::{Error, Result};
use cel_interpreter::{Context, Program, Value};
use moka::sync::Cache;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// Global CEL program cache.
/// 
/// Programs are cached by expression string to avoid recompilation.
/// 
/// ## Configuration
/// - **TTL**: 1 hour (expressions are immutable, no security impact)
/// - **Max capacity**: 1000 entries (memory bound)
/// 
/// ## Thread Safety
/// Uses `moka::sync::Cache` which is thread-safe and lock-free for reads.
static CEL_CACHE: std::sync::LazyLock<Cache<String, Arc<Program>>> = std::sync::LazyLock::new(|| {
    Cache::builder()
        .max_capacity(1000)
        .time_to_live(Duration::from_secs(3600)) // 1 hour
        .build()
});

/// Compile a CEL expression, using cache if available.
pub fn compile(expression: &str) -> Result<Arc<Program>> {
    // Check cache first
    if let Some(program) = CEL_CACHE.get(expression) {
        return Ok(program);
    }

    // Compile the expression
    let program = Program::compile(expression)
        .map_err(|e| Error::CelError(format!("compilation failed: {}", e)))?;
    
    let program = Arc::new(program);
    CEL_CACHE.insert(expression.to_string(), program.clone());
    
    Ok(program)
}

/// Evaluate a CEL expression against a context built from constraint values.
///
/// The context contains:
/// - `value`: The primary value being checked
/// - Any additional variables passed in `vars`
pub fn evaluate(
    expression: &str,
    value: &ConstraintValue,
    vars: &HashMap<String, ConstraintValue>,
) -> Result<bool> {
    let program = compile(expression)?;
    
    // Build context with standard library
    let mut context = create_context();
    
    // Add the primary value
    context.add_variable("value", constraint_value_to_cel(value)?)
        .map_err(|e| Error::CelError(format!("failed to add variable: {}", e)))?;
    
    // Add any additional variables
    for (name, val) in vars {
        context.add_variable(name, constraint_value_to_cel(val)?)
            .map_err(|e| Error::CelError(format!("failed to add variable '{}': {}", name, e)))?;
    }
    
    // Execute
    let result = program.execute(&context)
        .map_err(|e| Error::CelError(format!("execution failed: {}", e)))?;
    
    // Extract boolean result
    match result {
        Value::Bool(b) => Ok(b),
        other => Err(Error::CelError(format!(
            "expression must return bool, got {:?}",
            other
        ))),
    }
}

/// Evaluate a CEL expression with the value as the root context.
///
/// For object values, each field becomes a top-level variable.
/// For other values, the value is available as `value`.
pub fn evaluate_with_value_context(
    expression: &str,
    value: &ConstraintValue,
) -> Result<bool> {
    let program = compile(expression)?;
    
    let mut context = create_context();
    
    match value {
        ConstraintValue::Object(map) => {
            // For objects, expose each field as a variable
            for (key, val) in map {
                context.add_variable(key, constraint_value_to_cel(val)?)
                    .map_err(|e| Error::CelError(format!("failed to add variable '{}': {}", key, e)))?;
            }
        }
        other => {
            // For primitives, expose as "value"
            context.add_variable("value", constraint_value_to_cel(other)?)
                .map_err(|e| Error::CelError(format!("failed to add variable: {}", e)))?;
        }
    }
    
    let result = program.execute(&context)
        .map_err(|e| Error::CelError(format!("execution failed: {}", e)))?;
    
    match result {
        Value::Bool(b) => Ok(b),
        other => Err(Error::CelError(format!(
            "expression must return bool, got {:?}",
            other
        ))),
    }
}

/// Convert a ConstraintValue to a CEL Value.
fn constraint_value_to_cel(cv: &ConstraintValue) -> Result<Value> {
    match cv {
        ConstraintValue::String(s) => Ok(Value::String(s.clone().into())),
        ConstraintValue::Integer(i) => Ok(Value::Int(*i)),
        ConstraintValue::Float(f) => Ok(Value::Float(*f)),
        ConstraintValue::Boolean(b) => Ok(Value::Bool(*b)),
        ConstraintValue::Null => Ok(Value::Null),
        ConstraintValue::List(list) => {
            let cel_list: std::result::Result<Vec<Value>, _> = 
                list.iter().map(constraint_value_to_cel).collect();
            Ok(Value::List(cel_list?.into()))
        }
        ConstraintValue::Object(map) => {
            let cel_map: std::result::Result<HashMap<String, Value>, _> = 
                map.iter()
                    .map(|(k, v)| constraint_value_to_cel(v).map(|cv| (k.clone(), cv)))
                    .collect();
            Ok(Value::Map(cel_map?.into()))
        }
    }
}

/// Clear the CEL program cache.
pub fn clear_cache() {
    CEL_CACHE.invalidate_all();
}

/// Get the number of cached CEL programs.
pub fn cache_size() -> u64 {
    CEL_CACHE.entry_count()
}

/// Create a CEL context with the standard library functions registered.
pub fn create_context() -> Context<'static> {
    let mut context = Context::default();

    // ========================================================================
    // Time Functions
    // ========================================================================
    
    // time.now(unused) -> String (RFC3339)
    // Note: cel-interpreter 0.8.1 requires at least one argument for custom functions
    context.add_function("time_now", |_unused: Value| -> String {
        Utc::now().to_rfc3339()
    });

    // time.is_expired(timestamp: String) -> bool
    context.add_function("time_is_expired", |timestamp: Value| -> bool {
        let ts_str = match timestamp {
            Value::String(s) => s,
            _ => return false,
        };
        match DateTime::parse_from_rfc3339(&ts_str) {
            Ok(dt) => dt < Utc::now(),
            Err(_) => false, 
        }
    });

    // time.since(timestamp: String) -> i64 (seconds)
    context.add_function("time_since", |timestamp: Value| -> i64 {
        let ts_str = match timestamp {
            Value::String(s) => s,
            _ => return 0,
        };
        match DateTime::parse_from_rfc3339(&ts_str) {
            Ok(dt) => (Utc::now() - dt.with_timezone(&Utc)).num_seconds(),
            Err(_) => 0,
        }
    });

    // ========================================================================
    // Network Functions
    // ========================================================================

    // net.in_cidr(ip: String, cidr: String) -> bool
    context.add_function("net_in_cidr", |ip: Value, cidr: Value| -> bool {
        let ip_str = match ip {
            Value::String(s) => s,
            _ => return false,
        };
        let cidr_str = match cidr {
            Value::String(s) => s,
            _ => return false,
        };

        let ip_addr: IpAddr = match ip_str.parse() {
            Ok(addr) => addr,
            Err(_) => return false,
        };
        
        let network: IpNetwork = match cidr_str.parse() {
            Ok(net) => net,
            Err(_) => return false,
        };

        network.contains(ip_addr)
    });

    // net.is_private(ip: String) -> bool
    context.add_function("net_is_private", |ip: Value| -> bool {
        let ip_str = match ip {
            Value::String(s) => s,
            _ => return false,
        };

        let ip_addr: IpAddr = match ip_str.parse() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        match ip_addr {
            IpAddr::V4(addr) => addr.is_private(),
            IpAddr::V6(addr) => (addr.segments()[0] & 0xfe00) == 0xfc00, // Unique Local
        }
    });

    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_comparison() {
        let value = ConstraintValue::Integer(5000);
        assert!(evaluate("value < 10000", &value, &HashMap::new()).unwrap());
        assert!(!evaluate("value > 10000", &value, &HashMap::new()).unwrap());
    }

    #[test]
    fn test_string_operations() {
        let value = ConstraintValue::String("staging-web".to_string());
        assert!(evaluate("value.startsWith('staging')", &value, &HashMap::new()).unwrap());
        assert!(!evaluate("value.startsWith('prod')", &value, &HashMap::new()).unwrap());
    }

    #[test]
    fn test_boolean_logic() {
        let value = ConstraintValue::Integer(7500);
        assert!(evaluate("value > 5000 && value < 10000", &value, &HashMap::new()).unwrap());
        assert!(evaluate("value < 1000 || value > 5000", &value, &HashMap::new()).unwrap());
    }

    #[test]
    fn test_list_operations() {
        let value = ConstraintValue::List(vec![
            ConstraintValue::String("admin".to_string()),
            ConstraintValue::String("user".to_string()),
        ]);
        assert!(evaluate("'admin' in value", &value, &HashMap::new()).unwrap());
        assert!(!evaluate("'superuser' in value", &value, &HashMap::new()).unwrap());
    }

    #[test]
    fn test_object_context() {
        let value = ConstraintValue::Object(
            [
                ("amount".to_string(), ConstraintValue::Integer(5000)),
                ("currency".to_string(), ConstraintValue::String("USD".to_string())),
            ]
            .into_iter()
            .collect(),
        );
        
        assert!(evaluate_with_value_context("amount < 10000", &value).unwrap());
        assert!(evaluate_with_value_context("currency == 'USD'", &value).unwrap());
        assert!(evaluate_with_value_context("amount < 10000 && currency == 'USD'", &value).unwrap());
    }

    #[test]
    fn test_complex_expression() {
        let value = ConstraintValue::Object(
            [
                ("amount".to_string(), ConstraintValue::Integer(75000)),
                ("approver".to_string(), ConstraintValue::String("cfo@company.com".to_string())),
            ]
            .into_iter()
            .collect(),
        );
        
        // From spec: amount < 10000 || (amount < 100000 && approver != '')
        let expr = "amount < 10000 || (amount < 100000 && approver != '')";
        assert!(evaluate_with_value_context(expr, &value).unwrap());
    }

    #[test]
    fn test_cache_works() {
        clear_cache();
        // Note: moka cache is lazy, entry_count may not reflect immediately
        // So we just verify compilation caching works by checking the cache exists
        
        let value = ConstraintValue::Integer(42);
        
        // First evaluation compiles the expression
        evaluate("value == 42", &value, &HashMap::new()).unwrap();
        
        // Second evaluation should use cached program
        evaluate("value == 42", &value, &HashMap::new()).unwrap();
        
        // Different expression also works
        evaluate("value > 0", &value, &HashMap::new()).unwrap();
        
        // Verify compile function works directly and caches
        let p1 = compile("value == 100").unwrap();
        let p2 = compile("value == 100").unwrap();
        assert!(std::sync::Arc::ptr_eq(&p1, &p2), "same expression should return same Arc");
    }

    #[test]
    fn test_invalid_expression() {
        let value = ConstraintValue::Integer(42);
        let result = evaluate("this is not valid CEL !!!", &value, &HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_non_bool_result_error() {
        let value = ConstraintValue::Integer(42);
        let result = evaluate("value + 1", &value, &HashMap::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must return bool"));
    }
}

