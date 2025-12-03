//! CEL (Common Expression Language) evaluation for Tenuo constraints.
//!
//! This module provides cached CEL evaluation using the cel-interpreter crate.
//! CEL programs are compiled once and cached for performance.

use crate::constraints::ConstraintValue;
use crate::error::{Error, Result};
use cel_interpreter::{Context, Program, Value};
use moka::sync::Cache;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Global CEL program cache.
/// 
/// Programs are cached by expression hash to avoid recompilation.
/// The cache has a 10-minute TTL and max 1000 entries.
static CEL_CACHE: std::sync::LazyLock<Cache<String, Arc<Program>>> = std::sync::LazyLock::new(|| {
    Cache::builder()
        .max_capacity(1000)
        .time_to_live(Duration::from_secs(600))
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
    
    // Build context
    let mut context = Context::default();
    
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
    
    let mut context = Context::default();
    
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

