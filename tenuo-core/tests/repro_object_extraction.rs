#[cfg(test)]
mod tests {
    use tenuo_core::{extraction::extract_json_path, ConstraintValue};
    use serde_json::json;

    #[test]
    fn test_extract_object() {
        let body = json!({
            "meta": {
                "cost": 100,
                "owner": "admin"
            }
        });

        // Try to extract the whole "meta" object
        let result = extract_json_path(&body, "meta");
        
        // Current behavior: returns None because json_to_constraint_value returns None for Objects
        // Desired behavior: returns Some(ConstraintValue::Object(...))
        if let Some(ConstraintValue::Object(map)) = result {
             assert_eq!(map.get("cost"), Some(&ConstraintValue::Integer(100)));
             assert_eq!(map.get("owner"), Some(&ConstraintValue::String("admin".to_string())));
        } else {
             panic!("Failed to extract object: {:?}", result);
        }
    }
}
