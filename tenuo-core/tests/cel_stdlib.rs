use tenuo_core::cel::evaluate_with_value_context;
use tenuo_core::constraints::ConstraintValue;

#[test]
fn test_cel_time_functions() {
    let value = ConstraintValue::Integer(1); // Dummy value

    // Test time.now() returns a string
    // Note: time_now requires a dummy argument due to library limitation
    assert!(evaluate_with_value_context("time_now(null).startsWith('20')", &value).unwrap());

    // Test time.is_expired
    // Past date
    assert!(
        evaluate_with_value_context("time_is_expired('2000-01-01T00:00:00Z')", &value).unwrap()
    );
    // Future date
    assert!(
        !evaluate_with_value_context("time_is_expired('2099-01-01T00:00:00Z')", &value).unwrap()
    );

    // Test time.since
    // Past date should have positive duration
    assert!(evaluate_with_value_context("time_since('2000-01-01T00:00:00Z') > 0", &value).unwrap());
}

#[test]
fn test_cel_network_functions() {
    let value = ConstraintValue::Integer(1); // Dummy value

    // Test net.in_cidr
    assert!(
        evaluate_with_value_context("net_in_cidr('192.168.1.5', '192.168.1.0/24')", &value)
            .unwrap()
    );
    assert!(
        !evaluate_with_value_context("net_in_cidr('10.0.0.5', '192.168.1.0/24')", &value).unwrap()
    );

    // IPv6
    assert!(
        evaluate_with_value_context("net_in_cidr('2001:db8::1', '2001:db8::/32')", &value).unwrap()
    );

    // Test net.is_private
    assert!(evaluate_with_value_context("net_is_private('192.168.1.1')", &value).unwrap());
    assert!(evaluate_with_value_context("net_is_private('10.0.0.1')", &value).unwrap());
    assert!(!evaluate_with_value_context("net_is_private('8.8.8.8')", &value).unwrap());
}
