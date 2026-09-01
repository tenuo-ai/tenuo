//! OpenTelemetry API instrumentation. The application owns the provider.

use opentelemetry::global;
use opentelemetry::trace::{Span, Tracer};
use opentelemetry::KeyValue;

/// Record a `tenuo.authorize` span. Never changes allow/deny. Never waits for export.
pub(crate) fn record_authorize(outcome: &str, reason_code: &str, observe_only: bool) {
    let tracer = global::tracer("tenuo.rust");
    let mut span = tracer.start("tenuo.authorize");
    span.set_attribute(KeyValue::new("tenuo.operation", "authorize"));
    span.set_attribute(KeyValue::new("tenuo.sdk.language", "rust"));
    span.set_attribute(KeyValue::new("tenuo.decision", outcome.to_string()));
    span.set_attribute(KeyValue::new("tenuo.reason_code", reason_code.to_string()));
    span.set_attribute(KeyValue::new(
        "tenuo.policy.mode",
        if observe_only { "observe" } else { "enforce" },
    ));
    // Expected policy denials stay Unset. Do not attach arguments, keys, or signatures.
    span.end();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_provider_does_not_panic() {
        record_authorize("allow", "allowed", false);
        record_authorize("deny", "tool-not-authorized", true);
    }

    #[test]
    fn source_has_no_forbidden_default_attributes() {
        let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/sdk/telemetry.rs"));
        assert!(!src.contains(&["warrant", "_bytes"].concat()));
        assert!(!src.contains(&["private", "_key"].concat()));
        assert!(!src.contains(&["pop", "_signature"].concat()));
        assert!(!src.contains(&["raw", "_args"].concat()));
    }
}
