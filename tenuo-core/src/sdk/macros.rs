/// Build an owned argument map. Infallible for `Into<ConstraintValue>` values.
///
/// Structural bounds are applied later by [`Call::owned`] / the guard.
/// Does not accept a capability, policy, authority, or approval.
#[macro_export]
macro_rules! args {
    ( $( $key:expr => $value:expr ),* $(,)? ) => {{
        let mut map = ::std::collections::HashMap::new();
        $(
            let _ = map.insert(
                ::std::string::String::from($key),
                $crate::ConstraintValue::from($value),
            );
        )*
        map
    }};
}
