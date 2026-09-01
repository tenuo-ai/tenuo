/// Build an owned argument map. Infallible for `Into<ConstraintValue>` values.
///
/// Structural bounds are applied later by [`Call::owned`] / the guard.
/// Does not accept a capability, policy, authority, or approval.
#[macro_export]
macro_rules! args {
    ( $( $key:expr => $value:expr ),* $(,)? ) => {{
        #[allow(unused_mut)]
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

/// Build a [`ConstraintSet`] for one capability.
///
/// The authoring counterpart to [`args!`]: `args!` describes one call,
/// `constraints!` describes what calls a warrant permits. Values are anything
/// that converts into a `Constraint`.
///
/// ```
/// use tenuo::{constraints, Exact, Pattern};
///
/// let set = constraints! {
///     "path" => Pattern::new("/data/*").expect("valid glob"),
///     "mode" => Exact::new("read"),
/// };
/// assert!(set.get("path").is_some());
/// ```
///
/// An empty invocation is an open-world constraint set — every argument is
/// permitted. Prefer naming every field the capability accepts.
///
/// [`ConstraintSet`]: crate::ConstraintSet
#[macro_export]
macro_rules! constraints {
    ( $( $field:expr => $constraint:expr ),* $(,)? ) => {{
        #[allow(unused_mut)]
        let mut set = $crate::ConstraintSet::new();
        $(
            set.insert($field, $constraint);
        )*
        set
    }};
}
