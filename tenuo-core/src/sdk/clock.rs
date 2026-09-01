//! One clock per [`Guard`]. Each attempt captures one instant from it.

use chrono::{DateTime, Utc};

/// Time source for live authorization. Production uses [`SystemClock`].
pub trait Clock: Send + Sync {
    /// Current time. Called once per attempt, never inside one.
    fn now(&self) -> DateTime<Utc>;
}

/// Wall clock. Production default.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Deterministic clock. Available only behind `test-utils`. Not for production.
#[cfg(feature = "test-utils")]
#[derive(Clone, Copy, Debug)]
pub struct FixedClock {
    instant: DateTime<Utc>,
}

#[cfg(feature = "test-utils")]
impl FixedClock {
    /// A clock pinned to `instant`.
    pub fn new(instant: DateTime<Utc>) -> Self {
        Self { instant }
    }

    /// The pinned instant.
    pub fn instant(&self) -> DateTime<Utc> {
        self.instant
    }
}

#[cfg(feature = "test-utils")]
impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.instant
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_does_not_advance() {
        let instant = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let clock = FixedClock::new(instant);
        assert_eq!(clock.now(), instant);
        assert_eq!(clock.now(), clock.now());
    }
}
