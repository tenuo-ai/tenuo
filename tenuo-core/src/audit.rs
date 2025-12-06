//! Audit Logging infrastructure.
//!
//! Provides traits and implementations for logging security-critical events.

use crate::approval::AuditEvent;
use std::sync::{Arc, RwLock};

/// Trait for audit loggers.
pub trait AuditLogger: Send + Sync + std::fmt::Debug {
    /// Log an audit event.
    fn log(&self, event: AuditEvent);
}

/// A logger that writes events to stdout as JSON lines.
///
/// This is suitable for containerized environments (Kubernetes, Docker) where
/// logs are scraped by an external agent (Fluentd, Datadog, etc.).
#[derive(Debug, Default)]
pub struct StdoutLogger;

impl StdoutLogger {
    pub fn new() -> Self {
        Self
    }
}

impl AuditLogger for StdoutLogger {
    fn log(&self, event: AuditEvent) {
        if let Ok(json) = serde_json::to_string(&event) {
            println!("{}", json);
        } else {
            eprintln!("Failed to serialize audit event: {:?}", event);
        }
    }
}

/// A logger that does nothing (for testing or when auditing is disabled).
#[derive(Debug, Default)]
pub struct NoOpLogger;

impl AuditLogger for NoOpLogger {
    fn log(&self, _event: AuditEvent) {}
}

/// Global audit logger instance.
///
/// We use a global logger to avoid threading it through every function call.
/// It is initialized to NoOpLogger by default.
static GLOBAL_LOGGER: RwLock<Option<Arc<dyn AuditLogger>>> = RwLock::new(None);

/// Set the global audit logger.
pub fn set_global_logger(logger: Arc<dyn AuditLogger>) {
    let mut lock = GLOBAL_LOGGER.write().unwrap();
    *lock = Some(logger);
}

/// Log an event using the global logger.
pub fn log_event(event: AuditEvent) {
    if let Ok(lock) = GLOBAL_LOGGER.read() {
        if let Some(logger) = lock.as_ref() {
            logger.log(event);
        }
    }
}
