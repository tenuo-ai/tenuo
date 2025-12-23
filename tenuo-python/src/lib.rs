//! Tenuo Python SDK
//!
//! This crate re-exports the Python bindings from tenuo.

use pyo3::prelude::*;

// Re-export the Python module from tenuo crate
#[pymodule]
fn tenuo_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Call the public module initialization function from tenuo crate
    // The pymodule name stays "tenuo_core" for Python import compatibility
    ::tenuo::python::tenuo_core(m)
}
