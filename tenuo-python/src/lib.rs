//! Tenuo Python SDK
//!
//! This crate re-exports the Python bindings from tenuo-core.

use pyo3::prelude::*;

// Re-export the Python module from tenuo-core
#[pymodule]
fn tenuo_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Call the public module initialization function from tenuo-core
    // Use ::tenuo_core to disambiguate from the pymodule name
    ::tenuo_core::python::tenuo_core(m)
}
