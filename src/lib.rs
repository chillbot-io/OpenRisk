//! OpenLabels Native Rust Extension
//!
//! Provides high-performance pattern matching using Rust's regex crate.
//! Releases the GIL during scanning, enabling true parallelism with Python threads.

use pyo3::prelude::*;

mod matcher;
mod validators;

use matcher::{PatternMatcher, RawMatch};

/// OpenLabels native extension module
#[pymodule]
fn _rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PatternMatcher>()?;
    m.add_class::<RawMatch>()?;
    m.add_function(wrap_pyfunction!(validate_luhn, m)?)?;
    m.add_function(wrap_pyfunction!(validate_ssn_format, m)?)?;
    m.add_function(wrap_pyfunction!(is_native_available, m)?)?;
    Ok(())
}

/// Validate credit card number using Luhn algorithm
#[pyfunction]
fn validate_luhn(number: &str) -> bool {
    validators::luhn(number)
}

/// Validate SSN format (not context)
#[pyfunction]
fn validate_ssn_format(ssn: &str) -> bool {
    validators::ssn_format(ssn)
}

/// Check if native extension is working
#[pyfunction]
fn is_native_available() -> bool {
    true
}
