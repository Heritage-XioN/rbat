//! # Thread Error Collector
//!
//! This module provides a thread-safe helper to catch the first error encountered
//! during concurrent plugin execution, signaling other threads to terminate.

use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use crate::core::RbatError;

/// Saves the first error that occurs to the shared Mutex and triggers the cancellation flag.
/// Subsequent errors are discarded to preserve the root cause error.
pub fn capture_error_and_cancel(
    state: &Mutex<Option<RbatError>>,
    err: RbatError,
    cancel_flag: &AtomicBool,
) {
    if matches!(err, RbatError::ErrorAnalysisCancelled) {
        return;
    }

    let mut guard = state.lock().unwrap();
    if guard.is_none() {
        *guard = Some(err);
        cancel_flag.store(true, Ordering::Relaxed);
    }
}
