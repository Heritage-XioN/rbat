use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use crate::core::RbatError;

// A quick helper function to keep the thread closures clean.
// It only saves the *first* error that occurs.
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
