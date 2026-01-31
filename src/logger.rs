use crate::sanitize::sanitize_for_display;
use std::sync::atomic::{AtomicBool, Ordering};

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_debug(enabled: bool) {
    DEBUG_ENABLED.store(enabled, Ordering::SeqCst);
}

pub fn is_debug() -> bool {
    DEBUG_ENABLED.load(Ordering::SeqCst)
}

pub fn debug(message: &str) {
    if is_debug() {
        eprintln!("[DEBUG] {}", sanitize_for_display(message));
    }
}

pub fn error(message: &str) {
    if is_debug() {
        eprintln!("[ERROR] {}", sanitize_for_display(message));
    }
}

pub fn error_raw(message: &str) {
    if is_debug() {
        eprintln!("[ERROR] {message}");
    }
}
