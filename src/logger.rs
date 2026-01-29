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
        eprintln!("[DEBUG] {message}");
    }
}

pub fn error(message: &str) {
    if is_debug() {
        eprintln!("[ERROR] {message}");
    }
}
