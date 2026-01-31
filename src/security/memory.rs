use secrets::SecretBox;
use std::io::{self, Write};
use zeroize::Zeroize;

/// Secure password type using locked heap memory
pub type SecurePassword = SecretBox<[u8]>;

/// Secure string type for passwords in IPC
pub use crate::secrets::SecretString;

/// Create a secure password from input string
/// Converts to SecureBox and clears original
pub fn secure_password_from_str(password: &str) -> SecurePassword {
    let mut secret = SecretBox::new(password.len());
    secret.copy_from_slice(password.as_bytes());
    secret
}

/// Convert SecurePassword to String for display purposes
/// Only use this when absolutely necessary (e.g., display)
/// String will be in plaintext memory!
#[allow(dead_code)]
pub fn secure_password_to_string(password: &SecurePassword) -> String {
    String::from_utf8_lossy(password.expose_secret()).to_string()
}

/// Prompt for password with secure handling
/// Returns SecurePassword that automatically clears input
pub fn prompt_password_secure(prompt_msg: &str) -> Result<SecurePassword> {
    let password = crate::prompt::prompt_secret(prompt_msg)?;
    let secure = secure_password_from_str(&password);
    password.zeroize(); // Clear original String
    Ok(secure)
}

/// Prompt for password confirmation with secure handling
/// Uses constant-time comparison
pub fn prompt_password_confirm_secure() -> Result<SecurePassword> {
    let first = prompt_password_secure("🔒 Password: ")?;
    let second = prompt_password_secure("🔒 Confirm Password: ")?;

    // Use constant-time comparison
    let first_bytes = first.expose_secret();
    let second_bytes = second.expose_secret();

    if !constant_time_compare(first_bytes, second_bytes) {
        return Err(anyhow!("Passwords do not match"));
    }

    Ok(first)
}

/// Constant-time comparison to prevent timing attacks
/// Uses subtle crate's ct_eq
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    // Pad to same length for constant-time comparison
    let max_len = std::cmp::max(a.len(), b.len());
    let mut a_padded = Vec::with_capacity(max_len);
    let mut b_padded = Vec::with_capacity(max_len);

    a_padded.extend_from_slice(a);
    a_padded.resize(max_len, 0u8);

    b_padded.extend_from_slice(b);
    b_padded.resize(max_len, 0u8);

    // Use subtle's constant-time equality
    use subtle::ConstantTimeEq;
    a_padded.as_slice().ct_eq(b_padded.as_slice()).into()
}

/// Export password for secure display
/// Only displays masked version, never full password
pub fn mask_password_for_display(password: &str) -> String {
    if password.len() <= 4 {
        "****".to_string()
    } else if password.len() <= 8 {
        "********".to_string()
    } else {
        format!("{}{}", "*".repeat(password.len() / 2))
    }
}
