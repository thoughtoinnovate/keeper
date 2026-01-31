use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure password type - wrapper for Vec<u8> with zeroization
#[derive(Clone)]
pub struct SecurePassword {
    bytes: Vec<u8>,
}

impl Zeroize for SecurePassword {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for SecurePassword {}

impl SecurePassword {
    /// Create a new secure password from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Create from string
    pub fn from_str(password: &str) -> Self {
        Self {
            bytes: password.as_bytes().to_vec(),
        }
    }

    /// Get reference to underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for SecurePassword {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<str> for SecurePassword {
    fn as_ref(&self) -> &str {
        std::str::from_utf8(&self.bytes).unwrap_or("")
    }
}

impl SecurePassword {
    /// Get password as string
    pub fn as_str(&self) -> String {
        String::from_utf8_lossy(&self.bytes).to_string()
    }
}

/// Secure string type for passwords in IPC
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretString {
    s: String,
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.s.zeroize();
    }
}

impl ZeroizeOnDrop for SecretString {}

impl SecretString {
    pub fn new(s: String) -> Self {
        Self { s }
    }

    /// Get reference to inner string
    pub fn as_str(&self) -> &str {
        &self.s
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        &self.s
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.s.zeroize();
    }
}

impl From<SecurePassword> for SecretString {
    fn from(password: SecurePassword) -> Self {
        Self {
            s: String::from_utf8_lossy(password.as_bytes()).to_string(),
        }
    }
}

impl From<SecretString> for SecurePassword {
    fn from(secret: SecretString) -> Self {
        Self {
            bytes: secret.s.clone().into_bytes(),
        }
    }
}

/// Create a secure password from input string
/// Converts to SecurePassword and clears original
pub fn secure_password_from_str(password: &str) -> SecurePassword {
    SecurePassword::from_str(password)
}

/// Convert SecurePassword to String for display purposes
/// Only use this when absolutely necessary (e.g., display)
/// String will be in plaintext memory!
#[allow(dead_code)]
pub fn secure_password_to_string(password: &SecurePassword) -> String {
    String::from_utf8_lossy(password.as_bytes()).to_string()
}

/// Prompt for password with secure handling
/// Returns SecurePassword that automatically clears input
pub fn prompt_password_secure(prompt_msg: &str) -> Result<SecurePassword> {
    crate::prompt::prompt_secret(prompt_msg)
}

/// Prompt for password confirmation with secure handling
/// Uses constant-time comparison
pub fn prompt_password_confirm_secure() -> Result<SecurePassword> {
    let first = prompt_password_secure("🔒 Password: ")?;
    let second = prompt_password_secure("🔒 Confirm Password: ")?;

    let first_bytes = first.as_bytes();
    let second_bytes = second.as_bytes();

    if !constant_time_compare(first_bytes, second_bytes) {
        return Err(anyhow!("Passwords do not match"));
    }

    Ok(first)
}

/// Constant-time comparison to prevent timing attacks
/// Uses subtle crate's ct_eq
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    let max_len = std::cmp::max(a.len(), b.len());
    let mut a_padded = Vec::with_capacity(max_len);
    let mut b_padded = Vec::with_capacity(max_len);

    a_padded.extend_from_slice(a);
    a_padded.resize(max_len, 0u8);

    b_padded.extend_from_slice(b);
    b_padded.resize(max_len, 0u8);

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
        format!("{}*", "*".repeat(password.len() / 2))
    }
}
