use crate::logger;
use crate::security::memory::{
    mask_password_for_display, secure_password_confirm_secure, secure_password_from_str,
    SecurePassword,
};
use anyhow::{anyhow, Result};
use std::io::{self, IsTerminal, Write};
use std::process::{Command, Stdio};

pub fn prompt_password() -> Result<SecurePassword> {
    prompt_secret("🔒 Enter Keeper Vault Password: ")
}

pub fn prompt_current_password() -> Result<SecurePassword> {
    prompt_secret("🔒 Current Keeper Vault Password: ")
}

pub fn prompt_password_confirm() -> Result<SecurePassword> {
    secure_password_confirm_secure()
}

pub fn prompt_recovery_code() -> Result<SecurePassword> {
    prompt_secret("🧩 Enter Recovery Code: ")
}

pub fn prompt_export_password() -> Result<SecurePassword> {
    prompt_secret("🔐 Export Password: ")
}

pub fn prompt_export_password_confirm() -> Result<SecurePassword> {
    prompt_secret("🔐 Confirm Export Password: ")
}

pub fn prompt_export_password_secure() -> Result<SecurePassword> {
    let first = prompt_secret("🔐 Export Password: ")?;
    let second = prompt_secret("🔐 Confirm Export Password: ")?;

    let first_bytes = first.expose_secret();
    let second_bytes = second.expose_secret();

    if !constant_time_compare(first_bytes, second_bytes) {
        return Err(anyhow!("Passwords do not match"));
    }

    Ok(first)
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    let max_len = std::cmp::max(a.len(), b.len());
    let mut a_padded = Vec::with_capacity(max_len);
    let mut b_padded = Vec::with_capacity(max_len);

    a_padded.extend_from_slice(a);
    a_padded.resize(max_len, 0u8);

    b_padded.extend_from_slice(b);
    b_padded.resize(max_len, 0u8);

    a_padded.as_slice().ct_eq(b_padded.as_slice()).into()
}

pub fn display_password_masked(password: &SecurePassword) {
    let password_str = std::str::from_utf8_lossy(password.expose_secret());
    print!("{}", mask_password_for_display(&password_str));
}

fn prompt_secret(prompt: &str) -> Result<SecurePassword> {
    print!("{prompt}");
    io::stdout().flush()?;

    let stdin = io::stdin();
    let is_tty = stdin.is_terminal();

    if is_tty {
        set_terminal_echo(false);
    }

    let mut secret = String::new();
    stdin.read_line(&mut secret)?;

    if is_tty {
        set_terminal_echo(true);
        println!();
    }

    Ok(secure_password_from_str(&secret.trim().to_string()))
}

fn set_terminal_echo(enabled: bool) {
    #[cfg(unix)]
    {
        let arg = if enabled { "echo" } else { "-echo" };
        if let Err(err) = Command::new("stty")
            .arg(arg)
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            logger::debug(&format!("Failed to set terminal echo: {err}"));
        }
    }
}
