use crate::logger;
use crate::security::memory::{
    constant_time_compare, mask_password_for_display, prompt_password_confirm_secure,
    secure_password_from_str, SecurePassword,
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
    prompt_password_confirm_secure()
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

    let first_bytes = first.as_bytes();
    let second_bytes = second.as_bytes();

    if !constant_time_compare(first_bytes, second_bytes) {
        return Err(anyhow!("Passwords do not match"));
    }

    Ok(first)
}

pub fn display_password_masked(password: &SecurePassword) {
    let password_str = String::from_utf8_lossy(password.as_bytes());
    print!("{}", mask_password_for_display(&password_str));
}

pub(crate) fn prompt_secret(prompt: &str) -> Result<SecurePassword> {
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
