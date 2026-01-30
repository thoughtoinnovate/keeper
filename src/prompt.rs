use crate::logger;
use anyhow::{Result, anyhow};
use std::io::{self, IsTerminal, Write};
use std::process::{Command, Stdio};

pub fn prompt_password() -> Result<String> {
    prompt_secret("🔒 Enter Keeper Vault Password: ")
}

pub fn prompt_current_password() -> Result<String> {
    prompt_secret("🔒 Current Keeper Vault Password: ")
}

pub fn prompt_password_confirm() -> Result<String> {
    let first = prompt_secret("🔒 Create Keeper Vault Password: ")?;
    let second = prompt_secret("🔒 Confirm Keeper Vault Password: ")?;
    if first != second {
        return Err(anyhow!("Passwords do not match"));
    }
    Ok(first)
}

pub fn prompt_recovery_code() -> Result<String> {
    prompt_secret("🧩 Enter Recovery Code: ")
}

pub fn prompt_export_password() -> Result<String> {
    prompt_secret("🔐 Export Password: ")
}

pub fn prompt_export_password_confirm() -> Result<String> {
    prompt_secret("🔐 Confirm Export Password: ")
}

fn prompt_secret(prompt: &str) -> Result<String> {
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

    Ok(secret.trim().to_string())
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
