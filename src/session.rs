use crate::keystore::Keystore;
use crate::logger;
use crate::paths::KeeperPaths;
use crate::{client, prompt, security};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use std::io::Write;
use std::process::{Command, Stdio};
use zeroize::Zeroize;

pub struct UnlockOutcome {
    pub master_key: [u8; security::MASTER_KEY_LEN],
    pub recovery_code: Option<String>,
}

pub fn unlock_or_init_master_key(paths: &KeeperPaths) -> Result<UnlockOutcome> {
    if !paths.keystore_path().exists() {
        if paths.db_path.exists() {
            return Err(anyhow::anyhow!(
                "Keystore missing but vault exists. If the daemon is running, run `keeper keystore rebuild`. Otherwise the vault is unrecoverable."
            ));
        }
        let mut password = prompt::prompt_password_confirm()?;
        let (keystore, recovery_code, master_key) = Keystore::create_new(&password)?;
        keystore.save(paths.keystore_path())?;
        password.zeroize();
        return Ok(UnlockOutcome {
            master_key,
            recovery_code: Some(recovery_code),
        });
    }

    let mut password = prompt::prompt_password()?;
    let keystore = Keystore::load(paths.keystore_path())?;
    let master_key = keystore.unwrap_with_password(&password)?;
    password.zeroize();

    Ok(UnlockOutcome {
        master_key,
        recovery_code: None,
    })
}

pub fn start_daemon(paths: &KeeperPaths, master_key: &[u8], debug: bool) -> Result<u32> {
    let payload = STANDARD_NO_PAD.encode(master_key);
    let exe = std::env::current_exe().context("Unable to locate keeper binary")?;
    let mut cmd = Command::new(exe);
    if debug {
        cmd.arg("--debug");
    }
    if let Some(vault) = &paths.vault_arg {
        cmd.arg("--vault").arg(vault);
    }
    let mut child = cmd
        .arg("daemon")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to spawn daemon")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("{payload}\n").as_bytes())
            .context("Failed to send key to daemon")?;
    }

    logger::debug("Daemon process spawned");

    Ok(child.id())
}

pub fn ensure_daemon(paths: &KeeperPaths, master_key: &[u8], debug: bool) -> Result<Option<u32>> {
    if client::daemon_running(paths) {
        return Ok(None);
    }
    let pid = start_daemon(paths, master_key, debug)?;
    Ok(Some(pid))
}
