use crate::export;
use crate::ipc::{DaemonRequest, DaemonResponse};
use crate::keystore;
use crate::paths::KeeperPaths;
use crate::{client, db, models, prompt, security, session};
use anyhow::{Result, anyhow};
use zeroize::Zeroize;

pub fn run_export(paths: &KeeperPaths, args: crate::cli::ExportArgs) -> Result<()> {
    let (json_path, encrypted_path) = match (args.json, args.encrypted) {
        (Some(json), None) => (Some(json), None),
        (None, Some(enc)) => (None, Some(enc)),
        (None, None) => {
            return Err(anyhow!(
                "Provide --json <path> or --encrypted <path> to export"
            ));
        }
        _ => {
            return Err(anyhow!(
                "Only one export format is supported at a time (choose --json or --encrypted)"
            ));
        }
    };

    if let Some(path) = json_path {
        if path.exists() && !args.force {
            return Err(anyhow!(
                "Export file already exists. Use --force to overwrite."
            ));
        }
        let items = fetch_items_for_export(paths)?;
        let count = export::write_plain_export(&path, items)?;
        println!("Exported {count} item(s) to {}", path.display());
    } else if let Some(path) = encrypted_path {
        if path.exists() && !args.force {
            return Err(anyhow!(
                "Export file already exists. Use --force to overwrite."
            ));
        }
        let password = prompt_export_password()?;
        export::write_encrypted_export(paths, &path, &password)?;
        println!("Encrypted export written to {}", path.display());
    }

    Ok(())
}

pub fn run_import(paths: &KeeperPaths, args: crate::cli::ImportArgs) -> Result<()> {
    let (json_path, encrypted_path) = match (args.json, args.encrypted) {
        (Some(json), None) => (Some(json), None),
        (None, Some(enc)) => (None, Some(enc)),
        (None, None) => {
            return Err(anyhow!(
                "Provide --json <path> or --encrypted <path> to import"
            ));
        }
        _ => {
            return Err(anyhow!(
                "Only one import format is supported at a time (choose --json or --encrypted)"
            ));
        }
    };

    if let Some(path) = json_path {
        let payload = export::read_plain_export(&path)?;
        let count = import_items(paths, payload.items)?;
        println!("Imported {count} item(s) from {}", path.display());
        return Ok(());
    }

    if client::daemon_running(paths) {
        return Err(anyhow!(
            "Stop the daemon before importing encrypted bundles."
        ));
    }

    if let Some(path) = encrypted_path {
        let password =         prompt_export_password()?;
        let (vault_db, keystore_json) = export::read_encrypted_export(&path, &password)?;
        export::write_bundle_to_paths(paths, &vault_db, &keystore_json, args.force)?;
        println!(
            "Encrypted import restored vault at {}",
            paths.db_path.display()
        );
    }

    Ok(())
}

fn fetch_items_for_export(paths: &KeeperPaths) -> Result<Vec<models::Item>> {
    if client::daemon_running(paths) {
        return Err(anyhow!("Stop the daemon before exporting"));
    }
    if !paths.db_path.exists() {
        return Err(anyhow!("Vault not found at {}", paths.db_path.display()));
    }
    let password = prompt::prompt_password()?;
    let keystore = keystore::Keystore::load(paths.keystore_path())?;
    let mut master_key = keystore.unwrap_with_password(&password)?;
    password.zeroize();
    let db_key = security::derive_db_key_hex(&master_key);
    let db = db::Db::open(&paths.db_path, &db_key)?;
    master_key.zeroize();
    let items = db.get_items(None, None, None, None, true, false)?;
    master_key.zeroize();
    Ok(items)
}

fn import_items(paths: &KeeperPaths, items: Vec<models::Item>) -> Result<usize> {
    if client::daemon_running(paths) {
        return Err(anyhow!("Stop the daemon before importing"));
    }
    if !paths.db_path.exists() {
        return Err(anyhow!("Vault not found at {}", paths.db_path.display()));
    }
    let password = prompt::prompt_password()?;
    let keystore = keystore::Keystore::load(paths.keystore_path())?;
    let mut master_key = keystore.unwrap_with_password(&password)?;
    password.zeroize();
    let db_key = security::derive_db_key_hex(&master_key);
    let db = db::Db::open(&paths.db_path, &db_key)?;
    master_key.zeroize();
    let mut count = 0;
    let mut error = None;
    for item in items {
        match db.upsert_item(item) {
            Ok(()) => count += 1,
            Err(err) => {
                error = Some(err);
                break;
            }
        }
    }
    master_key.zeroize();
    Ok(count)
}

    if !paths.db_path.exists() {
        return Err(anyhow!("Vault not found at {}", paths.db_path.display()));
    }
    let mut password = prompt::prompt_password()?;
    let keystore = keystore::Keystore::load(paths.keystore_path())?;
    let mut master_key = keystore.unwrap_with_password(&password)?;
    password.zeroize();

    let db_key = security::derive_db_key_hex(&master_key);
    let db = db::Db::open(&paths.db_path, &db_key)?;
    let items = db.get_items(None, None, None, None, true, false)?;
    master_key.zeroize();
    Ok(items)
}

fn import_items(paths: &KeeperPaths, items: Vec<models::Item>) -> Result<usize> {
    if items.is_empty() {
        return Ok(0);
    }
    let count = items.len();

    if client::daemon_running(paths) {
        let response = client::send_request(paths, &DaemonRequest::ImportItems { items })?;
        return match response {
            DaemonResponse::OkMessage(_) => Ok(count),
            DaemonResponse::Error(err) => Err(anyhow!(err)),
            _ => Err(anyhow!("Unexpected response from daemon")),
        };
    }

    let outcome = session::unlock_or_init_master_key(paths)?;
    if let Some(recovery) = outcome.recovery_code.as_ref() {
        println!("🧩 Recovery Code (store this safely):\n{recovery}");
    }
    let mut master_key = outcome.master_key;
    let db_key = security::derive_db_key_hex(&master_key);
    let db = db::Db::open(&paths.db_path, &db_key)?;
    for item in &items {
        db.upsert_item(item)?;
    }
    master_key.zeroize();
    Ok(count)
}

fn prompt_export_password() -> Result<SecurePassword> {
    let first = prompt::prompt_export_password()?;
    let second = prompt::prompt_export_password_confirm()?;
    if first != second {
        return Err(anyhow!("Passwords do not match"));
    }
    Ok(first)
}

fn prompt_export_password_once() -> Result<String> {
    prompt::prompt_export_password()
}
