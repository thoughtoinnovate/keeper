mod cli;
mod client;
mod daemon;
mod db;
mod export;
mod formatting;
mod ipc;
mod keystore;
mod logger;
mod models;
mod paths;
mod prompt;
mod security;
mod self_update;
mod session;
mod sigil;
mod timeline;
mod tui;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use clap::Parser;
use std::io;
use std::io::IsTerminal;
use zeroize::Zeroize;

use crate::cli::{Cli, Commands};
use crate::ipc::{DaemonRequest, DaemonResponse};
use crate::paths::KeeperPaths;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    logger::set_debug(cli.debug);
    let paths = KeeperPaths::new(cli.vault.as_deref())?;

    match cli.command {
        Some(Commands::Start) => cmd_start(&paths, cli.debug),
        Some(Commands::Stop) => cmd_stop(&paths),
        Some(Commands::Status) => cmd_status(&paths),
        Some(Commands::Passwd) => cmd_passwd(&paths),
        Some(Commands::Recover(args)) => cmd_recover(&paths, args),
        Some(Commands::Note(args)) => cmd_note(&paths, args),
        Some(Commands::Get(args)) => cmd_get(&paths, args),
        Some(Commands::Mark { id, status }) => cmd_mark(&paths, id, status),
        Some(Commands::Update(args)) => cmd_update(&paths, args),
        Some(Commands::Dash(args)) => cmd_dash(&paths, args),
        Some(Commands::Export(args)) => cmd_export(&paths, args),
        Some(Commands::Import(args)) => cmd_import(&paths, args),
        Some(Commands::Keystore(args)) => cmd_keystore(&paths, args),
        Some(Commands::Delete(args)) => cmd_delete(&paths, args),
        Some(Commands::Undo(args)) => cmd_undo(&paths, args),
        Some(Commands::Archive) => cmd_archive(&paths),
        Some(Commands::Daemon) => cmd_daemon(&paths),
        None => tui::run_repl(&paths, cli.debug),
    }
}

fn cmd_start(paths: &KeeperPaths, debug: bool) -> Result<()> {
    if client::daemon_running(paths) {
        println!(
            "✅ Daemon already running. Vault: {}. Socket: {}",
            paths.db_path.display(),
            paths.socket_path_display()
        );
        return Ok(());
    }

    let outcome = session::unlock_or_init_master_key(paths)?;
    if let Some(recovery) = outcome.recovery_code.as_ref() {
        println!("🧩 Recovery Code (store this safely):\n{recovery}");
    }
    let pid = session::start_daemon(paths, &outcome.master_key, debug)?;
    let mut master_key = outcome.master_key;
    master_key.zeroize();

    if !client::wait_for_daemon(paths, 1500) {
        return Err(anyhow!("Daemon failed to start"));
    }

    println!(
        "✅ Daemon started. Vault: {}. PID: {}. Socket: {}",
        paths.db_path.display(),
        pid,
        paths.socket_path_display()
    );

    Ok(())
}

fn cmd_stop(paths: &KeeperPaths) -> Result<()> {
    let response = client::send_request(paths, &DaemonRequest::Shutdown)
        .context("Failed to contact daemon")?;
    match response {
        DaemonResponse::OkMessage(msg) => println!("{msg}"),
        DaemonResponse::Error(err) => return Err(anyhow!(err)),
        _ => println!("Daemon stopped"),
    }
    Ok(())
}

fn cmd_status(paths: &KeeperPaths) -> Result<()> {
    if client::daemon_running(paths) {
        println!("✅ Daemon running. Socket: {}", paths.socket_path_display());
    } else {
        println!("❌ Daemon not running.");
    }
    Ok(())
}

fn cmd_note(paths: &KeeperPaths, args: cli::NoteArgs) -> Result<()> {
    let (content, bucket, priority, due_date) = sigil::parse_note_args(&args)?;
    if content.is_empty() {
        return Err(anyhow!("Note content cannot be empty"));
    }

    let request = DaemonRequest::CreateNote {
        bucket,
        content,
        priority,
        due_date,
    };
    let response = client::send_request(paths, &request)?;
    match response {
        DaemonResponse::OkMessage(msg) => println!("{msg}"),
        DaemonResponse::Error(err) => return Err(anyhow!(err)),
        _ => println!("[✓] Saved"),
    }
    Ok(())
}

fn cmd_get(paths: &KeeperPaths, args: cli::GetArgs) -> Result<()> {
    let bucket_filter = args.bucket_flag.or(args.bucket);
    let request = DaemonRequest::GetItems {
        bucket_filter,
        priority_filter: None,
        status_filter: Some(models::Status::Open),
        date_cutoff: None,
        include_notes: args.all,
        notes_only: args.notes,
    };
    let response = client::send_request(paths, &request)?;

    match response {
        DaemonResponse::OkItems(items) => {
            let table = formatting::format_items_table(items);
            println!("{table}");
        }
        DaemonResponse::Error(err) => return Err(anyhow!(err)),
        _ => println!("No items"),
    }
    Ok(())
}

fn cmd_mark(paths: &KeeperPaths, id: i64, status: String) -> Result<()> {
    let status = daemon::parse_status(&status).ok_or_else(|| anyhow!("Invalid status"))?;
    let request = DaemonRequest::UpdateStatus {
        id,
        new_status: status,
    };
    let response = client::send_request(paths, &request)?;
    match response {
        DaemonResponse::OkMessage(msg) => println!("{msg}"),
        DaemonResponse::Error(err) => return Err(anyhow!(err)),
        _ => println!("Updated"),
    }
    Ok(())
}

fn cmd_update(paths: &KeeperPaths, args: cli::UpdateArgs) -> Result<()> {
    if args.self_update || args.id.is_none() {
        if args.id.is_some() {
            return Err(anyhow!("Self-update does not take an id"));
        }
        if !args.content.is_empty() {
            return Err(anyhow!(
                "Self-update does not take item content. Run `keeper update <id> <content...>` to update an item."
            ));
        }
        return self_update::run_self_update(self_update::SelfUpdateOptions { tag: args.tag });
    }

    if args.tag.is_some() {
        return Err(anyhow!(
            "Release tags are only valid for self-update. Run `keeper update --self --tag <tag>`."
        ));
    }

    let id = args
        .id
        .ok_or_else(|| anyhow!("Provide an id or use --self to update keeper"))?;
    let spec = sigil::parse_update_args(&args)?;
    if spec.content.is_none()
        && spec.bucket.is_none()
        && spec.priority.is_none()
        && spec.due_date.is_none()
    {
        return Err(anyhow!("No updates provided"));
    }
    if let Some(ref content) = spec.content
        && content.trim().is_empty()
    {
        return Err(anyhow!("Note content cannot be empty"));
    }
    let request = DaemonRequest::UpdateItem {
        id,
        bucket: spec.bucket,
        content: spec.content,
        priority: spec.priority,
        due_date: spec.due_date.flatten(),
        clear_due_date: matches!(spec.due_date, Some(None)),
    };
    let response = client::send_request(paths, &request)?;
    match response {
        DaemonResponse::OkMessage(msg) => println!("{msg}"),
        DaemonResponse::Error(err) => return Err(anyhow!(err)),
        _ => println!("Updated"),
    }
    Ok(())
}

fn cmd_delete(paths: &KeeperPaths, args: cli::DeleteArgs) -> Result<()> {
    if args.all {
        if !args.yes && !confirm("Type YES to archive all notes: ")? {
            println!("Aborted.");
            return Ok(());
        }
        let _ = prompt::prompt_password()?;
        let response = client::send_request(paths, &DaemonRequest::ArchiveAll)?;
        match response {
            DaemonResponse::OkMessage(msg) => println!("{msg}"),
            DaemonResponse::Error(err) => return Err(anyhow!(err)),
            _ => println!("Archived"),
        }
        return Ok(());
    }

    let id = args
        .id
        .ok_or_else(|| anyhow!("Provide an id or use --all"))?;
    let request = DaemonRequest::UpdateStatus {
        id,
        new_status: models::Status::Deleted,
    };
    let response = client::send_request(paths, &request)?;
    match response {
        DaemonResponse::OkMessage(msg) => println!("{msg}"),
        DaemonResponse::Error(err) => return Err(anyhow!(err)),
        _ => println!("Archived"),
    }
    Ok(())
}

fn cmd_undo(paths: &KeeperPaths, args: cli::UndoArgs) -> Result<()> {
    let response = client::send_request(paths, &DaemonRequest::Undo { id: args.id })?;
    match response {
        DaemonResponse::OkMessage(msg) => println!("{msg}"),
        DaemonResponse::Error(err) => return Err(anyhow!(err)),
        _ => println!("Undo complete"),
    }
    Ok(())
}

fn cmd_archive(paths: &KeeperPaths) -> Result<()> {
    let request = DaemonRequest::GetItems {
        bucket_filter: None,
        priority_filter: None,
        status_filter: Some(models::Status::Deleted),
        date_cutoff: None,
        include_notes: true,
        notes_only: false,
    };
    let response = client::send_request(paths, &request)?;
    match response {
        DaemonResponse::OkItems(items) => {
            let table = formatting::format_items_table(items);
            println!("{table}");
        }
        DaemonResponse::Error(err) => return Err(anyhow!(err)),
        _ => println!("No archived items"),
    }
    Ok(())
}

fn cmd_passwd(paths: &KeeperPaths) -> Result<()> {
    if !client::daemon_running(paths) {
        return Err(anyhow!("Daemon not running. Start the vault first."));
    }
    let mut request = DaemonRequest::RotatePassword {
        current_password: prompt::prompt_current_password()?,
        new_password: prompt::prompt_password_confirm()?,
    };
    let response = client::send_request(paths, &request)?;
    if let DaemonRequest::RotatePassword {
        current_password,
        new_password,
    } = &mut request
    {
        current_password.zeroize();
        new_password.zeroize();
    }
    match response {
        DaemonResponse::OkMessage(msg) => println!("{msg}"),
        DaemonResponse::Error(err) => {
            if err.contains("missing field `password`") {
                return Err(anyhow!(
                    "Daemon is out of date. Run `keeper stop` then `keeper start` and retry."
                ));
            }
            return Err(anyhow!(err));
        }
        _ => println!("Password updated"),
    }
    Ok(())
}

fn cmd_recover(paths: &KeeperPaths, args: cli::RecoverArgs) -> Result<()> {
    let keystore = keystore::Keystore::load(paths.keystore_path())
        .context("Keystore not found; start the vault first")?;
    let mut recovery = match args.code {
        Some(code) => code,
        None => prompt::prompt_recovery_code()?,
    };
    let master_key = keystore.unwrap_with_recovery(&recovery)?;
    recovery.zeroize();

    let mut new_password = prompt::prompt_password_confirm()?;
    let mut keystore = keystore;
    keystore.rewrap_password(&new_password, &master_key)?;
    keystore.save(paths.keystore_path())?;
    new_password.zeroize();
    let mut master_key = master_key;
    master_key.zeroize();

    println!("✅ Password reset. You can now run `keeper start`.");
    Ok(())
}

fn cmd_daemon(paths: &KeeperPaths) -> Result<()> {
    let mut key = String::new();
    io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err(anyhow!("Missing key"));
    }
    let key_bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(key)
        .map_err(|_| anyhow!("Invalid master key data"))?;
    if key_bytes.len() != security::MASTER_KEY_LEN {
        return Err(anyhow!("Invalid master key length"));
    }
    let mut master_key = [0u8; security::MASTER_KEY_LEN];
    master_key.copy_from_slice(&key_bytes);
    logger::debug("Daemon starting");
    #[cfg(unix)]
    {
        let mut d = daemonize::Daemonize::new();
        if logger::is_debug() {
            d = d
                .stdout(daemonize::Stdio::keep())
                .stderr(daemonize::Stdio::keep());
        } else {
            d = d
                .stdout(daemonize::Stdio::devnull())
                .stderr(daemonize::Stdio::devnull());
        }
        d.start().context("Failed to daemonize")?;
    }
    match daemon::run_daemon(master_key, paths) {
        Ok(()) => Ok(()),
        Err(err) => {
            logger::error(&format!("Daemon error: {err}"));
            Err(err)
        }
    }
}

fn cmd_dash(paths: &KeeperPaths, args: cli::DashArgs) -> Result<()> {
    match args.command {
        cli::DashCommands::DueTimeline { mermaid } => cmd_dash_due_timeline(paths, mermaid),
    }
}

fn cmd_keystore(paths: &KeeperPaths, args: cli::KeystoreArgs) -> Result<()> {
    match args.command {
        cli::KeystoreCommands::Rebuild => cmd_keystore_rebuild(paths),
    }
}

fn cmd_keystore_rebuild(paths: &KeeperPaths) -> Result<()> {
    if !client::daemon_running(paths) {
        return Err(anyhow!(
            "Daemon not running. Start it first to rebuild keystore."
        ));
    }
    let mut new_password = prompt::prompt_password_confirm()?;
    let response = client::send_request(
        paths,
        &DaemonRequest::RebuildKeystore {
            new_password: new_password.clone(),
        },
    )?;
    new_password.zeroize();
    match response {
        DaemonResponse::OkRecoveryCode(code) => {
            println!("✅ Keystore rebuilt.");
            println!("🧩 New Recovery Code (store this safely):\n{code}");
            Ok(())
        }
        DaemonResponse::Error(err) => Err(anyhow!(err)),
        _ => Err(anyhow!("Unexpected response")),
    }
}

fn cmd_dash_due_timeline(paths: &KeeperPaths, mermaid: bool) -> Result<()> {
    let today = chrono::Local::now().date_naive();
    let cutoff = today + chrono::Duration::days(15);
    let response = client::send_request(
        paths,
        &DaemonRequest::GetItems {
            bucket_filter: None,
            priority_filter: None,
            status_filter: Some(models::Status::Open),
            date_cutoff: Some(cutoff),
            include_notes: false,
            notes_only: false,
        },
    )?;

    let items = match response {
        DaemonResponse::OkItems(items) => items,
        _ => Vec::new(),
    };

    let mut overdue = Vec::new();
    let mut upcoming = Vec::new();

    for item in items {
        if let Some(due) = item.due_date {
            if due < today {
                overdue.push(item);
            } else if due <= cutoff {
                upcoming.push(item);
            }
        }
    }

    let mermaid_code = timeline::build_mermaid_due_timeline(&upcoming, cutoff)?;
    if mermaid {
        println!("{mermaid_code}");
        return Ok(());
    }
    let link = timeline::mermaid_live_edit_url(&mermaid_code)?;
    let link_label = if std::io::stdout().is_terminal() {
        timeline::format_terminal_hyperlink("timeline", &link)
    } else {
        "timeline".to_string()
    };

    println!("🧭 DUE TIMELINE (Next 15 Days)");
    if overdue.is_empty() {
        println!("Overdue: (none)");
    } else {
        println!("Overdue:");
        overdue.sort_by(|a, b| a.due_date.cmp(&b.due_date).then(a.id.cmp(&b.id)));
        for item in overdue {
            let due = timeline::format_date(item.due_date);
            println!(
                " - [{}] {} ({}) due {}",
                item.priority, item.content, item.bucket, due
            );
        }
    }
    println!();
    let ascii = timeline::mermaid_timeline_to_ascii(&mermaid_code);
    println!("{ascii}");
    println!("Timeline: {link_label}");
    println!("Timeline URL: {link}");
    Ok(())
}

fn cmd_export(paths: &KeeperPaths, args: cli::ExportArgs) -> Result<()> {
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

fn cmd_import(paths: &KeeperPaths, args: cli::ImportArgs) -> Result<()> {
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
        let password = prompt_export_password_once()?;
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
        let response = client::send_request(
            paths,
            &DaemonRequest::GetItems {
                bucket_filter: None,
                priority_filter: None,
                status_filter: None,
                date_cutoff: None,
                include_notes: true,
                notes_only: false,
            },
        )?;
        return match response {
            DaemonResponse::OkItems(items) => Ok(items),
            DaemonResponse::Error(err) => Err(anyhow!(err)),
            _ => Err(anyhow!("Unexpected response from daemon")),
        };
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

fn prompt_export_password() -> Result<String> {
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

fn confirm(prompt: &str) -> Result<bool> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim() == "YES")
}
