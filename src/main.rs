mod backup;
mod cli;
mod client;
mod config;
mod daemon;
mod db;
mod export;
mod formatting;
mod ipc;
mod keystore;
mod logger;
mod migration;
mod models;
mod paths;
mod prompt;
mod sanitize;
mod security;
mod self_update;
mod session;
mod sigil;
mod timeline;
mod transfer;
mod tui;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use clap::Parser;
use std::io;
use std::io::IsTerminal;
use std::path::PathBuf;
use zeroize::Zeroize;

use crate::cli::{Cli, Commands};
use crate::ipc::{DaemonRequest, DaemonResponse};
use crate::migration::{MigrationManager, MigrationStatus};
use crate::paths::KeeperPaths;
use crate::security::memory::SecurePassword;

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
        Some(Commands::Start) => cmd_start(&paths, cli.debug, cli.show_recovery),
        Some(Commands::Stop) => cmd_stop(&paths),
        Some(Commands::Status) => cmd_status(&paths),
        Some(Commands::Passwd) => cmd_passwd(&paths),
        Some(Commands::Recover(args)) => cmd_recover(&paths, args),
        Some(Commands::Note(args)) => cmd_note(&paths, args),
        Some(Commands::Get(args)) => cmd_get(&paths, args),
        Some(Commands::Mark { id, status }) => cmd_mark(&paths, id, status),
        Some(Commands::Update(args)) => cmd_update(&paths, args),
        Some(Commands::Dash(args)) => cmd_dash(&paths, args),
        Some(Commands::Export(args)) => transfer::run_export(&paths, args),
        Some(Commands::Import(args)) => transfer::run_import(&paths, args),
        Some(Commands::Workspace(args)) => cmd_workspace(&paths, args),
        Some(Commands::Bucket(args)) => cmd_bucket(&paths, args),
        Some(Commands::Keystore(args)) => cmd_keystore(&paths, args),
        Some(Commands::Delete(args)) => cmd_delete(&paths, args),
        Some(Commands::Undo(args)) => cmd_undo(&paths, args),
        Some(Commands::Archive) => cmd_archive(&paths),
        Some(Commands::Daemon) => cmd_daemon(&paths),
        Some(Commands::Migrate(args)) => cmd_migrate(&paths, args),
        None => tui::run_repl(&paths, cli.debug),
    }
}

fn cmd_start(paths: &KeeperPaths, debug: bool, show_recovery: bool) -> Result<()> {
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
        if show_recovery {
            println!("🧩 Recovery Code (store this safely):\n{recovery}");
        } else {
            display_recovery_secure(recovery)?;
        }
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

fn display_recovery_secure(recovery: &str) -> Result<()> {
    use std::io::{self, IsTerminal, Write};

    print!("🧩 Recovery Code: [{} characters]", recovery.len());
    io::stdout().flush()?;

    if io::stdin().is_terminal() {
        print!("\nPress Enter when you've saved the code securely...");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        #[cfg(unix)]
        {
            print!("\x1b[2J\x1b[H");
            io::stdout().flush()?;
        }
    } else {
        println!();
    }

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
    let config = config::Config::load(paths)?;
    let (content, bucket, priority, due_date) =
        sigil::parse_note_args(&args, &config.default_workspace)?;
    if !bucket.contains('/') {
        return Err(anyhow!(
            "Bucket must include workspace (e.g. @default/inbox)"
        ));
    }
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
    let bucket_filter = match args.bucket_flag.or(args.bucket) {
        Some(bucket) => Some(sigil::normalize_bucket_filter(&bucket)?),
        None => None,
    };
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

        // Check migration before self-update
        if !args.skip_migration_check {
            let manager = MigrationManager::new(paths.clone())?;
            let current_version = env!("CARGO_PKG_VERSION");
            let target_version = args.tag.as_deref().unwrap_or("latest");

            match manager.check_migration_needed(current_version, target_version)? {
                MigrationStatus::NoActionRequired => {
                    // Safe to proceed
                }
                MigrationStatus::MigrationRequired(_) => {
                    if !args.force {
                        eprintln!("⚠️  Migration check: Update requires migration.");
                        eprintln!("   Run `keeper migrate check` for details.");
                        eprintln!("   Create backup: `keeper migrate backup`");
                        eprintln!("   Or use --force to skip this check (not recommended)");
                        return Err(anyhow!("Migration required"));
                    }
                }
                MigrationStatus::Incompatible(reason) => {
                    return Err(anyhow!(
                        "Cannot update: {}. Run `keeper migrate check` for details.",
                        reason
                    ));
                }
            }
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
    let config = config::Config::load(paths)?;
    let spec = sigil::parse_update_args(&args, &config.default_workspace)?;
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
        due_date: spec.due_date,
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

fn cmd_workspace(paths: &KeeperPaths, args: cli::WorkspaceArgs) -> Result<()> {
    match args.command {
        cli::WorkspaceCommands::List => {
            let db = load_db(paths)?;
            let mut workspaces = db.list_workspaces()?;
            if workspaces.is_empty() {
                workspaces.push(config::default_workspace().to_string());
            }
            for ws in workspaces {
                println!("{ws}");
            }
            Ok(())
        }
        cli::WorkspaceCommands::Current => {
            let config = config::Config::load(paths)?;
            println!("{}", config.default_workspace);
            Ok(())
        }
        cli::WorkspaceCommands::Set { name } => {
            if !name.starts_with('@') {
                return Err(anyhow!("Workspace must start with @"));
            }
            let mut config = config::Config::load(paths)?;
            config.default_workspace = name;
            config.save(paths)?;
            println!("Default workspace set to {}", config.default_workspace);
            Ok(())
        }
    }
}

fn cmd_bucket(paths: &KeeperPaths, args: cli::BucketArgs) -> Result<()> {
    match args.command {
        cli::BucketCommands::List { workspace } => {
            let db = load_db(paths)?;
            let buckets = db.list_buckets()?;
            let filtered: Vec<_> = if let Some(ws) = workspace {
                buckets
                    .into_iter()
                    .filter(|b| b == &ws || b.starts_with(&format!("{ws}/")))
                    .collect()
            } else {
                buckets
            };
            for bucket in filtered {
                println!("{bucket}");
            }
            Ok(())
        }
        cli::BucketCommands::Move { from, to } => {
            let mut db = load_db(paths)?;
            let count = db.move_bucket_prefix(&from, &to)?;
            println!("Moved {count} item(s)");
            Ok(())
        }
    }
}

fn load_db(paths: &KeeperPaths) -> Result<db::Db> {
    if client::daemon_running(paths) {
        return Err(anyhow!("Stop the daemon to manage workspaces or buckets."));
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
    master_key.zeroize();
    Ok(db)
}

fn cmd_passwd(paths: &KeeperPaths) -> Result<()> {
    if !client::daemon_running(paths) {
        return Err(anyhow!("Daemon not running. Start the vault first."));
    }

    if let Some(backup_msg) = session::create_vault_backup(paths)? {
        println!("✓ {backup_msg}");
    }

    let mut request = DaemonRequest::RotatePassword {
        current_password: prompt::prompt_current_password()?.into(),
        new_password: prompt::prompt_password_confirm()?.into(),
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
    let mut keystore = keystore::Keystore::load(paths.keystore_path())
        .context("Keystore not found; start the vault first")?;
    let recovery = match args.code {
        Some(code) => keystore::normalize_recovery_code(&code),
        None => prompt::prompt_recovery_code()?.as_str(),
    };
    let master_key = keystore.unwrap_with_recovery(recovery)?;

    let new_password = prompt::prompt_password_confirm()?;
    keystore.rewrap_password(&new_password, &master_key)?;
    keystore.save(paths.keystore_path())?;

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
        cli::DashCommands::DueTimeline { mermaid, workspace } => {
            cmd_dash_due_timeline(paths, mermaid, workspace)
        }
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

    if let Some(backup_msg) = session::create_vault_backup(paths)? {
        println!("✓ {backup_msg}");
    }

    let new_password = prompt::prompt_password_confirm()?;

    let response = client::send_request(
        paths,
        &DaemonRequest::RebuildKeystore {
            new_password: new_password.into(),
        },
    )?;
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

fn cmd_dash_due_timeline(
    paths: &KeeperPaths,
    mermaid: bool,
    workspace: Option<String>,
) -> Result<()> {
    let today = chrono::Local::now().date_naive();
    let cutoff = today + chrono::Duration::days(15);
    let bucket_filter = match workspace {
        Some(ws) => Some(sigil::normalize_bucket_filter(&ws)?),
        None => None,
    };
    let response = client::send_request(
        paths,
        &DaemonRequest::GetItems {
            bucket_filter,
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

    let mut overdue_counts = timeline::OverdueCounts {
        p1: 0,
        p2: 0,
        p3: 0,
        notes: 0,
    };
    for item in &overdue {
        match item.priority {
            models::Priority::P1_Urgent => overdue_counts.p1 += 1,
            models::Priority::P2_Important => overdue_counts.p2 += 1,
            models::Priority::P3_Task => overdue_counts.p3 += 1,
            models::Priority::None => overdue_counts.notes += 1,
        }
    }

    let mermaid_code =
        timeline::build_mermaid_due_timeline(&upcoming, &overdue_counts, today, cutoff)?;
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

fn confirm(prompt: &str) -> Result<bool> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim() == "YES")
}

fn cmd_migrate(paths: &KeeperPaths, args: cli::MigrateArgs) -> Result<()> {
    match args.command {
        cli::MigrateCommands::Check => cmd_migrate_check(paths),
        cli::MigrateCommands::Backup { path } => cmd_migrate_backup(paths, path),
        cli::MigrateCommands::Restore { path } => cmd_migrate_restore(paths, path),
        cli::MigrateCommands::List => cmd_migrate_list(paths),
        cli::MigrateCommands::Cleanup => cmd_migrate_cleanup(paths),
    }
}

fn cmd_migrate_check(paths: &KeeperPaths) -> Result<()> {
    let manager = MigrationManager::new(paths.clone())?;
    let current_version = env!("CARGO_PKG_VERSION");
    let target_version = "latest"; // In production, this would be fetched

    println!("Checking migration status...");
    println!("  Current version: {}", current_version);
    println!("  Target version: {}", target_version);

    match manager.check_migration_needed(current_version, target_version)? {
        MigrationStatus::NoActionRequired => {
            println!("✅ No migration needed - safe to update");
            Ok(())
        }
        MigrationStatus::MigrationRequired(req) => {
            println!("⚠️  Migration required for update");
            println!("  Type: {:?}", req.migration_type);
            let changes = manager.get_breaking_changes(current_version, target_version)?;
            if !changes.is_empty() {
                println!("\nBreaking changes:");
                for change in changes {
                    println!("  - {}: {}", change.version, change.description);
                    println!("    Migration required: {}", change.requires_migration);
                    println!("    Type: {:?}", change.migration_type);
                }
            }
            Ok(())
        }
        MigrationStatus::Incompatible(reason) => {
            println!("❌ Cannot migrate: {}", reason);
            Err(anyhow!("Migration incompatible"))
        }
    }
}

fn cmd_migrate_backup(paths: &KeeperPaths, output: PathBuf) -> Result<()> {
    if client::daemon_running(paths) {
        return Err(anyhow!(
            "Daemon is running. Please stop it first with `keeper stop`"
        ));
    }

    if !paths.db_path.exists() {
        return Err(anyhow!("Vault not found at {}", paths.db_path.display()));
    }

    let manager = MigrationManager::new(paths.clone())?;
    let current_version = env!("CARGO_PKG_VERSION");
    let target_version = "latest";

    println!("Creating pre-update backup...");

    let mut password = prompt::prompt_password()?;
    let secure_pass = SecurePassword::new(password.as_bytes().to_vec());

    let backup = manager.create_pre_update_backup(current_version, target_version, &secure_pass)?;

    password.zeroize();

    // Move backup to requested output path if different
    if output != backup.backup_dir {
        println!("Moving backup to: {}", output.display());
        std::fs::rename(&backup.backup_dir, &output)?;
        println!("✅ Backup complete");
        println!("  Location: {}", output.display());
    } else {
        println!("✅ Backup complete");
        println!("  Location: {}", backup.backup_dir.display());
    }
    println!("  Checksum: {}...", &backup.checksum[..16]);

    Ok(())
}

fn cmd_migrate_restore(paths: &KeeperPaths, backup_path: PathBuf) -> Result<()> {
    if client::daemon_running(paths) {
        return Err(anyhow!(
            "Daemon is running. Please stop it first with `keeper stop`"
        ));
    }

    if !backup_path.exists() {
        return Err(anyhow!("Backup not found at {}", backup_path.display()));
    }

    println!("⚠️  This will restore your vault from backup.");
    println!("   Current vault data will be replaced.");
    println!("   Backup: {}", backup_path.display());

    if !confirm("Type YES to restore: ")? {
        println!("Aborted.");
        return Ok(());
    }

    let manager = MigrationManager::new(paths.clone())?;

    let mut password = prompt::prompt_password()?;
    let secure_pass = SecurePassword::new(password.as_bytes().to_vec());

    // Find backup in the path
    let backups = manager.list_backups()?;
    let backup = backups
        .into_iter()
        .find(|b| b.backup_dir == backup_path)
        .ok_or_else(|| anyhow!("Backup not found in migration system"))?;

    manager.manual_restore(&backup, &secure_pass)?;

    password.zeroize();

    println!("✅ Restore complete");
    println!("   Your vault has been restored from backup.");

    Ok(())
}

fn cmd_migrate_list(paths: &KeeperPaths) -> Result<()> {
    let manager = MigrationManager::new(paths.clone())?;
    let backups = manager.list_backups()?;

    if backups.is_empty() {
        println!("No backups found.");
        return Ok(());
    }

    println!("Available backups:");
    for (i, backup) in backups.iter().enumerate() {
        let verified = manager.verify_backup(backup)?;
        let status = if verified { "✅" } else { "❌" };
        println!(
            "  {}. {} -> {} ({}) {}",
            i + 1,
            backup.original_version,
            backup.target_version,
            backup.created_at.split('T').next().unwrap_or("unknown"),
            status
        );
        println!("     Path: {}", backup.backup_dir.display());
        println!("     Checksum: {}...", &backup.checksum[..16]);
    }

    Ok(())
}

fn cmd_migrate_cleanup(paths: &KeeperPaths) -> Result<()> {
    let manager = MigrationManager::new(paths.clone())?;

    let backups = manager.list_backups()?;
    if backups.len() <= 5 {
        println!(
            "No cleanup needed ({} backup(s) found, keep 5)",
            backups.len()
        );
        return Ok(());
    }

    println!("Found {} backup(s), keeping 5 most recent", backups.len());
    println!("The following backups will be removed:");

    for backup in backups.iter().skip(5) {
        println!(
            "  - {} ({} -> {})",
            backup.backup_dir.display(),
            backup.original_version,
            backup.target_version
        );
    }

    if !confirm("Type YES to clean up old backups: ")? {
        println!("Aborted.");
        return Ok(());
    }

    manager.cleanup_old_backups(5)?;
    println!("✅ Cleanup complete");

    Ok(())
}
