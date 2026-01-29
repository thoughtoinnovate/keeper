mod cli;
mod client;
mod daemon;
mod db;
mod ipc;
mod models;
mod paths;
mod security;
mod sigil;
mod tui;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use std::io::{self, Write};
use std::process::{Command, Stdio};
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
    let paths = KeeperPaths::new()?;

    match cli.command {
        Some(Commands::Start) => cmd_start(&paths),
        Some(Commands::Stop) => cmd_stop(&paths),
        Some(Commands::Status) => cmd_status(&paths),
        Some(Commands::Note(args)) => cmd_note(&paths, args),
        Some(Commands::Get(args)) => cmd_get(&paths, args),
        Some(Commands::Mark { id, status }) => cmd_mark(&paths, id, status),
        Some(Commands::Daemon) => cmd_daemon(&paths),
        None => tui::run_repl(&paths),
    }
}

fn cmd_start(paths: &KeeperPaths) -> Result<()> {
    if client::daemon_running(paths) {
        println!("✅ Daemon already running. Socket: {}", paths.socket_path_display());
        return Ok(());
    }

    let password = prompt_password()?;
    let key = security::derive_key(&password)?;
    let mut password = password;
    password.zeroize();

    let exe = std::env::current_exe().context("Unable to locate keeper binary")?;
    let mut child = Command::new(exe)
        .arg("daemon")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to spawn daemon")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(key.as_bytes())
            .context("Failed to send key to daemon")?;
    }

    println!(
        "✅ Daemon started. PID: {}. Socket: {}",
        child.id(),
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
    let (content, bucket, priority, due_date) = sigil::parse_note_args(&args);
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
        status_filter: None,
        date_cutoff: None,
    };
    let response = client::send_request(paths, &request)?;

    match response {
        DaemonResponse::OkItems(items) => {
            let table = format_items_table(items);
            println!("{table}");
        }
        DaemonResponse::Error(err) => return Err(anyhow!(err)),
        _ => println!("No items"),
    }
    Ok(())
}

fn cmd_mark(paths: &KeeperPaths, id: i64, status: String) -> Result<()> {
    let status = daemon::parse_status(&status).ok_or_else(|| anyhow!("Invalid status"))?;
    let request = DaemonRequest::UpdateStatus { id, new_status: status };
    let response = client::send_request(paths, &request)?;
    match response {
        DaemonResponse::OkMessage(msg) => println!("{msg}"),
        DaemonResponse::Error(err) => return Err(anyhow!(err)),
        _ => println!("Updated"),
    }
    Ok(())
}

fn cmd_daemon(paths: &KeeperPaths) -> Result<()> {
    let mut key = String::new();
    io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err(anyhow!("Missing key"));
    }
    #[cfg(unix)]
    {
        daemonize::Daemonize::new()
            .stdout(daemonize::Stdio::devnull())
            .stderr(daemonize::Stdio::devnull())
            .start()
            .context("Failed to daemonize")?;
    }
    daemon::run_daemon(key, paths)
}

fn prompt_password() -> Result<String> {
    print!("🔒 Enter Keeper Vault Password: ");
    io::stdout().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    Ok(password.trim().to_string())
}

fn format_items_table(items: Vec<models::Item>) -> String {
    use chrono::{Duration, Local, NaiveDate};
    use tabled::Tabled;

    #[derive(Tabled)]
    struct Row {
        #[tabled(rename = "ID")]
        id: i64,
        #[tabled(rename = "Bucket")]
        bucket: String,
        #[tabled(rename = "Content")]
        content: String,
        #[tabled(rename = "Priority")]
        priority: String,
        #[tabled(rename = "Due")]
        due: String,
    }

    fn display_due_date(date: Option<NaiveDate>) -> String {
        let today = Local::now().date_naive();
        let tomorrow = today + Duration::days(1);
        match date {
            Some(d) if d == today => "Today".to_string(),
            Some(d) if d == tomorrow => "Tomorrow".to_string(),
            Some(d) => d.format("%Y-%m-%d").to_string(),
            None => "".to_string(),
        }
    }

    let rows: Vec<Row> = items
        .into_iter()
        .map(|item| Row {
            id: item.id,
            bucket: item.bucket,
            content: item.content,
            priority: item.priority.to_string(),
            due: display_due_date(item.due_date),
        })
        .collect();

    if rows.is_empty() {
        return "(no items)".to_string();
    }

    tabled::Table::new(rows).to_string()
}
