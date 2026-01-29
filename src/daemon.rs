use crate::db::Db;
use crate::ipc::{DaemonRequest, DaemonResponse};
use crate::models::{Priority, Status};
use crate::paths::KeeperPaths;
use anyhow::{Context, Result};
use chrono::NaiveDate;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use zeroize::Zeroize;

pub fn run_daemon(mut key: String, paths: &KeeperPaths) -> Result<()> {
    paths.ensure_base_dir()?;
    paths.remove_socket_if_exists();

    let db = Db::open(&paths.db_path, &key).context("Failed to open database")?;

    let listener = UnixListener::bind(&paths.socket_path)?;
    paths.set_socket_permissions()?;

    let running = Arc::new(AtomicBool::new(true));

    while running.load(Ordering::SeqCst) {
        let (stream, _) = listener.accept()?;
        handle_connection(stream, &db, &running)?;
    }

    key.zeroize();
    paths.remove_socket_if_exists();
    Ok(())
}

fn handle_connection(stream: UnixStream, db: &Db, running: &AtomicBool) -> Result<()> {
    let mut stream = stream;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    let req: DaemonRequest = match serde_json::from_slice(&buf) {
        Ok(req) => req,
        Err(err) => {
            let resp = DaemonResponse::Error(format!("Invalid request: {err}"));
            send_response(&mut stream, &resp)?;
            return Ok(());
        }
    };

    let response = match req {
        DaemonRequest::CreateNote {
            bucket,
            content,
            priority,
            due_date,
        } => match db.insert_item(&bucket, &content, priority, due_date) {
            Ok(id) => DaemonResponse::OkMessage(format!("[✓] Saved to {bucket} (ID: {id})")),
            Err(err) => DaemonResponse::Error(format!("Failed to save note: {err}")),
        },
        DaemonRequest::GetItems {
            bucket_filter,
            priority_filter,
            status_filter,
            date_cutoff,
        } => match db.get_items(bucket_filter, priority_filter, status_filter, date_cutoff) {
            Ok(items) => DaemonResponse::OkItems(items),
            Err(err) => DaemonResponse::Error(format!("Failed to fetch items: {err}")),
        },
        DaemonRequest::UpdateStatus { id, new_status } => match db.update_status(id, new_status) {
            Ok(_) => DaemonResponse::OkMessage("Updated status".to_string()),
            Err(err) => DaemonResponse::Error(format!("Failed to update status: {err}")),
        },
        DaemonRequest::GetDashboardStats => match db.stats() {
            Ok((open, done_today, p1)) => DaemonResponse::OkStats {
                open,
                done_today,
                p1,
            },
            Err(err) => DaemonResponse::Error(format!("Failed to fetch stats: {err}")),
        },
        DaemonRequest::Shutdown => {
            running.store(false, Ordering::SeqCst);
            DaemonResponse::OkMessage("Daemon shutting down".to_string())
        }
    };

    send_response(&mut stream, &response)?;
    Ok(())
}

fn send_response(stream: &mut UnixStream, response: &DaemonResponse) -> Result<()> {
    let payload = serde_json::to_vec(response)?;
    stream.write_all(&payload)?;
    Ok(())
}

pub fn parse_status(value: &str) -> Option<Status> {
    match value.to_lowercase().as_str() {
        "open" => Some(Status::Open),
        "done" => Some(Status::Done),
        "deleted" => Some(Status::Deleted),
        _ => None,
    }
}

pub fn parse_priority(value: &str) -> Option<Priority> {
    match value.to_lowercase().as_str() {
        "p1" | "!p1" => Some(Priority::P1_Urgent),
        "p2" | "!p2" => Some(Priority::P2_Important),
        "p3" | "!p3" => Some(Priority::P3_Task),
        "none" => Some(Priority::None),
        _ => None,
    }
}

pub fn parse_date_filter(value: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
}
