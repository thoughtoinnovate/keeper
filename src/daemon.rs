use crate::db::{Db, InsertOutcome};
use crate::ipc::{DaemonRequest, DaemonResponse};
use crate::keystore::Keystore;
use crate::models::{Priority, Status};
use crate::paths::KeeperPaths;
use crate::{logger, security};
use anyhow::Result;
use chrono::{NaiveDate, Utc};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use zeroize::Zeroize;

pub fn run_daemon(
    mut master_key: [u8; security::MASTER_KEY_LEN],
    paths: &KeeperPaths,
) -> Result<()> {
    logger::debug("Daemon initializing");
    paths.ensure_base_dir()?;
    paths.remove_socket_if_exists();

    let mut db_key = security::derive_db_key_hex(&master_key);
    let db = match Db::open(&paths.db_path, &db_key) {
        Ok(db) => db,
        Err(err) => {
            logger::error(&format!("Failed to open database: {err}"));
            return Err(err);
        }
    };
    db_key.zeroize();
    if let Ok(count) = db.purge_archived_before(Utc::now() - chrono::Duration::days(1)) {
        if count > 0 {
            logger::debug(&format!("Purged {count} archived items"));
        }
    }

    let listener = match UnixListener::bind(&paths.socket_path) {
        Ok(listener) => listener,
        Err(err) => {
            logger::error(&format!("Failed to bind socket: {err}"));
            return Err(err.into());
        }
    };
    paths.set_socket_permissions()?;

    let running = Arc::new(AtomicBool::new(true));

    while running.load(Ordering::SeqCst) {
        let (stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(err) => {
                logger::error(&format!("IPC accept failed: {err}"));
                continue;
            }
        };
        logger::debug("Accepted IPC connection");
        if let Err(err) = handle_connection(stream, &db, &running, paths, &master_key) {
            logger::error(&format!("IPC handler error: {err}"));
        }
    }

    master_key.zeroize();
    paths.remove_socket_if_exists();
    logger::debug("Daemon shutdown complete");
    Ok(())
}

fn handle_connection(
    stream: UnixStream,
    db: &Db,
    running: &AtomicBool,
    paths: &KeeperPaths,
    master_key: &[u8; security::MASTER_KEY_LEN],
) -> Result<()> {
    let mut stream = stream;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    let req: DaemonRequest = match serde_json::from_slice(&buf) {
        Ok(req) => req,
        Err(err) => {
            logger::error(&format!("Invalid request: {err}"));
            let resp = DaemonResponse::Error(format!("Invalid request: {err}"));
            send_response(&mut stream, &resp)?;
            return Ok(());
        }
    };

    logger::debug("Handling IPC request");
    let response = match req {
        DaemonRequest::CreateNote {
            bucket,
            content,
            priority,
            due_date,
        } => match db.insert_item(&bucket, &content, priority, due_date) {
            Ok(InsertOutcome::Inserted(id)) => {
                DaemonResponse::OkMessage(format!("[✓] Saved to {bucket} (ID: {id})"))
            }
            Ok(InsertOutcome::Duplicate(id)) => DaemonResponse::OkMessage(format!(
                "[=] Duplicate ignored in {bucket} (ID: {id})"
            )),
            Err(err) => DaemonResponse::Error(format!("Failed to save note: {err}")),
        },
        DaemonRequest::GetItems {
            bucket_filter,
            priority_filter,
            status_filter,
            date_cutoff,
            include_notes,
            notes_only,
        } => match db.get_items(
            bucket_filter,
            priority_filter,
            status_filter,
            date_cutoff,
            include_notes,
            notes_only,
        ) {
            Ok(items) => DaemonResponse::OkItems(items),
            Err(err) => DaemonResponse::Error(format!("Failed to fetch items: {err}")),
        },
        DaemonRequest::UpdateStatus { id, new_status } => match db.update_status(id, new_status) {
            Ok(true) => DaemonResponse::OkMessage("Updated status".to_string()),
            Ok(false) => DaemonResponse::Error("Item not found".to_string()),
            Err(err) => DaemonResponse::Error(format!("Failed to update status: {err}")),
        },
        DaemonRequest::UpdateItem {
            id,
            bucket,
            content,
            priority,
            due_date,
            clear_due_date,
        } => {
            let due_update = if clear_due_date {
                Some(None)
            } else {
                due_date.map(Some)
            };
            match db.update_item(id, bucket, content, priority, due_update) {
                Ok(true) => DaemonResponse::OkMessage("Updated item".to_string()),
                Ok(false) => DaemonResponse::Error("Item not found or no updates".to_string()),
                Err(err) => DaemonResponse::Error(format!("Failed to update item: {err}")),
            }
        }
        DaemonRequest::RotatePassword {
            current_password,
            new_password,
        } => {
            let mut current_password = current_password;
            let mut new_password = new_password;
            let response = match Keystore::load(paths.keystore_path()) {
                Ok(mut keystore) => match keystore.unwrap_with_password(&current_password) {
                    Ok(mut unwrapped) => {
                        if &unwrapped != master_key {
                            unwrapped.zeroize();
                            DaemonResponse::Error(
                                "Current password does not match active vault".to_string(),
                            )
                        } else {
                            unwrapped.zeroize();
                            match keystore.rewrap_password(&new_password, master_key) {
                                Ok(()) => match keystore.save(paths.keystore_path()) {
                                    Ok(()) => {
                                        DaemonResponse::OkMessage("Password updated".to_string())
                                    }
                                    Err(err) => {
                                        DaemonResponse::Error(format!(
                                            "Failed to save keystore: {err}"
                                        ))
                                    }
                                },
                                Err(err) => {
                                    DaemonResponse::Error(format!("Failed to update password: {err}"))
                                }
                            }
                        }
                    }
                    Err(_) => DaemonResponse::Error("Invalid current password".to_string()),
                },
                Err(err) => DaemonResponse::Error(format!("Failed to load keystore: {err}")),
            };
            current_password.zeroize();
            new_password.zeroize();
            response
        }
        DaemonRequest::RebuildKeystore { new_password } => {
            let mut new_password = new_password;
            let response = match Keystore::create_from_master_key(&new_password, master_key) {
                Ok((keystore, recovery)) => match keystore.save(paths.keystore_path()) {
                    Ok(()) => DaemonResponse::OkRecoveryCode(recovery),
                    Err(err) => DaemonResponse::Error(format!("Failed to save keystore: {err}")),
                },
                Err(err) => DaemonResponse::Error(format!("Failed to rebuild keystore: {err}")),
            };
            new_password.zeroize();
            response
        }
        DaemonRequest::GetDashboardStats => match db.stats() {
            Ok((open, done_today, p1)) => DaemonResponse::OkStats {
                open,
                done_today,
                p1,
            },
            Err(err) => DaemonResponse::Error(format!("Failed to fetch stats: {err}")),
        },
        DaemonRequest::ArchiveAll => match db.archive_all() {
            Ok(count) => DaemonResponse::OkMessage(format!("Archived {count} item(s)")),
            Err(err) => DaemonResponse::Error(format!("Failed to archive: {err}")),
        },
        DaemonRequest::Undo { id } => {
            if let Some(id) = id {
                match db.update_status(id, Status::Open) {
                    Ok(true) => DaemonResponse::OkMessage(format!("Restored {id}")),
                    Ok(false) => DaemonResponse::Error("Item not found".to_string()),
                    Err(err) => DaemonResponse::Error(format!("Failed to undo: {err}")),
                }
            } else {
                match db.undo_last() {
                    Ok(Some(id)) => DaemonResponse::OkMessage(format!("Restored {id}")),
                    Ok(None) => DaemonResponse::OkMessage("No archived items".to_string()),
                    Err(err) => DaemonResponse::Error(format!("Failed to undo: {err}")),
                }
            }
        }
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
