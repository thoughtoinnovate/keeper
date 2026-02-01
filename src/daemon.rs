use crate::db::{Db, InsertOutcome};
use crate::ipc::{DaemonRequest, DaemonResponse};
use crate::keystore::Keystore;
use crate::models::Status;
use crate::paths::KeeperPaths;
use crate::sanitize::sanitize_for_display;
use crate::{logger, security};
use anyhow::Result;
use chrono::Utc;
use governor::{Quota, RateLimiter};
use nonzero_ext::nonzero;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const MAX_IPC_MSG_SIZE: usize = 10_485_760; // 10MB
const CONNECTION_TIMEOUT_SECS: u64 = 30;
const RATE_LIMIT_PER_MINUTE: u32 = 60;

pub fn run_daemon(
    mut master_key: [u8; security::MASTER_KEY_LEN],
    paths: &KeeperPaths,
) -> Result<()> {
    logger::debug("Daemon initializing");
    paths.ensure_base_dir()?;

    #[cfg(unix)]
    {
        use libc::{MCL_CURRENT, MCL_FUTURE, RLIMIT_CORE, mlockall, setrlimit};
        
        // Skip mlockall in test mode to allow CI testing without CAP_IPC_LOCK
        let test_mode = std::env::var("KEEPER_TEST_MODE").is_ok();
        
        unsafe {
            if !test_mode {
                if mlockall(MCL_CURRENT | MCL_FUTURE) != 0 {
                    return Err(anyhow::anyhow!(
                        "CRITICAL: Failed to lock memory. Keys would be swapped to disk. \
                         Increase ulimit -l or run with CAP_IPC_LOCK permission. \
                         Exiting for security."
                    ));
                }
            } else {
                logger::debug("Test mode: skipping mlockall()");
            }

            // Disable core dumps to prevent sensitive data leakage (MISC-001)
            let new_limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            setrlimit(RLIMIT_CORE, &new_limit);
        }
    }

    paths.remove_socket_if_exists();

    let listener = loop {
        match UnixListener::bind(&paths.socket_path) {
            Ok(l) => break l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if let Ok(metadata) = std::fs::metadata(&paths.socket_path) {
                        let current_uid = unsafe { libc::getuid() };
                        if metadata.uid() != current_uid {
                            return Err(anyhow::anyhow!(
                                "Socket exists but owned by another user. Remove {}",
                                paths.socket_path.display()
                            ));
                        }
                    }
                }
                paths.remove_socket_if_exists();
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    };
    paths.set_socket_permissions()?;

    let mut db_key = security::derive_db_key_hex(&master_key);
    let db = match Db::open(&paths.db_path, &db_key) {
        Ok(db) => db,
        Err(err) => {
            logger::error(&format!("Failed to open database: {err}"));
            return Err(err);
        }
    };
    db_key.zeroize();
    if let Ok(count) = db.purge_archived_before(Utc::now() - chrono::Duration::days(1))
        && count > 0
    {
        logger::debug(&format!("Purged {count} archived items"));
    }

    let running = Arc::new(AtomicBool::new(true));
    let start_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let last_activity = Arc::new(AtomicU64::new(start_time));
    let password_attempts = Arc::new(AtomicU64::new(0));
    let last_password_attempt = Arc::new(AtomicU64::new(0));
    let connection_count = Arc::new(AtomicUsize::new(0));
    const MAX_CONNECTIONS: usize = 50;

    let rate_limiter = Arc::new(RateLimiter::direct(Quota::per_minute(nonzero!(
        RATE_LIMIT_PER_MINUTE
    ))));

    while running.load(Ordering::SeqCst) {
        if connection_count.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            logger::error("Maximum connections reached");
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }

        let (stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(err) => {
                logger::error(&format!("IPC accept failed: {err}"));
                continue;
            }
        };

        // Verify peer credentials (AUTH-001)
        if let Err(err) = verify_peer_credentials(&stream) {
            logger::warn(&format!("Peer credential verification failed: {err}"));
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        }

        let last_activity = last_activity.clone();
        let password_attempts = password_attempts.clone();
        let last_password_attempt = last_password_attempt.clone();
        let connection_count = connection_count.clone();
        let rate_limiter = rate_limiter.clone();

        connection_count.fetch_add(1, Ordering::SeqCst);

        logger::debug("Accepted IPC connection");
        // Check rate limit before handling connection
        match rate_limiter.check() {
            Ok(()) => {
                if let Err(err) = handle_connection(
                    stream,
                    &db,
                    &running,
                    paths,
                    &master_key,
                    &last_activity,
                    &password_attempts,
                    &last_password_attempt,
                ) {
                    logger::error(&format!("IPC handler error: {err}"));
                }
            }
            Err(_) => {
                logger::warn("Rate limit exceeded for connection");
                let _ = stream.shutdown(Shutdown::Both);
            }
        }

        connection_count.fetch_sub(1, Ordering::SeqCst);
    }

    master_key.zeroize();
    paths.remove_socket_if_exists();
    logger::debug("Daemon shutdown complete");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_connection(
    stream: UnixStream,
    db: &Db,
    running: &AtomicBool,
    paths: &KeeperPaths,
    master_key: &[u8; security::MASTER_KEY_LEN],
    last_activity: &AtomicU64,
    password_attempts: &AtomicU64,
    last_password_attempt: &AtomicU64,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let last = last_activity.load(Ordering::SeqCst);

    if now - last > security::INACTIVITY_TIMEOUT_SECONDS {
        return Err(anyhow::anyhow!(
            "Vault locked due to inactivity. Restart daemon."
        ));
    }

    let mut stream = stream;
    let start_time = Instant::now();
    let timeout_duration = Duration::from_secs(CONNECTION_TIMEOUT_SECS);

    // Bounded read with size limit
    let mut buf = Vec::with_capacity(8192);
    let mut bytes_read = 0;
    let mut chunk = [0u8; 8192];

    loop {
        // Check for connection timeout
        if start_time.elapsed() > timeout_duration {
            logger::warn("Connection timeout - possible slowloris attack");
            return Err(anyhow::anyhow!("Connection timeout"));
        }

        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }

        bytes_read += n;
        if bytes_read > MAX_IPC_MSG_SIZE {
            logger::error("IPC message exceeds 10MB limit");
            let resp = DaemonResponse::Error("Message too large (max 10MB)".to_string());
            send_response(&mut stream, &resp)?;
            return Ok(());
        }

        buf.extend_from_slice(&chunk[..n]);
    }

    let req: DaemonRequest = match serde_json::from_slice(&buf) {
        Ok(req) => req,
        Err(err) => {
            logger::error(&format!("Invalid request: {err}"));
            let sanitized = sanitize_for_display(&err.to_string());
            let resp = DaemonResponse::Error(format!("Invalid request: {sanitized}"));
            send_response(&mut stream, &resp)?;
            return Ok(());
        }
    };

    let is_password_operation = matches!(
        req,
        DaemonRequest::RotatePassword { .. } | DaemonRequest::RebuildKeystore { .. }
    );

    if is_password_operation {
        let attempts = password_attempts.fetch_add(1, Ordering::SeqCst);
        let last_attempt = last_password_attempt.swap(now, Ordering::SeqCst);

        if now - last_attempt < 30 && attempts >= 3 {
            let lockout_duration = 30u64.pow((attempts.saturating_sub(2)).min(6) as u32);
            return Err(anyhow::anyhow!(
                "Too many failed password attempts. Try again in {} seconds.",
                lockout_duration
            ));
        }
    }

    logger::debug("Handling IPC request");
    let response = match req {
        DaemonRequest::CreateNote {
            bucket,
            content,
            priority,
            due_date,
        } => {
            last_activity.store(now, Ordering::SeqCst);
            match db.insert_item(&bucket, &content, priority, due_date) {
                Ok(InsertOutcome::Inserted(id)) => {
                    DaemonResponse::OkMessage(format!("[✓] Saved to {bucket} (ID: {id})"))
                }
                Ok(InsertOutcome::Duplicate(id)) => DaemonResponse::OkMessage(format!(
                    "[=] Duplicate ignored in {bucket} (ID: {id})"
                )),
                Err(err) => {
                    let sanitized = sanitize_for_display(&err.to_string());
                    DaemonResponse::Error(format!("Failed to save note: {sanitized}"))
                }
            }
        }
        DaemonRequest::GetItems {
            bucket_filter,
            priority_filter,
            status_filter,
            date_cutoff,
            include_notes,
            notes_only,
        } => {
            last_activity.store(now, Ordering::SeqCst);
            match db.get_items(
                bucket_filter,
                priority_filter,
                status_filter,
                date_cutoff,
                include_notes,
                notes_only,
            ) {
                Ok(items) => DaemonResponse::OkItems(items),
                Err(err) => {
                    let sanitized = sanitize_for_display(&err.to_string());
                    DaemonResponse::Error(format!("Failed to fetch items: {sanitized}"))
                }
            }
        }
        DaemonRequest::ListBuckets => {
            last_activity.store(now, Ordering::SeqCst);
            match db.list_buckets() {
                Ok(buckets) => DaemonResponse::OkBuckets(buckets),
                Err(err) => {
                    let sanitized = sanitize_for_display(&err.to_string());
                    DaemonResponse::Error(format!("Failed to list buckets: {sanitized}"))
                }
            }
        }
        DaemonRequest::UpdateStatus { id, new_status } => {
            last_activity.store(now, Ordering::SeqCst);
            match db.update_status(id, new_status) {
                Ok(true) => DaemonResponse::OkMessage("Updated status".to_string()),
                Ok(false) => DaemonResponse::Error("Item not found".to_string()),
                Err(err) => {
                    let sanitized = sanitize_for_display(&err.to_string());
                    DaemonResponse::Error(format!("Failed to update status: {sanitized}"))
                }
            }
        }
        DaemonRequest::UpdateItem {
            id,
            bucket,
            content,
            priority,
            due_date,
            clear_due_date,
        } => {
            last_activity.store(now, Ordering::SeqCst);
            let due_update = if clear_due_date { Some(None) } else { due_date };
            match db.update_item(id, bucket, content, priority, due_update) {
                Ok(true) => DaemonResponse::OkMessage("Updated item".to_string()),
                Ok(false) => DaemonResponse::Error("Item not found or no updates".to_string()),
                Err(err) => {
                    let sanitized = sanitize_for_display(&err.to_string());
                    DaemonResponse::Error(format!("Failed to update item: {sanitized}"))
                }
            }
        }
        DaemonRequest::RotatePassword {
            current_password,
            new_password,
        } => {
            last_activity.store(now, Ordering::SeqCst);
            let mut current_password = current_password;
            let mut new_password = new_password;
            let response = match Keystore::load(paths.keystore_path()) {
                Ok(mut keystore) => match keystore.unwrap_with_password(&current_password) {
                    Ok(mut unwrapped) => {
                        if &unwrapped != master_key {
                            unwrapped.zeroize();
                            password_attempts.fetch_add(1, Ordering::SeqCst);
                            DaemonResponse::Error(
                                "Current password does not match active vault".to_string(),
                            )
                        } else {
                            unwrapped.zeroize();
                            password_attempts.store(0, Ordering::SeqCst);
                            match keystore.rewrap_password(&new_password, master_key) {
                                Ok(()) => match keystore.save(paths.keystore_path()) {
                                    Ok(()) => {
                                        DaemonResponse::OkMessage("Password updated".to_string())
                                    }
                                    Err(err) => {
                                        let sanitized = sanitize_for_display(&err.to_string());
                                        DaemonResponse::Error(format!(
                                            "Failed to save keystore: {sanitized}"
                                        ))
                                    }
                                },
                                Err(err) => {
                                    let sanitized = sanitize_for_display(&err.to_string());
                                    DaemonResponse::Error(format!(
                                        "Failed to update password: {sanitized}"
                                    ))
                                }
                            }
                        }
                    }
                    Err(_) => {
                        password_attempts.fetch_add(1, Ordering::SeqCst);
                        DaemonResponse::Error("Invalid current password".to_string())
                    }
                },
                Err(err) => {
                    let sanitized = sanitize_for_display(&err.to_string());
                    DaemonResponse::Error(format!("Failed to load keystore: {sanitized}"))
                }
            };
            current_password.zeroize();
            new_password.zeroize();
            response
        }
        DaemonRequest::RebuildKeystore { new_password } => {
            last_activity.store(now, Ordering::SeqCst);
            let mut new_password = new_password;
            let response = match Keystore::create_from_master_key(&new_password, master_key) {
                Ok((keystore, recovery)) => match keystore.save(paths.keystore_path()) {
                    Ok(()) => DaemonResponse::OkRecoveryCode(recovery),
                    Err(err) => {
                        let sanitized = sanitize_for_display(&err.to_string());
                        DaemonResponse::Error(format!("Failed to save keystore: {sanitized}"))
                    }
                },
                Err(err) => {
                    let sanitized = sanitize_for_display(&err.to_string());
                    DaemonResponse::Error(format!("Failed to rebuild keystore: {sanitized}"))
                }
            };
            new_password.zeroize();
            password_attempts.store(0, Ordering::SeqCst);
            response
        }
        DaemonRequest::GetDashboardStats => {
            last_activity.store(now, Ordering::SeqCst);
            match db.stats() {
                Ok((open, done_today, p1)) => DaemonResponse::OkStats {
                    open,
                    done_today,
                    p1,
                },
                Err(err) => {
                    let sanitized = sanitize_for_display(&err.to_string());
                    DaemonResponse::Error(format!("Failed to fetch stats: {sanitized}"))
                }
            }
        }
        DaemonRequest::ImportItems { items } => {
            last_activity.store(now, Ordering::SeqCst);
            let mut count = 0usize;
            let mut error = None;
            for item in items {
                match db.upsert_item(&item) {
                    Ok(()) => count += 1,
                    Err(err) => {
                        let sanitized = sanitize_for_display(&err.to_string());
                        error = Some(format!("Failed to import item {}: {sanitized}", item.id));
                        break;
                    }
                }
            }
            match error {
                Some(err) => DaemonResponse::Error(err),
                None => DaemonResponse::OkMessage(format!("Imported {count} items")),
            }
        }
        DaemonRequest::ArchiveAll => {
            last_activity.store(now, Ordering::SeqCst);
            match db.archive_all() {
                Ok(count) => DaemonResponse::OkMessage(format!("Archived {count} item(s)")),
                Err(err) => {
                    let sanitized = sanitize_for_display(&err.to_string());
                    DaemonResponse::Error(format!("Failed to archive: {sanitized}"))
                }
            }
        }
        DaemonRequest::Undo { id } => {
            last_activity.store(now, Ordering::SeqCst);
            if let Some(id) = id {
                match db.update_status(id, Status::Open) {
                    Ok(true) => DaemonResponse::OkMessage(format!("Restored {id}")),
                    Ok(false) => DaemonResponse::Error("Item not found".to_string()),
                    Err(err) => {
                        let sanitized = sanitize_for_display(&err.to_string());
                        DaemonResponse::Error(format!("Failed to undo: {sanitized}"))
                    }
                }
            } else {
                match db.undo_last() {
                    Ok(Some(id)) => DaemonResponse::OkMessage(format!("Restored {id}")),
                    Ok(None) => DaemonResponse::OkMessage("No archived items".to_string()),
                    Err(err) => {
                        let sanitized = sanitize_for_display(&err.to_string());
                        DaemonResponse::Error(format!("Failed to undo: {sanitized}"))
                    }
                }
            }
        }
        DaemonRequest::Shutdown => {
            last_activity.store(now, Ordering::SeqCst);
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

#[cfg(unix)]
fn verify_peer_credentials(stream: &UnixStream) -> Result<()> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use nix::unistd::Uid;

    let creds = getsockopt(stream, PeerCredentials)
        .map_err(|e| anyhow::anyhow!("Failed to get peer credentials: {e}"))?;

    let peer_uid = Uid::from_raw(creds.uid());
    let effective_uid = Uid::effective();

    if peer_uid != effective_uid {
        return Err(anyhow::anyhow!(
            "Unauthorized user: expected UID {effective_uid}, got {peer_uid}"
        ));
    }

    Ok(())
}

#[cfg(not(unix))]
fn verify_peer_credentials(_stream: &UnixStream) -> Result<()> {
    Ok(())
}
