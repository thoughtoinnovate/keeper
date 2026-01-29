use crate::ipc::{DaemonRequest, DaemonResponse};
use crate::logger;
use crate::paths::KeeperPaths;
use anyhow::{Result, anyhow};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

pub fn send_request(paths: &KeeperPaths, req: &DaemonRequest) -> Result<DaemonResponse> {
    logger::debug("Sending IPC request");
    let mut stream = UnixStream::connect(&paths.socket_path).map_err(|err| {
        logger::error(&format!("IPC connect failed: {err}"));
        anyhow!("Daemon is not running")
    })?;
    let payload = serde_json::to_vec(req)?;
    stream.write_all(&payload)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let resp: DaemonResponse = serde_json::from_slice(&buf)?;
    logger::debug("Received IPC response");
    Ok(resp)
}

pub fn daemon_running(paths: &KeeperPaths) -> bool {
    UnixStream::connect(&paths.socket_path).is_ok()
}

pub fn wait_for_daemon(paths: &KeeperPaths, timeout_ms: u64) -> bool {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {
        if daemon_running(paths) {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}
