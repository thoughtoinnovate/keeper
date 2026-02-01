use crate::ipc::{DaemonRequest, DaemonResponse};
use crate::logger;
use crate::paths::KeeperPaths;
use anyhow::{Result, anyhow};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

const MAX_IPC_MSG_SIZE: usize = 10_485_760; // 10MB

pub fn send_request(paths: &KeeperPaths, req: &DaemonRequest) -> Result<DaemonResponse> {
    logger::debug("Sending IPC request");
    let mut stream = UnixStream::connect(&paths.socket_path).map_err(|err| {
        logger::error(&format!("IPC connect failed: {err}"));
        anyhow!("Daemon is not running")
    })?;
    let payload = serde_json::to_vec(req)?;
    stream.write_all(&payload)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    // Bounded read with size limit
    let mut buf = Vec::with_capacity(8192);
    let mut bytes_read = 0;
    let mut chunk = [0u8; 8192];

    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }

        bytes_read += n;
        if bytes_read > MAX_IPC_MSG_SIZE {
            return Err(anyhow!(
                "IPC message too large (max 10MB, got {} bytes)",
                bytes_read
            ));
        }

        buf.extend_from_slice(&chunk[..n]);
    }

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
