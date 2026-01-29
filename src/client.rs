use crate::ipc::{DaemonRequest, DaemonResponse};
use crate::paths::KeeperPaths;
use anyhow::{anyhow, Result};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

pub fn send_request(paths: &KeeperPaths, req: &DaemonRequest) -> Result<DaemonResponse> {
    let mut stream = UnixStream::connect(&paths.socket_path)
        .map_err(|_| anyhow!("Daemon is not running"))?;
    let payload = serde_json::to_vec(req)?;
    stream.write_all(&payload)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let resp: DaemonResponse = serde_json::from_slice(&buf)?;
    Ok(resp)
}

pub fn daemon_running(paths: &KeeperPaths) -> bool {
    UnixStream::connect(&paths.socket_path).is_ok()
}
