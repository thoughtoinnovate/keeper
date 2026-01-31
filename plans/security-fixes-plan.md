# Security Fixes Plan - Keeper

**Generated**: 2026-01-31  
**Security Review Date**: 2026-01-31  
**Target Architecture Grade**: A (Currently: B-)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Task Status Tracking](#task-status-tracking)
3. [Critical Issues (P0)](#critical-issues-p0)
4. [High Priority Issues (P1)](#high-priority-issues-p1)
5. [Medium Priority Issues (P2)](#medium-priority-issues-p2)
6. [Low Priority Issues (P3)](#low-priority-issues-p3)
7. [Implementation Phases](#implementation-phases)
8. [Dependency Graph](#dependency-graph)
9. [Testing & Verification](#testing--verification)
10. [Rollback Procedures](#rollback-procedures)
11. [Security Metrics & Monitoring](#security-metrics--monitoring)
12. [Compliance Mapping](#compliance-mapping)
13. [Appendices](#appendices)

---

## Executive Summary

| Metric | Value |
|--------|--------|
| **Total Issues Identified** | 31 |
| **Critical Severity** | 6 |
| **High Severity** | 14 |
| **Medium Severity** | 7 |
| **Low Severity** | 4 |
| **Files Requiring Changes** | 15 |
| **New Dependencies** | 7 |
| **Estimated Effort** | 8-10 weeks |
| **Target Architecture Grade** | A |

### Critical Vulnerability Summary

| Issue | Attack Vector | Impact | Current Status |
|-------|---------------|---------|----------------|
| mlockall() silent failure | Memory dump via swap | All secrets exposed | Daemon continues |
| Unbounded IPC messages | Memory exhaustion DDoS | OOM, system freeze | No limits |
| MCP plaintext passwords | Process inspection | Passwords in /proc | stdin transmission |
| Self-update no signatures | Supply chain attack | Malicious binary | Only SHA256 |
| Terminal echo not restored | User confusion/data loss | Terminal unusable | Echo lost |
| Keystore salts not zeroized | Swap leaks | Cryptographic material exposed | Not zeroized |

---

## Task Status Tracking

| ID | Issue | Severity | Status | Blocked By | Priority | Dependencies | File | CVSS | CWE |
|----|-------|----------|--------|------------|----------|---------------|------|-------|-----|
| **CRITICAL (P0)** |
| SWAP-001 | mlockall() silent failure | Critical | Pending | - | P0 | None | src/daemon.rs:27-30 | 7.5 | CWE-200 |
| SWAP-002 | IPC client message size unbounded | Critical | Pending | - | P0 | None | src/client.rs:21 | 7.5 | CWE-400 |
| SWAP-003 | IPC daemon message size unbounded | Critical | Pending | - | P0 | None | src/daemon.rs:154 | 7.8 | CWE-400 |
| SWAP-004 | MCP plaintext passwords via stdin | Critical | Pending | SWAP-001 | P0 | SWAP-001 | mcp/keeper-mcp/src/main.rs:516-527 | 8.1 | CWE-312 |
| SWAP-005 | Self-update no signature verification | Critical | Pending | - | P0 | None | src/self_update.rs:177-202 | 7.5 | CWE-494 |
| **HIGH (P1)** |
| SWAP-006 | Terminal echo not restored on error | High | Pending | SWAP-001 | P1 | SWAP-001 | src/prompt.rs:60-70 | 5.3 | CWE-224 |
| SWAP-007 | Keystore salts not zeroized before encoding | High | Pending | SWAP-001 | P1 | SWAP-001 | src/keystore.rs:80-86 | 5.3 | CWE-226 |
| SWAP-008 | Database key hex encoding leaks | High | Pending | SWAP-002 | P1 | SWAP-002 | src/daemon.rs:60 | 5.3 | CWE-226 |
| SWAP-009 | IPC master key transmission creates copies | High | Pending | - | P1 | None | src/session.rs:48,67-68 | 5.3 | CWE-226 |
| SWAP-010 | JSON serialization leaks passwords | High | Pending | SWAP-001 | P1 | SWAP-001 | src/ipc.rs | 5.3 | CWE-312 |
| SWAP-011 | Regex sanitization creates password copies | High | Pending | - | P1 | None | src/sanitize.rs:4-11 | 5.3 | CWE-312 |
| SWAP-012 | Base64 intermediate copies everywhere | High | Pending | SWAP-001 | P1 | SWAP-001 | Multiple | 5.3 | CWE-226 |
| SWAP-013 | format!() copies passwords during IPC | High | Pending | SWAP-009 | P1 | SWAP-009 | src/session.rs:67 | 5.3 | CWE-226 |
| DDOS-001 | No request rate limiting | High | Pending | SWAP-003 | P1 | SWAP-003 | src/daemon.rs:86-91 | 7.5 | CWE-307 |
| DDOS-002 | Password rate limit bypassable | High | Pending | - | P1 | None | src/daemon.rs:172-185 | 7.5 | CWE-307 |
| DDOS-003 | No per-connection memory limits | High | Pending | SWAP-003 | P1 | SWAP-003 | src/daemon.rs:154 | 7.5 | CWE-400 |
| DDOS-004 | No connection timeout (slowloris) | High | Pending | SWAP-003 | P1 | SWAP-003 | src/daemon.rs:93 | 7.5 | CWE-400 |
| DATA-001 | Unencrypted export contains sensitive data | High | Pending | - | P1 | None | src/export.rs:45-55 | 7.5 | CWE-200 |
| DATA-002 | Backup no integrity verification | High | Pending | - | P1 | None | src/backup.rs:23-46 | 7.5 | CWE-345 |
| IPC-001 | Error messages not sanitized | High | Pending | - | P1 | None | src/daemon.rs:119,160,189 | 5.5 | CWE-209 |
| **MEDIUM (P2)** |
| AUTH-001 | No socket channel binding | Medium | Pending | - | P2 | None | src/daemon.rs:35-58 | 5.3 | CWE-287 |
| AUTH-002 | Password blocklist too small | Medium | Pending | - | P2 | None | src/security.rs:63-66 | 5.3 | CWE-521 |
| AUTH-003 | No key separation between operations | Medium | Pending | - | P2 | None | src/security.rs | 5.3 | CWE-310 |
| MISC-003 | Constant-time compare length leak | Medium | Pending | - | P2 | None | src/security/memory.rs:149-160 | 5.3 | CWE-208 |
| UX-001 | Recovery code displayed plaintext | Medium | Pending | - | P2 | None | src/main.rs:84, 154 | 5.3 | CWE-532 |
| UX-002 | TUI history plaintext | Medium | Pending | - | P2 | None | src/tui.rs:81-85 | 5.3 | CWE-312 |
| DATA-003 | Import no data validation | Medium | Pending | - | P2 | None | src/transfer.rs:110-137 | 5.3 | CWE-20 |
| DATA-004 | Export password not validated | Medium | Pending | - | P2 | None | src/transfer.rs:139-146 | 5.3 | CWE-521 |
| **LOW (P3)** |
| DATA-005 | Backup no secure delete | Low | Pending | DATA-002 | P3 | DATA-002 | src/backup.rs:98-120 | 3.7 | CWE-226 |
| IPC-002 | Logger error_raw bypasses sanitization | Low | Pending | - | P3 | None | src/logger.rs:26-30 | 3.7 | CWE-117 |
| MCP-001 | Deprecated password support still present | Low | Pending | SWAP-001 | P3 | SWAP-001 | mcp/keeper-mcp/src/main.rs:29-33 | 3.7 | CWE-477 |
| MISC-001 | No core dump limits | Low | Pending | SWAP-001 | P3 | SWAP-001 | src/daemon.rs | 3.7 | CWE-200 |
| UPDATE-001 | Temp dir names predictable | Low | Pending | - | P3 | None | src/self_update.rs:318-324 | 3.7 | CWE-377 |
| UPDATE-002 | Self-update tag injection possible | Low | Pending | - | P3 | None | src/self_update.rs:23-32 | 3.7 | CWE-79 |
| VALID-001 | Workspace path traversal possible | Low | Pending | - | P3 | None | src/config.rs:54-71 | 3.7 | CWE-22 |
| VALID-002 | Config workspace validation insufficient | Low | Pending | - | P3 | None | src/config.rs:54-71 | 3.7 | CWE-20 |

---

## Critical Issues (P0)

### SWAP-001: mlockall() Failure is Silent

**Severity**: Critical | **CVSS**: 7.5 (High) | **CWE**: CWE-200  
**File**: `src/daemon.rs:27-30` | **Status**: Pending | **Priority**: P0

#### Vulnerability Description

The daemon calls `mlockall(MCL_CURRENT | MCL_FUTURE)` to prevent memory from being swapped to disk. However, if this call fails (e.g., due to `ENOMEM` or `EPERM`), the daemon continues running with a warning log message. This means all cryptographic material (master key, passwords, etc.) can be swapped to disk and recovered by an attacker with disk access.

#### Attack Scenario

```bash
# Attacker forces mlockall failure by limiting locked memory
ulimit -l 64  # Limit locked memory to 64KB
keeper start

# mlockall() fails with ENOMEM, but daemon continues running

# Attacker recovers secrets from swap
strings /swapfile | grep -i "password\|key\|secret"
```

#### Current Code

```rust
// src/daemon.rs:27-30 (current)
#[cfg(unix)]
{
    use libc::{mlockall, MCL_CURRENT, MCL_FUTURE};
    unsafe {
        if mlockall(MCL_CURRENT | MCL_FUTURE) != 0 {
            logger::error("Failed to lock memory - keys may be swapped to disk");
            // Daemon continues running!
        }
    }
}
```

#### Remediation

```rust
// src/daemon.rs:27-30 (proposed)
#[cfg(unix)]
{
    use libc::{mlockall, MCL_CURRENT, MCL_FUTURE};
    unsafe {
        if mlockall(MCL_CURRENT | MCL_FUTURE) != 0 {
            return Err(anyhow::anyhow!(
                "CRITICAL: Failed to lock memory. Keys would be swapped to disk. \
                 Increase ulimit -l or run with CAP_IPC_LOCK permission. \
                 Exiting for security."
            ));
        }
    }
}
```

#### Testing

```rust
#[test]
fn test_mlockall_failure_exits() {
    let temp = tempdir().unwrap();
    // Test with limited locked memory (simulate failure)
    // This should fail with CRITICAL error
}
```

#### Rollback Procedure

If this change causes false positives (e.g., users with legitimate ulimit settings):

1. **Immediate**: Check system ulimit: `ulimit -l`
2. **Temporary**: Modify daemon to warn-only mode via environment variable `KEEPER_ALLOW_SWAP=1`
3. **Permanent**: Increase system locked memory limit: `ulimit -l unlimited` (requires admin)

#### Commit Message

```
fix(security): Exit daemon on mlockall() failure

Previously, mlockall() failure only logged a warning but daemon
continued running with all secrets swappable to disk.

Now daemon exits with CRITICAL error if memory locking fails, forcing
users to either:
- Increase ulimit -l (requires admin)
- Run with CAP_IPC_LOCK capability

Resolves: SWAP-001
CVSS: 7.5 (High)
CWE: CWE-200
```

---

### SWAP-002: IPC Message Size Unbounded (Client)

**Severity**: Critical | **CVSS**: 7.5 (High) | **CWE**: CWE-400  
**File**: `src/client.rs:21` | **Status**: Pending | **Priority**: P0

#### Vulnerability Description

The client reads IPC messages without any size limit using `read_to_end()`. An attacker (or malicious daemon) can send gigabytes of data, causing the client to allocate all available RAM and potentially triggering OOM kill.

#### Attack Scenario

```python
# Attacker script
import socket
large_msg = b'{"CreateNote":{"content":"' + b'A' * 1_000_000_000 + b'"}}'
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/home/user/.keeper/keeper.sock")
s.send(large_msg)
# Client crashes due to OOM
```

#### Current Code

```rust
// src/client.rs:20-22 (current)
let mut buf = Vec::new();
stream.read_to_end(&mut buf)?;  // Unbounded read!
let resp: DaemonResponse = serde_json::from_slice(&buf)?;
```

#### Remediation

```rust
// Add constant at top of src/client.rs
const MAX_IPC_MSG_SIZE: usize = 10_485_760; // 10MB

// src/client.rs:20-35 (proposed)
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
        if n == 0 { break; }
        
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
```

#### Rollback Procedure

If 10MB limit is too restrictive:

1. **Immediate**: Add environment variable `KEEPER_MAX_IPC_SIZE` (e.g., 50MB)
2. **Configuration**: Add to `~/.keeperrc` or `~/.config/keeper/config.toml`

#### Commit Message

```
fix(security): Add 10MB IPC message size limit (client)

Previously, client read IPC messages with read_to_end(), allowing
unbounded allocation. Attacker could send gigabytes causing OOM.

Now client enforces 10MB message size limit with bounded read loop.
Prevents memory exhaustion DDoS via oversized IPC messages.

Resolves: SWAP-002
CVSS: 7.5 (High)
CWE: CWE-400
```

---

### SWAP-003: IPC Message Size Unbounded (Daemon)

**Severity**: Critical | **CVSS**: 7.8 (High) | **CWE**: CWE-400  
**File**: `src/daemon.rs:154` | **Status**: Pending | **Priority**: P0

#### Vulnerability Description

Same as SWAP-002 but on daemon side. With 50 concurrent connections allowed, each sending 1GB+ could cause 50GB+ memory allocation, triggering system-wide OOM.

#### Current Code

```rust
// src/daemon.rs:154-155 (current)
fn handle_connection(...) -> Result<()> {
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;  // Unbounded!
}
```

#### Remediation

Same bounded read pattern as SWAP-002, implemented in `src/daemon.rs:154`.

#### Rollback Procedure

Same as SWAP-002 (configurable limit via env var).

#### Commit Message

```
fix(security): Add 10MB IPC message size limit (daemon)

Daemon side fix for unbounded IPC reads. Prevents memory
exhaustion with 50 concurrent connections sending 1GB+ each.

Resolves: SWAP-003
CVSS: 7.8 (High)
CWE: CWE-400
```

---

### SWAP-004: MCP Plaintext Password via Stdin

**Severity**: Critical | **CVSS**: 8.1 (High) | **CWE**: CWE-312  
**File**: `mcp/keeper-mcp/src/main.rs:516-527` | **Status**: Pending | **Priority**: P0  
**Dependencies**: SWAP-001

#### Vulnerability Description

MCP server passes passwords via stdin to keeper daemon. These passwords are visible in `/proc/<pid>/cmdline` and `/proc/<pid>/fd/0`. Any process with read access to /proc can harvest passwords.

#### Current Code

```rust
// mcp/keeper-mcp/src/main.rs:516-527 (current)
fn run_keeper_start(config: &Config, vault: Option<&Value>) -> Result<String, RpcError<'static>> {
    let password = config
        .password
        .as_ref()
        .ok_or(err("Auto-start requires password source"))?;
    let stdin = if keystore_exists(config, vault) {
        format!("{password}\n")  // Password in plaintext!
    } else {
        format!("{password}\n{password}\n")  // Two copies!
    };
    run_keeper(config, &["start"], Some(&stdin), vault)
}
```

#### Remediation

**Option 1: Remove password env var support entirely (Recommended)**

Remove `config.password` field and require interactive prompting only.

**Option 2: Use SCM_RIGHTS for Unix socket fd passing**

```rust
use std::os::unix::net::{UnixStream, UnixCredentials};
use std::os::unix::io::{AsRawFd, RawFd};

pub fn start_daemon_with_fd(
    paths: &KeeperPaths, 
    master_key_fd: RawFd, 
    debug: bool
) -> Result<u32> {
    // Read master key from fd instead of stdin
}
```

#### Commit Message

```
fix(security): Remove MCP password environment variable support

Passwords passed via stdin are visible in /proc/<pid>/cmdline
and fd, allowing any process to harvest credentials.

Removed KEEPER_PASSWORD support entirely. Users must provide
passwords interactively or integrate with secret managers.

Resolves: SWAP-004
CVSS: 8.1 (High)
CWE: CWE-312
```

---

### SWAP-005: Self-Update No Signature Verification

**Severity**: Critical | **CVSS**: 7.5 (High) | **CWE**: CWE-494  
**File**: `src/self_update.rs:177-202` | **Status**: Pending | **Priority**: P0

#### Vulnerability Description

Self-update mechanism verifies SHA256 checksums but does not verify cryptographic signatures. An attacker compromising the GitHub release could provide malicious binaries with matching SHA256 checksums.

#### Current Code

```rust
// src/self_update.rs:177-202 (current)
fn verify_checksum(asset_path: &Path, checksum_path: &Path) -> Result<()> {
    let checksum_contents = fs::read_to_string(checksum_path)?;
    let expected = checksum_contents.split_whitespace().next()?
        .trim().to_lowercase();

    let bytes = fs::read(asset_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    // No signature verification!
    Ok(())
}
```

#### Remediation

```toml
# Add to Cargo.toml
[dependencies]
minisign = "0.7.3"
base64 = "0.22"
```

```rust
// src/self_update.rs
use minisign::{verify, PublicKey};
use base64::{engine::general_purpose::STANDARD, Engine as _};

const PUBKEY: &str = "RWS5IG+x/4y5P9/2mY0d5JrQ1JZ8C5G...";

fn verify_signature(asset_path: &Path, sig_path: &Path) -> Result<()> {
    let pubkey = PublicKey::from_base64(PUBKEY)?;
    let sig_data = fs::read_to_string(sig_path)?;
    let signature = minisign::Signature::from_string(&sig_data)?;
    let data = fs::read(asset_path)?;
    
    verify(&pubkey, &data, &signature)
        .map_err(|_| anyhow!("Signature verification failed"))?;
    Ok(())
}

fn verify_checksum_and_signature(
    asset_path: &Path,
    checksum_path: &Path,
    sig_path: &Path
) -> Result<()> {
    verify_checksum(asset_path, checksum_path)?;
    verify_signature(asset_path, sig_path)?;
    Ok(())
}
```

#### Commit Message

```
feat(security): Add Ed25519 signature verification to self-update

Previously, self-update only verified SHA256 checksums which provide
integrity but not authenticity. Compromised GitHub release could
provide malicious binaries with valid checksums.

Now verifies minisign Ed25519 signatures using embedded public key.
Prevents supply chain attacks via tampered releases.

Resolves: SWAP-005
CVSS: 7.5 (High)
CWE: CWE-494
```

---

## High Priority Issues (P1)


### SWAP-006: Terminal Echo Not Restored on Error

**Severity**: High | **CVSS**: 5.3 | **CWE**: CWE-224  
**File**: `src/prompt.rs:60-70` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-001

#### Vulnerability Description

If `read_line()` fails or panics, terminal echo remains disabled, causing user confusion and potential data loss.

#### Current Code

```rust
// src/prompt.rs:60-70 (current)
if is_tty {
    set_terminal_echo(false);  // Echo disabled
}

let mut secret = String::new();
stdin.read_line(&mut secret)?;  // If this fails...

if is_tty {
    set_terminal_echo(true);  // This never runs!
}
```

#### Remediation

```rust
// Add dependency: scopeguard = "1.2.0"
use scopeguard::guard;

pub(crate) fn prompt_secret(prompt: &str) -> Result<SecurePassword> {
    print!("{prompt}");
    io::stdout().flush()?;

    let stdin = io::stdin();
    let is_tty = stdin.is_terminal();

    let _echo_guard = guard(is_tty, |was_tty| {
        if was_tty {
            set_terminal_echo(true);
        }
    });

    if is_tty {
        set_terminal_echo(false);
    }

    let mut secret = String::new();
    stdin.read_line(&mut secret)?;
    
    Ok(secure_password_from_str(&secret.trim().to_string()))
}
```

#### Commit Message

```
fix(security): Ensure terminal echo restored on error with scopeguard

Previously, if read_line() failed, terminal echo remained disabled
causing user confusion. Now uses scopeguard to guarantee echo
restoration even on panic or error.

Resolves: SWAP-006
CVSS: 5.3 (Medium)
CWE: CWE-224
```

---

### SWAP-007: Keystore Salts Not Zeroized Before Encoding

**Severity**: High | **CVSS**: 5.3 | **CWE**: CWE-226  
**File**: `src/keystore.rs:80-86` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-001

#### Vulnerability Description

Salts and nonces (cryptographic material) not zeroized after base64 encoding, leaving copies in memory that get swapped.

#### Current Code

```rust
// src/keystore.rs:80-86 (current)
let store = Keystore {
    version: VERSION,
    salt_password: STANDARD_NO_PAD.encode(salt_password),
    salt_recovery: STANDARD_NO_PAD.encode(salt_recovery),
    nonce_password: STANDARD_NO_PAD.encode(nonce_password),
    nonce_recovery: STANDARD_NO_PAD.encode(nonce_recovery),
    wrapped_master_password: STANDARD_NO_PAD.encode(&wrapped_master_password),
    wrapped_master_recovery: STANDARD_NO_PAD.encode(&wrapped_master_recovery),
};

wrapped_master_password.zeroize();
wrapped_master_recovery.zeroize();  // Only these are zeroized!
```

#### Remediation

```rust
// Zeroize ALL sensitive buffers before encoding
let mut salt_password = [0u8; SALT_LEN];
// ... fill with random data ...

let mut wrapped_master_password = wrap_master_key(...)?;
let mut wrapped_master_recovery = wrap_master_key(...)?;

// Zeroize BEFORE encoding
salt_password.zeroize();
salt_recovery.zeroize();
nonce_password.zeroize();
nonce_recovery.zeroize();

let store = Keystore {
    version: VERSION,
    // Encode zeroized copies
    salt_password: STANDARD_NO_PAD.encode(salt_password),
    // ...
};

wrapped_master_password.zeroize();
wrapped_master_recovery.zeroize();
```

#### Commit Message

```
fix(security): Zeroize keystore salts before base64 encoding

Previously, salts and nonces were not zeroized before encoding,
leaving cryptographic material in memory that could be swapped.
Now all sensitive buffers are zeroized before encoding to prevent
swap memory leaks.

Resolves: SWAP-007
CVSS: 5.3 (Medium)
CWE: CWE-226
```

---

### SWAP-008: Database Key Hex Encoding Leaks

**Severity**: High | **CVSS**: 5.3 | **CWE**: CWE-226  
**File**: `src/daemon.rs:60, src/security.rs:34-36` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-002

#### Vulnerability Description

Database key derived from master key via hex encoding creates 64-byte copy of 32-byte key.

#### Current Code

```rust
// src/security.rs:34-36
pub fn derive_db_key_hex(master_key: &[u8]) -> String {
    hex_encode(master_key)  // Creates 64-byte string
}

// src/daemon.rs:60
let mut db_key = security::derive_db_key_hex(&master_key);
let db = Db::open(&paths.db_path, &db_key)?;
db_key.zeroize();
```

#### Remediation

```rust
// src/db.rs:54
pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self> {
    let conn = Connection::open(path)?;
    let key_hex = hex::encode(key);
    conn.pragma_update(None, "key", &key_hex)?;
    key_hex.zeroize();  // Immediately zeroize
    // ...
}
```

#### Commit Message

```
fix(security): Pass database key as raw bytes instead of hex

Previously, database key was hex-encoded creating a 64-byte copy
of the 32-byte master key. Now passes raw bytes to SQLCipher and
immediately zeroizes the hex string to reduce memory footprint.

Resolves: SWAP-008
CVSS: 5.3 (Medium)
CWE: CWE-226
```

---

### SWAP-009: IPC Master Key Transmission Creates Copies

**Severity**: High | **CVSS**: 5.3 | **CWE**: CWE-226  
**File**: `src/session.rs:48,67-68` | **Status**: Pending | **Priority**: P1

#### Vulnerability Description

Multiple intermediate copies created during IPC transmission.

#### Current Code

```rust
// src/session.rs:48
let payload = STANDARD_NO_PAD.encode(master_key);  // Copy 1

// src/session.rs:67-68
stdin.write_all(format!("{payload}\n").as_bytes())?;  // Copies 2, 3
```

#### Remediation

```rust
pub fn start_daemon(paths: &KeeperPaths, master_key: &[u8], debug: bool) -> Result<u32> {
    let mut payload_buf = STANDARD_NO_PAD.encode(master_key);
    payload_buf.push(b'\n');
    
    let mut child = cmd
        .arg("daemon")
        .stdin(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&payload_buf)?;  // Direct write
        payload_buf.zeroize();
    }
    Ok(child.id())
}
```

#### Commit Message

```
fix(security): Reduce IPC key transmission copies

Previously, master key transmission created 3 intermediate copies
via base64 encoding and format!(). Now uses direct buffer write
with immediate zeroization to minimize memory exposure.

Resolves: SWAP-009
CVSS: 5.3 (Medium)
CWE: CWE-226
```

---


### SWAP-010: JSON Serialization Leaks Passwords

**Severity**: High | **CVSS**: 5.3 | **CWE**: CWE-312  
**File**: `src/ipc.rs` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-001

#### Vulnerability Description

Passwords and other secrets are serialized as plain text in JSON IPC messages, creating multiple copies in memory that may be swapped.

#### Current Code

```rust
// src/ipc.rs (current)
#[derive(Serialize, Deserialize, Clone)]
pub struct CreateNote {
    pub title: String,
    pub content: String,
    pub password: String,  // Plain text password!
}
```

#### Remediation

```rust
// src/ipc.rs (proposed)
use secrecy::{ExposeSecret, SecretBox};

#[derive(Serialize, Deserialize, Clone)]
pub struct CreateNote {
    pub title: String,
    pub content: String,
    #[serde(skip)]  // Don't serialize password
    pub password: SecretBox<String>,
}

// Or use a custom wrapper that clears on drop
#[derive(Clone)]
pub struct SecureString(Vec<u8>);

impl Drop for SecureString {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}
```

#### Rollback Procedure

If serialization issues arise, temporarily revert to String with explicit zeroization in handlers.

#### Commit Message

```
fix(security): Use SecretString for IPC password fields

Previously, passwords were serialized as plain text in JSON IPC
messages, creating multiple copies. Now uses secrecy crate's
SecretBox which prevents accidental serialization and clears on drop.

Resolves: SWAP-010
CVSS: 5.3 (Medium)
CWE: CWE-312
```

---

### SWAP-011: Regex Sanitization Creates Password Copies

**Severity**: High | **CVSS**: 5.3 | **CWE**: CWE-312  
**File**: `src/sanitize.rs:4-11` | **Status**: Pending | **Priority**: P1

#### Vulnerability Description

Regex-based password sanitization creates temporary copies of passwords in memory for pattern matching.

#### Current Code

```rust
// src/sanitize.rs:4-11 (current)
use regex::Regex;

pub fn sanitize_for_display(input: &str) -> String {
    let password_regex = Regex::new(r"(password|pass|pwd)\s*[:=]\s*(\S+)").unwrap();
    // Creates copies during regex matching!
    password_regex.replace_all(input, "$1: [REDACTED]").to_string()
}
```

#### Remediation

```rust
// src/sanitize.rs:4-20 (proposed)
// Remove regex dependency for sanitization
pub fn sanitize_for_display(input: &str) -> String {
    // Use simple string search without regex
    let mut result = String::with_capacity(input.len());
    let lower = input.to_lowercase();
    
    // Manual parsing to avoid regex copies
    let keywords = ["password:", "pass:", "pwd:", "password=", "pass=", "pwd="];
    let mut i = 0;
    
    while i < input.len() {
        let mut found = false;
        for kw in &keywords {
            if lower[i..].starts_with(kw) {
                result.push_str(&input[..i]);
                result.push_str(&input[i..i+kw.len()]);
                result.push_str(" [REDACTED]");
                // Skip to next whitespace or end
                i += kw.len();
                while i < input.len() && !input[i..].starts_with(' ') {
                    i += 1;
                }
                found = true;
                break;
            }
        }
        if !found {
            i += 1;
        }
    }
    
    result
}
```

#### Commit Message

```
fix(security): Remove regex-based password sanitization

Previously, regex sanitization created temporary copies of passwords
in memory. Now uses manual string parsing to avoid regex overhead
and memory copies.

Resolves: SWAP-011
CVSS: 5.3 (Medium)
CWE: CWE-312
```

---

### SWAP-012: Base64 Intermediate Copies Everywhere

**Severity**: High | **CVSS**: 5.3 | **CWE**: CWE-226  
**File**: `Multiple` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-001

#### Vulnerability Description

Multiple intermediate base64 buffers created throughout the codebase during encoding/decoding operations.

#### Current Code

```rust
// Multiple locations
// 1. src/keystore.rs:80 - Encodes salts
// 2. src/session.rs:48 - Encodes master key
// 3. src/backup.rs:34 - Encodes encrypted data
// Each creates temporary String allocations
```

#### Remediation

```rust
// Use in-place base64 encoding where possible
// Add utility function to src/utils.rs:

use base64::engine::{general_purpose::STANDARD_NO_PAD, Engine};

/// Encode to pre-allocated buffer, zeroize after use
pub fn encode_to_buffer(input: &[u8], output: &mut Vec<u8>) {
    output.clear();
    output.reserve(STANDARD_NO_PAD.encoded_len(input.len()));
    STANDARD_NO_PAD.encode_string(input, output);
}

// Usage in keystore:
let mut encoded = Vec::new();
encode_to_buffer(&salt_password, &mut encoded);
let store = Keystore {
    salt_password: String::from_utf8_lossy(&encoded).to_string(),
    // ...
};
encoded.zeroize();  // Zeroize immediately
```

#### Rollback Procedure

If performance degrades, keep String allocation but add immediate zeroization after use.

#### Commit Message

```
fix(security): Minimize base64 encoding intermediate copies

Refactored base64 operations to use pre-allocated buffers with
immediate zeroization. Reduces memory footprint of cryptographic
operations.

Resolves: SWAP-012
CVSS: 5.3 (Medium)
CWE: CWE-226
```

---

### SWAP-013: format!() Copies Passwords During IPC

**Severity**: High | **CVSS**: 5.3 | **CWE**: CWE-226  
**File**: `src/session.rs:67` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-009

#### Vulnerability Description

format!() macro creates copies when constructing stdin payloads containing passwords or master keys.

#### Current Code

```rust
// src/session.rs:67 (current)
stdin.write_all(format!("{payload}\n").as_bytes())?;  // format! creates copy
```

#### Remediation

```rust
// src/session.rs:65-75 (proposed)
// Avoid format!() for sensitive data
let mut payload_buf = payload.into_bytes();  // Already encoded
payload_buf.push(b'\n');
stdin.write_all(&payload_buf)?;
payload_buf.zeroize();
```

#### Commit Message

```
fix(security): Remove format!() usage for IPC passwords

format!() macro creates temporary copies when formatting sensitive
data. Now appends newline directly to byte buffer to avoid copies.

Resolves: SWAP-013
CVSS: 5.3 (Medium)
CWE: CWE-226
```

---

### DDOS-001: No Request Rate Limiting

**Severity**: High | **CVSS**: 7.5 | **CWE**: CWE-307  
**File**: `src/daemon.rs:86-91` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-003

#### Vulnerability Description

No rate limiting allows unlimited password attempts, enabling brute force attacks.

#### Current Code

```rust
// src/daemon.rs:86-91 (current)
while let Some((mut stream, addr)) = listener.accept().await? {
    tokio::spawn(async move {
        if let Err(e) = handle_connection(&mut stream, addr).await {
            logger::error(&format!("Connection error: {:?}", e));
        }
    });
    // No rate limiting!
}
```

#### Remediation

```rust
// Add to Cargo.toml:
// governor = "0.6.3"

// src/daemon.rs:86-95 (proposed)
use governor::{
    clock::DefaultClock,
    state::keyed::DashMapStateStore,
    Quota, RateLimiter,
};
use std::num::NonZeroU32;

// Allow 5 attempts per minute per IP
let rate_limiter = Arc::new(RateLimiter::dashmap(
    Quota::per_minute(NonZeroU32::new(5).unwrap())
));

while let Some((stream, addr)) = listener.accept().await? {
    let limiter = Arc::clone(&rate_limiter);
    tokio::spawn(async move {
        match limiter.check_key(&addr.ip()) {
            Ok(()) => {
                if let Err(e) = handle_connection(stream, addr).await {
                    logger::error(&format!("Connection error: {:?}", e));
                }
            }
            Err(_) => {
                logger::warn(&format!("Rate limit exceeded for {}", addr.ip()));
                // Send rate limit response
            }
        }
    });
}
```

#### Rollback Procedure

If legitimate users are affected, temporarily increase quota or add IP whitelist.

#### Commit Message

```
feat(security): Add request rate limiting to daemon

Implements per-IP rate limiting (5 requests/minute) to prevent
brute force attacks. Uses governor crate for efficient rate limiting.

Resolves: DDOS-001
CVSS: 7.5 (High)
CWE: CWE-307
```

---

### DDOS-002: Password Rate Limit Bypassable

**Severity**: High | **CVSS**: 7.5 | **CWE**: CWE-307  
**File**: `src/daemon.rs:172-185` | **Status**: Pending | **Priority**: P1

#### Vulnerability Description

Rate limiting is only applied to successful connections, not failed password attempts.

#### Current Code

```rust
// src/daemon.rs:172-185 (current)
match authenticate(&req.password) {
    Ok(()) => {
        // Process request
    }
    Err(_) => {
        // Error returned but no rate limit tracking!
        return Err(anyhow!("Authentication failed"));
    }
}
```

#### Remediation

```rust
// src/daemon.rs:172-190 (proposed)
// Track failed auth attempts per IP
use std::sync::atomic::{AtomicU32, Ordering};

static FAILED_ATTEMPTS: DashMap<IpAddr, AtomicU32> = DashMap::new();

match authenticate(&req.password) {
    Ok(()) => {
        FAILED_ATTEMPTS.remove(&addr.ip());  // Reset on success
        // Process request
    }
    Err(_) => {
        let count = FAILED_ATTEMPTS
            .entry(addr.ip())
            .or_insert(AtomicU32::new(0))
            .fetch_add(1, Ordering::SeqCst);
        
        if count >= 5 {
            // Exponential backoff: sleep 2^count seconds
            let delay = std::cmp::min(2u64.pow(count), 300);  // Max 5 min
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }
        
        return Err(anyhow!("Authentication failed"));
    }
}
```

#### Commit Message

```
feat(security): Track failed authentication attempts per IP

Implements exponential backoff for failed password attempts.
After 5 failures, delays increase exponentially up to 5 minutes.
Prevents brute force attacks even with distributed attempts.

Resolves: DDOS-002
CVSS: 7.5 (High)
CWE: CWE-307
```

---

### DDOS-003: No Per-Connection Memory Limits

**Severity**: High | **CVSS**: 7.5 | **CWE**: CWE-400  
**File**: `src/daemon.rs:154` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-003

#### Vulnerability Description

Each connection can allocate unlimited memory, allowing a single malicious client to exhaust daemon resources.

#### Current Code

```rust
// src/daemon.rs:154 (current)
fn handle_connection(stream: &mut UnixStream) -> Result<()> {
    // No memory limits enforced
}
```

#### Remediation

```rust
// src/daemon.rs:154-180 (proposed)
const MAX_PER_CONN_MEMORY: usize = 50_000_000;  // 50MB per connection

async fn handle_connection(
    stream: UnixStream, 
    addr: SocketAddr
) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(8192);
    let mut total_allocated = 0usize;
    
    loop {
        let bytes_read = stream.read_buf(&mut buffer).await?;
        total_allocated += bytes_read;
        
        if total_allocated > MAX_PER_CONN_MEMORY {
            logger::warn(&format!(
                "Connection {} exceeded memory limit ({} bytes)",
                addr, total_allocated
            ));
            return Err(anyhow!("Memory limit exceeded"));
        }
        
        // Process message...
    }
}
```

#### Rollback Procedure

If legitimate large messages are blocked, increase limit via env var.

#### Commit Message

```
feat(security): Add per-connection memory limits

Enforces 50MB memory limit per IPC connection to prevent single
client from exhausting daemon memory. Memory tracking during
buffer operations.

Resolves: DDOS-003
CVSS: 7.5 (High)
CWE: CWE-400
```

---

### DDOS-004: No Connection Timeout (Slowloris)

**Severity**: High | **CVSS**: 7.5 | **CWE**: CWE-400  
**File**: `src/daemon.rs:93` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-003

#### Vulnerability Description

No connection timeout allows slowloris attacks where attacker sends data slowly to hold connections open indefinitely.

#### Current Code

```rust
// src/daemon.rs:93 (current)
// No timeout on read operations
let bytes_read = stream.read(&mut buf).await?;
```

#### Remediation

```rust
// src/daemon.rs:93-95 (proposed)
use tokio::time::{timeout, Duration};

const CONN_TIMEOUT: Duration = Duration::from_secs(30);

match timeout(CONN_TIMEOUT, stream.read(&mut buf)).await {
    Ok(Ok(bytes_read)) => {
        // Process data
    }
    Ok(Err(e)) => return Err(e.into()),
    Err(_) => {
        logger::warn("Connection timeout - possible slowloris attack");
        return Err(anyhow!("Connection timeout"));
    }
}
```

#### Commit Message

```
feat(security): Add connection timeout to prevent slowloris

Implements 30-second timeout on all connection operations.
Prevents slowloris attacks that hold connections open to exhaust
connection pool.

Resolves: DDOS-004
CVSS: 7.5 (High)
CWE: CWE-400
```

---

### DATA-001: Unencrypted Export Contains Sensitive Data

**Severity**: High | **CVSS**: 7.5 | **CWE**: CWE-200  
**File**: `src/export.rs:45-55` | **Status**: Pending | **Priority**: P1

#### Vulnerability Description

Export feature creates plaintext JSON/CSV files containing all passwords and notes, readable by any process with file access.

#### Current Code

```rust
// src/export.rs:45-55 (current)
pub fn export_to_json(items: &[Item], path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(items)?;  // Plain text!
    fs::write(path, json)?;
    Ok(())
}
```

#### Remediation

```rust
// src/export.rs:45-65 (proposed)
use age::Encryptor;
use std::io::Write;

pub fn export_encrypted(
    items: &[Item], 
    path: &Path,
    export_password: &str
) -> Result<()> {
    let json = serde_json::to_string(items)?;
    
    // Encrypt with age (curve25519 or scrypt passphrase)
    let encryptor = Encryptor::with_user_passphrase(
        SecretString::new(export_password.into())
    );
    
    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(json.as_bytes())?;
    writer.finish()?;
    
    fs::write(path, encrypted)?;
    Ok(())
}
```

#### Rollback Procedure

Add `--legacy` flag for unencrypted export if needed for compatibility.

#### Commit Message

```
feat(security): Encrypt exports by default with age

Previously, exports were plaintext JSON/CSV containing all secrets.
Now uses age encryption with user-provided passphrase by default.
Adds --encrypt flag and --legacy for backward compatibility.

Resolves: DATA-001
CVSS: 7.5 (High)
CWE: CWE-200
```

---

### DATA-002: Backup No Integrity Verification

**Severity**: High | **CVSS**: 7.5 | **CWE**: CWE-345  
**File**: `src/backup.rs:23-46` | **Status**: Pending | **Priority**: P1

#### Vulnerability Description

Backup files have no integrity verification (no hash/signature), allowing silent tampering.

#### Current Code

```rust
// src/backup.rs:23-46 (current)
pub fn create_backup(src: &Path, dest: &Path) -> Result<()> {
    fs::copy(src, dest)?;  // Just copies file
    // No integrity check!
    Ok(())
}
```

#### Remediation

```rust
// src/backup.rs:23-60 (proposed)
use sha2::{Sha256, Digest};
use hex;

pub fn create_backup(src: &Path, dest: &Path) -> Result<()> {
    fs::copy(src, dest)?;
    
    // Calculate and store hash
    let data = fs::read(dest)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hex::encode(hasher.finalize());
    
    let hash_path = dest.with_extension("sha256");
    fs::write(&hash_path, hash)?;
    
    Ok(())
}

pub fn verify_backup(backup_path: &Path) -> Result<bool> {
    let data = fs::read(backup_path)?;
    let stored_hash = fs::read_to_string(
        backup_path.with_extension("sha256")
    )?;
    
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let computed_hash = hex::encode(hasher.finalize());
    
    Ok(stored_hash.trim() == computed_hash)
}
```

#### Commit Message

```
feat(security): Add SHA256 integrity verification to backups

Creates .sha256 sidecar files during backup for integrity
verification. verify_backup() function allows checking backup
validity before restore.

Resolves: DATA-002
CVSS: 7.5 (High)
CWE: CWE-345
```

---

### IPC-001: Error Messages Not Sanitized

**Severity**: High | **CVSS**: 5.5 | **CWE**: CWE-209  
**File**: `src/daemon.rs:119,160,189` | **Status**: Pending | **Priority**: P1

#### Vulnerability Description

Error messages may contain sensitive information (passwords, paths) that gets logged and potentially exposed.

#### Current Code

```rust
// src/daemon.rs:119 (current)
logger::error(&format!("Auth failed: {}", e));  // May contain password!
```

#### Remediation

```rust
// src/daemon.rs:119 (proposed)
use crate::sanitize::sanitize_for_display;

logger::error(&format!(
    "Auth failed: {}", 
    sanitize_for_display(&e.to_string())
));
```

#### Commit Message

```
fix(security): Sanitize all error messages in daemon

Applies sanitize_for_display() to all error logging to prevent
accidental exposure of passwords or sensitive paths in logs.

Resolves: IPC-001
CVSS: 5.5 (Medium)
CWE: CWE-209
```

---

## Medium Priority Issues (P2)

### AUTH-001: No Socket Channel Binding

**Severity**: Medium | **CVSS**: 5.3 | **CWE**: CWE-287  
**File**: `src/daemon.rs:35-58` | **Status**: Pending | **Priority**: P2

#### Vulnerability Description

No verification that IPC connection comes from the expected process or user, allowing privilege escalation via socket impersonation.

#### Current Code

```rust
// src/daemon.rs:35-58 (current)
let listener = UnixListener::bind(&socket_path)?;  // No auth!
```

#### Remediation

```rust
// src/daemon.rs:35-65 (proposed)
use nix::unistd::{Uid, Gid};

// Set socket permissions
std::fs::set_permissions(
    &socket_path,
    std::fs::Permissions::from_mode(0o600)  // Owner only
)?;

// Verify peer credentials
#[cfg(unix)]
fn verify_peer(stream: &UnixStream) -> Result<()> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    
    let creds = getsockopt(stream.as_raw_fd(), PeerCredentials)?;
    let uid = Uid::from_raw(creds.uid());
    
    // Only allow same user
    if uid != Uid::effective() {
        return Err(anyhow!("Unauthorized user: {:?}", uid));
    }
    
    Ok(())
}
```

#### Commit Message

```
feat(security): Add Unix socket peer credential verification

Implements SO_PEERCRED verification to ensure only the same UID
can connect to the IPC socket. Sets socket permissions to 0o600.

Resolves: AUTH-001
CVSS: 5.3 (Medium)
CWE: CWE-287
```

---

### AUTH-002: Password Blocklist Too Small

**Severity**: Medium | **CVSS**: 5.3 | **CWE**: CWE-521  
**File**: `src/security.rs:63-66` | **Status**: Pending | **Priority**: P2

#### Vulnerability Description

Only 6 passwords in blocklist, insufficient to prevent use of common passwords.

#### Current Code

```rust
// src/security.rs:63-66 (current)
const BLOCKLIST: &[&str] = &[
    "password",
    "123456",
    "qwerty",
    "keeper",
    "admin",
    "letmein",
];
```

#### Remediation

```rust
// src/security.rs:63-85 (proposed)
use std::collections::HashSet;
use lazy_static::lazy_static;

// Load 100,000 most common passwords
lazy_static! {
    static ref BLOCKLIST: HashSet<&'static str> = {
        let mut set = HashSet::new();
        // Common passwords
        set.extend([
            "password", "123456", "123456789", "qwerty", "abc123",
            "password123", "12345678", "iloveyou", "adobe123",
            // ... add 10,000+ most common
        ].iter().cloned());
        set
    };
}

pub fn validate_password_strength(password: &str) -> Result<()> {
    // Check minimum length
    if password.len() < 12 {
        return Err(anyhow!("Password must be at least 12 characters"));
    }
    
    // Check blocklist
    if BLOCKLIST.contains(password.to_lowercase().as_str()) {
        return Err(anyhow!("Password is too common"));
    }
    
    // Check entropy
    let entropy = calculate_entropy(password);
    if entropy < 50.0 {
        return Err(anyhow!("Password is too predictable"));
    }
    
    Ok(())
}
```

#### Commit Message

```
feat(security): Expand password blocklist to 10,000 entries

Increases password blocklist from 6 to 10,000 common passwords.
Adds minimum length (12 chars) and entropy requirements.

Resolves: AUTH-002
CVSS: 5.3 (Medium)
CWE: CWE-521
```

---

### AUTH-003: No Key Separation Between Operations

**Severity**: Medium | **CVSS**: 5.3 | **CWE**: CWE-310  
**File**: `src/security.rs` | **Status**: Pending | **Priority**: P2

#### Vulnerability Description

Same master key used for all operations (database encryption, IPC, export) instead of deriving separate keys.

#### Current Code

```rust
// src/security.rs (current)
// Single master key used everywhere
pub fn get_master_key() -> [u8; 32] {
    MASTER_KEY.clone()  // Used for DB, IPC, export...
}
```

#### Remediation

```rust
// src/security.rs:50-80 (proposed)
use blake2::{Blake2b512, Digest};

const CONTEXT_DB: &[u8] = b"keeper-db-v1";
const CONTEXT_IPC: &[u8] = b"keeper-ipc-v1";
const CONTEXT_EXPORT: &[u8] = b"keeper-export-v1";

pub fn derive_operation_key(
    master_key: &[u8; 32],
    context: &[u8]
) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(master_key);
    hasher.update(context);
    let result = hasher.finalize();
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

// Usage:
let db_key = derive_operation_key(&master_key, CONTEXT_DB);
let ipc_key = derive_operation_key(&master_key, CONTEXT_IPC);
```

#### Commit Message

```
feat(security): Implement key separation for different operations

Derives separate keys for database encryption, IPC communication,
and export operations using domain separation with Blake2b.
Prevents key reuse attacks.

Resolves: AUTH-003
CVSS: 5.3 (Medium)
CWE: CWE-310
```

---

### MISC-003: Constant-Time Compare Length Leak

**Severity**: Medium | **CVSS**: 5.3 | **CWE**: CWE-208  
**File**: `src/security/memory.rs:149-160` | **Status**: Pending | **Priority**: P2

#### Vulnerability Description

Constant-time comparison leaks password length via early return on length mismatch.

#### Current Code

```rust
// src/security/memory.rs:149-160 (current)
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;  // Leaks length!
    }
    // ... constant time comparison
}
```

#### Remediation

```rust
// src/security/memory.rs:149-175 (proposed)
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    // Compare all bytes regardless of length
    let max_len = std::cmp::max(a.len(), b.len());
    let mut result = 0u8;
    
    for i in 0..max_len {
        let a_byte = if i < a.len() { a[i] } else { 0 };
        let b_byte = if i < b.len() { b[i] } else { 0 };
        result |= a_byte ^ b_byte;
    }
    
    // Also compare lengths in constant time
    result |= (a.len() ^ b.len()) as u8;
    
    result == 0
}
```

#### Commit Message

```
fix(security): Eliminate timing leak in constant_time_compare

Modified constant_time_compare to not leak password length.
Now compares all bytes regardless of length, padding shorter
arrays with zeros. Also compares lengths in constant time.

Resolves: MISC-003
CVSS: 5.3 (Medium)
CWE: CWE-208
```

---

### UX-001: Recovery Code Displayed Plaintext

**Severity**: Medium | **CVSS**: 5.3 | **CWE**: CWE-532  
**File**: `src/main.rs:84, 154` | **Status**: Pending | **Priority**: P2

#### Vulnerability Description

Recovery code displayed as plaintext in terminal, may be logged by terminal emulator or screen capture.

#### Current Code

```rust
// src/main.rs:84 (current)
println!("Recovery code: {}", recovery_code);  // Visible!
```

#### Remediation

```rust
// src/main.rs:84-95 (proposed)
use std::io::{self, Write};

fn display_recovery_code_secure(code: &str) {
    // Clear screen first
    print!("\x1B[2J\x1B[H");  // ANSI clear
    io::stdout().flush().unwrap();
    
    println!("╔════════════════════════════════════════════════╗");
    println!("║      RECOVERY CODE - WRITE THIS DOWN NOW       ║");
    println!("╚════════════════════════════════════════════════╝");
    println!();
    println!("{}", code);
    println!();
    println!("This code will only be shown once.");
    println!("Press Enter after writing it down...");
    
    let _ = io::stdin().read_line(&mut String::new());
    
    // Clear again
    print!("\x1B[2J\x1B[H");
    io::stdout().flush().unwrap();
}
```

#### Commit Message

```
feat(security): Secure display for recovery codes

Clears terminal before/after showing recovery code to prevent
logging. Requires user confirmation before clearing.

Resolves: UX-001
CVSS: 5.3 (Medium)
CWE: CWE-532
```

---

### UX-002: TUI History Plaintext

**Severity**: Medium | **CVSS**: 5.3 | **CWE**: CWE-312  
**File**: `src/tui.rs:81-85` | **Status**: Pending | **Priority**: P2

#### Vulnerability Description

TUI history stores item content in plaintext in memory, may be swapped.

#### Current Code

```rust
// src/tui.rs:81-85 (current)
pub struct HistoryEntry {
    pub id: String,
    pub content: String,  // Plaintext!
    pub timestamp: i64,
}
```

#### Remediation

```rust
// src/tui.rs:81-95 (proposed)
use secrecy::SecretString;

pub struct HistoryEntry {
    pub id: String,
    pub content: SecretString,  // Protected
    pub timestamp: i64,
}

impl Drop for HistoryEntry {
    fn drop(&mut self) {
        // SecretString auto-clears on drop
    }
}
```

#### Commit Message

```
fix(security): Use SecretString for TUI history content

Replaces plaintext String with secrecy::SecretString for history
entries. Content is automatically cleared from memory on drop.

Resolves: UX-002
CVSS: 5.3 (Medium)
CWE: CWE-312
```

---

### DATA-003: Import No Data Validation

**Severity**: Medium | **CVSS**: 5.3 | **CWE**: CWE-20  
**File**: `src/transfer.rs:110-137` | **Status**: Pending | **Priority**: P2

#### Vulnerability Description

Import accepts any JSON data without validation, could import malicious or malformed data.

#### Current Code

```rust
// src/transfer.rs:110-137 (current)
let items: Vec<Item> = serde_json::from_str(&data)?;  // No validation!
for item in items {
    db.insert(&item)?;  // Blindly inserts
}
```

#### Remediation

```rust
// src/transfer.rs:110-150 (proposed)
pub fn validate_import_data(items: &[Item]) -> Result<()> {
    // Validate structure
    if items.len() > 100_000 {
        return Err(anyhow!("Import too large: {} items", items.len()));
    }
    
    for (i, item) in items.iter().enumerate() {
        // Validate fields
        if item.title.len() > 1000 {
            return Err(anyhow!("Item {}: title too long", i));
        }
        
        // Check for suspicious patterns
        if contains_suspicious_content(&item.content) {
            return Err(anyhow!("Item {}: suspicious content detected", i));
        }
        
        // Validate sigils
        validate_workspace(&item.workspace)?;
    }
    
    Ok(())
}

// Usage:
let items: Vec<Item> = serde_json::from_str(&data)?;
validate_import_data(&items)?;
for item in items {
    db.insert(&item)?;
}
```

#### Commit Message

```
feat(security): Add import data validation

Validates imported data for size limits, field lengths, and
suspicious patterns. Prevents import of malformed or malicious
data files.

Resolves: DATA-003
CVSS: 5.3 (Medium)
CWE: CWE-20
```

---

### DATA-004: Export Password Not Validated

**Severity**: Medium | **CVSS**: 5.3 | **CWE**: CWE-521  
**File**: `src/transfer.rs:139-146` | **Status**: Pending | **Priority**: P2

#### Vulnerability Description

Export encryption password not validated for strength, weak passwords compromise encrypted exports.

#### Current Code

```rust
// src/transfer.rs:139-146 (current)
pub fn export_with_password(items: &[Item], password: &str) -> Result<Vec<u8>> {
    // No password validation!
    encrypt_export(items, password)
}
```

#### Remediation

```rust
// src/transfer.rs:139-155 (proposed)
pub fn export_with_password(items: &[Item], password: &str) -> Result<Vec<u8>> {
    // Validate password strength
    if password.len() < 12 {
        return Err(anyhow!("Export password must be at least 12 characters"));
    }
    
    if !has_sufficient_entropy(password) {
        return Err(anyhow!("Export password is too weak"));
    }
    
    if is_common_password(password) {
        return Err(anyhow!("Export password is too common"));
    }
    
    encrypt_export(items, password)
}
```

#### Commit Message

```
feat(security): Validate export encryption password strength

Enforces minimum length (12 chars), entropy requirements, and
blocklist check for export passwords. Prevents weak passwords
on encrypted exports.

Resolves: DATA-004
CVSS: 5.3 (Medium)
CWE: CWE-521
```

---

## Low Priority Issues (P3)

### DATA-005: Backup No Secure Delete

**Severity**: Low | **CVSS**: 3.7 | **CWE**: CWE-226  
**File**: `src/backup.rs:98-120` | **Status**: Pending | **Priority**: P3  
**Dependencies**: DATA-002

#### Vulnerability Description

Old backups are deleted with regular file removal, data remains on disk and could be recovered.

#### Current Code

```rust
// src/backup.rs:98-120 (current)
fn delete_old_backup(path: &Path) -> Result<()> {
    fs::remove_file(path)?;  // Standard delete - data remains on disk!
    Ok(())
}
```

#### Remediation

```rust
// src/backup.rs:98-125 (proposed)
use std::fs::OpenOptions;

fn secure_delete(path: &Path) -> Result<()> {
    // Overwrite file with random data before deletion
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)?;
    
    let metadata = file.metadata()?;
    let size = metadata.len() as usize;
    
    // 3-pass overwrite: random, zeros, ones
    let mut rng = rand::thread_rng();
    for pass in 0..3 {
        let data: Vec<u8> = match pass {
            0 => (0..size).map(|_| rng.gen()).collect(),  // Random
            1 => vec![0u8; size],  // Zeros
            _ => vec![0xFFu8; size],  // Ones
        };
        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(&data)?;
        file.sync_all()?;
    }
    
    // Rename to obscure original name
    let temp_name = format!(".tmp_{}", Uuid::new_v4());
    let temp_path = path.with_file_name(&temp_name);
    fs::rename(path, &temp_path)?;
    
    // Finally delete
    fs::remove_file(&temp_path)?;
    
    Ok(())
}
```

#### Commit Message

```
feat(security): Implement secure deletion for old backups

Overwrites backup files with 3-pass random/zeros/ones pattern
before deletion. Renames to obscure original filename to prevent
data recovery.

Resolves: DATA-005
CVSS: 3.7 (Low)
CWE: CWE-226
```

---

### IPC-002: Logger error_raw Bypasses Sanitization

**Severity**: Low | **CVSS**: 3.7 | **CWE**: CWE-117  
**File**: `src/logger.rs:26-30` | **Status**: Pending | **Priority**: P3

#### Vulnerability Description

`error_raw()` function logs messages without sanitization, can be used to accidentally log secrets.

#### Current Code

```rust
// src/logger.rs:26-30 (current)
pub fn error_raw(msg: &str) {
    // Logs directly without sanitization
    eprintln!("[ERROR] {}", msg);  // Bypasses sanitize_for_display!
}
```

#### Remediation

```rust
// src/logger.rs:26-35 (proposed)
use crate::sanitize::sanitize_for_display;

pub fn error_raw(msg: &str) {
    // Always sanitize, even for "raw" errors
    let sanitized = sanitize_for_display(msg);
    eprintln!("[ERROR] {}", sanitized);
}

// For truly internal errors (no user data):
pub fn error_internal(msg: &str) {
    // Only for internal errors with no external input
    #[cfg(debug_assertions)]
    eprintln!("[ERROR INTERNAL] {}", msg);
}
```

#### Commit Message

```
fix(security): Apply sanitization to error_raw logging

error_raw() now applies sanitize_for_display() to prevent accidental
logging of sensitive data. Internal errors use separate function.

Resolves: IPC-002
CVSS: 3.7 (Low)
CWE: CWE-117
```

---

### MCP-001: Deprecated Password Support Still Present

**Severity**: Low | **CVSS**: 3.7 | **CWE**: CWE-477  
**File**: `mcp/keeper-mcp/src/main.rs:29-33` | **Status**: Pending | **Priority**: P3  
**Dependencies**: SWAP-001

#### Vulnerability Description

Deprecated password environment variable support still exists in code, encouraging insecure practices.

#### Current Code

```rust
// mcp/keeper-mcp/src/main.rs:29-33 (current)
// Still has KEEPER_PASSWORD support
if let Ok(pass) = env::var("KEEPER_PASSWORD") {
    return Some(pass);  // Deprecated but functional!
}
```

#### Remediation

```rust
// mcp/keeper-mcp/src/main.rs:29-40 (proposed)
// Remove KEEPER_PASSWORD support entirely
pub fn get_password() -> Option<String> {
    // Only allow interactive or keychain-based auth
    if env::var("KEEPER_PASSWORD").is_ok() {
        eprintln!("WARNING: KEEPER_PASSWORD is deprecated and ignored");
    }
    
    // Try keychain
    keychain_get_password()
}
```

#### Commit Message

```
delete(security): Remove KEEPER_PASSWORD environment variable

Removes deprecated KEEPER_PASSWORD support. Users must now use
interactive prompts or keychain integration for authentication.

Resolves: MCP-001
CVSS: 3.7 (Low)
CWE: CWE-477
```

---

### MISC-001: No Core Dump Limits

**Severity**: Low | **CVSS**: 3.7 | **CWE**: CWE-200  
**File**: `src/daemon.rs` | **Status**: Pending | **Priority**: P3  
**Dependencies**: SWAP-001

#### Vulnerability Description

No limits on core dump size, daemon crash could write sensitive memory to disk.

#### Current Code

```rust
// src/daemon.rs (current)
// No core dump configuration
```

#### Remediation

```rust
// src/daemon.rs:40-55 (proposed)
#[cfg(unix)]
fn disable_core_dumps() -> Result<()> {
    use nix::sys::resource::{setrlimit, Resource};
    
    // Set core dump size to 0
    setrlimit(Resource::RLIMIT_CORE, 0, 0)?;
    
    // Also use prctl on Linux to prevent any core dumps
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    
    Ok(())
}

// Call at daemon startup
disable_core_dumps()?;
```

#### Commit Message

```
feat(security): Disable core dumps in daemon

Prevents core dumps from exposing sensitive memory on crash.
Sets RLIMIT_CORE to 0 and uses PR_SET_DUMPABLE on Linux.

Resolves: MISC-001
CVSS: 3.7 (Low)
CWE: CWE-200
```

---

### UPDATE-001: Temp Dir Names Predictable

**Severity**: Low | **CVSS**: 3.7 | **CWE**: CWE-377  
**File**: `src/self_update.rs:318-324` | **Status**: Pending | **Priority**: P3

#### Vulnerability Description

Temporary directory names use predictable pattern based on timestamp, vulnerable to race condition attacks.

#### Current Code

```rust
// src/self_update.rs:318-324 (current)
let temp_dir = format!("/tmp/keeper_update_{}", timestamp);
fs::create_dir(&temp_dir)?;  // Predictable name!
```

#### Remediation

```rust
// src/self_update.rs:318-325 (proposed)
use tempfile::Builder;

// Use secure random temp directory
let temp_dir = Builder::new()
    .prefix("keeper_update_")
    .rand_bytes(16)  // 16 random bytes
    .tempdir()?;

let path = temp_dir.path();
```

#### Commit Message

```
fix(security): Use random temp directory names for updates

Replaces predictable timestamp-based temp directories with
cryptographically random names from tempfile crate.

Resolves: UPDATE-001
CVSS: 3.7 (Low)
CWE: CWE-377
```

---

### UPDATE-002: Self-Update Tag Injection Possible

**Severity**: Low | **CVSS**: 3.7 | **CWE**: CWE-79  
**File**: `src/self_update.rs:23-32` | **Status**: Pending | **Priority**: P3

#### Vulnerability Description

GitHub release tag not validated before use, could inject malicious URLs.

#### Current Code

```rust
// src/self_update.rs:23-32 (current)
let tag = fetch_latest_tag()?;
let url = format!("https://github.com/.../{}/...", tag);  // No validation!
```

#### Remediation

```rust
// src/self_update.rs:23-40 (proposed)
use regex::Regex;

fn validate_tag(tag: &str) -> Result<()> {
    // Only allow semantic version format: v1.2.3
    let re = Regex::new(r"^v\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$").unwrap();
    
    if !re.is_match(tag) {
        return Err(anyhow!("Invalid tag format: {}", tag));
    }
    
    // Reject suspicious patterns
    if tag.contains("..") || tag.contains("://") {
        return Err(anyhow!("Suspicious tag pattern detected"));
    }
    
    Ok(())
}

// Usage:
let tag = fetch_latest_tag()?;
validate_tag(&tag)?;
```

#### Commit Message

```
feat(security): Validate release tags in self-update

Adds semantic version format validation for GitHub release tags.
Prevents injection of malicious URLs through malformed tags.

Resolves: UPDATE-002
CVSS: 3.7 (Low)
CWE: CWE-79
```

---

### VALID-001: Workspace Path Traversal Possible

**Severity**: Low | **CVSS**: 3.7 | **CWE**: CWE-22  
**File**: `src/config.rs:54-71` | **Status**: Pending | **Priority**: P3

#### Vulnerability Description

Workspace names not validated for path traversal sequences, could access files outside vault.

#### Current Code

```rust
// src/config.rs:54-71 (current)
pub fn workspace_path(&self, name: &str) -> PathBuf {
    self.vault_dir.join("workspaces").join(name)  // No validation!
}
```

#### Remediation

```rust
// src/config.rs:54-80 (proposed)
use std::path::Component;

pub fn workspace_path(&self, name: &str) -> Result<PathBuf> {
    // Validate workspace name
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(anyhow!("Invalid workspace name: {}", name));
    }
    
    let path = self.vault_dir.join("workspaces").join(name);
    
    // Ensure path is within vault
    let canonical_vault = self.vault_dir.canonicalize()?;
    let canonical_workspace = path.canonicalize()?;
    
    if !canonical_workspace.starts_with(&canonical_vault) {
        return Err(anyhow!("Workspace path outside vault"));
    }
    
    Ok(path)
}
```

#### Commit Message

```
fix(security): Validate workspace paths to prevent traversal

Rejects workspace names containing path traversal sequences.
Canonicalizes and verifies workspace path is within vault directory.

Resolves: VALID-001
CVSS: 3.7 (Low)
CWE: CWE-22
```

---

### VALID-002: Config Workspace Validation Insufficient

**Severity**: Low | **CVSS**: 3.7 | **CWE**: CWE-20  
**File**: `src/config.rs:54-71` | **Status**: Pending | **Priority**: P3

#### Vulnerability Description

Workspace names not validated for length or character set, could cause filesystem issues.

#### Current Code

```rust
// src/config.rs:54-71 (current)
pub fn set_workspace(&mut self, name: &str) {
    self.workspace = name.to_string();  // Any string accepted!
}
```

#### Remediation

```rust
// src/config.rs:54-85 (proposed)
const MAX_WORKSPACE_LEN: usize = 64;
const VALID_WORKSPACE_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";

pub fn set_workspace(&mut self, name: &str) -> Result<()> {
    // Length check
    if name.is_empty() {
        return Err(anyhow!("Workspace name cannot be empty"));
    }
    if name.len() > MAX_WORKSPACE_LEN {
        return Err(anyhow!("Workspace name too long (max {} chars)", MAX_WORKSPACE_LEN));
    }
    
    // Character validation
    for c in name.chars() {
        if !VALID_WORKSPACE_CHARS.contains(c) {
            return Err(anyhow!("Invalid character in workspace name: {}", c));
        }
    }
    
    // Reserved names
    let reserved = ["con", "prn", "aux", "nul", "com1", "lpt1"];
    if reserved.contains(&name.to_lowercase().as_str()) {
        return Err(anyhow!("Reserved workspace name: {}", name));
    }
    
    self.workspace = name.to_string();
    Ok(())
}
```

#### Commit Message

```
feat(security): Add workspace name validation

Validates workspace names for length, character set, and reserved
names. Prevents filesystem issues and path injection.

Resolves: VALID-002
CVSS: 3.7 (Low)
CWE: CWE-20
```

---

## Implementation Phases

### Phase 1: Foundation - Memory Protection (Week 1)

**Objective**: Establish secure memory foundation for all subsequent fixes.

| Issue | Time | Owner | Risk |
|-------|------|-------|------|
| SWAP-001: mlockall failure handling | 2 days | Security Lead | High - requires testing on limited systems |
| SWAP-002: IPC client bounds | 1 day | Backend | Medium |
| SWAP-003: IPC daemon bounds | 1 day | Backend | Medium |
| SWAP-012: Base64 copies | 2 days | Security Lead | Low |

**Dependencies**: None
**Exit Criteria**:
- All P0 memory issues resolved
- Unit tests pass
- Memory stress tests pass (10MB+ allocations handled)

**Rollback Procedure**:
1. Restore previous src/daemon.rs and src/client.rs
2. Remove any added dependencies from Cargo.toml
3. Rebuild and restart daemon

**Commit Strategy**: Single commit per issue, rebase to maintain clean history

---

### Phase 2: Critical IPC & Communication (Week 2)

**Objective**: Secure all IPC communication channels.

| Issue | Time | Owner | Risk |
|-------|------|-------|------|
| SWAP-009: IPC key transmission | 2 days | Backend | Medium |
| SWAP-013: format!() elimination | 1 day | Backend | Low |
| SWAP-010: JSON serialization | 2 days | Backend | Medium |
| SWAP-004: MCP plaintext | 2 days | Security Lead | High - requires MCP refactor |

**Dependencies**: Phase 1 (SWAP-001, SWAP-002, SWAP-003)
**Exit Criteria**:
- No plaintext passwords in /proc
- All IPC messages bounded
- MCP tests pass

**Rollback Procedure**:
1. Revert MCP changes to allow env password temporarily
2. Restore original IPC serialization
3. Document temporary security degradation

---

### Phase 3: Self-Update Security (Week 2-3)

**Objective**: Implement cryptographic verification for updates.

| Issue | Time | Owner | Risk |
|-------|------|-------|------|
| SWAP-005: Signature verification | 3 days | Security Lead | High - critical infrastructure |
| UPDATE-001: Temp dir names | 1 day | Backend | Low |
| UPDATE-002: Tag validation | 1 day | Backend | Low |

**Dependencies**: None (can parallel with Phase 2)
**Exit Criteria**:
- Self-update verifies signatures
- Invalid signature blocks update
- Temp directories are random

**Rollback Procedure**:
1. Emergency: Use manual update procedure
2. Temporarily disable auto-update: `keeper config set auto_update false`
3. Restore previous binary from backup

**Testing**:
```bash
# Test invalid signature rejection
cargo test self_update_invalid_signature

# Test valid signature acceptance  
cargo test self_update_valid_signature
```

---

### Phase 4: DDoS & Rate Limiting (Week 3)

**Objective**: Protect against resource exhaustion attacks.

| Issue | Time | Owner | Risk |
|-------|------|-------|------|
| DDOS-001: Request rate limiting | 2 days | Backend | Medium |
| DDOS-002: Password rate limiting | 2 days | Backend | Medium |
| DDOS-003: Memory limits | 1 day | Backend | Low |
| DDOS-004: Connection timeouts | 1 day | Backend | Low |

**Dependencies**: Phase 1 (SWAP-003 for connection handling)
**Exit Criteria**:
- Rate limits enforced
- Timeout tests pass
- Memory limits trigger correctly

**Rollback Procedure**:
1. Increase limits via environment variables
2. Temporarily disable rate limiting if blocking legitimate users
3. Add IP whitelist for trusted clients

**Configuration**:
```bash
# Emergency rate limit adjustment
export KEEPER_RATE_LIMIT_PER_MINUTE=100
export KEEPER_CONN_TIMEOUT_SECS=60
export KEEPER_MAX_MEMORY_MB=100
```

---

### Phase 5: Data Protection & Integrity (Week 4)

**Objective**: Secure data at rest and in transit.

| Issue | Time | Owner | Risk |
|-------|------|-------|------|
| DATA-001: Encrypted exports | 3 days | Security Lead | High - UX impact |
| DATA-002: Backup integrity | 2 days | Backend | Medium |
| DATA-003: Import validation | 2 days | Backend | Medium |
| DATA-004: Export password validation | 1 day | Backend | Low |
| DATA-005: Secure delete | 1 day | Backend | Low |

**Dependencies**: DATA-002 must complete before DATA-005
**Exit Criteria**:
- Exports encrypted by default
- Backups have integrity hashes
- Import validation rejects malicious data

**Rollback Procedure**:
1. Restore unencrypted export with `--legacy` flag
2. Disable integrity verification if causing issues
3. Increase import size limits if blocking legitimate use

---

### Phase 6: Authentication & Access Control (Week 5)

**Objective**: Strengthen authentication mechanisms.

| Issue | Time | Owner | Risk |
|-------|------|-------|------|
| AUTH-001: Socket channel binding | 2 days | Backend | Medium |
| AUTH-002: Password blocklist | 2 days | Security Lead | Medium - may affect existing users |
| AUTH-003: Key separation | 3 days | Security Lead | High - requires keystore migration |
| AUTH-004: Constant-time compare | 1 day | Backend | Low |

**Dependencies**: Phase 1 (for secure key handling)
**Exit Criteria**:
- Socket credentials verified
- Weak passwords rejected
- Separate keys for each operation

**Rollback Procedure**:
1. Temporarily allow weaker passwords with warning
2. Restore single-key mode in emergency
3. Document security degradation

---

### Phase 7: UX & Polish (Week 6)

**Objective**: Address remaining medium and low priority issues.

| Issue | Time | Owner | Risk |
|-------|------|-------|------|
| SWAP-006: Terminal echo restoration | 1 day | Frontend | Low |
| SWAP-007: Keystore salts zeroized | 1 day | Security Lead | Low |
| SWAP-008: Database key encoding | 1 day | Backend | Low |
| SWAP-011: Regex sanitization | 1 day | Backend | Low |
| IPC-001: Error message sanitization | 1 day | Backend | Low |
| IPC-002: Logger sanitization | 1 day | Backend | Low |
| UX-001: Recovery code display | 1 day | Frontend | Low |
| UX-002: TUI history protection | 1 day | Frontend | Low |
| MISC-001: Core dump limits | 1 day | Backend | Low |
| VALID-001: Workspace path validation | 1 day | Backend | Low |
| VALID-002: Workspace name validation | 1 day | Backend | Low |
| MCP-001: Remove deprecated password | 1 day | MCP | Medium |

**Dependencies**: Various from previous phases
**Exit Criteria**:
- All P2/P3 issues resolved
- No plaintext secrets in TUI history
- Workspace validation complete

**Rollback Procedure**: Individual issues can be reverted independently

---

## Dependency Graph

```
SWAP-001 (mlockall)
├── SWAP-004 (MCP plaintext)
├── SWAP-006 (Terminal echo)
├── SWAP-007 (Keystore salts)
├── SWAP-012 (Base64 copies)
├── MISC-001 (Core dumps)
└── MCP-001 (Deprecated password)

SWAP-002 (Client bounds)
└── SWAP-008 (DB key encoding)

SWAP-003 (Daemon bounds)
├── DDOS-001 (Rate limiting)
├── DDOS-003 (Memory limits)
└── DDOS-004 (Timeouts)

SWAP-009 (IPC transmission)
└── SWAP-013 (format!() elimination)

DATA-002 (Backup integrity)
└── DATA-005 (Secure delete)

Auth & Crypto (Parallel tracks)
├── AUTH-001 (Socket binding)
├── AUTH-002 (Blocklist)
├── AUTH-003 (Key separation)
└── MISC-003 (Constant-time)

UX & Polish (Final phase)
├── UX-001 (Recovery display)
├── UX-002 (TUI history)
├── IPC-001 (Error sanitization)
└── IPC-002 (Logger sanitization)
```

**Critical Path**: SWAP-001 → SWAP-004, SWAP-009 → All dependent fixes

---

## Testing & Verification

### Unit Tests

Add to `src/security/tests.rs`:

```rust
#[test]
fn test_mlockall_failure_exits() {
    // Simulate mlockall failure and verify exit
}

#[test]
fn test_bounded_ipc_read() {
    // Verify 10MB limit enforced
}

#[test]
fn test_rate_limit_enforcement() {
    // Verify 5 attempts per minute
}

#[test]
fn test_signature_verification() {
    // Verify valid/invalid signatures
}

#[test]
fn test_export_encryption() {
    // Verify encrypted export format
}
```

### Integration Tests

Add to `tests/security_integration.rs`:

```rust
#[tokio::test]
async fn test_memory_locked() {
    // Verify no swap usage
}

#[tokio::test]
async fn test_ipc_bounds() {
    // Send oversized message, verify rejection
}

#[tokio::test]
async fn test_rate_limiting() {
    // Rapid connections, verify throttling
}

#[test]
fn test_backup_integrity() {
    // Create backup, verify hash
}
```

### Memory Analysis

```bash
# Run with valgrind to detect memory leaks
valgrind --leak-check=full --show-leak-kinds=all ./target/debug/keeper

# Check for swapped memory
sudo cat /proc/$(pgrep keeper)/smaps | grep Swap

# Verify locked memory
ulimit -l
sudo cat /proc/$(pgrep keeper)/status | grep VmLck
```

### Security Audit Checklist

- [ ] No plaintext passwords in /proc
- [ ] All IPC messages bounded (10MB)
- [ ] Rate limiting active (5 req/min)
- [ ] Self-update verifies signatures
- [ ] Exports encrypted
- [ ] Backups have integrity hashes
- [ ] Workspace paths validated
- [ ] Error messages sanitized
- [ ] Memory locked (mlockall success)
- [ ] Core dumps disabled

---

## Rollback Procedures

### Phase Rollback

If critical issues discovered during implementation:

**Phase 1 (Foundation)**:
```bash
# Emergency rollback to pre-security-fixes state
git checkout HEAD~N  # N = number of security commits
cargo build --release
systemctl restart keeper
```

**Database Migration Rollback**:
```bash
# If AUTH-003 (key separation) causes issues
keeper restore --from-backup pre-key-separation.backup
```

**Configuration Overrides**:
```bash
# Emergency bypasses
export KEEPER_ALLOW_SWAP=1              # Bypass mlockall
export KEEPER_MAX_IPC_SIZE=52428800     # 50MB limit
export KEEPER_RATE_LIMIT_OFF=1          # Disable rate limiting
export KEEPER_LEGACY_EXPORT=1           # Unencrypted export
```

**Binary Rollback**:
```bash
# Restore previous version
cp /usr/local/bin/keeper.backup /usr/local/bin/keeper
keeper --version  # Verify rollback
```

---

## Security Metrics & Monitoring

### Key Metrics

| Metric | Target | Alert Threshold | Measurement |
|--------|--------|-----------------|-------------|
| Failed auth / min | < 5 | > 10 | daemon.log |
| IPC message size | < 10MB | > 10MB | daemon.log |
| Memory usage | < 100MB | > 200MB | /proc/[pid]/status |
| Locked memory | > 50KB | < 10KB | /proc/[pid]/status |
| Rate limit hits | < 1% | > 5% | daemon.log |
| Core dump count | 0 | > 0 | audit.log |

### Log Analysis

```bash
# Monitor failed authentication attempts
grep "Auth failed" /var/log/keeper/daemon.log | tail -100

# Monitor rate limiting
grep "Rate limit exceeded" /var/log/keeper/daemon.log | wc -l

# Monitor memory usage
ps aux | grep keeper | awk '{print $4"%"}'  # CPU
ps aux | grep keeper | awk '{print $6"KB"}' # RSS
```

### Alerting Rules

```yaml
# alerts/keeper-security.yml
alerts:
  - name: keeper_auth_failures
    condition: rate(keeper_auth_failures[5m]) > 5
    severity: warning
    
  - name: keeper_rate_limit_hits
    condition: rate(keeper_rate_limit_exceeded[5m]) > 10
    severity: critical
    
  - name: keeper_memory_unlocked
    condition: keeper_memory_locked == 0
    severity: critical
```

---

## Compliance Mapping

### OWASP Top 10 2021

| OWASP | Issue ID | Mitigation |
|-------|----------|------------|
| A01: Broken Access Control | AUTH-001 | Socket credential verification |
| A02: Cryptographic Failures | SWAP-001, AUTH-003 | mlockall, key separation |
| A03: Injection | VALID-001 | Workspace path validation |
| A04: Insecure Design | SWAP-005 | Signature verification |
| A05: Security Misconfiguration | MISC-001 | Core dump limits |
| A06: Vulnerable Components | UPDATE-002 | Tag validation |
| A07: ID & Auth Failures | DDOS-002 | Password rate limiting |
| A08: Data Integrity Failures | DATA-002 | Backup integrity verification |
| A09: Security Logging | IPC-001 | Error message sanitization |
| A10: SSRF | - | Not applicable |

### NIST Cybersecurity Framework

| Function | Category | Issue IDs |
|----------|----------|-----------|
| Identify | Asset Management | VALID-001, VALID-002 |
| Protect | Access Control | AUTH-001, DDOS-001 |
| Protect | Data Security | DATA-001, DATA-005 |
| Protect | Protective Technology | SWAP-001, MISC-001 |
| Detect | Anomalies & Events | DDOS-002, IPC-001 |
| Respond | Response Planning | Rollback procedures |
| Recover | Recovery Planning | DATA-002, Rollback |

### CWE Coverage

- CWE-200: Information Exposure (SWAP-001, DATA-001, IPC-001)
- CWE-208: Observable Timing Discrepancy (MISC-003)
- CWE-22: Path Traversal (VALID-001)
- CWE-226: Sensitive Data in Resource (SWAP-007, SWAP-012, DATA-005)
- CWE-287: Improper Authentication (AUTH-001)
- CWE-310: Cryptographic Issues (AUTH-003)
- CWE-312: Cleartext Storage (SWAP-010, SWAP-011, UX-002)
- CWE-345: Insufficient Verification (DATA-002)
- CWE-377: Insecure Temp File (UPDATE-001)
- CWE-400: Uncontrolled Resource (SWAP-002, SWAP-003, DDOS-003)
- CWE-477: Deprecated Features (MCP-001)
- CWE-494: Download of Code Without Integrity (SWAP-005)
- CWE-521: Weak Password Requirements (AUTH-002, DATA-004)
- CWE-532: Insertion of Sensitive Info (UX-001)

---

## Appendices

### Appendix A: File Changes Summary

| File | Lines Changed | Issues Addressed |
|------|---------------|------------------|
| src/daemon.rs | +45, -12 | SWAP-001, SWAP-003, DDOS-001, DDOS-003, DDOS-004, AUTH-001, MISC-001 |
| src/client.rs | +25, -3 | SWAP-002 |
| src/session.rs | +18, -5 | SWAP-009, SWAP-013 |
| src/keystore.rs | +20, -8 | SWAP-007 |
| src/security.rs | +35, -10 | AUTH-002, AUTH-003 |
| src/security/memory.rs | +15, -5 | MISC-003 |
| src/self_update.rs | +40, -5 | SWAP-005, UPDATE-001, UPDATE-002 |
| src/export.rs | +25, -8 | DATA-001 |
| src/backup.rs | +30, -5 | DATA-002, DATA-005 |
| src/transfer.rs | +20, -3 | DATA-003, DATA-004 |
| src/sanitize.rs | +25, -8 | SWAP-011, IPC-001, IPC-002 |
| src/ipc.rs | +15, -5 | SWAP-010 |
| src/config.rs | +25, -3 | VALID-001, VALID-002 |
| src/prompt.rs | +12, -3 | SWAP-006 |
| src/tui.rs | +10, -3 | UX-002 |
| src/main.rs | +8, -2 | UX-001 |
| mcp/keeper-mcp/src/main.rs | +5, -10 | SWAP-004, MCP-001 |

**Total**: ~370 lines changed across 17 files

### Appendix B: New Dependencies

```toml
[dependencies]
# Security
governor = "0.6.3"              # Rate limiting
minisign = "0.7.3"              # Signature verification
scopeguard = "1.2.0"            # RAII guards
secrecy = "0.10.0"              # Secret types
zeroize = "1.8.0"               # Secure zeroization

# Unix-specific
nix = { version = "0.29", features = ["user", "resource"] }

# Testing
tempfile = "3.12"               # Secure temp files (also prod use)
```

### Appendix C: Test Files

```
tests/
├── security_integration.rs     # Integration tests
├── security_unit.rs            # Unit tests  
├── memory_tests.rs             # Memory protection tests
├── rate_limit_tests.rs         # DoS protection tests
└── snapshots/
    └── security_fixes/         # Expected outputs

benches/
└── security_benchmarks.rs      # Performance regression tests
```

### Appendix D: Environment Variables

| Variable | Purpose | Default | Security Impact |
|----------|---------|---------|-----------------|
| KEEPER_ALLOW_SWAP | Bypass mlockall check | false | HIGH - allows swap |
| KEEPER_MAX_IPC_SIZE | IPC message limit | 10485760 | Medium |
| KEEPER_RATE_LIMIT_PER_MINUTE | Request limit | 5 | Medium |
| KEEPER_CONN_TIMEOUT_SECS | Connection timeout | 30 | Low |
| KEEPER_LEGACY_EXPORT | Unencrypted export | false | HIGH |
| KEEPER_DEBUG_SECURITY | Verbose security logging | false | Low |

### Appendix E: Migration Guide

**For Users**:

1. **Backup before upgrade**:
   ```bash
   keeper backup create --name pre-security-upgrade
   ```

2. **Verify mlockall works**:
   ```bash
   ulimit -l  # Should be > 64KB
   keeper start
   ```

3. **Update exports**:
   ```bash
   # Old exports may need re-encryption
   keeper export --encrypt --format json
   ```

**For Administrators**:

1. **Update system limits**:
   ```bash
   # /etc/security/limits.conf
   * soft memlock 65536
   * hard memlock unlimited
   ```

2. **Monitor new metrics**:
   - Failed auth rate
   - Rate limit hits
   - Memory lock status

3. **Update runbooks**:
   - New rollback procedures
   - Emergency bypass procedures
   - Incident response for security alerts

---

**Document End**

*This security plan was generated on 2026-01-31.*
*Next review date: 2026-04-31*
*Owner: Security Team*
*Status: Draft - Pending Implementation*
