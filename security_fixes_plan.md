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
| **Total Issues Identified** | 40 |
| **Critical Severity** | 6 |
| **High Severity** | 14 |
| **Medium Severity** | 15 |
| **Low Severity** | 8 |
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

| ID | Issue | Severity | Status | Blocked By | Priority | Dependencies |
|----|-------|----------|--------|------------|----------|---------------|
| SWAP-001 | mlockall() silent failure | Critical | Pending | - | P0 | None |
| SWAP-002 | IPC client message size unbounded | Critical | Pending | - | P0 | None |
| SWAP-003 | IPC daemon message size unbounded | Critical | Pending | - | P0 | None |
| SWAP-004 | MCP plaintext passwords via stdin | Critical | Pending | SWAP-001 | P0 | SWAP-001 |
| SWAP-005 | Self-update no signature verification | Critical | Pending | - | P0 | None |
| SWAP-006 | Terminal echo not restored on error | High | Pending | SWAP-001 | P1 | SWAP-001 |
| SWAP-007 | Keystore salts not zeroized before encoding | High | Pending | - | P1 | SWAP-001 |
| SWAP-008 | Database key hex encoding leaks | High | Pending | SWAP-002 | P1 | SWAP-002 |
| SWAP-009 | IPC master key transmission creates copies | High | Pending | - | P1 | None |
| SWAP-010 | JSON serialization leaks passwords | High | Pending | SWAP-001 | P1 | SWAP-001 |
| SWAP-011 | Regex sanitization creates password copies | High | Pending | - | P1 | None |
| SWAP-012 | Base64 intermediate copies everywhere | High | Pending | - | P1 | SWAP-001 |
| SWAP-013 | format!() copies passwords during IPC | High | Pending | SWAP-009 | P1 | SWAP-009 |
| DDOS-001 | No request rate limiting | High | Pending | SWAP-003 | P1 | SWAP-003 |
| DDOS-002 | Password rate limit bypassable | High | Pending | - | P1 | None |
| DDOS-003 | No per-connection memory limits | High | Pending | SWAP-003 | P1 | SWAP-003 |
| DDOS-004 | No connection timeout (slowloris) | High | Pending | SWAP-003 | P1 | SWAP-003 |
| AUTH-001 | No socket channel binding | Medium | Pending | - | P2 | None |
| AUTH-002 | Password blocklist too small | Medium | Pending | - | P2 | None |
| AUTH-003 | No key separation between operations | Medium | Pending | - | P2 | None |
| DATA-001 | Unencrypted export contains sensitive data | High | Pending | - | P1 | None |
| DATA-002 | Backup no integrity verification | High | Pending | - | P1 | None |
| DATA-003 | Import no data validation | Medium | Pending | - | P2 | None |
| DATA-004 | Export password not validated | Medium | Pending | - | P2 | None |
| DATA-005 | Backup no secure delete | Low | Pending | DATA-002 | P3 | DATA-002 |
| IPC-001 | Error messages not sanitized | High | Pending | - | P1 | None |
| IPC-002 | Logger error_raw bypasses sanitization | Low | Pending | - | P3 | None |
| MCP-001 | Deprecated password support still present | Low | Pending | SWAP-001 | P3 | SWAP-001 |
| MISC-001 | No core dump limits | Low | Pending | SWAP-001 | P3 | SWAP-001 |
| MISC-002 | unwrap() calls in test code | Low | Pending | - | P3 | None |
| MISC-003 | Constant-time compare length leak | Medium | Pending | - | P2 | None |
| UPDATE-001 | Temp dir names predictable | Low | Pending | - | P3 | None |
| UPDATE-002 | Self-update tag injection possible | Low | Pending | - | P3 | None |
| VALID-001 | Workspace path traversal possible | Low | Pending | - | P3 | None |
| VALID-002 | Config workspace validation insufficient | Low | Pending | - | P3 | None |
| UX-001 | Recovery code displayed plaintext | Medium | Pending | - | P2 | None |
| UX-002 | TUI history plaintext | Medium | Pending | - | P2 | None |

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
strings /swapfile | grep -i "password|key|secret"
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

**Severity**: High | **CVSS**: 5.3 (Medium) | **CWE**: CWE-224  
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

---

### SWAP-007: Keystore Salts Not Zeroized Before Encoding

**Severity**: High | **CVSS**: 5.3 (Medium) | **CWE**: CWE-226  
**File**: `src/keystore.rs:80-86` | **Status**: Pending | **Priority**: P1

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

---

### SWAP-008: Database Key Hex Encoding Leaks

**Severity**: High | **CVSS**: 5.3 (Medium) | **CWE**: CWE-226  
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

---

### SWAP-009: IPC Master Key Transmission Creates Copies

**Severity**: High | **CVSS**: 5.3 (Medium) | **CWE**: CWE-226  
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

---

### SWAP-010: JSON Serialization Leaks Passwords

**Severity**: High | **CVSS**: 5.3 (Medium) | **CWE**: CWE-312  
**File**: `src/ipc.rs` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-001

#### Vulnerability Description

`serde_json::to_vec()` creates full JSON string with password values in memory.

#### Current Code

```rust
pub enum DaemonRequest {
    RotatePassword {
        current_password: SecretString,
        new_password: SecretString,
    },
}
// Serializes to: {"RotatePassword":{"current_password":"MySecret123"}}
```

#### Remediation

Implement custom serializer that excludes sensitive fields:

```rust
impl Serialize for DaemonRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            DaemonRequest::RotatePassword { .. } => {
                let mut state = serializer.serialize_struct("DaemonRequest", 3)?;
                state.serialize_field("type", "RotatePassword")?;
                state.serialize_field("current_password", "[REDACTED]")?;
                state.serialize_field("new_password", "[REDACTED]")?;
                state.end()
            }
            _ => self.serialize_normal(serializer),
        }
    }
}
```

---

### SWAP-011: Regex Sanitization Creates Password Copies

**Severity**: High | **CVSS**: 5.3 (Medium) | **CWE**: CWE-312  
**File**: `src/sanitize.rs:4-11` | **Status**: Pending | **Priority**: P1

#### Vulnerability Description

`replace_all()` creates new String containing matched password.

#### Current Code

```rust
static SENSITIVE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(password|key|secret|token|master|vault|keeper)[\s:=]+[^\s]+").unwrap()
});

pub fn sanitize_for_display(message: &str) -> String {
    let sanitized = SENSITIVE_PATTERN.replace_all(message, "$1=[REDACTED]");
    sanitized.to_string()  // Creates copy!
}
```

#### Remediation

```rust
pub fn sanitize_for_display(message: &str) -> String {
    let mut result = String::with_capacity(message.len());
    let mut pos = 0;
    
    while let Some(mat) = SENSITIVE_PATTERN.find_at(message, pos) {
        result.push_str(&message[pos..mat.start()]);
        result.push_str("[REDACTED]");
        pos = mat.end();
    }
    
    result.push_str(&message[pos..]);
    result
}
```

---

### SWAP-012: Base64 Intermediate Copies Everywhere

**Severity**: High | **CVSS**: 5.3 (Medium) | **CWE**: CWE-226  
**File**: Multiple | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-001

#### Vulnerability Description

Base64 encoding creates reversible copies of sensitive data.

#### Remediation

Apply zeroization pattern everywhere:

```rust
let mut sensitive_data = [0u8; N];
// ... fill with sensitive data ...
let encoded = STANDARD_NO_PAD.encode(sensitive_data);
sensitive_data.zeroize();  // Always zeroize source

// Use encoded immediately, then:
let mut decoded = STANDARD_NO_PAD.decode(encoded)?;
encoded.zeroize();
decoded.zeroize();
```

---

### SWAP-013: format!() Copies Passwords During IPC

**Severity**: High | **CVSS**: 5.3 (Medium) | **CWE**: CWE-226  
**File**: `src/session.rs:67` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-009

#### Vulnerability Description

`format!("{payload}\n")` creates additional String copies.

#### Remediation

Same as SWAP-009: Use direct buffer manipulation.

---

### DDOS-001: No Request Rate Limiting

**Severity**: High | **CVSS**: 7.5 (High) | **CWE**: CWE-307  
**File**: `src/daemon.rs:86-91` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-003

#### Vulnerability Description

Daemon accepts requests as fast as connections can be established, allowing CPU exhaustion attacks.

#### Current Code

```rust
// src/daemon.rs:86-91
if connection_count.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
    logger::error("Maximum connections reached");
    std::thread::sleep(std::time::Duration::from_millis(100));
    continue;
}
```

#### Remediation

Implement token bucket rate limiter:

```rust
struct RateLimiter {
    clients: Mutex<HashMap<UnixAddr, ClientState>>,
    max_requests_per_second: u32,
}

impl RateLimiter {
    fn check_rate(&self, addr: &UnixAddr) -> Result<()> {
        let mut clients = self.clients.lock().unwrap();
        let state = clients.entry(*addr).or_insert(ClientState {
            tokens: self.max_requests_per_second as f32,
        });
        
        state.tokens = (state.tokens + 1.0).min(self.max_requests_per_second as f32);
        
        if state.tokens < 1.0 {
            return Err(anyhow!("Rate limit exceeded"));
        }
        
        state.tokens -= 1.0;
        Ok(())
    }
}
```

---

### DDOS-002: Password Rate Limit Bypassable

**Severity**: High | **CVSS**: 7.5 (High) | **CWE**: CWE-307  
**File**: `src/daemon.rs:172-185` | **Status**: Pending | **Priority**: P1

#### Vulnerability Description

30-second window resets, allowing unlimited brute force by waiting 31 seconds.

#### Current Code

```rust
// src/daemon.rs:172-185
if is_password_operation {
    let attempts = password_attempts.fetch_add(1, Ordering::SeqCst);
    let last_attempt = last_password_attempt.swap(now, Ordering::SeqCst);

    if now - last_attempt < 30 {
        if attempts >= 3 {
            // Lockout
        }
    }
}
```

#### Remediation

Sliding window with exponential backoff:

```rust
struct PasswordAttemptTracker {
    attempts: VecDeque<Instant>,
}

impl PasswordAttemptTracker {
    fn new() -> Self {
        Self {
            attempts: VecDeque::with_capacity(10),
        }
    }
    
    fn record_attempt(&mut self) -> Result<()> {
        let now = Instant::now();
        self.attempts.push_back(now);
        
        let cutoff = now - Duration::from_secs(60);
        while let Some(&old) = self.attempts.front() {
            if old < cutoff {
                self.attempts.pop_front();
            } else {
                break;
            }
        }
        
        let count = self.attempts.len();
        if count >= 3 {
            let backoff = 2u64.pow(count as u32).min(300);
            return Err(anyhow!("Too many attempts. Wait {} seconds.", backoff));
        }
        
        Ok(())
    }
    
    fn record_success(&mut self) {
        self.attempts.clear();
    }
}
```

---

### DDOS-003: No Per-Connection Memory Limits

**Severity**: High | **CVSS**: 7.5 (High) | **CWE**: CWE-400  
**File**: `src/daemon.rs:154` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-003

#### Vulnerability Description

Each connection can allocate unlimited memory.

#### Remediation

```rust
struct ConnectionMemoryTracker {
    max_per_connection: usize,
    current_total: AtomicUsize,
}

impl ConnectionMemoryTracker {
    fn new() -> Self {
        Self {
            max_per_connection: 100 * 1024 * 1024,  // 100MB
            current_total: AtomicUsize::new(0),
        }
    }
    
    fn allocate(&self, bytes: usize) -> Result<()> {
        let current = self.current_total.load(Ordering::SeqCst);
        if current + bytes > self.max_per_connection {
            return Err(anyhow!("Memory limit exceeded"));
        }
        self.current_total.fetch_add(bytes, Ordering::SeqCst);
        Ok(())
    }
}
```

---

### DDOS-004: No Connection Timeout (Slowloris)

**Severity**: High | **CVSS**: 7.5 (High) | **CWE**: CWE-400  
**File**: `src/daemon.rs:93` | **Status**: Pending | **Priority**: P1  
**Dependencies**: SWAP-003

#### Vulnerability Description

No timeout on connections, slow connections block accept loop.

#### Current Code

```rust
// src/daemon.rs:93-99
let (stream, _) = match listener.accept() {
    Ok(pair) => pair,
    Err(err) => {
        logger::error(&format!("IPC accept failed: {err}"));
        continue;
    }
};
```

#### Remediation

```rust
let (stream, peer_addr) = match listener.accept() {
    Ok(pair) => pair,
    Err(err) => {
        logger::error(&format!("IPC accept failed: {err}"));
        continue;
    }
};

stream.set_read_timeout(Some(Duration::from_secs(30)))?;
stream.set_write_timeout(Some(Duration::from_secs(30)))?;
```

---

### IPC-001: Error Messages Not Sanitized

**Severity**: High | **CVSS**: 5.5 (Medium) | **CWE**: CWE-209  
**File**: `src/daemon.rs:119,160,189` | **Status**: Pending | **Priority**: P1

#### Vulnerability Description

Raw error messages leak internal paths, usernames, and system information.

#### Current Code

```rust
logger::error(&format!("IPC handler error: {err}"));
logger::error(&format!("Failed to open database: {err}"));
```

#### Remediation

```rust
logger::error(&sanitize_for_display(&format!("IPC handler error: {err}")));
```

---

### DATA-001: Unencrypted Export Contains Sensitive Data

**Severity**: High | **CVSS**: 7.5 (High) | **CWE**: CWE-200  
**File**: `src/export.rs:45-55` | **Status**: Pending | **Priority**: P1

#### Vulnerability Description

Plain JSON export dumps all items unencrypted.

#### Current Code

```rust
pub fn write_plain_export(path: &Path, items: Vec<Item>) -> Result<usize> {
    let payload = PlainExportFile {
        version: EXPORT_VERSION,
        exported_at: Utc::now().to_rfc3339(),
        items,  // All items in plaintext!
    };
    let data = serde_json::to_string_pretty(&payload)?;
    fs::write(path, data)?;
    Ok(payload.items.len())
}
```

#### Remediation

```rust
pub fn write_plain_export(path: &Path, items: Vec<Item>) -> Result<usize> {
    println!("WARNING: Plain exports contain unencrypted sensitive data.");
    if !confirm("Type 'I UNDERSTAND THE RISKS' to continue: ") {
        return Err(anyhow!("Export cancelled"));
    }
    // ...
}
```

---

### DATA-002: Backup No Integrity Verification

**Severity**: High | **CVSS**: 7.5 (High) | **CWE**: CWE-345  
**File**: `src/backup.rs:23-46` | **Status**: Pending | **Priority**: P1

#### Vulnerability Description

Backups are unsigned copies, tampered backups could be restored.

#### Current Code

```rust
pub fn create_backup(&self, vault_path: &Path, keystore_path: &Path) -> Result<PathBuf> {
    fs::copy(vault_path, &vault_backup)?;
    fs::copy(keystore_path, &keystore_backup)?;
}
```

#### Remediation

```rust
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

fn create_hmac(data: &[u8]) -> Vec<u8> {
    let mut hmac = HmacSha256::new_from_slice(b"keeper-backup-key");
    hmac.update(data);
    hmac.finalize().into_bytes().to_vec()
}

pub fn create_backup(&self, vault_path: &Path, keystore_path: &Path) -> Result<PathBuf> {
    // ... copy files ...
    
    // Create HMAC signature
    let vault_data = fs::read(&vault_backup)?;
    let keystore_data = fs::read(&keystore_backup)?;
    let mut combined = vault_data;
    combined.extend_from_slice(&keystore_data);
    let hmac = create_hmac(&combined);
    fs::write(&hmac_file, &hmac)?;
}
```

---

## Medium Priority Issues (P2)

### AUTH-001: No Socket Channel Binding

**Severity**: Medium | **CVSS**: 5.3 (Medium) | **CWE**: CWE-287  
**File**: `src/daemon.rs:35-58` | **Status**: Pending | **Priority**: P2

#### Remediation

```rust
use std::os::unix::net::UnixPeerCredentials;

let (stream, _) = listener.accept()?;

#[cfg(unix)]
{
    if let Ok(creds) = UnixPeerCredentials::new() {
        let uid = creds.uid();
        let current_uid = unsafe { libc::getuid() };
        if uid != current_uid {
            logger::error(&format!("Connection from unauthorized UID: {}", uid));
            continue;
        }
    }
}
```

---

### AUTH-002: Password Blocklist Too Small

**Severity**: Medium | **CVSS**: 5.3 (Medium) | **CWE**: CWE-521  
**File**: `src/security.rs:63-66` | **Status**: Pending | **Priority**: P2

#### Current Code

```rust
let common_passwords = [
    "password", "123456", "qwerty", "letmein", "admin", "welcome", "monkey", "dragon",
    "master", "hello", "login",
];
```

#### Remediation

Use zxcvbn for entropy estimation:

```rust
// Add: zxcvbn = "2.2.2" to Cargo.toml
use zxcvbn::zxcvbn;

pub fn validate_password_strength<S: AsRef<str>>(password: S) -> Result<()> {
    let password = password.as_ref();
    
    if password.len() < 12 {
        return Err(anyhow!("Password must be at least 12 characters"));
    }

    let estimate = zxcvbn(password);
    if estimate.score() < 3 {
        return Err(anyhow!(
            "Password is too weak (estimated crack time: {}).",
            estimate.crack_time_display()
        ));
    }

    Ok(())
}
```

---

### AUTH-003: No Key Separation Between Operations

**Severity**: Medium | **CVSS**: 5.3 (Medium) | **CWE**: CWE-310  
**File**: `src/security.rs`, `src/keystore.rs` | **Status**: Pending | **Priority**: P2

#### Remediation

Derive separate keys via HKDF:

```rust
// Add: hkdf = "0.12.3", sha2 = "0.10.6"
use hkdf::Hkdf;
use sha2::Sha256;

const DB_KEY_LABEL: &[u8] = b"keeper-database-key";
const ITEM_KEY_LABEL: &[u8] = b"keeper-item-key";

pub fn derive_separated_keys(master_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    
    let mut db_key = [0u8; 32];
    let mut item_key = [0u8; 32];
    
    hk.expand(DB_KEY_LABEL, &[], &mut db_key);
    hk.expand(ITEM_KEY_LABEL, &[], &mut item_key);
    
    (db_key, item_key)
}
```

---

### MISC-003: Constant-Time Compare Length Leak

**Severity**: Medium | **CVSS**: 5.3 (Medium) | **CWE**: CWE-208  
**File**: `src/security/memory.rs:149-160` | **Status**: Pending | **Priority**: P2

#### Current Code

```rust
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    let max_len = std::cmp::max(a.len(), b.len());
    // Length check before comparison leaks information
    use subtle::ConstantTimeEq;
    a_padded.as_slice().ct_eq(b_padded.as_slice()).into()
}
```

#### Remediation

Use `subtle::ConstantTimeEq` without length-dependent padding.

---

### UX-001: Recovery Code Displayed Plaintext

**Severity**: Medium | **CVSS**: 5.3 (Medium) | **CWE**: CWE-532  
**File**: `src/main.rs:84, 154` | **Status**: Pending | **Priority**: P2

#### Remediation

Use secure display with one-time reveal warning and masked storage.

---

### UX-002: TUI History Plaintext

**Severity**: Medium | **CVSS**: 5.3 (Medium) | **CWE**: CWE-312  
**File**: `src/tui.rs:81-85` | **Status**: Pending | **Priority**: P2

#### Remediation

Configure history file with 0o600 permissions and filter sensitive commands.

---

### DATA-003: Import No Data Validation

**Severity**: Medium | **CVSS**: 5.3 (Medium) | **CWE**: CWE-20  
**File**: `src/transfer.rs:110-137` | **Status**: Pending | **Priority**: P2

#### Remediation

Validate all imported items before insertion: check workspace/bucket format, verify due dates.

---

### DATA-004: Export Password Not Validated

**Severity**: Medium | **CVSS**: 5.3 (Medium) | **CWE**: CWE-521  
**File**: `src/transfer.rs:139-146` | **Status**: Pending | **Priority**: P2

#### Remediation

Validate export passwords with same strength requirements as vault passwords.

---

## Low Priority Issues (P3)

### IPC-002: Logger error_raw Bypasses Sanitization

**Severity**: Low | **CVSS**: 3.7 (Low) | **CWE**: CWE-117  
**File**: `src/logger.rs:26-30` | **Status**: Pending | **Priority**: P3

#### Remediation

```rust
pub fn error_raw(message: &str) {
    if is_debug() {
        eprintln!("[ERROR] {}", sanitize_for_display(message));
    }
}
```

---

### MCP-001: Deprecated Password Support Still Present

**Severity**: Low | **CVSS**: 3.7 (Low) | **CWE**: CWE-477  
**File**: `mcp/keeper-mcp/src/main.rs:29-33` | **Status**: Pending | **Priority**: P3  
**Dependencies**: SWAP-001

#### Remediation

Remove all KEEPER_PASSWORD environment variable support.

---

### MISC-001: No Core Dump Limits

**Severity**: Low | **CVSS**: 3.7 (Low) | **CWE**: CWE-200  
**File**: `src/daemon.rs` | **Status**: Pending | **Priority**: P3  
**Dependencies**: SWAP-001

#### Remediation

```rust
#[cfg(unix)]
{
    unsafe {
        libc::setrlimit(
            libc::RLIMIT_CORE,
            &libc::rlimit { rlim_cur: 0, rlim_max: 0 },
        );
    }
}
```

---

### UPDATE-001: Temp Dir Names Predictable

**Severity**: Low | **CVSS**: 3.7 (Low) | **CWE**: CWE-377  
**File**: `src/self_update.rs:318-324` | **Status**: Pending | **Priority**: P3

#### Remediation

Use `tempfile::TempDir` for secure random naming.

---

### UPDATE-002: Self-Update Tag Injection Possible

**Severity**: Low | **CVSS**: 3.7 (Low) | **CWE**: CWE-79  
**File**: `src/self_update.rs:23-32` | **Status**: Pending | **Priority**: P3

#### Remediation

Validate tag format (must be semver or 'latest').

---

### VALID-001: Workspace Path Traversal Possible

**Severity**: Low | **CVSS**: 3.7 (Low) | **CWE**: CWE-22  
**File**: `src/config.rs:54-71` | **Status**: Pending | **Priority**: P3

#### Remediation

Reject special characters in workspace names: `../`, `./`, absolute paths.

---

### VALID-002: Config Workspace Validation Insufficient

**Severity**: Low | **CVSS**: 3.7 (Low) | **CWE**: CWE-20  
**File**: `src/config.rs:54-71` | **Status**: Pending | **Priority**: P3

#### Remediation

Reject workspace names containing: `..`, `/`, `\`, null bytes.

---

### DATA-005: Backup No Secure Delete

**Severity**: Low | **CVSS**: 3.7 (Low) | **CWE-226**  
**File**: `src/backup.rs:98-120` | **Status**: Pending | **Priority**: P3  
**Dependencies**: DATA-002

#### Remediation

Overwrite files with random data before deletion:

```rust
use std::io::{Write, Seek};

fn secure_delete(path: &Path) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    let metadata = file.metadata()?;
    let len = metadata.len();
    
    let mut rng = rand::thread_rng();
    let mut buffer = vec![0u8; 4096];
    
    let mut written = 0u64;
    while written < len {
        rng.fill_bytes(&mut buffer);
        file.write_all(&buffer)?;
        written += buffer.len() as u64;
    }
    
    file.sync_all()?;
    drop(file);
    fs::remove_file(path)?;
    Ok(())
}
```

---

## Implementation Phases

### Phase 1: Critical Memory Protection (Week 1-2)

**Blocked on**: None  
**Deliverable**: Memory locked, no swap leaks

| Task | ID | Effort | Dependencies |
|------|-----|---------|--------------|
| Exit daemon on mlockall failure | SWAP-001 | 4h | None |
| Add client message size limit | SWAP-002 | 3h | None |
| Add daemon message size limit | SWAP-003 | 3h | None |
| Add terminal echo guard | SWAP-006 | 2h | SWAP-001 |

**Commit Template**:
```
fix(security): Phase 1 - Critical memory protection

- mlockall() failure exits daemon (SWAP-001)
- 10MB IPC message size limits (SWAP-002, SWAP-003)
- Terminal echo restoration with scopeguard (SWAP-006)
```

---

### Phase 2: Critical DDoS Protection (Week 2-3)

**Blocked on**: Phase 1  
**Deliverable**: DDoS-resistant daemon

| Task | ID | Effort | Dependencies |
|------|-----|---------|--------------|
| Request rate limiting | DDOS-001 | 8h | SWAP-003 |
| Password rate limit fix | DDOS-002 | 4h | None |
| Per-connection memory limits | DDOS-003 | 4h | SWAP-003 |
| Connection timeout | DDOS-004 | 2h | SWAP-003 |

---

### Phase 3: Memory Leak Prevention (Week 3-4)

**Blocked on**: Phase 1  
**Deliverable**: Zeroized intermediate copies

| Task | ID | Effort | Dependencies |
|------|-----|---------|--------------|
| Keystore salts zeroization | SWAP-007 | 2h | SWAP-001 |
| Database key binary | SWAP-008 | 3h | SWAP-002 |
| IPC key transmission | SWAP-009 | 4h | None |
| JSON serialization sanitization | SWAP-010 | 8h | SWAP-001 |
| Regex manual iteration | SWAP-011 | 3h | None |
| Base64 immediate zeroization | SWAP-012 | 12h | SWAP-001 |
| format!() avoidance | SWAP-013 | 2h | SWAP-009 |

---

### Phase 4: Supply Chain Security (Week 4-5)

**Blocked on**: None  
**Deliverable**: Signed releases

| Task | ID | Effort | Dependencies |
|------|-----|---------|--------------|
| Ed25519 signature verification | SWAP-005 | 16h | None |
| Remove deprecated password support | MCP-001 | 4h | SWAP-001 |

---

### Phase 5: Data Protection (Week 5-6)

**Blocked on**: Phase 3  
**Deliverable**: Safe exports and backups

| Task | ID | Effort | Dependencies |
|------|-----|---------|--------------|
| Error sanitization | IPC-001 | 4h | None |
| Export warnings | DATA-001 | 2h | None |
| Backup HMAC verification | DATA-002 | 8h | None |
| Backup secure delete | DATA-005 | 3h | DATA-002 |
| Import validation | DATA-003 | 6h | None |
| Export password validation | DATA-004 | 2h | None |

---

### Phase 6: Medium Priority (Week 7-8)

| Task | ID | Effort | Dependencies |
|------|-----|---------|--------------|
| Socket channel binding | AUTH-001 | 2h | None |
| Password strength zxcvbn | AUTH-002 | 3h | None |
| Key separation HKDF | AUTH-003 | 3h | None |
| Constant-time fix | MISC-003 | 1h | None |
| Recovery code display | UX-001 | 2h | None |
| TUI history protection | UX-002 | 2h | None |

---

### Phase 7: Low Priority Cleanup (Week 9-10)

| Task | ID | Effort | Dependencies |
|------|-----|---------|--------------|
| Logger error_raw fix | IPC-002 | 0.5h | None |
| Core dump limits | MISC-001 | 0.5h | SWAP-001 |
| Secure temp dir | UPDATE-001 | 1h | None |
| Tag validation | UPDATE-002 | 0.5h | None |
| Workspace validation | VALID-001 | 1h | None |
| Config validation | VALID-002 | 1h | None |

---

## Dependency Graph

```
PHASE 1 (Critical Memory)
SWAP-001 ──┬─► SWAP-006 (Echo Guard)
SWAP-002 ──┤
SWAP-003 ──┴─► DDOS-001 (Rate Limit) ──► DDOS-003 (Mem) ──► DDOS-004 (Timeout)
                     │
                     └─► DDOS-002 (Password)
                     │
SWAP-001 ──────────► SWAP-007 (Keystore) ──► SWAP-012 (Base64)
SWAP-002 ──────────► SWAP-008 (DB Key)
SWAP-001 ──────────► SWAP-010 (JSON)
                    │
SWAP-009 ──────────► SWAP-013 (format!)

PHASE 4 (Supply Chain)
SWAP-005 (Signatures)
SWAP-001 ──────────► MCP-001 (No Password)

PHASE 5 (Data Protection)
IPC-001 (Error Sanitize)
DATA-001 (Export Warning)
DATA-002 (Backup HMAC) ──► DATA-005 (Secure Delete)
```

---

## Testing & Verification

### Unit Tests

```rust
// tests/security/swap_tests.rs
#[cfg(test)]
mod swap_tests {
    #[test] fn test_mlockall_failure_exits() {}
    #[test] fn test_ipc_size_limit_enforced() {}
    #[test] fn test_terminal_echo_restored() {}
    #[test] fn test_keystore_salts_zeroized() {}
    #[test] fn test_base64_immediate_zeroization() {}
    #[test] fn test_regex_no_password_copies() {}
}

// tests/security/ddos_tests.rs
#[cfg(test)]
mod ddos_tests {
    #[test] fn test_rate_limiting() {}
    #[test] fn test_password_rate_limit() {}
    #[test] fn test_per_connection_memory_limit() {}
    #[test] fn test_connection_timeout() {}
}

// tests/security/cryptography_tests.rs
#[cfg(test)]
mod cryptography_tests {
    #[test] fn test_signature_verification() {}
    #[test] fn test_backup_hmac() {}
    #[test] fn test_key_separation() {}
}
```

### Integration Tests

```rust
#[test]
fn test_swap_protection_e2e() {
    let temp = tempdir().unwrap();
    
    cargo_bin_cmd!("keeper")
        .env("HOME", temp.path())
        .env("KEEPER_TEST_MLOCKALL_FAIL", "1")
        .arg("start")
        .write_stdin("password\npassword\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("CRITICAL"));
}

#[test]
fn test_ddos_resistance_e2e() {
    // Rate limiting test
    // Password lockout test
    // Message size limit test
}
```

### Memory Analysis Test Script

```bash
#!/bin/bash
# tests/security/swap_analysis.sh
set -e

VAULT_DIR=$(mktemp -d -t keeper-test-XXXXXX)
export HOME="$VAULT_DIR"

sudo swapoff /swapfile 2>/dev/null || echo "Warning: Could not disable swap"

keeper start <<EOF
TestPassword123!
TestPassword123!
EOF

keeper note "Secret task with password MySecretKey !p1"

SECRETS=("password" "key" "secret" "token" "master" "vault")
FOUND=false
for secret in "${SECRETS[@]}"; do
    if strings /swapfile 2>/dev/null | grep -i "$secret" | grep -v "keeper" > /dev/null; then
        echo "WARNING: Found '$secret' in swap!"
        FOUND=true
    fi
done

if [ "$FOUND" = true ]; then
    echo "TEST FAILED: Secrets found in swap"
    exit 1
else
    echo "TEST PASSED: No secrets found in swap"
fi

keeper stop
rm -rf "$VAULT_DIR"
sudo swapon /swapfile 2>/dev/null || echo "Swap restored"
```

---

## Rollback Procedures

### Phase 1 Rollback

```bash
# mlockall exit - allow swap with warning
export KEEPER_ALLOW_SWAP=1
keeper start

# Message size limit - increase to 50MB
export KEEPER_MAX_IPC_SIZE=52428800
```

### Phase 2 Rollback

```bash
# Disable rate limiting
export KEEPER_DISABLE_RATE_LIMIT=1

# Reduce lockout
echo "PASSWORD_LOCKOUT_SEC=60" >> ~/.keeperrc
```

### Phase 4 Rollback

```bash
# Skip signature check (DANGER)
export KEEPER_SKIP_SIGNATURE_CHECK=1
```

### Phase 5 Rollback

```bash
# Skip HMAC check (DANGER)
export KEEPER_SKIP_HMAC_CHECK=1
```

---

## Security Metrics & Monitoring

### Metrics to Track

| Metric | Collection Method | Alert Threshold |
|--------|------------------|-----------------|
| Swap secrets detected | Periodic swap analysis | > 0 |
| mlockall failures | Daemon logs | > 0/hour |
| Failed auth attempts | Rate limiter | > 10/min |
| Password lockouts | Daemon logs | > 5/hour |
| Rate limit hits | Daemon metrics | > 100/min |
| Memory limit hits | Daemon metrics | > 10/min |
| Oversized messages | Daemon logs | > 1/hour |
| Backup verifications failed | Restore logs | > 0 |
| Signature failures | Update logs | > 0 |

### Alert Script

```bash
#!/bin/bash
# scripts/security-alert.sh

if journalctl -u keeper --since "5 minutes ago" | grep -q "mlockall_failures=[1-9]"; then
    echo "ALERT: mlockall failure detected" | mail -s "Keeper Security Alert" admin@example.com
fi

if journalctl -u keeper --since "5 minutes ago" | grep -q "failed_auth_attempts>100"; then
    echo "ALERT: High failed auth rate" | mail -s "Keeper Security Alert" admin@example.com
fi
```

---

## Compliance Mapping

| Standard | Keeper (Current) | Keeper (After Fixes) | Status |
|----------|------------------|---------------------|--------|
| CWE-120 (Buffer Overflow) | Safe Rust | Safe Rust + size limits | Pass |
| CWE-200 (Sensitive Info) | Swap leaks | Full protection | Pass |
| CWE-307 (Auth) | Weak rate limiting | Sliding window | Pass |
| CWE-400 (Resource Consumption) | No limits | All mitigations | Pass |
| CWE-494 (Supply Chain) | No signatures | Ed25519 | Pass |
| OWASP A2 (Crypto) | No key separation | HKDF separation | Pass |
| OWASP A5 (Auth) | Weak password rules | zxcvbn entropy | Pass |
| GDPR Article 32 (Data Security) | Swap leaks | Full protection | Pass |

---

## Appendices

### Appendix A: Files Modified Summary

| File | Lines Changed | Changes | Tests Added |
|------|---------------|---------|--------------|
| src/daemon.rs | 27-30, 60, 84-99, 119, 160, 172-185 | mlockall, size limit, rate limiting, timeouts, error sanitization | 4 |
| src/client.rs | 21 | Message size limit | 2 |
| src/session.rs | 48, 67-68 | Direct byte write, avoid format! | 2 |
| src/keystore.rs | 80-86 | Zeroize before encoding | 2 |
| src/security.rs | 34-36, 63-76 | Binary key, zxcvbn | 3 |
| src/security/memory.rs | 149-160 | Constant-time fix | 1 |
| src/sanitize.rs | 4-11 | Manual iteration | 2 |
| src/prompt.rs | 60-70 | scopeguard | 1 |
| src/db.rs | 54-66 | Binary key acceptance | 2 |
| src/export.rs | 45-55, 72-76, 89-94 | Warnings, password validation | 3 |
| src/backup.rs | 23-46, 98-120 | HMAC, secure delete | 3 |
| src/transfer.rs | 139-146 | Export password validation | 1 |
| src/logger.rs | 26-30 | error_raw sanitization | 1 |
| src/self_update.rs | 23-32, 177-202 | Tag validation, signature verification | 2 |
| mcp/keeper-mcp/src/main.rs | 29-33, 516-527 | Remove password support | 1 |

### Appendix B: New Dependencies

```toml
[dependencies]
scopeguard = "1.2.0"
minisign = "0.7.3"
base64 = "0.22"
zxcvbn = "2.2.2"
hkdf = "0.12.3"
hmac = "0.12.1"
sha2 = "0.10.6"
```

### Appendix C: New Test Files

| File | Tests |
|------|-------|
| tests/security/swap_tests.rs | 7 tests |
| tests/security/ddos_tests.rs | 4 tests |
| tests/security/cryptography_tests.rs | 3 tests |
| tests/e2e/security_e2e.rs | 2 tests |
| scripts/security_audit.sh | - |
| scripts/security-alert.sh | - |
| tests/security/swap_analysis.sh | - |

---

**End of Security Fixes Plan**
