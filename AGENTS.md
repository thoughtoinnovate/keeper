# AGENTS.md - Agent Coding Guidelines for Keeper

This document provides guidelines for AI agents working on the Keeper codebase.

## Build & Test Commands

### Core Commands
```bash
cargo build                    # Debug build
cargo build --release          # Release build
cargo fmt --all -- --check     # Check formatting (use `cargo fmt` to fix)
cargo clippy -- -D warnings    # Lint with warnings as errors
cargo test                     # Run all tests
```

### Running Single Tests
```bash
cargo test <test_name>                        # Run specific test by name
cargo test <module_name> -- --test-threads=1  # Run tests in specific module
cargo test -- --test bdd                      # Run BDD tests
cargo test -- --test e2e                      # Run e2e tests
cargo test -- --list                          # List all available tests
```

### Snapshots
```bash
cargo test --accept          # Update all snapshots
# Snapshots stored in tests/snapshots/
# Use insta::assert_snapshot!(output) for output verification
```

### Cross-compilation
- Uses Cross.toml for aarch64-linux-gnu targets
- Dependencies: libssl-dev:arm64, zlib1g-dev:arm64

## Code Style

### Imports
External crates first, alphabetically. Internal modules with `use crate::*`. Separate groups with blank lines:
```rust
use std::fs;
use std::path::Path;

use anyhow::{Result, anyhow};
use chrono::Utc;

use crate::models::Item;
use crate::paths::KeeperPaths;
```

### Types & Naming
- `anyhow::Result<T>` for fallible functions
- `snake_case` for functions/variables
- `PascalCase` for types/structs/enums
- `SCREAMING_SNAKE_CASE` for constants
- Async: `async fn` prefix

### Error Handling
```rust
use anyhow::{Result, anyhow};

// Simple errors
return Err(anyhow!("Invalid input"));

// Error with context
db.insert_item(...).context("Failed to save item")?;

// IMPORTANT: Sanitize before logging
logger::debug(&sanitize_for_display(&format!("Key: {}", key)));
```

**CRITICAL**: Never log passwords, keys, or recovery codes. Always use `sanitize_for_display()` from `src/sanitize.rs`.

### Security Practices (MUST FOLLOW)
```rust
use zeroize::Zeroize;
use crate::security::memory::{SecurePassword, SecretString, constant_time_compare};

// Zeroize sensitive data immediately after use
let mut password = vec![...];
password.zeroize();

// Use SecurePassword/SecretString for IPC
let secure_pass = SecurePassword::from_str("secret");

// Constant-time comparison for passwords
if constant_time_compare(pass1.as_bytes(), pass2.as_bytes()) {
    // ...
}

// Validate all inputs
validate_workspace(workspace)?;
validate_bucket(bucket)?;
parse_due_date_strict(date)?;
```

**File Permissions (Unix)**:
- Vault directory: `0o700`
- vault.db: `0o600`
- keystore.json: `0o600`
- socket: `0o600`

### Testing
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example() {
        assert_eq!(result, expected);
    }
}
```

**E2e tests** (`tests/e2e.rs`):
```rust
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn test_flow() {
    let temp = tempdir().unwrap();
    cargo_bin_cmd!("keeper")
        .env("HOME", temp.path())
        .arg("start")
        .write_stdin("password\npassword\n")
        .assert()
        .success();
}
```

**BDD tests** (`tests/bdd/features/*.feature`):
- Use Gherkin syntax (Given/When/Then)
- Implementation in `tests/bdd.rs`
- Run with `cargo test --test bdd`

**Snapshots**:
```rust
insta::assert_snapshot!(output);
```

Add sleep after daemon start:
```rust
std::thread::sleep(std::time::Duration::from_millis(200));
```

### Code Organization
- One public purpose per file
- Keep functions under 50 lines when possible
- Use early returns: `if error { return Err(...); }`
- Module declarations in `src/main.rs`

## Architecture

### Core Components
- **Daemon**: `src/daemon.rs` - Background process holding master key in RAM (30-min auto-lock)
- **Client**: `src/client.rs` - CLI sends requests via Unix socket
- **IPC**: `src/ipc.rs` - DaemonRequest/DaemonResponse enums for communication
- **Database**: `src/db.rs` - SQLite with SQLCipher encryption (AES-256-CBC)
- **Keystore**: `src/keystore.rs` - Master key wrapped by password & 24-word recovery
- **Security**: `src/security.rs` - Argon2id KDF, memory protection, constant-time ops
- **Sigil**: `src/sigil.rs` - Parse `@workspace/bucket`, `!p1/p2/p3`, `^date`

### MCP Server
Separate binary: `mcp/keeper-mcp/`
```rust
// Environment vars
KEEPER_VAULT="/path/to/vault"
KEEPER_READONLY="true"
KEEPER_ALLOW_PASSWORD_OPS="false"
KEEPER_AUTO_START="false"
```
Tools: keeper.status, keeper.note, keeper.get, keeper.update, keeper.mark, keeper.delete, keeper.archive, keeper.dash_due_timeline

### Sigil Syntax
- `@workspace/bucket` - Context/category (default: `@default/inbox`)
- `!p1`, `!p2`, `!p3` - Priority (P1=Urgent, P2=Important, P3=Task)
- `^date` - Due date (`^2026-01-31`, `^today`, `^tomorrow`)

## Security Requirements

### NEVER Do:
- Log passwords, keys, or recovery codes (use `sanitize_for_display()`)
- Write secrets to files without proper permissions
- Store plaintext passwords in memory longer than necessary

### ALWAYS Do:
- Zeroize sensitive data: `password.zeroize()`, `master_key.zeroize()`
- Use constant-time comparison for password checks
- Validate workspace names: start with `@`, 2-50 chars, valid chars only
- Set `0o600` permissions on vault.db, keystore.json, and socket on Unix
- Use `SecurePassword`/`SecretString` for passwords in IPC

### Key Files Reference
- `src/security.rs` - KDF, master key generation, password validation
- `src/security/memory.rs` - Secure types, constant-time comparison
- `src/sanitize.rs` - Error message sanitization
- `src/keystore.rs` - Key wrapping/unwrapping with XChaCha20Poly1305
- `src/ipc.rs` - IPC message definitions
