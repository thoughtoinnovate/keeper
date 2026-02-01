# Keeper

Keeper is an encrypted CLI "second brain" that runs a local daemon so you can capture notes and tasks without re-entering your password every time.

## Features
- Encrypted vault backed by SQLCipher
- Password + 24-word recovery code
- Fast capture via CLI and REPL dashboard
- Due-date timeline (ASCII + Mermaid)
- Optional MCP server for AI tool access

## Install
```bash
curl -fsSL https://github.com/thoughtoinnovate/keeper/raw/main/install.sh | sh
```

The installer downloads the latest release, verifies a SHA-256 checksum, and **automatically sets up security capabilities** (on Linux).

### 🔐 Security Setup (Linux/macOS)

Keeper uses memory locking to prevent your encryption keys from being swapped to disk. This requires the `CAP_IPC_LOCK` capability on Linux.

**The install script handles this automatically**, but if you see permission errors:

```bash
# Grant capability (one-time setup)
sudo setcap cap_ipc_lock+ep /usr/local/bin/keeper

# Verify it's set
getpcaps $(pgrep -f "keeper daemon")
```

**⚠️ Important:** Never run `keeper start` with `sudo`. It creates root-owned files you can't access without sudo. Use capabilities instead.

## Quick start
```bash
# Start the daemon (first run initializes vault + recovery code)
keeper start

# Capture a task
keeper note "Fix auth bug" @default/work !p1 ^2026-02-01

# Fetch items
keeper get @default

# Stop the daemon
keeper stop
```

## Workspaces and buckets
Buckets are hierarchical. The top-level segment is the workspace:
```
@default/inbox
@feedback/bugs
@ideas/buckets
```

If you omit a bucket, Keeper uses the default workspace inbox (e.g. `@default/inbox`). If you specify a bucket, it must include a workspace.

## Vaults and paths
By default, Keeper uses:
- `~/.keeper/vault.db`
- `~/.keeper/keystore.json`

Use `--vault` to target a different location:
```bash
keeper --vault /path/to/vault start
keeper --vault /path/to/vault note "..." @default/work !p2
```

Notes:
- `--vault` can be a directory or a `vault.db` file.
- Each vault has its own socket and keystore in the vault directory.

## Recovery and password changes
- Recovery (forgot password):
  ```bash
  keeper recover
  ```
- Change password while daemon runs:
  ```bash
  keeper passwd
  ```

## Update keeper
```bash
keeper update
keeper update --tag v0.1.0
```
Updates verify SHA-256 checksums before installing.

## Export / import
Plain JSON (merge by id on import):
```bash
keeper export --json keeper.json
keeper import --json keeper.json
```

Encrypted bundle (password-protected):
```bash
keeper export --encrypted backup.keeper
keeper import --encrypted backup.keeper
```

Use `--force` to overwrite existing export files or existing vault files on encrypted import.

## Commands
- `keeper start|stop|status`
- `keeper note <text...> [@workspace/bucket] [!p1|!p2|!p3] [^date]`
- `keeper get [@workspace|@workspace/bucket] [--all] [--notes]`
- `keeper mark <id> <open|done|deleted>`
- `keeper update <id> <text...> [@workspace/bucket] [!p1|p2|p3|none] [^date|^clear]`
- `keeper workspace list|current|set @workspace`
- `keeper bucket list [@workspace]`
- `keeper bucket move <from> <to>`
- `keeper delete <id>` / `keeper delete --all`
- `keeper undo [id]`
- `keeper archive`
- `keeper dash due_timeline [--mermaid] [--workspace @default]` (Mermaid output colors by priority)

## MCP server (AI tools)
The MCP server is a separate binary under `mcp/keeper-mcp`. See `MCP_AGENT_GUIDE.md` for setup and tool docs.

## License
MIT. See `LICENSE`.
