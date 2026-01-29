# Keeper User Guide

## What Keeper Is
Keeper is a fast, encrypted CLI “second brain” that runs a local daemon. The daemon keeps the vault key in RAM so you can capture notes without re‑entering your password each time.

## Quick Start
```bash
# Start the daemon (first run will initialize a vault + show a recovery code)
keeper start

# Capture a task
keeper note "Fix auth bug" @work !p1 ^2026-02-01

# Fetch items
keeper get @work

# Stop the daemon (wipes key from RAM)
keeper stop
```

## Vaults and Paths
By default, Keeper uses `~/.keeper/vault.db` and `~/.keeper/keystore.json`.

Use `--vault` to target a different location:
```bash
keeper --vault /path/to/vault start
keeper --vault /path/to/vault note "..." @work !p2
```

Notes:
- `--vault` can be a directory **or** a `vault.db` file.
- Relative `--vault` paths are resolved to absolute paths automatically.
- Each vault has its own socket and keystore in the vault directory.

## Security Model (Short Version)
- The DB is encrypted with a **random 256‑bit master key**.
- The master key is stored only in `keystore.json`, **wrapped** by:
  - your password, and
  - your 24‑word recovery code.
- `keystore.json` never stores your password or recovery code in plaintext.
- When the daemon is running, the master key is held in RAM.

### File Permissions
On Unix, Keeper automatically hardens permissions:
- Vault directory: `0700`
- `vault.db`: `0600`
- `keystore.json`: `0600`

## Recovery Code (Backup Code)
You receive a 24‑word recovery code **once**, when a vault is created:
```
🧩 Recovery Code (store this safely):
<24 words>
```
Store it offline. It cannot be shown again.

## Password Reset (Recovery Flow)
If you forgot your password but still have the recovery code:
```bash
keeper recover
```
You’ll be prompted for the 24‑word code and a new password.

With a custom vault:
```bash
keeper --vault /path/to/vault recover
```

## Change Password (Daemon Running)
If the daemon is running, rotate the password:
```bash
keeper passwd
```
You must enter the **current password** and then set a new one.

## Commands
### Session
- `keeper start` — unlocks/starts the daemon (auto‑init on first run)
- `keeper stop` — stops the daemon and wipes key from RAM
- `keeper status` — shows daemon status

### Capture and Retrieval
- `keeper note <text...> [@bucket] [!p1|!p2|!p3] [^date]`
- `keeper get [@bucket] [--all] [--notes]`
  - default shows open tasks
  - `--all` includes notes
  - `--notes` shows only notes
- `keeper mark <id> <open|done|deleted>`
- `keeper update <id> <text...> [@bucket] [!p1|p2|p3|none] [^date|^clear]`

### Archive and Undo
- `keeper delete <id>` — soft‑delete a single item
- `keeper delete --all` — archive all items (requires `YES` confirmation)
- `keeper undo [id]` — restore last archived or a specific id
- `keeper archive` — list archived items

### Security
- `keeper passwd` — change password (requires current password)
- `keeper recover` — reset password using recovery code

### REPL / Dashboard
Run `keeper` with no arguments to enter the interactive dashboard (REPL).

## Sigil Syntax (Quick Capture)
Use sigils anywhere in note text:
- `@bucket` → context/category (default: `@inbox`)
- `!p1 !p2 !p3` → priority (task vs note)
- `^date` → due date (`YYYY-MM-DD`, `^today`, `^tomorrow`)

Example:
```bash
keeper note "Prep deck @work !p1 ^2026-02-10"
```

Update a task by id:
```bash
keeper update 42 "!p2 ^2026-02-15"
keeper update 42 "New content @work"
keeper update 42 "^clear"
```

## Duplicate Handling
If an identical open item already exists in the same bucket with the same priority and due date, Keeper will return:
```
[=] Duplicate ignored ...
```

## Backups (Recommended)
Backup **all three**:
- `vault.db`
- `keystore.json`
- your recovery code (offline)

If `keystore.json` is lost, the vault is unrecoverable once the daemon stops.

## Troubleshooting
### “Daemon failed to start”
Usually means the socket wasn’t created. Ensure you have permissions to write the vault directory.

### “Invalid request: missing field `password`”
Your daemon is older than your CLI. Run:
```bash
keeper stop
keeper start
```

## Tests
Run all tests:
```bash
cargo test
```

Current coverage:
- Sigil parsing unit tests (`src/sigil.rs`)
- End‑to‑end quick capture flow (`tests/e2e.rs`)
- BDD scenarios in `tests/bdd/features/` (run via `cargo test --test bdd`)

Not yet covered:
- REPL behaviors
- Permission hardening verification on all platforms
- Archive/undo edge cases
