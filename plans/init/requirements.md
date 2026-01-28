# 📘 Document 1: Requirements Specification (requirements.md)

### 1. Vision & Scope
**"Keeper"** is a high-performance, lightweight, command-line "second brain" and task manager. It is designed for terminal-centric users who value speed, security, and frictionless capture. It prioritizes keyboard-driven workflows over graphical interfaces.

### 2. Core Principles
1.  **Security First:** Data is encrypted at rest (AES-256 via SQLCipher). The decryption key exists only in the RAM of the background daemon process.
2.  **Instant Capture:** Adding notes must be sub-millisecond operations that do not require a password prompt.
3.  **Keyboard Centric:** All interactions (CLI and Interactive Dashboard) must be operable via keyboard.
4.  **Single Binary:** The tool compiles to a single, portable Rust executable containing both client and daemon logic.

### 3. Functional Requirements

#### 3.1. Session Management (The Daemon)
* **`keeper start`**: Prompts for password once. Derives key, starts background daemon, detaches process.
* **`keeper stop`**: Stops daemon, wiping key from RAM.
* **`keeper status`**: Checks if daemon is running and listening.

#### 3.2. Quick Capture (Client CLI)
* **`keeper note <text...> [flags]`**: Sends item to daemon. **No password required** if daemon is running.
* **Sigil Syntax Parsing:** The client must parse special characters within the input text arguments:
    * `@bucket`: Context/Category (e.g., `@work`). Default: `@inbox`.
    * `!p1`, `!p2`, `!p3`: Priority levels.
    * `^date`: Due date (natural language like `^today` or ISO `^2025-12-31`).
* **Reference vs. Task Logic:**
    * If a priority sigil (`!pX`) exists, it is a **Task**.
    * If NO priority sigil exists, it is a **Reference Note** (internally `Priority::None`).

#### 3.3. Retrieval & Management
* **`keeper get [filters]`**: Retrieves items based on flags (bucket, priority, date).
* **`keeper mark <id> <status>`**: Updates item status (e.g., `done`, `deleted`).
* **`keeper update <id> <content...>`**: Modifies existing item text or attributes via sigils.

#### 3.4. The Interactive Dashboard (REPL)
* **`keeper` (no args)**: Connects to daemon and enters interactive TUI.
* **The Dash:** Displays immediately on entry (Top P1s, Upcoming Deadlines, Stats). See `mocks.md`.
* **Shell:** Provides auto-completion for commands and existing buckets.

### 4. Non-Functional Requirements
* **Performance:** CLI commands return in <50ms.
* **Storage:** Encrypted SQLite file at `~/.keeper/vault.db`.
* **Config:** TOML file at `~/.keeper/config.toml`.
