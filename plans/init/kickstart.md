# 🚀 Document 6: Agent Kickstart Guide (kickstart.md)

**Welcome, Agent.** Your mission is to build "Keeper" in Rust. Follow this guide sequentially.

---

### 📂 Documentation Map

| Filename | Purpose for Agent |
| :--- | :--- |
| **`requirements.md`** | Understand user behavior and syntax rules. |
| **`hld.md`** | Understand Client vs. Daemon responsibility split. |
| **`lld.md`** | **Primary Blueprint.** Copy dependencies, structs, SQL, IPC exactly. |
| **`mocks.md`** | Target visual output for validation. |
| **`testing.md`** | Tools and strategies for verification. |

---

### 🛠️ Implementation Phases

#### Phase 1: Foundation & Domain
1.  Init project. Copy dependencies from **`lld.md`** to `Cargo.toml`.
2.  Implement Structs and Enums defined in **`lld.md`**.
3.  Set up `clap` CLI structure from **`lld.md`**.
4.  *Task:* Implement the sigil parser (`@`, `!`, `^`) to convert raw text into a `NoteArgs` struct. Write unit tests.

#### Phase 2: Storage Layer (SQLite)
1.  Set up `rusqlite` with SQLCipher.
2.  Implement SQL schema migration from **`lld.md`**.
3.  Create DB traits/functions: `init(key)`, `insert_item`, `query_items`. Implement data conversion between Rust Structs and SQL types (especially Dates).

#### Phase 3: The Daemon Core
1.  Implement `keeper start`: Password prompt -> Argon2 KDF -> Daemonize.
2.  Set up Tokio runtime. Create Unix Socket listener.
3.  Implement IPC loop: Deserialize `DaemonRequest` (from `lld.md`), execute DB call, serialize `DaemonResponse`.

#### Phase 4: Client Connection
1.  Implement client logic to connect to the Unix Socket.
2.  Wire up `note` and `get` CLI commands to send IPC requests.
3.  Format responses using `tabled` to match **`mocks.md`**.
4.  *Test:* Write E2E tests using strategies in **`testing.md`**.

#### Phase 5: Interactive Dashboard (REPL)
1.  Implement `reedline` loop for interactive mode.
2.  On connect, fetch dash stats from daemon.
3.  Render ASCII dashboard matching **`mocks.md`**.
4.  *Test:* Use `insta` snapshots to verify TUI layout.
