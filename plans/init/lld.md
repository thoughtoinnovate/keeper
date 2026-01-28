# 📘 Document 3: Low-Level Design (lld.md) - Rust Specific

### 1. Cargo Dependencies (Cargo.toml)
Use these specific crates and feature flags.

```toml
[dependencies]
# CLI & Async
clap = { version = "4.4", features = ["derive"] }
tokio = { version = "1.32", features = ["full"] }
# UI & Formatting
reedline = "0.24"
tabled = "0.14"
# Daemon & IPC
daemonize = "0.5"
interprocess = "1.2" # Or tokio::net::UnixStream
# Database (Crucial: bundled-sqlcipher)
rusqlite = { version = "0.29", features = ["bundled-sqlcipher"] }
# Security
argon2 = "0.5"
zeroize = "1.6"
# Time & Serialization
chrono = { version = "0.4", features = ["serde"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
# Utils
thiserror = "1.0"
anyhow = "1.0"
directories = "5.0" # For finding home dir correctly across OS
```

### 2. Core Data Models (Rust Structs)

```rust
// models.rs
use chrono::{DateTime, Utc, NaiveDate};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Serialize, Deserialize, PartialEq, PartialOrd, Clone, Copy)]
pub enum Priority {
    P1_Urgent,   // !p1
    P2_Important,// !p2
    P3_Task,     // !p3
    None,        // No sigil provided (Reference Note)
}

// Needed for displaying in tables
impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Priority::P1_Urgent => write!(f, "🚨 P1"),
            Priority::P2_Important => write!(f, "⭐ P2"),
            Priority::P3_Task => write!(f, "✅ P3"),
            Priority::None => write!(f, "📝 Note"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
pub enum Status {
    Open,
    Done,
    Deleted,
}

// The main entity. Note: dates are typically stored as strings in SQLite.
// Ensure your DB layer handles conversion between Option<NaiveDate> and String.
#[derive(Debug, Serialize, Deserialize)]
pub struct Item {
    pub id: i64,
    pub bucket: String,
    pub content: String,
    pub priority: Priority,
    pub status: Status,
    pub due_date: Option<NaiveDate>, 
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>, 
}
```

### 3. Database Schema (SQL)

```sql
-- migration_init.sql
-- Note: PRAGMA key is handled by rusqlite code, not sql file.

CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket TEXT NOT NULL,
    content TEXT NOT NULL,
    priority TEXT NOT NULL, -- Store enum as string
    status TEXT NOT NULL,   -- Store enum as string
    due_date TEXT,          -- Store as ISO8601 YYYY-MM-DD or NULL
    created_at TEXT NOT NULL, -- ISO8601 timestamp
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bucket ON items(bucket);
CREATE INDEX IF NOT EXISTS idx_status_priority ON items(status, priority);
CREATE INDEX IF NOT EXISTS idx_due_date ON items(due_date);
```

### 4. IPC Protocol (Client <-> Daemon)
Serialize these enums using `serde_json` over Unix Socket.

```rust
// ipc.rs
use crate::models::{Item, Priority, Status};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonRequest {
    CreateNote {
        bucket: String,
        content: String,
        priority: Priority,
        due_date: Option<NaiveDate>,
    },
    GetItems {
        bucket_filter: Option<String>,
        priority_filter: Option<Priority>,
        status_filter: Option<Status>,
        date_cutoff: Option<NaiveDate>, 
    },
    UpdateStatus { id: i64, new_status: Status },
    GetDashboardStats, 
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonResponse {
    OkMessage(String),
    OkItems(Vec<Item>),
    // Create a specific struct for dash stats if needed
    OkStats { open: i64, done_today: i64, p1: i64 }, 
    Error(String),
}
```

### 5. CLI Structure (Clap)

```rust
// cli.rs
use clap::{Parser, Subcommand, Args};

#[derive(Parser)]
#[command(name = "keeper", about = "Encrypted second brain terminal tool.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Start,
    Stop,
    Status,
    Note(NoteArgs),
    Get(GetArgs),
    Mark { id: i64, status: String },
}

#[derive(Args)]
pub struct NoteArgs {
    /// Raw text content, may contain sigils (@bucket !p1 ^date)
    pub content: Vec<String>, 
}

#[derive(Args)]
pub struct GetArgs {
    #[arg(short, long)]
    pub bucket: Option<String>,
    // Add other filters...
}
```
