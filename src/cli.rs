use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "keeper", about = "Encrypted second brain terminal tool.")]
pub struct Cli {
    #[arg(long, global = true, help = "Enable debug logging")]
    pub debug: bool,
    #[arg(
        long,
        global = true,
        value_name = "path",
        help = "Vault directory or vault.db path"
    )]
    pub vault: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Start,
    Stop,
    Status,
    Passwd,
    Recover(RecoverArgs),
    Note(NoteArgs),
    Get(GetArgs),
    Mark { id: i64, status: String },
    Delete(DeleteArgs),
    Undo(UndoArgs),
    Archive,
    #[command(hide = true)]
    Daemon,
}

#[derive(Args)]
pub struct NoteArgs {
    /// Raw text content, may contain sigils (@bucket !p1 ^date)
    pub content: Vec<String>,
}

#[derive(Args)]
pub struct GetArgs {
    /// Bucket filter (positional), e.g. @work
    #[arg(value_name = "bucket")]
    pub bucket: Option<String>,
    #[arg(short, long)]
    pub bucket_flag: Option<String>,
    /// Include notes (no due date)
    #[arg(long)]
    pub all: bool,
    /// Show only notes (no due date)
    #[arg(long)]
    pub notes: bool,
    // Add other filters...
}

#[derive(Args)]
pub struct DeleteArgs {
    pub id: Option<i64>,
    #[arg(long)]
    pub all: bool,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct UndoArgs {
    pub id: Option<i64>,
}

#[derive(Args)]
pub struct RecoverArgs {
    #[arg(long)]
    pub code: Option<String>,
}
