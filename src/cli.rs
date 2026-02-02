use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "keeper",
    about = "Encrypted second brain terminal tool.",
    version
)]
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
    #[arg(
        long,
        global = true,
        help = "Show recovery code on screen (default: secure display)"
    )]
    pub show_recovery: bool,
    #[command(subcommand)]
    pub command: Option<Commands>,
    #[arg(long, global = true, help = "Check if a newer version is available")]
    pub check_update: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    Start,
    Stop,
    Status,
    Doctor(DoctorArgs),
    Passwd,
    Recover(RecoverArgs),
    Note(NoteArgs),
    Get(GetArgs),
    Mark {
        id: i64,
        status: String,
    },
    Update(UpdateArgs),
    Dash(DashArgs),
    Keystore(KeystoreArgs),
    Delete(DeleteArgs),
    Undo(UndoArgs),
    Archive,
    Export(ExportArgs),
    Import(ImportArgs),
    Workspace(WorkspaceArgs),
    Bucket(BucketArgs),
    Migrate(MigrateArgs),
    #[command(hide = true)]
    Daemon,
}

#[derive(Args)]
pub struct NoteArgs {
    /// Raw text content, may contain sigils (@workspace/bucket !p1 ^date)
    pub content: Vec<String>,
}

#[derive(Args)]
pub struct GetArgs {
    /// Bucket/workspace filter (positional), e.g. @default or @default/work
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
pub struct UpdateArgs {
    pub id: Option<i64>,
    #[arg(trailing_var_arg = true)]
    pub content: Vec<String>,
    #[arg(
        long,
        value_name = "TAG",
        help = "Update keeper to a specific release tag (e.g. v0.2.0)"
    )]
    pub tag: Option<String>,
    #[arg(long = "self", help = "Update the keeper binary itself")]
    pub self_update: bool,
    #[arg(long, help = "Skip migration check (for automation)")]
    pub skip_migration_check: bool,
    #[arg(long, help = "Force update even if migration issues")]
    pub force: bool,
}

#[derive(Args)]
pub struct RecoverArgs {
    #[arg(long)]
    pub code: Option<String>,
}

#[derive(Args)]
pub struct DoctorArgs {
    #[arg(long, help = "Attempt to apply recommended fixes (may require sudo)")]
    pub fix: bool,
}

#[derive(Args)]
pub struct DashArgs {
    #[command(subcommand)]
    pub command: DashCommands,
}

#[derive(Subcommand)]
pub enum DashCommands {
    #[command(name = "due_timeline", alias = "due-timeline")]
    DueTimeline {
        #[arg(long)]
        mermaid: bool,
        #[arg(long, value_name = "workspace")]
        workspace: Option<String>,
    },
}

#[derive(Args)]
pub struct KeystoreArgs {
    #[command(subcommand)]
    pub command: KeystoreCommands,
}

#[derive(Subcommand)]
pub enum KeystoreCommands {
    Rebuild,
}

#[derive(Args)]
pub struct WorkspaceArgs {
    #[command(subcommand)]
    pub command: WorkspaceCommands,
}

#[derive(Subcommand)]
pub enum WorkspaceCommands {
    List,
    Current,
    Set { name: String },
}

#[derive(Args)]
pub struct BucketArgs {
    #[command(subcommand)]
    pub command: BucketCommands,
}

#[derive(Subcommand)]
pub enum BucketCommands {
    List { workspace: Option<String> },
    Move { from: String, to: String },
}

#[derive(Args)]
pub struct ExportArgs {
    #[arg(long, value_name = "path", help = "Export plaintext JSON to a file")]
    pub json: Option<PathBuf>,
    #[arg(long, value_name = "path", help = "Export encrypted bundle to a file")]
    pub encrypted: Option<PathBuf>,
    #[arg(long, help = "Overwrite existing export file")]
    pub force: bool,
}

#[derive(Args)]
pub struct ImportArgs {
    #[arg(long, value_name = "path", help = "Import plaintext JSON file")]
    pub json: Option<PathBuf>,
    #[arg(long, value_name = "path", help = "Import encrypted bundle file")]
    pub encrypted: Option<PathBuf>,
    #[arg(
        long,
        help = "Overwrite existing vault files when importing encrypted bundles"
    )]
    pub force: bool,
}

#[derive(Args)]
pub struct MigrateArgs {
    #[command(subcommand)]
    pub command: MigrateCommands,
}

#[derive(Subcommand)]
pub enum MigrateCommands {
    /// Check if migration is needed for current version to latest
    Check,
    /// Create manual backup before update
    Backup {
        #[arg(value_name = "path", help = "Backup destination path")]
        path: PathBuf,
    },
    /// Restore from backup
    Restore {
        #[arg(value_name = "path", help = "Backup source path to restore from")]
        path: PathBuf,
    },
    /// List available backups
    List,
    /// Clean up old backups
    Cleanup,
}
