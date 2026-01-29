use clap::{Args, Parser, Subcommand};

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
    // Add other filters...
}
