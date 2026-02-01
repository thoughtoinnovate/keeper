//! Migration system for Keeper
//!
//! This module handles:
//! - Detecting breaking changes between versions
//! - Creating encrypted backups before updates
//! - Applying migrations after updates
//! - Rolling back on failure

pub mod backup;
pub mod manager;
pub mod manifest;

// These are public API exports - may not be used internally but available for external use
#[allow(unused_imports)]
pub use backup::{BackupManager, MigrationBackup};
#[allow(unused_imports)]
pub use manager::{MigrationManager, MigrationStatus};
#[allow(unused_imports)]
pub use manifest::{BreakingChange, MigrationManifest, MigrationType, VersionRequirement};
