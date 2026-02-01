use anyhow::{Result, anyhow};

use crate::migration::backup::{BackupManager, MigrationBackup};
use crate::migration::manifest::{
    BreakingChange, MigrationManifest, MigrationType, VersionRequirement,
};
use crate::paths::KeeperPaths;
use crate::security::memory::SecurePassword;

/// Manages the complete migration process
pub struct MigrationManager {
    paths: KeeperPaths,
    manifest: MigrationManifest,
    backup_manager: BackupManager,
}

/// Result of a migration check
#[derive(Debug, Clone)]
pub enum MigrationStatus {
    /// No migration needed - safe to update
    NoActionRequired,
    /// Migration required - backup needed
    MigrationRequired(VersionRequirement),
    /// Cannot migrate - version incompatible
    Incompatible(String),
}

impl MigrationManager {
    /// Create a new migration manager
    pub fn new(paths: KeeperPaths) -> Result<Self> {
        // Load manifest from config directory
        let manifest_path = paths.base_dir.join("migration_manifest.json");
        let manifest = if manifest_path.exists() {
            MigrationManifest::load(&manifest_path)?
        } else {
            // Create default manifest if none exists
            MigrationManifest {
                manifest_version: "1.0.0".to_string(),
                versions: std::collections::HashMap::new(),
            }
        };

        let backup_dir = paths.base_dir.join("migrations");
        let backup_manager = BackupManager::new(backup_dir);

        Ok(Self {
            paths,
            manifest,
            backup_manager,
        })
    }

    /// Check if migration is needed for an update
    pub fn check_migration_needed(
        &self,
        current_version: &str,
        target_version: &str,
    ) -> Result<MigrationStatus> {
        match self
            .manifest
            .check_migration(current_version, target_version)
        {
            Ok(requirement) => match requirement.migration_type {
                MigrationType::NoAction => Ok(MigrationStatus::NoActionRequired),
                _ => Ok(MigrationStatus::MigrationRequired(requirement)),
            },
            Err(e) => Ok(MigrationStatus::Incompatible(e.to_string())),
        }
    }

    /// Get detailed information about breaking changes
    pub fn get_breaking_changes(
        &self,
        current_version: &str,
        target_version: &str,
    ) -> Result<Vec<BreakingChange>> {
        self.manifest
            .get_breaking_changes(current_version, target_version)
    }

    /// Create pre-update backup
    pub fn create_pre_update_backup(
        &self,
        current_version: &str,
        target_version: &str,
        password: &SecurePassword,
    ) -> Result<MigrationBackup> {
        println!("📦 Creating pre-update backup...");
        println!("   From version: {}", current_version);
        println!("   To version: {}", target_version);

        let backup = self.backup_manager.create_backup(
            &self.paths,
            current_version,
            target_version,
            password,
        )?;

        println!("✅ Backup created successfully");
        println!("   Location: {}", backup.backup_dir.display());
        println!("   Checksum: {}", &backup.checksum[..16]);

        Ok(backup)
    }

    /// Apply migration after update
    // Public API for CLI - may not be used internally
    #[allow(dead_code)]
    pub fn apply_migration(
        &self,
        backup: &MigrationBackup,
        password: &SecurePassword,
    ) -> Result<()> {
        println!("🔄 Applying migration...");

        // Verify backup integrity
        if !self.backup_manager.verify_backup(backup)? {
            return Err(anyhow!(
                "Backup verification failed! Cannot proceed with migration."
            ));
        }

        // Restore from backup
        self.backup_manager
            .restore_backup(backup, &self.paths, password)?;

        println!("✅ Migration applied successfully");

        // Cleanup backup after successful migration
        self.backup_manager.cleanup_backup(backup)?;
        println!("🧹 Backup cleaned up");

        Ok(())
    }

    /// Rollback to pre-update state on failure
    // Public API for CLI - may not be used internally
    #[allow(dead_code)]
    pub fn rollback(&self, backup: &MigrationBackup, password: &SecurePassword) -> Result<()> {
        eprintln!("⚠️  Migration failed! Initiating rollback...");

        // Attempt to restore from backup
        match self
            .backup_manager
            .restore_backup(backup, &self.paths, password)
        {
            Ok(_) => {
                eprintln!("✅ Rollback successful");
                eprintln!(
                    "   Your vault has been restored to version {}",
                    backup.original_version
                );
                Ok(())
            }
            Err(e) => {
                eprintln!("❌ Rollback failed: {}", e);
                eprintln!(
                    "   Manual recovery required from backup at: {}",
                    backup.backup_dir.display()
                );
                Err(anyhow!("Rollback failed: {}", e))
            }
        }
    }

    /// List all available backups
    pub fn list_backups(&self) -> Result<Vec<MigrationBackup>> {
        self.backup_manager.list_backups()
    }

    /// Verify a specific backup
    pub fn verify_backup(&self, backup: &MigrationBackup) -> Result<bool> {
        self.backup_manager.verify_backup(backup)
    }

    /// Manual restore from a backup
    pub fn manual_restore(
        &self,
        backup: &MigrationBackup,
        password: &SecurePassword,
    ) -> Result<()> {
        println!("🔄 Manual restore from backup...");
        println!("   Backup from version: {}", backup.original_version);
        println!("   Created at: {}", backup.created_at);

        // Verify first
        if !self.backup_manager.verify_backup(backup)? {
            return Err(anyhow!("Backup verification failed!"));
        }

        // Perform restore
        self.backup_manager
            .restore_backup(backup, &self.paths, password)?;

        println!("✅ Restore completed successfully");
        println!("   Your vault has been restored to the backup state.");

        Ok(())
    }

    /// Get the latest backup (most recent)
    // Public API for CLI - may not be used internally
    #[allow(dead_code)]
    pub fn get_latest_backup(&self) -> Result<Option<MigrationBackup>> {
        let backups = self.list_backups()?;
        Ok(backups.into_iter().next())
    }

    /// Cleanup old backups (keep only last N)
    pub fn cleanup_old_backups(&self, keep_count: usize) -> Result<()> {
        let backups = self.list_backups()?;

        if backups.len() > keep_count {
            for backup in backups.iter().skip(keep_count) {
                println!("🧹 Cleaning up old backup: {}", backup.backup_dir.display());
                self.backup_manager.cleanup_backup(backup)?;
            }
        }

        Ok(())
    }
}

/// Utility functions for migration
pub mod utils {
    use super::*;

    /// Get current application version
    #[allow(dead_code)]
    pub fn get_current_version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Compare two version strings
    #[allow(dead_code)]
    pub fn compare_versions(v1: &str, v2: &str) -> Result<std::cmp::Ordering> {
        let parts1: Vec<u32> = v1.split('.').map(|s| s.parse().unwrap_or(0)).collect();
        let parts2: Vec<u32> = v2.split('.').map(|s| s.parse().unwrap_or(0)).collect();

        if parts1.len() != 3 || parts2.len() != 3 {
            return Err(anyhow!("Invalid version format. Expected x.y.z"));
        }

        Ok(parts1.cmp(&parts2))
    }

    /// Check if update is an upgrade or downgrade
    #[allow(dead_code)]
    pub fn is_upgrade(current: &str, target: &str) -> Result<bool> {
        match compare_versions(current, target)? {
            std::cmp::Ordering::Less => Ok(true),     // Upgrade
            std::cmp::Ordering::Greater => Ok(false), // Downgrade
            std::cmp::Ordering::Equal => Ok(true),    // Same version (no-op)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::utils;

    #[test]
    fn test_version_comparison() {
        assert_eq!(
            utils::compare_versions("0.2.0", "0.3.0").unwrap(),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            utils::compare_versions("0.3.0", "0.2.0").unwrap(),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            utils::compare_versions("0.2.0", "0.2.0").unwrap(),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn test_is_upgrade() {
        assert!(utils::is_upgrade("0.2.0", "0.3.0").unwrap());
        assert!(!utils::is_upgrade("0.3.0", "0.2.0").unwrap());
        assert!(utils::is_upgrade("0.2.0", "0.2.0").unwrap());
    }
}
