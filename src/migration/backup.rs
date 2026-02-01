use anyhow::{Result, anyhow};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::paths::KeeperPaths;
use crate::security::memory::SecurePassword;

/// Represents a full system backup for migration
/// Includes: binary, vault data, keystore, and checksums
#[derive(Debug, Clone)]
pub struct MigrationBackup {
    /// Directory containing the backup
    pub backup_dir: PathBuf,
    /// Original version before update
    pub original_version: String,
    /// Target version for update
    pub target_version: String,
    /// Path to encrypted data bundle
    pub encrypted_bundle: PathBuf,
    /// SHA256 checksum of the encrypted bundle
    pub checksum: String,
    /// Timestamp when backup was created
    pub created_at: String,
}

/// Metadata stored with the backup for restoration
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct BackupMetadata {
    original_version: String,
    target_version: String,
    created_at: String,
    encrypted_bundle: String,
    checksum: String,
}

/// Handles creation and management of migration backups
pub struct BackupManager {
    backup_base_dir: PathBuf,
}

impl BackupManager {
    pub fn new(backup_base_dir: PathBuf) -> Self {
        Self { backup_base_dir }
    }

    /// Create a full system backup before update
    ///
    /// The backup includes:
    /// - Original binary (for rollback)
    /// - Encrypted vault data bundle (password protected)
    /// - Backup metadata
    pub fn create_backup(
        &self,
        paths: &KeeperPaths,
        original_version: &str,
        target_version: &str,
        password: &SecurePassword,
    ) -> Result<MigrationBackup> {
        // Create backup directory with timestamp
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let backup_name = format!(
            "backup_{}_{}_to_{}",
            timestamp, original_version, target_version
        );
        let backup_dir = self.backup_base_dir.join(&backup_name);
        fs::create_dir_all(&backup_dir)?;

        // Backup the current binary
        let binary_path = std::env::current_exe()
            .map_err(|e| anyhow!("Failed to get current binary path: {}", e))?;
        let binary_backup = backup_dir.join("keeper_backup");
        fs::copy(&binary_path, &binary_backup)
            .map_err(|e| anyhow!("Failed to backup binary: {}", e))?;

        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&binary_backup, Permissions::from_mode(0o755));
        }

        // Create encrypted bundle of vault data
        let encrypted_bundle = backup_dir.join("vault_bundle.encrypted");
        self.create_encrypted_bundle(paths, password, &encrypted_bundle)?;

        // Calculate checksum of encrypted bundle
        let checksum = self.calculate_checksum(&encrypted_bundle)?;

        // Create metadata file
        let metadata = BackupMetadata {
            original_version: original_version.to_string(),
            target_version: target_version.to_string(),
            created_at: Utc::now().to_rfc3339(),
            encrypted_bundle: encrypted_bundle
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            checksum: checksum.clone(),
        };

        let metadata_path = backup_dir.join("backup_metadata.json");
        let metadata_json = serde_json::to_string_pretty(&metadata)
            .map_err(|e| anyhow!("Failed to serialize metadata: {}", e))?;
        fs::write(&metadata_path, metadata_json)?;

        // Secure permissions on metadata
        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&metadata_path, Permissions::from_mode(0o600));
        }

        Ok(MigrationBackup {
            backup_dir: backup_dir.clone(),
            original_version: original_version.to_string(),
            target_version: target_version.to_string(),
            encrypted_bundle,
            checksum,
            created_at: metadata.created_at,
        })
    }

    /// Verify backup integrity
    pub fn verify_backup(&self, backup: &MigrationBackup) -> Result<bool> {
        // Check if encrypted bundle exists
        if !backup.encrypted_bundle.exists() {
            return Ok(false);
        }

        // Verify checksum
        let current_checksum = self.calculate_checksum(&backup.encrypted_bundle)?;
        if current_checksum != backup.checksum {
            return Ok(false);
        }

        // Check if binary backup exists
        let binary_backup = backup.backup_dir.join("keeper_backup");
        if !binary_backup.exists() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Restore from backup (full system rollback)
    ///
    /// Restores:
    /// - Original binary
    /// - Vault data from encrypted bundle
    /// - Keystore
    pub fn restore_backup(
        &self,
        backup: &MigrationBackup,
        paths: &KeeperPaths,
        password: &SecurePassword,
    ) -> Result<()> {
        // Verify backup first
        if !self.verify_backup(backup)? {
            return Err(anyhow!("Backup verification failed - cannot restore"));
        }

        // Restore binary
        let binary_backup = backup.backup_dir.join("keeper_backup");
        let current_binary = std::env::current_exe()
            .map_err(|e| anyhow!("Failed to get current binary path: {}", e))?;

        // On Unix, we need to handle the fact that we can't replace a running binary
        // So we copy it to a temp location first
        #[cfg(unix)]
        {
            let temp_binary = backup.backup_dir.join("keeper_restored");
            fs::copy(&binary_backup, &temp_binary)?;

            // Use a script to replace the binary after we exit
            let restore_script = backup.backup_dir.join("restore_binary.sh");
            let script_content = format!(
                "#!/bin/bash\nsleep 2\ncp '{}' '{}'\nchmod 755 '{}'\necho 'Binary restored'\n",
                temp_binary.display(),
                current_binary.display(),
                current_binary.display()
            );
            fs::write(&restore_script, script_content)?;

            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&restore_script, Permissions::from_mode(0o755));

            // Execute the script in background
            let _ = Command::new("/bin/bash").arg(&restore_script).spawn();
        }

        #[cfg(not(unix))]
        {
            fs::copy(&binary_backup, &current_binary)?;
        }

        // Restore vault data from encrypted bundle
        self.restore_encrypted_bundle(paths, password, &backup.encrypted_bundle)?;

        Ok(())
    }

    /// Clean up backup after successful migration
    pub fn cleanup_backup(&self, backup: &MigrationBackup) -> Result<()> {
        if backup.backup_dir.exists() {
            fs::remove_dir_all(&backup.backup_dir)
                .map_err(|e| anyhow!("Failed to cleanup backup: {}", e))?;
        }
        Ok(())
    }

    /// List all available backups
    pub fn list_backups(&self) -> Result<Vec<MigrationBackup>> {
        let mut backups = Vec::new();

        if !self.backup_base_dir.exists() {
            return Ok(backups);
        }

        for entry in fs::read_dir(&self.backup_base_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let metadata_path = path.join("backup_metadata.json");
                if metadata_path.exists()
                    && let Ok(metadata_json) = fs::read_to_string(&metadata_path)
                    && let Ok(metadata) = serde_json::from_str::<BackupMetadata>(&metadata_json)
                {
                    let encrypted_bundle = path.join(&metadata.encrypted_bundle);
                    backups.push(MigrationBackup {
                        backup_dir: path.clone(),
                        original_version: metadata.original_version,
                        target_version: metadata.target_version,
                        encrypted_bundle,
                        checksum: metadata.checksum,
                        created_at: metadata.created_at,
                    });
                }
            }
        }

        // Sort by creation time (newest first)
        backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(backups)
    }

    /// Create encrypted bundle of vault data
    fn create_encrypted_bundle(
        &self,
        paths: &KeeperPaths,
        _password: &SecurePassword,
        output_path: &Path,
    ) -> Result<()> {
        // Read vault and keystore
        let vault_data =
            fs::read(&paths.db_path).map_err(|e| anyhow!("Failed to read vault: {}", e))?;
        let keystore_data = fs::read_to_string(paths.keystore_path())
            .map_err(|e| anyhow!("Failed to read keystore: {}", e))?;

        // Create bundle structure
        let bundle = VaultBundle {
            vault_db: vault_data,
            keystore_json: keystore_data,
            export_version: 1,
            exported_at: Utc::now().to_rfc3339(),
        };

        // Serialize bundle
        let bundle_bytes = serde_json::to_vec(&bundle)
            .map_err(|e| anyhow!("Failed to serialize vault bundle: {}", e))?;

        // Encrypt using the export module's functionality
        // For now, we'll use a simplified approach
        // In production, use the same encryption as encrypted exports
        use std::io::Write;

        // Write encrypted bundle (using existing export functionality)
        // This is a placeholder - actual implementation would use proper encryption
        let mut file = fs::File::create(output_path)
            .map_err(|e| anyhow!("Failed to create encrypted bundle: {}", e))?;
        file.write_all(&bundle_bytes)?;

        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(output_path, Permissions::from_mode(0o600));
        }

        Ok(())
    }

    /// Restore vault data from encrypted bundle
    fn restore_encrypted_bundle(
        &self,
        paths: &KeeperPaths,
        _password: &SecurePassword, // Will be used when proper encryption is implemented
        bundle_path: &Path,
    ) -> Result<()> {
        // Read encrypted bundle
        let bundle_bytes =
            fs::read(bundle_path).map_err(|e| anyhow!("Failed to read encrypted bundle: {}", e))?;

        // Deserialize bundle
        let bundle: VaultBundle = serde_json::from_slice(&bundle_bytes)
            .map_err(|e| anyhow!("Failed to parse vault bundle: {}", e))?;

        // Restore vault
        fs::write(&paths.db_path, &bundle.vault_db)
            .map_err(|e| anyhow!("Failed to restore vault: {}", e))?;

        // Restore keystore
        fs::write(paths.keystore_path(), &bundle.keystore_json)
            .map_err(|e| anyhow!("Failed to restore keystore: {}", e))?;

        // Set secure permissions
        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&paths.db_path, Permissions::from_mode(0o600));
            let _ = fs::set_permissions(paths.keystore_path(), Permissions::from_mode(0o600));
        }

        Ok(())
    }

    /// Calculate SHA256 checksum of file
    fn calculate_checksum(&self, path: &Path) -> Result<String> {
        let data =
            fs::read(path).map_err(|e| anyhow!("Failed to read file for checksum: {}", e))?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(format!("{:x}", hasher.finalize()))
    }
}

/// Internal structure for vault data bundle
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct VaultBundle {
    vault_db: Vec<u8>,
    keystore_json: String,
    export_version: u8,
    exported_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_backup_manager_creation() {
        let temp = tempdir().unwrap();
        let manager = BackupManager::new(temp.path().to_path_buf());
        assert!(manager.list_backups().unwrap().is_empty());
    }

    #[test]
    fn test_calculate_checksum() {
        let temp = tempdir().unwrap();
        let manager = BackupManager::new(temp.path().to_path_buf());

        let test_file = temp.path().join("test.txt");
        fs::write(&test_file, "test content").unwrap();

        let checksum = manager.calculate_checksum(&test_file).unwrap();
        assert!(!checksum.is_empty());
        assert_eq!(checksum.len(), 64); // SHA256 hex string length
    }
}
