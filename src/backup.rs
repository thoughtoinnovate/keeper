use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Seek;
use std::path::{Path, PathBuf};

pub struct BackupManager {
    base_dir: PathBuf,
    max_backups: usize,
}

impl BackupManager {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            max_backups: 5,
        }
    }

    // Public API method - may be used by CLI
    #[allow(dead_code)]
    pub fn set_max_backups(&mut self, max: usize) {
        self.max_backups = max;
    }

    pub fn create_backup(&self, vault_path: &Path, keystore_path: &Path) -> Result<PathBuf> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let backup_dir = self.base_dir.join(format!("backups/backup_{timestamp}"));
        fs::create_dir_all(&backup_dir)?;

        let vault_backup = backup_dir.join("vault.db");
        let keystore_backup = backup_dir.join("keystore.json");

        fs::copy(vault_path, &vault_backup)?;
        fs::copy(keystore_path, &keystore_backup)?;

        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let perms = Permissions::from_mode(0o600);
            let _ = fs::set_permissions(&vault_backup, perms.clone());
            let _ = fs::set_permissions(&keystore_backup, perms);
        }

        // Generate SHA256 checksums for integrity verification (DATA-002)
        self.create_checksum(&vault_backup)?;
        self.create_checksum(&keystore_backup)?;

        self.cleanup_old_backups()?;

        Ok(backup_dir)
    }

    fn create_checksum(&self, file_path: &Path) -> Result<()> {
        let data = fs::read(file_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = format!("{:x}", hasher.finalize());

        let checksum_path = file_path.with_extension("sha256");
        fs::write(&checksum_path, hash)?;

        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&checksum_path, Permissions::from_mode(0o600));
        }

        Ok(())
    }

    // Public API method - may be used by CLI
    #[allow(dead_code)]
    pub fn verify_backup(&self, backup_dir: &Path) -> Result<bool> {
        let vault_backup = backup_dir.join("vault.db");
        let keystore_backup = backup_dir.join("keystore.json");

        if !vault_backup.exists() || !keystore_backup.exists() {
            return Ok(false);
        }

        let vault_valid = self.verify_checksum(&vault_backup)?;
        let keystore_valid = self.verify_checksum(&keystore_backup)?;

        Ok(vault_valid && keystore_valid)
    }

    // Public API method - may be used by CLI
    #[allow(dead_code)]
    fn verify_checksum(&self, file_path: &Path) -> Result<bool> {
        let checksum_path = file_path.with_extension("sha256");

        if !checksum_path.exists() {
            return Ok(false);
        }

        let data = fs::read(file_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let computed_hash = format!("{:x}", hasher.finalize());

        let stored_hash = fs::read_to_string(&checksum_path)?;

        Ok(computed_hash == stored_hash.trim())
    }

    // Public API method - may be used by CLI
    #[allow(dead_code)]
    pub fn list_backups(&self) -> Result<Vec<PathBuf>> {
        let backups_dir = self.base_dir.join("backups");
        if !backups_dir.exists() {
            return Ok(vec![]);
        }

        let mut backups: Vec<PathBuf> = fs::read_dir(&backups_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();

        backups.sort_by_key(|p| {
            p.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });

        Ok(backups)
    }

    // Public API method - may be used by CLI
    #[allow(dead_code)]
    pub fn restore_backup(
        &self,
        backup_dir: &Path,
        vault_path: &Path,
        keystore_path: &Path,
    ) -> Result<()> {
        let backup_vault = backup_dir.join("vault.db");
        let backup_keystore = backup_dir.join("keystore.json");

        if !backup_vault.exists() || !backup_keystore.exists() {
            return Err(anyhow!("Invalid backup directory: missing required files"));
        }

        // Verify checksums before restore (DATA-002)
        if !self.verify_checksum(&backup_vault)? {
            return Err(anyhow!("Backup vault integrity check failed"));
        }
        if !self.verify_checksum(&backup_keystore)? {
            return Err(anyhow!("Backup keystore integrity check failed"));
        }

        fs::copy(&backup_vault, vault_path)?;
        fs::copy(&backup_keystore, keystore_path)?;

        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let perms = Permissions::from_mode(0o600);
            let _ = fs::set_permissions(vault_path, perms.clone());
            let _ = fs::set_permissions(keystore_path, perms);
        }

        Ok(())
    }

    fn cleanup_old_backups(&self) -> Result<()> {
        let backups_dir = self.base_dir.join("backups");
        if !backups_dir.exists() {
            return Ok(());
        }

        let mut backups: Vec<_> = fs::read_dir(&backups_dir)?.filter_map(|e| e.ok()).collect();

        backups.sort_by_key(|e| {
            e.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });

        while backups.len() > self.max_backups {
            if let Some(oldest) = backups.first() {
                // Secure delete all files in the backup directory
                let path = oldest.path();
                if path.is_dir() {
                    for entry in fs::read_dir(&path)?.filter_map(|e| e.ok()) {
                        let file_path = entry.path();
                        if file_path.is_file() {
                            let _ = secure_delete(&file_path);
                        }
                    }
                    let _ = fs::remove_dir(&path);
                }
                backups.remove(0);
            }
        }

        Ok(())
    }
}

/// Securely delete a file by overwriting it with random data and zeros
/// before deletion (DATA-005)
fn secure_delete(path: &Path) -> Result<()> {
    use std::io::Write;

    let metadata = fs::metadata(path)?;
    let file_size = metadata.len() as usize;

    if file_size == 0 {
        fs::remove_file(path)?;
        return Ok(());
    }

    // Open file for writing
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .context("Failed to open file for secure deletion")?;

    // Pass 1: Overwrite with random bytes
    let mut random_buffer = vec![0u8; file_size];
    rand::thread_rng().fill_bytes(&mut random_buffer);
    file.write_all(&random_buffer)?;
    file.sync_all()?;

    // Pass 2: Overwrite with 0xFF
    let ones_buffer = vec![0xFFu8; file_size];
    file.seek(std::io::SeekFrom::Start(0))?;
    file.write_all(&ones_buffer)?;
    file.sync_all()?;

    // Pass 3: Overwrite with 0x00
    let zeros_buffer = vec![0x00u8; file_size];
    file.seek(std::io::SeekFrom::Start(0))?;
    file.write_all(&zeros_buffer)?;
    file.sync_all()?;

    // Close file and delete
    drop(file);
    fs::remove_file(path)?;

    Ok(())
}
