use anyhow::Result;
use chrono::Utc;
use std::fs;
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

        self.cleanup_old_backups()?;

        Ok(backup_dir)
    }

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

    pub fn restore_backup(
        &self,
        backup_dir: &Path,
        vault_path: &Path,
        keystore_path: &Path,
    ) -> Result<()> {
        let backup_vault = backup_dir.join("vault.db");
        let backup_keystore = backup_dir.join("keystore.json");

        if !backup_vault.exists() || !backup_keystore.exists() {
            return Err(anyhow::anyhow!(
                "Invalid backup directory: missing required files"
            ));
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
                let _ = fs::remove_dir_all(oldest.path());
                backups.remove(0);
            }
        }

        Ok(())
    }
}
