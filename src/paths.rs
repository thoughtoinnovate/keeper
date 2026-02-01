use anyhow::{Result, anyhow};
use directories::BaseDirs;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct KeeperPaths {
    pub base_dir: PathBuf,
    pub db_path: PathBuf,
    pub socket_path: PathBuf,
    pub keystore_path: PathBuf,
    pub config_path: PathBuf,
    pub vault_arg: Option<PathBuf>,
}

impl KeeperPaths {
    pub fn new(vault: Option<&Path>) -> Result<Self> {
        let base_dirs =
            BaseDirs::new().ok_or_else(|| anyhow!("Unable to resolve home directory"))?;
        let resolved_vault = match vault {
            Some(path) if path.is_absolute() => Some(path.to_path_buf()),
            Some(path) => Some(std::env::current_dir()?.join(path)),
            None => None,
        };
        let vault_arg = resolved_vault.clone();
        let (base_dir, db_path) = match resolved_vault.as_deref() {
            None => {
                let base = base_dirs.home_dir().join(".keeper");
                (base.clone(), base.join("vault.db"))
            }
            Some(path) => {
                if path.extension().and_then(|ext| ext.to_str()) == Some("db") || path.is_file() {
                    let parent = path
                        .parent()
                        .ok_or_else(|| anyhow!("Vault file must have a parent directory"))?;
                    (parent.to_path_buf(), path.to_path_buf())
                } else {
                    (path.to_path_buf(), path.join("vault.db"))
                }
            }
        };

        Ok(Self {
            db_path,
            socket_path: base_dir.join("keeper.sock"),
            keystore_path: base_dir.join("keystore.json"),
            config_path: base_dir.join("config.json"),
            base_dir,
            vault_arg,
        })
    }

    pub fn socket_path_display(&self) -> String {
        self.socket_path
            .to_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.socket_path.display().to_string())
    }

    pub fn ensure_base_dir(&self) -> Result<()> {
        if self.base_dir.exists() && !self.base_dir.is_dir() {
            return Err(anyhow!(
                "Vault base path {} exists and is not a directory. Move it or use --vault to choose a different location.",
                self.base_dir.display()
            ));
        }
        std::fs::create_dir_all(&self.base_dir)?;
        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let perms = Permissions::from_mode(0o700);
            std::fs::set_permissions(&self.base_dir, perms)?;
        }
        Ok(())
    }

    pub fn remove_socket_if_exists(&self) {
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }

    pub fn set_socket_permissions(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let perms = Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.socket_path, perms)?;
        }
        Ok(())
    }

    pub fn keystore_path(&self) -> &Path {
        &self.keystore_path
    }
}
