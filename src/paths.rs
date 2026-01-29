use anyhow::{anyhow, Result};
use directories::BaseDirs;
use std::path::{Path, PathBuf};

pub struct KeeperPaths {
    pub base_dir: PathBuf,
    pub db_path: PathBuf,
    pub socket_path: PathBuf,
    pub pid_path: PathBuf,
}

impl KeeperPaths {
    pub fn new() -> Result<Self> {
        let base_dirs = BaseDirs::new().ok_or_else(|| anyhow!("Unable to resolve home directory"))?;
        let base_dir = base_dirs.home_dir().join(".keeper");
        std::fs::create_dir_all(&base_dir)?;
        Ok(Self {
            db_path: base_dir.join("vault.db"),
            socket_path: base_dir.join("keeper.sock"),
            pid_path: base_dir.join("keeper.pid"),
            base_dir,
        })
    }

    pub fn socket_path_display(&self) -> String {
        self.socket_path
            .to_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.socket_path.display().to_string())
    }

    pub fn ensure_base_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.base_dir)?;
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

    pub fn db_dir(&self) -> &Path {
        &self.base_dir
    }
}
