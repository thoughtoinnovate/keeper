use crate::paths::KeeperPaths;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

const DEFAULT_WORKSPACE: &str = "@default";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub default_workspace: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_workspace: DEFAULT_WORKSPACE.to_string(),
        }
    }
}

impl Config {
    pub fn load(paths: &KeeperPaths) -> Result<Self> {
        if !paths.config_path.exists() {
            return Ok(Config::default());
        }
        let data = fs::read_to_string(&paths.config_path)?;
        let config: Config = serde_json::from_str(&data).unwrap_or_default();
        Ok(config)
    }

    pub fn save(&self, paths: &KeeperPaths) -> Result<()> {
        if let Some(parent) = paths.config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)?;
        fs::write(&paths.config_path, data)?;
        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let perms = Permissions::from_mode(0o600);
            fs::set_permissions(&paths.config_path, perms)?;
        }
        Ok(())
    }
}

pub fn default_workspace() -> &'static str {
    DEFAULT_WORKSPACE
}
