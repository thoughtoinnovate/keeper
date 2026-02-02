use crate::paths::KeeperPaths;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;

const DEFAULT_WORKSPACE: &str = "@default";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub default_workspace: String,
    #[serde(default)]
    pub allow_insecure_memlock: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_workspace: DEFAULT_WORKSPACE.to_string(),
            allow_insecure_memlock: false,
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
        validate_workspace(&config.default_workspace)?;
        Ok(config)
    }

    pub fn save(&self, paths: &KeeperPaths) -> Result<()> {
        validate_workspace(&self.default_workspace)?;
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

fn validate_workspace(workspace: &str) -> Result<()> {
    if !workspace.starts_with('@') {
        return Err(anyhow!("Workspace must start with @"));
    }
    if workspace.len() < 2 {
        return Err(anyhow!("Workspace name too short (minimum 2 characters)"));
    }
    if workspace.len() > 50 {
        return Err(anyhow!("Workspace name too long (maximum 50 characters)"));
    }

    // Check for null bytes (VALID-001)
    if workspace.contains('\0') {
        return Err(anyhow!("Workspace cannot contain null bytes"));
    }

    // Check for path traversal sequences (VALID-002)
    if workspace.contains("..") || workspace.contains("../") || workspace.contains("..\\") {
        return Err(anyhow!("Workspace cannot contain path traversal sequences"));
    }

    // Valid characters: alphanumeric, @, /, -, _ (VALID-001/002)
    if !workspace
        .chars()
        .all(|c| c.is_alphanumeric() || c == '@' || c == '/' || c == '_' || c == '-')
    {
        return Err(anyhow!("Workspace contains invalid characters"));
    }
    Ok(())
}
