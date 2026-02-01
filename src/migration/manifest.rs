use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// The migration manifest tracks breaking changes between versions
/// This is stored in an external JSON file that can be updated
/// without recompiling the application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationManifest {
    /// Manifest format version
    pub manifest_version: String,
    /// Map of version numbers to their breaking changes
    pub versions: HashMap<String, VersionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Human-readable description of changes
    pub description: String,
    /// Whether this version requires data migration
    #[serde(default)]
    pub requires_migration: bool,
    /// Type of migration required
    #[serde(default)]
    pub migration_type: MigrationType,
    /// Minimum version that can migrate to this version
    #[serde(default)]
    pub minimum_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MigrationType {
    /// Full export/import with encrypted backup
    FullExportImport,
    /// In-place schema migration
    SchemaUpdate,
    /// No migration needed (backward compatible)
    #[default]
    #[serde(other)]
    NoAction,
}

/// Represents a single breaking change entry
#[derive(Debug, Clone)]
pub struct BreakingChange {
    pub version: String,
    pub description: String,
    pub requires_migration: bool,
    pub migration_type: MigrationType,
    #[allow(dead_code)]
    pub minimum_version: Option<String>,
}

/// Requirements for migration between versions
#[derive(Debug, Clone)]
pub struct VersionRequirement {
    #[allow(dead_code)]
    pub from_version: String,
    #[allow(dead_code)]
    pub to_version: String,
    pub migration_type: MigrationType,
    #[allow(dead_code)]
    pub description: String,
}

impl MigrationManifest {
    /// Load manifest from a JSON file
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            anyhow!(
                "Failed to read migration manifest from {}: {}",
                path.display(),
                e
            )
        })?;

        let manifest: MigrationManifest = serde_json::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse migration manifest: {}", e))?;

        Ok(manifest)
    }

    /// Save manifest to a JSON file
    #[allow(dead_code)]
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialize migration manifest: {}", e))?;

        fs::write(path, content).map_err(|e| {
            anyhow!(
                "Failed to write migration manifest to {}: {}",
                path.display(),
                e
            )
        })?;

        Ok(())
    }

    /// Check if migration is needed between two versions
    pub fn check_migration(&self, from: &str, to: &str) -> Result<VersionRequirement> {
        // Parse version strings
        let from_ver = parse_version(from)?;
        let to_ver = parse_version(to)?;

        // If downgrading, always require full migration
        if from_ver > to_ver {
            return Ok(VersionRequirement {
                from_version: from.to_string(),
                to_version: to.to_string(),
                migration_type: MigrationType::FullExportImport,
                description: format!("Downgrade from {} to {} requires full migration", from, to),
            });
        }

        // If same version, no migration needed
        if from_ver == to_ver {
            return Ok(VersionRequirement {
                from_version: from.to_string(),
                to_version: to.to_string(),
                migration_type: MigrationType::NoAction,
                description: "Same version, no migration needed".to_string(),
            });
        }

        // Check if target version has breaking changes
        if let Some(version_info) = self.versions.get(to)
            && version_info.requires_migration
        {
            // Check minimum version requirement
            if let Some(ref min_ver) = version_info.minimum_version {
                let min_version = parse_version(min_ver)?;
                if from_ver < min_version {
                    return Err(anyhow!(
                        "Cannot migrate from {} to {}. Minimum required version is {}.",
                        from,
                        to,
                        min_ver
                    ));
                }
            }

            return Ok(VersionRequirement {
                from_version: from.to_string(),
                to_version: to.to_string(),
                migration_type: version_info.migration_type.clone(),
                description: version_info.description.clone(),
            });
        }

        // No breaking changes detected
        Ok(VersionRequirement {
            from_version: from.to_string(),
            to_version: to.to_string(),
            migration_type: MigrationType::NoAction,
            description: "No breaking changes, update compatible".to_string(),
        })
    }

    /// Get all breaking changes between two versions
    pub fn get_breaking_changes(&self, from: &str, to: &str) -> Result<Vec<BreakingChange>> {
        let from_ver = parse_version(from)?;
        let to_ver = parse_version(to)?;

        let mut changes = Vec::new();

        for (version_str, info) in &self.versions {
            if let Ok(ver) = parse_version(version_str) {
                // Include versions between from and to (exclusive of from, inclusive of to)
                if ver > from_ver && ver <= to_ver && info.requires_migration {
                    changes.push(BreakingChange {
                        version: version_str.clone(),
                        description: info.description.clone(),
                        requires_migration: info.requires_migration,
                        migration_type: info.migration_type.clone(),
                        minimum_version: info.minimum_version.clone(),
                    });
                }
            }
        }

        // Sort by version
        changes.sort_by(|a, b| {
            parse_version(&a.version)
                .unwrap_or((0, 0, 0))
                .cmp(&parse_version(&b.version).unwrap_or((0, 0, 0)))
        });

        Ok(changes)
    }
}

/// Parse version string into tuple (major, minor, patch)
fn parse_version(version: &str) -> Result<(u32, u32, u32)> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!(
            "Invalid version format: {}. Expected x.y.z",
            version
        ));
    }

    let major = parts[0]
        .parse::<u32>()
        .map_err(|_| anyhow!("Invalid major version: {}", parts[0]))?;
    let minor = parts[1]
        .parse::<u32>()
        .map_err(|_| anyhow!("Invalid minor version: {}", parts[1]))?;
    let patch = parts[2]
        .parse::<u32>()
        .map_err(|_| anyhow!("Invalid patch version: {}", parts[2]))?;

    Ok((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_manifest() {
        let json = r#"{
            "manifest_version": "1.0.0",
            "versions": {
                "0.3.0": {
                    "description": "Breaking schema change",
                    "requires_migration": true,
                    "migration_type": "full_export_import",
                    "minimum_version": "0.2.0"
                }
            }
        }"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();

        let manifest = MigrationManifest::load(file.path()).unwrap();
        assert_eq!(manifest.manifest_version, "1.0.0");

        let v030 = manifest.versions.get("0.3.0").unwrap();
        assert!(v030.requires_migration);
        assert_eq!(v030.migration_type, MigrationType::FullExportImport);
    }

    #[test]
    fn test_check_migration_no_action() {
        let manifest = MigrationManifest {
            manifest_version: "1.0.0".to_string(),
            versions: HashMap::new(),
        };

        let req = manifest.check_migration("0.2.0", "0.2.1").unwrap();
        assert_eq!(req.migration_type, MigrationType::NoAction);
    }

    #[test]
    fn test_check_migration_required() {
        let mut versions = HashMap::new();
        versions.insert(
            "0.3.0".to_string(),
            VersionInfo {
                description: "Breaking change".to_string(),
                requires_migration: true,
                migration_type: MigrationType::FullExportImport,
                minimum_version: Some("0.2.0".to_string()),
            },
        );

        let manifest = MigrationManifest {
            manifest_version: "1.0.0".to_string(),
            versions,
        };

        let req = manifest.check_migration("0.2.0", "0.3.0").unwrap();
        assert_eq!(req.migration_type, MigrationType::FullExportImport);
        assert!(req.description.contains("Breaking"));
    }

    #[test]
    fn test_version_parsing() {
        assert_eq!(parse_version("1.2.3").unwrap(), (1, 2, 3));
        assert_eq!(parse_version("0.2.1").unwrap(), (0, 2, 1));
        assert!(parse_version("1.2").is_err());
        assert!(parse_version("invalid").is_err());
    }
}
