use crate::keystore::Keystore;
use crate::models::Item;
use crate::paths::KeeperPaths;
use crate::security;
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use chrono::Utc;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

const EXPORT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

#[derive(Debug, Serialize, Deserialize)]
pub struct PlainExportFile {
    pub version: u8,
    pub exported_at: String,
    pub items: Vec<Item>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedExportFile {
    pub version: u8,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Bundle {
    version: u8,
    vault_db_b64: String,
    keystore_json: String,
}

pub fn write_plain_export(path: &Path, items: Vec<Item>) -> Result<usize> {
    let payload = PlainExportFile {
        version: EXPORT_VERSION,
        exported_at: Utc::now().to_rfc3339(),
        items,
    };
    let data = serde_json::to_string_pretty(&payload)?;
    fs::write(path, data)?;
    set_file_permissions(path)?;
    Ok(payload.items.len())
}

pub fn read_plain_export(path: &Path) -> Result<PlainExportFile> {
    let data = fs::read_to_string(path)?;
    let payload: PlainExportFile = serde_json::from_str(&data)?;
    if payload.version != EXPORT_VERSION {
        return Err(anyhow!("Unsupported export version {}", payload.version));
    }
    Ok(payload)
}

pub fn write_encrypted_export<S: AsRef<str>>(
    paths: &KeeperPaths,
    path: &Path,
    password: S,
) -> Result<()> {
    let password_str = password.as_ref();
    let vault_db = fs::read(&paths.db_path)
        .map_err(|_| anyhow!("Vault database not found at {}", paths.db_path.display()))?;
    let keystore_json = fs::read_to_string(paths.keystore_path())
        .map_err(|_| anyhow!("Keystore not found at {}", paths.keystore_path().display()))?;

    let bundle = Bundle {
        version: EXPORT_VERSION,
        vault_db_b64: STANDARD_NO_PAD.encode(vault_db),
        keystore_json,
    };
    let bundle_bytes = serde_json::to_vec(&bundle)?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = security::derive_key_material(password_str, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), bundle_bytes.as_ref())
        .map_err(|_| anyhow!("Failed to encrypt export bundle"))?;
    key.zeroize();

    let export = EncryptedExportFile {
        version: EXPORT_VERSION,
        salt: STANDARD_NO_PAD.encode(salt),
        nonce: STANDARD_NO_PAD.encode(nonce),
        ciphertext: STANDARD_NO_PAD.encode(ciphertext),
    };
    let data = serde_json::to_string_pretty(&export)?;
    fs::write(path, data)?;
    set_file_permissions(path)?;
    Ok(())
}

pub fn read_encrypted_export<S: AsRef<str>>(path: &Path, password: S) -> Result<(Vec<u8>, String)> {
    let password_str = password.as_ref();
    let data = fs::read_to_string(path)?;
    let export: EncryptedExportFile = serde_json::from_str(&data)?;
    if export.version != EXPORT_VERSION {
        return Err(anyhow!("Unsupported export version {}", export.version));
    }

    let salt = decode_fixed(&export.salt, SALT_LEN, "salt")?;
    let nonce = decode_fixed(&export.nonce, NONCE_LEN, "nonce")?;
    let ciphertext = STANDARD_NO_PAD
        .decode(export.ciphertext)
        .map_err(|_| anyhow!("Invalid ciphertext encoding"))?;

    let mut key = security::derive_key_material(password_str, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("Invalid export password or corrupted file"))?;
    key.zeroize();

    let bundle: Bundle = serde_json::from_slice(&plaintext)?;
    if bundle.version != EXPORT_VERSION {
        return Err(anyhow!("Unsupported export version {}", bundle.version));
    }

    let vault_db = STANDARD_NO_PAD
        .decode(bundle.vault_db_b64)
        .map_err(|_| anyhow!("Invalid vault encoding"))?;
    Ok((vault_db, bundle.keystore_json))
}

pub fn write_bundle_to_paths(
    paths: &KeeperPaths,
    vault_db: &[u8],
    keystore_json: &str,
    force: bool,
) -> Result<()> {
    if (paths.db_path.exists() || paths.keystore_path().exists()) && !force {
        return Err(anyhow!(
            "Vault already exists. Use --force to overwrite existing vault files."
        ));
    }

    if let Some(parent) = paths.db_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&paths.db_path, vault_db)?;
    fs::write(paths.keystore_path(), keystore_json)?;
    set_file_permissions(&paths.db_path)?;
    set_file_permissions(paths.keystore_path())?;

    let _ = Keystore::load(paths.keystore_path())?;
    Ok(())
}

fn decode_fixed(encoded: &str, expected_len: usize, label: &str) -> Result<Vec<u8>> {
    let decoded = STANDARD_NO_PAD
        .decode(encoded)
        .map_err(|_| anyhow!("Invalid {label} encoding"))?;
    if decoded.len() != expected_len {
        return Err(anyhow!("Invalid {label} length"));
    }
    Ok(decoded)
}

fn set_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;
        let perms = Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}
