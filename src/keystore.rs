use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use bip39::{Language, Mnemonic};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

use crate::security::{self, MASTER_KEY_LEN};

const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

#[derive(Debug, Serialize, Deserialize)]
pub struct Keystore {
    pub version: u8,
    pub salt_password: String,
    pub salt_recovery: String,
    pub nonce_password: String,
    pub nonce_recovery: String,
    pub wrapped_master_password: String,
    pub wrapped_master_recovery: String,
}

impl Keystore {
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)?;
        let store: Keystore = serde_json::from_str(&data)?;
        if store.version != VERSION {
            return Err(anyhow!("Unsupported keystore version {}", store.version));
        }
        Ok(store)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data)?;
        Ok(())
    }

    pub fn create_new(password: &str) -> Result<(Self, String, [u8; MASTER_KEY_LEN])> {
        let master_key = security::generate_master_key();
        let recovery = Mnemonic::generate_in(Language::English, 24)?.to_string();

        let mut salt_password = [0u8; SALT_LEN];
        let mut salt_recovery = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt_password);
        OsRng.fill_bytes(&mut salt_recovery);

        let mut nonce_password = [0u8; NONCE_LEN];
        let mut nonce_recovery = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_password);
        OsRng.fill_bytes(&mut nonce_recovery);

        let mut wrapped_master_password =
            wrap_master_key(password, &salt_password, &nonce_password, &master_key)?;
        let mut wrapped_master_recovery =
            wrap_master_key(&recovery, &salt_recovery, &nonce_recovery, &master_key)?;

        let store = Keystore {
            version: VERSION,
            salt_password: STANDARD_NO_PAD.encode(salt_password),
            salt_recovery: STANDARD_NO_PAD.encode(salt_recovery),
            nonce_password: STANDARD_NO_PAD.encode(nonce_password),
            nonce_recovery: STANDARD_NO_PAD.encode(nonce_recovery),
            wrapped_master_password: STANDARD_NO_PAD.encode(&wrapped_master_password),
            wrapped_master_recovery: STANDARD_NO_PAD.encode(&wrapped_master_recovery),
        };

        wrapped_master_password.zeroize();
        wrapped_master_recovery.zeroize();

        Ok((store, recovery, master_key))
    }

    pub fn unwrap_with_password(&self, password: &str) -> Result<[u8; MASTER_KEY_LEN]> {
        unwrap_master_key(
            password,
            &self.salt_password,
            &self.nonce_password,
            &self.wrapped_master_password,
        )
    }

    pub fn unwrap_with_recovery(&self, recovery: &str) -> Result<[u8; MASTER_KEY_LEN]> {
        let mut normalized = normalize_recovery_code(recovery);
        let result = unwrap_master_key(
            &normalized,
            &self.salt_recovery,
            &self.nonce_recovery,
            &self.wrapped_master_recovery,
        );
        normalized.zeroize();
        result
    }

    pub fn rewrap_password(
        &mut self,
        password: &str,
        master_key: &[u8; MASTER_KEY_LEN],
    ) -> Result<()> {
        let mut salt_password = [0u8; SALT_LEN];
        let mut nonce_password = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt_password);
        OsRng.fill_bytes(&mut nonce_password);

        let mut wrapped =
            wrap_master_key(password, &salt_password, &nonce_password, master_key)?;

        self.salt_password = STANDARD_NO_PAD.encode(salt_password);
        self.nonce_password = STANDARD_NO_PAD.encode(nonce_password);
        self.wrapped_master_password = STANDARD_NO_PAD.encode(&wrapped);

        wrapped.zeroize();
        Ok(())
    }
}

fn wrap_master_key(
    secret: &str,
    salt: &[u8],
    nonce: &[u8],
    master_key: &[u8; MASTER_KEY_LEN],
) -> Result<Vec<u8>> {
    let mut wrap_key = security::derive_key_material(secret, salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&wrap_key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(nonce), master_key.as_ref())
        .map_err(|_| anyhow!("Failed to wrap master key"))?;
    wrap_key.zeroize();
    Ok(ciphertext)
}

fn unwrap_master_key(
    secret: &str,
    salt_b64: &str,
    nonce_b64: &str,
    wrapped_b64: &str,
) -> Result<[u8; MASTER_KEY_LEN]> {
    let salt = decode_fixed(salt_b64, SALT_LEN, "salt")?;
    let nonce = decode_fixed(nonce_b64, NONCE_LEN, "nonce")?;
    let wrapped = STANDARD_NO_PAD
        .decode(wrapped_b64)
        .map_err(|_| anyhow!("Invalid wrapped key data"))?;

    let mut wrap_key = security::derive_key_material(secret, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&wrap_key));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), wrapped.as_ref())
        .map_err(|_| anyhow!("Invalid password or recovery code"))?;
    wrap_key.zeroize();

    if plaintext.len() != MASTER_KEY_LEN {
        return Err(anyhow!("Invalid master key length"));
    }

    let mut master_key = [0u8; MASTER_KEY_LEN];
    master_key.copy_from_slice(&plaintext);
    Ok(master_key)
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

fn normalize_recovery_code(code: &str) -> String {
    code.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}
