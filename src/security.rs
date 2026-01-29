use anyhow::Result;
use argon2::Argon2;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

pub const MASTER_KEY_LEN: usize = 32;

pub fn generate_master_key() -> [u8; MASTER_KEY_LEN] {
    let mut key = [0u8; MASTER_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn derive_key_material(secret: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut output = [0u8; 32];
    let mut secret_bytes = secret.as_bytes().to_vec();
    Argon2::default()
        .hash_password_into(&secret_bytes, salt, &mut output)
        .map_err(|err| anyhow::anyhow!("Argon2 error: {err}"))?;
    secret_bytes.zeroize();
    Ok(output)
}

pub fn derive_db_key_hex(master_key: &[u8]) -> String {
    hex_encode(master_key)
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}
