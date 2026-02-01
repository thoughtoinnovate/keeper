pub mod memory;

use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

pub const MASTER_KEY_LEN: usize = 32;
pub const INACTIVITY_TIMEOUT_SECONDS: u64 = 1800;

pub fn generate_master_key() -> [u8; MASTER_KEY_LEN] {
    let mut key = [0u8; MASTER_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn derive_key_material(secret: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut output = [0u8; 32];
    let mut secret_bytes = secret.as_bytes().to_vec();

    let params = Params::new(65536, 3, 4, None)
        .map_err(|err| anyhow::anyhow!("Invalid Argon2 params: {err}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(&secret_bytes, salt, &mut output)
        .map_err(|err| anyhow::anyhow!("Argon2 error: {err}"))?;
    secret_bytes.zeroize();
    Ok(output)
}

pub fn derive_db_key_hex(master_key: &[u8]) -> String {
    hex_encode(master_key)
}

pub fn validate_password_strength<S: AsRef<str>>(password: S) -> Result<()> {
    let password = password.as_ref();
    if password.len() < 12 {
        return Err(anyhow::anyhow!("Password must be at least 12 characters"));
    }

    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password
        .chars()
        .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

    if !has_upper || !has_lower || !has_digit {
        return Err(anyhow::anyhow!(
            "Password must contain uppercase, lowercase, and digits"
        ));
    }

    if !has_special {
        return Err(anyhow::anyhow!(
            "Password must contain at least one special character (!@#$%^&*()_+-=[]{{}}|;:,.<>?)"
        ));
    }

    let common_passwords = [
        "password",
        "123456",
        "123456789",
        "qwerty",
        "password123",
        "abc123",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "hello",
        "login",
        "admin",
        "root",
        "12345678",
        "1234567",
        "1234567890",
        "baseball",
        "football",
        "superman",
        "batman",
        "trustno1",
        "shadow",
        "sunshine",
        "princess",
        "dragon",
        "whatever",
        "starwars",
        "passw0rd",
        "hunter",
        "ranger",
        "thomas",
        "robert",
        "michael",
        "jordan",
        "maggie",
        "buster",
        "daniel",
        "andrew",
        "joshua",
        "pepper",
        "ginger",
        "matthew",
        "amanda",
        "summer",
        "ashley",
        "nicole",
        "chelsea",
        "biteme",
        "merlin",
        "internet",
        "samantha",
        "victoria",
        "cookie",
        "chocolate",
        "silver",
        "guitar",
        "purple",
        "tigger",
        "orange",
        "cocacola",
        "soccer",
        "computer",
        "654321",
        "asdfgh",
        "freedom",
        "killer",
        "lovely",
        "jennifer",
        "taylor",
        "austin",
        "george",
        "alexander",
        "amazing",
        "fuckyou",
        "bullshit",
        "welcome1",
        "jessica",
        "jackson",
        "morgan",
        "michelle",
        "corvette",
        "richard",
        "121212",
        "zxcvbn",
        "qazwsx",
        "ninja",
        "muster",
        "zaq12wsx",
    ];
    let password_lower = password.to_lowercase();
    if common_passwords
        .iter()
        .any(|weak| password_lower.contains(weak))
    {
        return Err(anyhow::anyhow!("Password contains common weak patterns"));
    }

    Ok(())
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
