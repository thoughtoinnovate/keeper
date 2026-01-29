use anyhow::Result;
use argon2::Argon2;
use zeroize::Zeroize;

const SALT: &[u8] = b"keeper-salt-16"; // 16 bytes for Argon2 salt

pub fn derive_key(password: &str) -> Result<String> {
    let mut output = [0u8; 32];
    let mut pwd = password.as_bytes().to_vec();
    Argon2::default()
        .hash_password_into(&pwd, SALT, &mut output)
        .map_err(|err| anyhow::anyhow!("Argon2 error: {err}"))?;
    pwd.zeroize();
    let key = hex_encode(&output);
    output.zeroize();
    Ok(key)
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
