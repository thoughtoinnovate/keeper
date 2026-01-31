# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

Please report vulnerabilities by opening a GitHub Issue with the label "security" or contacting the maintainers directly.

## Security Features

Keeper implements defense-in-depth measures to protect your data.

### 1. Cryptographic Architecture
- **Key Derivation**: Passwords and recovery codes are hashed using **Argon2id** (19MB RAM, 2 iterations) to prevent brute-force attacks.
- **Key Wrapping**: The master key is encrypted using **XChaCha20Poly1305**.
- **Data Encryption**: The local SQLite database is encrypted with **SQLCipher** (AES-256-CBC) using the unwrapped master key.

### 2. Memory Protection
- **Anti-Swap**: The daemon uses `mlockall` to lock process memory, preventing sensitive keys from being swapped to disk.
- **Zeroization**: Cryptographic keys and passwords are zeroed out (wiped) from memory immediately after use or when the vault is locked.

### 3. Daemon Security
- **Auto-Lock**: The daemon automatically locks the vault after **30 minutes** of inactivity, wiping the master key from memory.
- **IPC Security**: Communication uses a Unix domain socket (`keeper.sock`), restricted to the user via file system permissions (`0600`).

### 4. Integrity
- **Update Verification**: The `keeper update` and install scripts verify SHA-256 checksums of downloaded binaries.

## User Best Practices

- **Socket Permissions**: Ensure your home directory (`~/.keeper`) is not readable by other users.
- **Recovery Codes**: Store your 12-word recovery code in a secure, offline location.
- **Strong Passwords**: Use a strong, unique password to maximize Argon2id protection.
