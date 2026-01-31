use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const REPO_URL: &str = "https://github.com/thoughtoinnovate/keeper";
const BIN_NAME: &str = "keeper";

// Ed25519 public key for release signature verification (SWAP-005)
// This is the minisign public key for verifying keeper releases
const RELEASE_PUBKEY: &str = "RWQfM2V3GXz+nRZv7D+K/s+xe3NGW5h8r2uJ0Q5x2G4=";

use minisign::{verify, PublicKeyBox};

pub struct SelfUpdateOptions {
    pub tag: Option<String>,
}

pub fn run_self_update(opts: SelfUpdateOptions) -> Result<()> {
    let exe_path = std::env::current_exe().context("Unable to locate keeper binary")?;
    let target_dir = exe_path
        .parent()
        .ok_or_else(|| anyhow!("Unable to resolve keeper install directory"))?;

    let target = detect_target()?;
    let asset_name = format!("{}-{}.{}", BIN_NAME, target.full_target, target.asset_ext);

    let normalized_tag = opts.tag.as_deref().map(normalize_tag);
    let download_url = match normalized_tag.as_deref() {
        Some(tag) => format!("{REPO_URL}/releases/download/{tag}/{asset_name}"),
        None => format!("{REPO_URL}/releases/latest/download/{asset_name}"),
    };
    let checksum_name = format!("{}-{}.sha256", BIN_NAME, target.full_target);
    let checksum_url = match normalized_tag.as_deref() {
        Some(tag) => format!("{REPO_URL}/releases/download/{tag}/{checksum_name}"),
        None => format!("{REPO_URL}/releases/latest/download/{checksum_name}"),
    };
    let sig_name = format!("{}.minisig", asset_name);
    let sig_url = match normalized_tag.as_deref() {
        Some(tag) => format!("{REPO_URL}/releases/download/{tag}/{sig_name}"),
        None => format!("{REPO_URL}/releases/latest/download/{sig_name}"),
    };

    ensure_prereqs(target.is_windows)?;

    let tmp_dir = TempDir::new()?;
    let asset_path = tmp_dir.path.join(&asset_name);

    log_info(&format!("Downloading {download_url}"));
    run_cmd(
        "curl",
        &["-fsSL", &download_url, "-o", asset_path.to_str().unwrap()],
    )
    .context("Download failed")?;

    let checksum_path = tmp_dir.path.join(&checksum_name);
    log_info(&format!("Downloading checksum {checksum_url}"));
    run_cmd(
        "curl",
        &[
            "-fsSL",
            &checksum_url,
            "-o",
            checksum_path.to_str().unwrap(),
        ],
    )
    .context("Checksum download failed")?;

    let sig_path = tmp_dir.path.join(&sig_name);
    log_info(&format!("Downloading signature {sig_url}"));
    run_cmd(
        "curl",
        &["-fsSL", &sig_url, "-o", sig_path.to_str().unwrap()],
    )
    .context("Signature download failed")?;

    verify_release(&asset_path, &checksum_path, &sig_path)?;

    log_info("Extracting release archive");
    extract_archive(&asset_path, &tmp_dir.path, &target)?;

    let bin_filename = format!("{}{}", BIN_NAME, target.bin_ext);
    let extracted_bin = tmp_dir.path.join(&bin_filename);
    if !extracted_bin.exists() {
        return Err(anyhow!(
            "Extraction failed. Binary not found at {}",
            extracted_bin.display()
        ));
    }

    if !target.is_windows {
        set_executable(&extracted_bin)?;
    }

    install_binary(&extracted_bin, &exe_path, target_dir, target.is_windows)?;

    let version = read_version(&exe_path).unwrap_or_else(|| "updated".to_string());
    println!("✅ Keeper {version}");

    Ok(())
}

struct TargetInfo {
    full_target: String,
    asset_ext: String,
    bin_ext: String,
    is_windows: bool,
}

fn detect_target() -> Result<TargetInfo> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    let (os_target, is_windows) = match os {
        "linux" => ("unknown-linux-gnu", false),
        "macos" => ("apple-darwin", false),
        "windows" => ("pc-windows-msvc", true),
        _ => return Err(anyhow!("Unsupported operating system: {os}")),
    };

    let arch_target = match arch {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        _ => return Err(anyhow!("Unsupported architecture: {arch}")),
    };

    let full_target = format!("{arch_target}-{os_target}");
    let asset_ext = if is_windows { "zip" } else { "tar.gz" };
    let bin_ext = if is_windows { ".exe" } else { "" };

    Ok(TargetInfo {
        full_target,
        asset_ext: asset_ext.to_string(),
        bin_ext: bin_ext.to_string(),
        is_windows,
    })
}

fn normalize_tag(tag: &str) -> String {
    if tag.starts_with('v') {
        tag.to_string()
    } else {
        format!("v{tag}")
    }
}

fn ensure_prereqs(is_windows: bool) -> Result<()> {
    require_command("curl")?;
    if is_windows {
        if !command_exists("unzip") && !command_exists("powershell") {
            return Err(anyhow!(
                "Either unzip or powershell is required but not installed."
            ));
        }
    } else {
        require_command("tar")?;
    }
    Ok(())
}

fn extract_archive(asset_path: &Path, tmp_dir: &Path, target: &TargetInfo) -> Result<()> {
    if target.is_windows {
        if command_exists("unzip") {
            run_cmd(
                "unzip",
                &[
                    "-q",
                    asset_path.to_str().unwrap(),
                    "-d",
                    tmp_dir.to_str().unwrap(),
                ],
            )?;
            return Ok(());
        }

        let asset = windows_escape(asset_path);
        let dest = windows_escape(tmp_dir);
        let command = format!("Expand-Archive -Path '{asset}' -DestinationPath '{dest}'");
        run_cmd("powershell", &["-Command", &command])?;
        return Ok(());
    }

    run_cmd(
        "tar",
        &[
            "-xzf",
            asset_path.to_str().unwrap(),
            "-C",
            tmp_dir.to_str().unwrap(),
        ],
    )?;
    Ok(())
}

fn verify_checksum(asset_path: &Path, checksum_path: &Path) -> Result<()> {
    let checksum_contents =
        fs::read_to_string(checksum_path).context("Failed to read checksum file")?;
    let expected = checksum_contents
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("Checksum file was empty"))?
        .trim()
        .to_lowercase();

    let bytes = fs::read(asset_path).context("Failed to read downloaded asset")?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut actual = String::with_capacity(digest.len() * 2);
    for byte in digest {
        actual.push_str(&format!("{:02x}", byte));
    }

    if expected != actual {
        return Err(anyhow!(
            "Checksum mismatch. Expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn verify_signature(asset_path: &Path, sig_path: &Path) -> Result<()> {
    // Load public key from embedded base64
    let pk_box = PublicKeyBox::from_string(RELEASE_PUBKEY)
        .map_err(|e| anyhow!("Invalid embedded public key: {e}"))?;
    let pk = pk_box
        .into_public_key()
        .map_err(|e| anyhow!("Failed to parse public key: {e}"))?;

    // Load signature from file
    let sig_data = fs::read_to_string(sig_path).context("Failed to read signature file")?;
    let signature_box = minisign::SignatureBox::from_string(&sig_data)
        .map_err(|e| anyhow!("Invalid signature format: {e}"))?;

    // Open data file for verification
    let data_file = fs::File::open(asset_path)
        .context("Failed to open downloaded asset for signature verification")?;
    let data_reader = std::io::BufReader::new(data_file);

    // Verify signature (trusted=true, legacy=false, prehash=false)
    verify(&pk, &signature_box, data_reader, true, false, false).map_err(|_| {
        anyhow!("Signature verification failed. The release may have been tampered with.")
    })?;

    Ok(())
}

fn verify_release(asset_path: &Path, checksum_path: &Path, sig_path: &Path) -> Result<()> {
    // Verify SHA256 checksum first (integrity)
    verify_checksum(asset_path, checksum_path)?;

    // Verify Ed25519 signature (authenticity)
    verify_signature(asset_path, sig_path)?;

    Ok(())
}

fn windows_escape(path: &Path) -> String {
    let display = path.display().to_string();
    display.replace('\\', "\\\\")
}

fn set_executable(path: &Path) -> Result<()> {
    let status = Command::new("chmod")
        .arg("+x")
        .arg(path)
        .status()
        .context("Failed to chmod new binary")?;
    if !status.success() {
        return Err(anyhow!("Failed to mark binary as executable"));
    }
    Ok(())
}

fn install_binary(
    new_binary: &Path,
    exe_path: &Path,
    target_dir: &Path,
    is_windows: bool,
) -> Result<()> {
    let target_path = exe_path.to_path_buf();

    if is_windows {
        install_windows(new_binary, &target_path)?;
        return Ok(());
    }

    let primary = run_cmd(
        "mv",
        &[new_binary.to_str().unwrap(), target_path.to_str().unwrap()],
    );
    if primary.is_ok() {
        return Ok(());
    }

    if command_exists("sudo") {
        run_cmd(
            "sudo",
            &[
                "mv",
                new_binary.to_str().unwrap(),
                target_path.to_str().unwrap(),
            ],
        )?;
        return Ok(());
    }

    Err(anyhow!(
        "Cannot write to {} and 'sudo' is not available.",
        target_dir.display()
    ))
}

fn install_windows(new_binary: &Path, target_path: &Path) -> Result<()> {
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent).context("Failed to create install directory")?;
    }

    if fs::rename(new_binary, target_path).is_ok() {
        return Ok(());
    }

    fs::copy(new_binary, target_path)
        .map(|_| ())
        .context("Failed to overwrite keeper binary. Close any running keeper processes and retry.")
}

fn read_version(exe_path: &Path) -> Option<String> {
    let output = Command::new(exe_path).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn command_exists(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

fn require_command(cmd: &str) -> Result<()> {
    if command_exists(cmd) {
        return Ok(());
    }
    Err(anyhow!("{cmd} is required but not installed."))
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute {cmd}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.trim().is_empty() {
            return Err(anyhow!("Command failed: {cmd}"));
        }
        return Err(anyhow!("Command failed: {cmd}: {stderr}"));
    }
    Ok(())
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Result<Self> {
        let suffix: u64 = rand::random();
        let mut path = std::env::temp_dir();
        path.push(format!("keeper-update-{suffix}"));
        fs::create_dir_all(&path).context("Failed to create temp dir")?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn log_info(message: &str) {
    println!("[INFO] {message}");
}
