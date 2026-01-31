use crate::security::memory::{constant_time_compare, SecurePassword};
use assert_cmd::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn test_password_returns_secure_type() {
    let temp = tempdir().unwrap();
    let home = temp.path();

    // Test that prompt_password returns SecurePassword
    let password = crate::prompt::prompt_password();
    assert!(password.expose_secret().len() > 0);
}

#[test]
fn test_password_confirm_constant_time() {
    // Test that password confirmation uses constant-time comparison
    let temp = tempdir().unwrap();
    let home = temp.path();

    // Create vault
    cargo_bin_cmd!("keeper")
        .env("HOME", home)
        .arg("start")
        .write_stdin("SecurePass123!\nSecurePass123!\n")
        .assert()
        .success();

    std::thread::sleep(std::time::Duration::from_millis(200));

    // Test password change with timing measurement
    let start = std::time::Instant::now();
    cargo_bin_cmd!("keeper")
        .env("HOME", home)
        .arg("passwd")
        .write_stdin("SecurePass123!\nNewSecurePass456!\nNewSecurePass456!\n")
        .assert()
        .success();
    let duration_correct = start.elapsed();

    // Test with wrong password (should take same time)
    let start = std::time::Instant::now();
    cargo_bin_cmd!("keeper")
        .env("HOME", home)
        .arg("passwd")
        .write_stdin("WrongPassword123!\nNewSecurePass456!\nNewSecurePass456!\n")
        .assert()
        .failure();
    let duration_wrong = start.elapsed();

    // Allow 15% variance
    let ratio = duration_correct.as_secs_f64() / duration_wrong.as_secs_f64();
    assert!(
        ratio > 0.9 && ratio < 1.1,
        "Timing attack vulnerability: ratio = {}",
        ratio
    );

    cargo_bin_cmd!("keeper")
        .env("HOME", home)
        .arg("stop")
        .assert()
        .success();
}

#[test]
fn test_constant_time_comparison_direct() {
    // Test the constant_time_compare function directly
    let short = b"abc123";
    let long = b"123abc123";

    // Should match
    assert!(constant_time_compare(short, short));
    assert!(constant_time_compare(long, long));

    // Different lengths should still compare correctly
    let short_pad = b"abc123\x00\x00\x00\x00";
    let long_pad = b"123abc123\x00\x00\x00\x00";
    assert!(constant_time_compare(short, short_pad));
    assert!(constant_time_compare(long, long_pad));

    // Different values should not match
    assert!(!constant_time_compare(short, long));
}
