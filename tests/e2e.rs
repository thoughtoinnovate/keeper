use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn test_quick_capture_flow() {
    let temp = tempdir().unwrap();
    let home = temp.path();

    cargo_bin_cmd!("keeper")
        .env("HOME", home)
        .arg("start")
        .write_stdin("pass\npass\n")
        .assert()
        .success();

    std::thread::sleep(std::time::Duration::from_millis(200));

    cargo_bin_cmd!("keeper")
        .env("HOME", home)
        .arg("note")
        .arg("test task")
        .arg("@test")
        .arg("!p1")
        .arg("^2025-12-31")
        .assert()
        .success()
        .stdout(predicate::str::contains("[✓] Saved"));

    let assert = cargo_bin_cmd!("keeper")
        .env("HOME", home)
        .arg("get")
        .arg("@test")
        .assert()
        .success();

    let output = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    insta::assert_snapshot!(output);

    cargo_bin_cmd!("keeper")
        .env("HOME", home)
        .arg("stop")
        .assert()
        .success();
}
