# 🧪 Document 5: Testing Strategy (testing.md)

### 1. Strategy
Use TDD for unit logic and BDD scenarios for End-to-End (E2E) CLI testing.

### 2. Required Test Crates
Add these to `[dev-dependencies]` in `Cargo.toml`.
* `assert_cmd = "2.0"`: For spawning and testing the CLI binary.
* `predicates = "3.0"`: For asserting on stdout/stderr content.
* `tempfile = "3.8"`: Crucial for creating isolated fake `$HOME` environments per test.
* `insta = { version = "1.34", features = ["yaml"] }`: For snapshot testing complex TUI/table output.

### 3. BDD Example Scenario (E2E)

**Scenario:** Quick Capture Flow
1.  **Given** a clean environment with running daemon.
2.  **When** user executes `keeper note "test task" @test !p1`.
3.  **Then** output should confirm save.
4.  **And** `keeper get @test` should show the task in a table.

### 4. E2E Implementation Example

```rust
// tests/e2e.rs
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn test_quick_capture() {
    // 1. Setup isolated environment
    let temp = tempdir().unwrap();
    let home = temp.path();
    let mut cmd = Command::cargo_bin("keeper").unwrap();
    cmd.env("HOME", home); // Tell keeper to use temp dir

    // 2. Start daemon (mocked password)
    cmd.clone().arg("start").write_stdin("pass\n").assert().success();

    // 3. Run Note command
    cmd.clone().arg("note").arg("test task").arg("@test").arg("!p1")
       .assert()
       .success()
       .stdout(predicate::str::contains("[✓] Saved"));

    // 4. Run Get command and snapshot result
    let assert = cmd.clone().arg("get").arg("@test").assert().success();
    let output = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    insta::assert_snapshot!(output);
}
```
**Important Note for Agent:** When running E2E tests that spawn daemons, ensure your socket paths are unique per test (using `tempfile`) to prevent tests from conflicting with each other.