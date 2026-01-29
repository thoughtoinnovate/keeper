use assert_cmd::cargo::cargo_bin;
use cucumber::{World, given, then, when};
use futures::FutureExt as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;
use tempfile::TempDir;

#[derive(Debug, World)]
#[world(init = Self::new)]
struct KeeperWorld {
    home: TempDir,
    cwd: PathBuf,
    last_output: Option<Output>,
    recovery_code: Option<String>,
}

impl KeeperWorld {
    fn new() -> Self {
        let home = TempDir::new().expect("tempdir");
        let cwd = home.path().to_path_buf();
        Self {
            home,
            cwd,
            last_output: None,
            recovery_code: None,
        }
    }

    fn run_keeper(&mut self, args: &[&str], stdin: Option<&str>) -> bool {
        let bin = cargo_bin("keeper");
        let mut cmd = Command::new(bin);
        cmd.env("HOME", self.home.path());
        cmd.current_dir(&self.cwd);
        cmd.args(args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }
        let mut child = cmd.spawn().expect("spawn keeper");
        if let Some(input) = stdin {
            if let Some(mut handle) = child.stdin.take() {
                use std::io::Write;
                handle.write_all(input.as_bytes()).expect("write stdin");
            }
        }
        let output = child.wait_with_output().expect("wait output");
        let success = output.status.success();
        self.last_output = Some(output);
        success
    }

    fn last_stdout(&self) -> String {
        let output = self.last_output.as_ref().expect("last output");
        String::from_utf8_lossy(&output.stdout).to_string()
    }

    fn last_stderr(&self) -> String {
        let output = self.last_output.as_ref().expect("last output");
        String::from_utf8_lossy(&output.stderr).to_string()
    }

    fn capture_recovery_code(&mut self) {
        let stdout = self.last_stdout();
        if let Some(idx) = stdout.find("Recovery Code") {
            let rest = &stdout[idx..];
            if let Some(line) = rest.lines().nth(1) {
                let code = line.trim().to_string();
                if !code.is_empty() {
                    self.recovery_code = Some(code);
                }
            }
        }
    }
}

#[given("a fresh keeper home")]
fn fresh_home(world: &mut KeeperWorld) {
    let new_home = TempDir::new().expect("tempdir");
    world.cwd = new_home.path().to_path_buf();
    world.home = new_home;
    world.last_output = None;
    world.recovery_code = None;
}

#[given(expr = "a vault directory {string}")]
fn vault_directory(world: &mut KeeperWorld, dir: String) {
    let path = world.home.path().join(dir);
    std::fs::create_dir_all(path).expect("create vault dir");
}

#[given(expr = "a vault file {string}")]
fn vault_file(world: &mut KeeperWorld, file: String) {
    let path = world.home.path().join(file);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create vault file parent");
    }
}

#[when(expr = "I start the daemon with password {string}")]
fn start_daemon(world: &mut KeeperWorld, password: String) {
    let input = format!("{password}\n{password}\n");
    let success = world.run_keeper(&["start"], Some(&input));
    world.capture_recovery_code();
    if success {
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[when(expr = "I start the daemon with password {string} and vault {string}")]
fn start_daemon_with_vault(world: &mut KeeperWorld, password: String, vault: String) {
    let input = format!("{password}\n{password}\n");
    let success = world.run_keeper(&["--vault", &vault, "start"], Some(&input));
    world.capture_recovery_code();
    if success {
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[when(expr = "I attempt to start with passwords {string} and {string}")]
fn start_daemon_mismatch(world: &mut KeeperWorld, first: String, second: String) {
    let input = format!("{first}\n{second}\n");
    world.run_keeper(&["start"], Some(&input));
}

#[when("I stop the daemon")]
#[then("I stop the daemon")]
fn stop_daemon(world: &mut KeeperWorld) {
    world.run_keeper(&["stop"], None);
}

#[when(
    expr = "I add a note {string} in bucket {string} with priority {string} and due date {string}"
)]
fn add_note(
    world: &mut KeeperWorld,
    content: String,
    bucket: String,
    priority: String,
    due: String,
) {
    world.run_keeper(&["note", &content, &bucket, &priority, &due], None);
}

#[when(expr = "I get notes for bucket {string}")]
fn get_notes(world: &mut KeeperWorld, bucket: String) {
    world.run_keeper(&["get", &bucket], None);
}

#[when("I run due timeline")]
fn run_due_timeline(world: &mut KeeperWorld) {
    world.run_keeper(&["dash", "due_timeline"], None);
}

#[when("I run due timeline with mermaid")]
fn run_due_timeline_mermaid(world: &mut KeeperWorld) {
    world.run_keeper(&["dash", "due_timeline", "--mermaid"], None);
}

#[when(expr = "I run {string} with no content")]
fn run_with_no_content(world: &mut KeeperWorld, cmd: String) {
    world.run_keeper(&[cmd.as_str()], None);
}

#[when(expr = "I recover the vault using the saved recovery code and new password {string}")]
fn recover_with_saved_code(world: &mut KeeperWorld, new_password: String) {
    let code = world
        .recovery_code
        .as_ref()
        .expect("recovery code")
        .to_string();
    let input = format!("{code}\n{new_password}\n{new_password}\n");
    world.run_keeper(&["recover"], Some(&input));
}

#[when(expr = "I attempt recovery with code {string} and new password {string}")]
fn recover_with_bad_code(world: &mut KeeperWorld, code: String, new_password: String) {
    let input = format!("{code}\n{new_password}\n{new_password}\n");
    world.run_keeper(&["recover"], Some(&input));
}

#[when(expr = "I attempt to rotate password from {string} to {string}")]
fn rotate_bad_password(world: &mut KeeperWorld, current: String, new_password: String) {
    let input = format!("{current}\n{new_password}\n{new_password}\n");
    world.run_keeper(&["passwd"], Some(&input));
}

#[when(expr = "I rotate password from {string} to {string}")]
fn rotate_password(world: &mut KeeperWorld, current: String, new_password: String) {
    let input = format!("{current}\n{new_password}\n{new_password}\n");
    world.run_keeper(&["passwd"], Some(&input));
}

#[then("the daemon status should be running")]
fn status_running(world: &mut KeeperWorld) {
    world.run_keeper(&["status"], None);
    assert!(
        world.last_stdout().contains("Daemon running"),
        "expected running, got: {}",
        world.last_stdout()
    );
}

#[then("the daemon status should be stopped")]
fn status_stopped(world: &mut KeeperWorld) {
    world.run_keeper(&["status"], None);
    assert!(
        world.last_stdout().contains("Daemon not running"),
        "expected stopped, got: {}",
        world.last_stdout()
    );
}

#[then(expr = "the vault database should exist at {string}")]
fn vault_db_exists(world: &mut KeeperWorld, path: String) {
    let full = world.home.path().join(path);
    assert!(full.exists(), "expected file to exist: {}", full.display());
}

#[then(expr = "the keystore should exist at {string}")]
fn keystore_exists(world: &mut KeeperWorld, path: String) {
    let full = world.home.path().join(path);
    assert!(full.exists(), "expected file to exist: {}", full.display());
}

#[then(expr = "the output should contain {string}")]
fn output_contains(world: &mut KeeperWorld, needle: String) {
    let out = world.last_stdout();
    assert!(
        out.contains(&needle),
        "expected stdout to contain `{needle}`, got: {out}"
    );
}

#[then(expr = "the command should fail with message {string}")]
fn command_failed_with(world: &mut KeeperWorld, needle: String) {
    let output = world.last_output.as_ref().expect("last output");
    assert!(!output.status.success(), "expected failure");
    let stderr = world.last_stderr();
    let stdout = world.last_stdout();
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains(&needle),
        "expected error to contain `{needle}`, got: {combined}"
    );
}

#[then("the command should succeed")]
fn command_succeeded(world: &mut KeeperWorld) {
    let output = world.last_output.as_ref().expect("last output");
    assert!(output.status.success(), "expected success");
}

#[tokio::main]
async fn main() {
    KeeperWorld::cucumber()
        .after(|_, _, _, _, world| {
            async move {
                if let Some(world) = world {
                    let _ = world.run_keeper(&["stop"], None);
                }
            }
            .boxed_local()
        })
        .run("tests/bdd/features")
        .await;
}
