use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::io::{self, BufRead, Write};
use std::process::{Command, Stdio};

const DOCS_URI: &str = "keeper://docs";
const DOCS_MIME: &str = "text/markdown";

#[derive(Debug, Clone)]
struct Config {
    keeper_bin: String,
    vault: Option<String>,
    password: Option<String>,
    read_only: bool,
    allow_password_ops: bool,
    auto_start: bool,
}

impl Config {
    fn from_env() -> Self {
        let keeper_bin = env::var("KEEPER_BIN").unwrap_or_else(|_| "keeper".to_string());
        let vault = env::var("KEEPER_VAULT").ok();
        let password = resolve_password();
        let read_only = env_bool("KEEPER_READONLY", true);
        let allow_password_ops = env_bool("KEEPER_ALLOW_PASSWORD_OPS", false);
        let auto_start = env_bool("KEEPER_AUTO_START", false);
        Self {
            keeper_bin,
            vault,
            password,
            read_only,
            allow_password_ops,
            auto_start,
        }
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(val) => matches!(
            val.to_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

fn resolve_password() -> Option<String> {
    let raw = env::var("KEEPER_PASSWORD").ok()?;
    if let Some(rest) = raw.strip_prefix("env:") {
        env::var(rest).ok()
    } else {
        Some(raw)
    }
}

#[derive(Debug, Deserialize)]
struct RpcRequest {
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct RpcResponse<'a> {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError<'a>>,
}

#[derive(Debug, Serialize)]
struct RpcError<'a> {
    code: i64,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

fn main() -> Result<()> {
    let config = Config::from_env();
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: RpcRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(_) => continue,
        };

        let id = req.id.clone().unwrap_or(json!(null));
        let response = handle_request(&config, req);
        let resp = RpcResponse {
            jsonrpc: "2.0",
            id,
            result: response.ok(),
            error: response.err(),
        };
        let payload = serde_json::to_string(&resp)?;
        writeln!(stdout, "{payload}")?;
        stdout.flush()?;
    }

    Ok(())
}

fn handle_request(config: &Config, req: RpcRequest) -> Result<Value, RpcError<'static>> {
    match req.method.as_str() {
        "initialize" => Ok(json!({
            "protocolVersion": req.params.as_ref().and_then(|p| p.get("protocolVersion")).cloned().unwrap_or(json!("1.0")),
            "capabilities": {
                "resources": { "list": true, "read": true },
                "tools": { "list": true, "call": true }
            },
            "serverInfo": { "name": "keeper-mcp", "version": "0.1.0" }
        })),
        "resources/list" => Ok(json!({
            "resources": [
                {
                    "uri": DOCS_URI,
                    "name": "Keeper MCP Tool/API Docs",
                    "mimeType": DOCS_MIME
                }
            ]
        })),
        "resources/read" => {
            let uri = req
                .params
                .as_ref()
                .and_then(|p| p.get("uri"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if uri != DOCS_URI {
                return Err(RpcError { code: -32602, message: "Unknown resource", data: None });
            }
            Ok(json!({
                "contents": [
                    { "uri": DOCS_URI, "mimeType": DOCS_MIME, "text": docs_text() }
                ]
            }))
        }
        "tools/list" => Ok(json!({ "tools": tool_list() })),
        "tools/call" => {
            let tool = req
                .params
                .as_ref()
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .ok_or(RpcError { code: -32602, message: "Missing tool name", data: None })?;
            let args = req.params.and_then(|p| p.get("arguments").cloned()).unwrap_or(json!({}));
            let result = call_tool(config, tool, args)?;
            Ok(json!({ "content": [{ "type": "text", "text": result }] }))
        }
        _ => Err(RpcError { code: -32601, message: "Method not found", data: None }),
    }
}

fn tool_list() -> Vec<Value> {
    vec![
        tool("keeper.status", "Check daemon status", json!({"type":"object","properties":{"vault":{"type":"string"}}})),
        tool("keeper.start", "Start daemon", json!({"type":"object","properties":{"vault":{"type":"string"}}})),
        tool("keeper.stop", "Stop daemon", json!({"type":"object","properties":{"vault":{"type":"string"}}})),
        tool(
            "keeper.note",
            "Create a note/task",
            json!({"type":"object","properties":{
                "content":{"type":"string"},
                "bucket":{"type":"string"},
                "priority":{"type":"string","enum":["p1","p2","p3","none"]},
                "due":{"type":"string"},
                "vault":{"type":"string"}
            },"required":["content"]}),
        ),
        tool(
            "keeper.get",
            "Retrieve items",
            json!({"type":"object","properties":{
                "bucket":{"type":"string"},
                "all":{"type":"boolean"},
                "notes":{"type":"boolean"},
                "vault":{"type":"string"}
            }}),
        ),
        tool(
            "keeper.update",
            "Update item attributes",
            json!({"type":"object","properties":{
                "id":{"type":"integer"},
                "content":{"type":"string"},
                "bucket":{"type":"string"},
                "priority":{"type":"string","enum":["p1","p2","p3","none"]},
                "due":{"type":"string"},
                "vault":{"type":"string"}
            },"required":["id"]}),
        ),
        tool(
            "keeper.mark",
            "Set item status",
            json!({"type":"object","properties":{
                "id":{"type":"integer"},
                "status":{"type":"string","enum":["open","done","deleted"]},
                "vault":{"type":"string"}
            },"required":["id","status"]}),
        ),
        tool(
            "keeper.delete",
            "Delete item or archive all",
            json!({"type":"object","properties":{
                "id":{"type":"integer"},
                "all":{"type":"boolean"},
                "confirm":{"type":"boolean"},
                "vault":{"type":"string"}
            }}),
        ),
        tool(
            "keeper.undo",
            "Undo last archive or specific id",
            json!({"type":"object","properties":{
                "id":{"type":"integer"},
                "vault":{"type":"string"}
            }}),
        ),
        tool("keeper.archive", "List archived items", json!({"type":"object","properties":{"vault":{"type":"string"}}})),
        tool(
            "keeper.dash_due_timeline",
            "Due-date timeline (next 15 days)",
            json!({"type":"object","properties":{
                "mermaid":{"type":"boolean"},
                "vault":{"type":"string"}
            }}),
        ),
        tool(
            "keeper.passwd",
            "Rotate password",
            json!({"type":"object","properties":{
                "current":{"type":"string"},
                "new":{"type":"string"},
                "vault":{"type":"string"}
            },"required":["current","new"]}),
        ),
        tool(
            "keeper.recover",
            "Reset password using recovery code",
            json!({"type":"object","properties":{
                "code":{"type":"string"},
                "new":{"type":"string"},
                "vault":{"type":"string"}
            },"required":["code","new"]}),
        ),
    ]
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    json!({ "name": name, "description": description, "inputSchema": schema })
}

fn call_tool(config: &Config, name: &str, args: Value) -> Result<String, RpcError<'static>> {
    match name {
        "keeper.status" => run_keeper(config, &["status"], None, args.get("vault"))?,
        "keeper.start" => run_keeper_start(config, args.get("vault"))?,
        "keeper.stop" => run_keeper(config, &["stop"], None, args.get("vault"))?,
        "keeper.note" => {
            ensure_daemon(config, args.get("vault"))?;
            require_write(config)?;
            let mut tokens = vec!["note".to_string()];
            let content = args.get("content").and_then(|v| v.as_str()).ok_or(err("Missing content"))?;
            tokens.push(content.to_string());
            if let Some(bucket) = args.get("bucket").and_then(|v| v.as_str()) {
                tokens.push(normalize_bucket(bucket));
            }
            if let Some(priority) = args.get("priority").and_then(|v| v.as_str()) {
                tokens.push(normalize_priority(priority));
            }
            if let Some(due) = args.get("due").and_then(|v| v.as_str()) {
                tokens.push(format!("^{}", due));
            }
            run_keeper(config, &string_args(&tokens), None, args.get("vault"))?
        }
        "keeper.get" => {
            ensure_daemon(config, args.get("vault"))?;
            let mut tokens = vec!["get".to_string()];
            if let Some(bucket) = args.get("bucket").and_then(|v| v.as_str()) {
                tokens.push(normalize_bucket(bucket));
            }
            if args.get("all").and_then(|v| v.as_bool()) == Some(true) {
                tokens.push("--all".to_string());
            }
            if args.get("notes").and_then(|v| v.as_bool()) == Some(true) {
                tokens.push("--notes".to_string());
            }
            run_keeper(config, &string_args(&tokens), None, args.get("vault"))?
        }
        "keeper.update" => {
            ensure_daemon(config, args.get("vault"))?;
            require_write(config)?;
            let id = args.get("id").and_then(|v| v.as_i64()).ok_or(err("Missing id"))?;
            let mut tokens = vec!["update".to_string(), id.to_string()];
            if let Some(content) = args.get("content").and_then(|v| v.as_str()) {
                tokens.push(content.to_string());
            }
            if let Some(bucket) = args.get("bucket").and_then(|v| v.as_str()) {
                tokens.push(normalize_bucket(bucket));
            }
            if let Some(priority) = args.get("priority").and_then(|v| v.as_str()) {
                tokens.push(normalize_priority(priority));
            }
            if let Some(due) = args.get("due").and_then(|v| v.as_str()) {
                if due == "clear" || due == "none" {
                    tokens.push("^clear".to_string());
                } else {
                    tokens.push(format!("^{}", due));
                }
            }
            run_keeper(config, &string_args(&tokens), None, args.get("vault"))?
        }
        "keeper.mark" => {
            ensure_daemon(config, args.get("vault"))?;
            require_write(config)?;
            let id = args.get("id").and_then(|v| v.as_i64()).ok_or(err("Missing id"))?;
            let status = args.get("status").and_then(|v| v.as_str()).ok_or(err("Missing status"))?;
            run_keeper(
                config,
                &["mark", &id.to_string(), status],
                None,
                args.get("vault"),
            )?
        }
        "keeper.delete" => {
            ensure_daemon(config, args.get("vault"))?;
            require_write(config)?;
            let all = args.get("all").and_then(|v| v.as_bool()) == Some(true);
            if all {
                if args.get("confirm").and_then(|v| v.as_bool()) != Some(true) {
                    return Err(err("Missing confirm=true for delete all"));
                }
                run_keeper(config, &["delete", "--all", "--yes"], None, args.get("vault"))?
            } else {
                let id = args.get("id").and_then(|v| v.as_i64()).ok_or(err("Missing id"))?;
                run_keeper(config, &["delete", &id.to_string()], None, args.get("vault"))?
            }
        }
        "keeper.undo" => {
            ensure_daemon(config, args.get("vault"))?;
            require_write(config)?;
            if let Some(id) = args.get("id").and_then(|v| v.as_i64()) {
                run_keeper(config, &["undo", &id.to_string()], None, args.get("vault"))?
            } else {
                run_keeper(config, &["undo"], None, args.get("vault"))?
            }
        }
        "keeper.archive" => {
            ensure_daemon(config, args.get("vault"))?;
            run_keeper(config, &["archive"], None, args.get("vault"))?
        }
        "keeper.dash_due_timeline" => {
            ensure_daemon(config, args.get("vault"))?;
            let mermaid = args.get("mermaid").and_then(|v| v.as_bool()) == Some(true);
            if mermaid {
                run_keeper(config, &["dash", "due_timeline", "--mermaid"], None, args.get("vault"))?
            } else {
                run_keeper(config, &["dash", "due_timeline"], None, args.get("vault"))?
            }
        }
        "keeper.passwd" => {
            ensure_daemon(config, args.get("vault"))?;
            if !config.allow_password_ops {
                return Err(err("Password operations disabled"));
            }
            let current = args.get("current").and_then(|v| v.as_str()).ok_or(err("Missing current password"))?;
            let new = args.get("new").and_then(|v| v.as_str()).ok_or(err("Missing new password"))?;
            let stdin = format!("{current}\n{new}\n{new}\n");
            run_keeper(config, &["passwd"], Some(&stdin), args.get("vault"))?
        }
        "keeper.recover" => {
            if !config.allow_password_ops {
                return Err(err("Password operations disabled"));
            }
            let code = args.get("code").and_then(|v| v.as_str()).ok_or(err("Missing recovery code"))?;
            let new = args.get("new").and_then(|v| v.as_str()).ok_or(err("Missing new password"))?;
            let stdin = format!("{code}\n{new}\n{new}\n");
            run_keeper(config, &["recover"], Some(&stdin), args.get("vault"))?
        }
        _ => return Err(err("Unknown tool")),
    };
    Ok(format_keeper_result())
}

fn format_keeper_result() -> String {
    let mut out = String::new();
    if let Some(stdout) = LAST_STDOUT.with(|s| s.borrow().clone()) {
        if !stdout.is_empty() {
            out.push_str("stdout:\n");
            out.push_str(&stdout);
            if !stdout.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    if let Some(stderr) = LAST_STDERR.with(|s| s.borrow().clone()) {
        if !stderr.is_empty() {
            out.push_str("stderr:\n");
            out.push_str(&stderr);
            if !stderr.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    if out.trim().is_empty() {
        out.push_str("ok");
    }
    out
}

thread_local! {
    static LAST_STDOUT: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
    static LAST_STDERR: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}

fn set_last_output(stdout: String, stderr: String) {
    LAST_STDOUT.with(|s| *s.borrow_mut() = Some(stdout));
    LAST_STDERR.with(|s| *s.borrow_mut() = Some(stderr));
}

fn ensure_daemon(config: &Config, vault: Option<&Value>) -> Result<(), RpcError<'static>> {
    let status = run_keeper(config, &["status"], None, vault)?;
    if status.contains("Daemon running") {
        return Ok(());
    }
    if !config.auto_start {
        return Err(err("Daemon not running and auto-start disabled"));
    }
    run_keeper_start(config, vault)?;
    let status = run_keeper(config, &["status"], None, vault)?;
    if status.contains("Daemon running") {
        Ok(())
    } else {
        Err(err("Failed to start daemon"))
    }
}

fn run_keeper_start(config: &Config, vault: Option<&Value>) -> Result<String, RpcError<'static>> {
    let password = config
        .password
        .as_ref()
        .ok_or(err("Auto-start requires password source"))?;
    let stdin = if keystore_exists(config, vault) {
        format!("{password}\n")
    } else {
        format!("{password}\n{password}\n")
    };
    run_keeper(config, &["start"], Some(&stdin), vault)
}

fn keystore_exists(config: &Config, vault: Option<&Value>) -> bool {
    let vault = vault
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .or_else(|| config.vault.clone());
    let Some(path) = vault else { return false };
    let path = std::path::Path::new(&path);
    let base = if path.extension().and_then(|e| e.to_str()) == Some("db") || path.is_file() {
        path.parent().map(|p| p.to_path_buf())
    } else {
        Some(path.to_path_buf())
    };
    let Some(base) = base else { return false };
    base.join("keystore.json").exists()
}

fn require_write(config: &Config) -> Result<(), RpcError<'static>> {
    if config.read_only {
        Err(err("Read-only mode enabled"))
    } else {
        Ok(())
    }
}

fn run_keeper(
    config: &Config,
    args: &[&str],
    stdin: Option<&str>,
    vault: Option<&Value>,
) -> Result<String, RpcError<'static>> {
    let mut cmd = Command::new(&config.keeper_bin);
    if let Some(vault) = vault.and_then(|v| v.as_str()) {
        cmd.arg("--vault").arg(vault);
    } else if let Some(vault) = &config.vault {
        cmd.arg("--vault").arg(vault);
    }
    cmd.args(args);
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().map_err(|_| err("Failed to spawn keeper"))?;
    if let Some(input) = stdin {
        if let Some(mut handle) = child.stdin.take() {
            let _ = handle.write_all(input.as_bytes());
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|_| err("Failed to read keeper output"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    set_last_output(stdout.clone(), stderr.clone());
    Ok(format!("{stdout}{stderr}"))
}

fn normalize_bucket(bucket: &str) -> String {
    if bucket.starts_with('@') {
        bucket.to_string()
    } else {
        format!("@{bucket}")
    }
}

fn normalize_priority(priority: &str) -> String {
    match priority {
        "p1" | "!p1" => "p1".to_string(),
        "p2" | "!p2" => "p2".to_string(),
        "p3" | "!p3" => "p3".to_string(),
        "none" | "!none" => "none".to_string(),
        other => other.to_string(),
    }
}

fn string_args(tokens: &[String]) -> Vec<&str> {
    tokens.iter().map(|s| s.as_str()).collect()
}

fn err(message: &'static str) -> RpcError<'static> {
    RpcError { code: -32602, message, data: None }
}

fn docs_text() -> &'static str {
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../MCP_AGENT_GUIDE.md"))
}
