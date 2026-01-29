use crate::client::{self, send_request};
use crate::ipc::DaemonRequest;
use crate::models::{Item, Priority, Status};
use crate::paths::KeeperPaths;
use crate::{logger, prompt, session, timeline};
use anyhow::Result;
use chrono::{Duration, Local};
use clap::CommandFactory;
use std::io::IsTerminal;
use reedline::{
    default_emacs_keybindings, ColumnarMenu, Completer, DefaultPrompt, DefaultPromptSegment,
    Emacs, Hinter, History, KeyCode, KeyModifiers, Reedline, ReedlineEvent, ReedlineMenu,
    Signal, Span, Suggestion,
};
use tabled::{Table, Tabled};
use zeroize::Zeroize;
use std::io::Write;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

#[derive(Tabled)]
struct UrgentRow {
    #[tabled(rename = "ID")]
    id: i64,
    #[tabled(rename = "Task")]
    task: String,
    #[tabled(rename = "Context")]
    context: String,
    #[tabled(rename = "Due")]
    due: String,
}

pub fn run_repl(paths: &KeeperPaths, debug: bool) -> Result<()> {
    if !client::daemon_running(paths) {
        let outcome = session::unlock_or_init_master_key(paths)?;
        if let Some(recovery) = outcome.recovery_code.as_ref() {
            println!("🧩 Recovery Code (store this safely):\n{recovery}");
        }
        let pid = session::ensure_daemon(paths, &outcome.master_key, debug)?;
        let mut master_key = outcome.master_key;
        master_key.zeroize();
        if let Some(pid) = pid {
            logger::debug(&format!("Daemon started from REPL (pid {pid})"));
        }
        if !client::wait_for_daemon(paths, 1500) {
            return Err(anyhow::anyhow!("Daemon failed to start"));
        }
    }
    println!("Vault: {}", paths.db_path.display());
    render_dashboard(paths)?;

    let base_commands = build_repl_commands();
    let mut commands = base_commands.clone();
    let help_topics = build_help_topics();
    for topic in &help_topics {
        commands.push(format!("help {topic}"));
    }
    let buckets = Arc::new(Mutex::new(load_buckets(paths)));
    let completer = Box::new(KeeperCompleter::new(
        commands.clone(),
        buckets.clone(),
        help_topics.clone(),
    ));
    let hinter = Box::new(CommandHinter::new(base_commands.clone(), help_topics.clone()));
    let completion_menu = Box::new(ColumnarMenu::default().with_name("completion_menu"));
    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    let edit_mode = Box::new(Emacs::new(keybindings));

    let mut line_editor = Reedline::create()
        .with_completer(completer)
        .with_hinter(hinter)
        .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
        .with_edit_mode(edit_mode);
    let prompt = DefaultPrompt::new(
        DefaultPromptSegment::Basic("keeper> ".to_string()),
        DefaultPromptSegment::Empty,
    );
    loop {
        match line_editor.read_line(&prompt) {
            Ok(Signal::Success(input)) => {
                let trimmed = input.trim();
                if trimmed.eq_ignore_ascii_case("exit")
                    || trimmed.eq_ignore_ascii_case("quit")
                {
                    break;
                }
                if !trimmed.is_empty() {
                    if let Err(err) = handle_repl_command(paths, trimmed, debug, &buckets) {
                        eprintln!("{err}");
                    }
                }
            }
            Ok(Signal::CtrlC) | Ok(Signal::CtrlD) => break,
            Err(err) => {
                eprintln!("REPL error: {err}");
                break;
            }
        }
    }

    Ok(())
}

fn handle_repl_command(
    paths: &KeeperPaths,
    line: &str,
    debug: bool,
    buckets: &Arc<Mutex<Vec<String>>>,
) -> Result<()> {
    let tokens = tokenize_input(line);
    if tokens.is_empty() {
        return Ok(());
    }

    match tokens[0].to_lowercase().as_str() {
        "help" => {
            if tokens.len() == 1 {
                println!("Commands: {}", build_repl_commands().join(", "));
            } else {
                let topic = tokens[1..].join(" ");
                if let Some(help) = repl_help_for(&topic) {
                    println!("{help}");
                } else {
                    println!("No help available for: {topic}");
                }
            }
            Ok(())
        }
        "clear" => {
            clear_screen();
            render_dashboard(paths)?;
            Ok(())
        }
        "start" => {
            if client::daemon_running(paths) {
                println!(
                    "✅ Daemon already running. Vault: {}. Socket: {}",
                    paths.db_path.display(),
                    paths.socket_path_display()
                );
                return Ok(());
            }
            let outcome = session::unlock_or_init_master_key(paths)?;
            if let Some(recovery) = outcome.recovery_code.as_ref() {
                println!("🧩 Recovery Code (store this safely):\n{recovery}");
            }
            let pid = session::start_daemon(paths, &outcome.master_key, debug)?;
            let mut master_key = outcome.master_key;
            master_key.zeroize();
            println!(
                "✅ Daemon started. Vault: {}. PID: {}. Socket: {}",
                paths.db_path.display(),
                pid,
                paths.socket_path_display()
            );
            Ok(())
        }
        "stop" => {
            let response = send_request(paths, &DaemonRequest::Shutdown)?;
            match response {
                crate::ipc::DaemonResponse::OkMessage(msg) => println!("{msg}"),
                crate::ipc::DaemonResponse::Error(err) => eprintln!("{err}"),
                _ => println!("Daemon stopped"),
            }
            Ok(())
        }
        "status" => {
            if client::daemon_running(paths) {
                println!("✅ Daemon running. Socket: {}", paths.socket_path_display());
            } else {
                println!("❌ Daemon not running.");
            }
            Ok(())
        }
        "note" => {
            let content = tokens[1..].to_vec();
            if content.is_empty() {
                println!("Usage: note <text...> [@bucket] [!p1|p1] [^date]");
                return Ok(());
            }
            let args = crate::cli::NoteArgs { content };
            let (content, bucket, priority, due_date) =
                match crate::sigil::parse_note_args(&args) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        eprintln!("{err}");
                        return Ok(());
                    }
                };
            if content.is_empty() {
                eprintln!("Note content cannot be empty");
                return Ok(());
            }
            let request = DaemonRequest::CreateNote {
                bucket: bucket.clone(),
                content,
                priority,
                due_date,
            };
            let response = send_request(paths, &request)?;
            match response {
                crate::ipc::DaemonResponse::OkMessage(msg) => {
                    println!("{msg}");
                    let mut bucket_list = buckets.lock().unwrap_or_else(|e| e.into_inner());
                    if !bucket_list.iter().any(|b| b == &bucket) {
                        bucket_list.push(bucket.clone());
                        bucket_list.sort();
                    }
                }
                crate::ipc::DaemonResponse::Error(err) => eprintln!("{err}"),
                _ => println!("[✓] Saved"),
            }
            Ok(())
        }
        "get" => {
            let mut bucket_filter: Option<String> = None;
            if tokens.len() > 1 {
                let mut iter = tokens.iter().skip(1).peekable();
                while let Some(token) = iter.next() {
                    if token == "--bucket" {
                        if let Some(value) = iter.peek() {
                            bucket_filter = Some((*value).clone());
                        }
                        continue;
                    }
                    if token.starts_with("--") {
                        continue;
                    }
                    bucket_filter = Some(token.clone());
                    break;
                }
            }
            let request = DaemonRequest::GetItems {
                bucket_filter,
                priority_filter: None,
                status_filter: Some(crate::models::Status::Open),
                date_cutoff: None,
                include_notes: tokens.iter().any(|t| t == "--all"),
                notes_only: tokens.iter().any(|t| t == "--notes"),
            };
            let response = send_request(paths, &request)?;
            match response {
                crate::ipc::DaemonResponse::OkItems(items) => {
                    let table = crate::formatting::format_items_table(items);
                    println!("{table}");
                }
                crate::ipc::DaemonResponse::Error(err) => eprintln!("{err}"),
                _ => println!("No items"),
            }
            Ok(())
        }
        "mark" => {
            if tokens.len() < 3 {
                println!("Usage: mark <id> <status>");
                return Ok(());
            }
            let id: i64 = tokens[1].parse().unwrap_or(0);
            let status = crate::daemon::parse_status(&tokens[2])
                .ok_or_else(|| anyhow::anyhow!("Invalid status"))?;
            let request = DaemonRequest::UpdateStatus { id, new_status: status };
            let response = send_request(paths, &request)?;
            match response {
                crate::ipc::DaemonResponse::OkMessage(msg) => println!("{msg}"),
                crate::ipc::DaemonResponse::Error(err) => eprintln!("{err}"),
                _ => println!("Updated"),
            }
            Ok(())
        }
        "update" => {
            if tokens.len() < 2 {
                println!("Usage: update <id> <text...> [@bucket] [!p1|p2|p3|none] [^date|^clear]");
                return Ok(());
            }
            let id: i64 = tokens[1].parse().unwrap_or(0);
            if id == 0 {
                println!("Invalid id");
                return Ok(());
            }
            let content_tokens: Vec<String> = tokens.iter().skip(2).cloned().collect();
            let spec = match crate::sigil::parse_update_tokens(&content_tokens) {
                Ok(spec) => spec,
                Err(err) => {
                    eprintln!("{err}");
                    return Ok(());
                }
            };
            if spec.content.is_none()
                && spec.bucket.is_none()
                && spec.priority.is_none()
                && spec.due_date.is_none()
            {
                println!("No updates provided");
                return Ok(());
            }
            let request = DaemonRequest::UpdateItem {
                id,
                bucket: spec.bucket,
                content: spec.content,
                priority: spec.priority,
                due_date: spec.due_date.flatten(),
                clear_due_date: matches!(spec.due_date, Some(None)),
            };
            let response = send_request(paths, &request)?;
            match response {
                crate::ipc::DaemonResponse::OkMessage(msg) => println!("{msg}"),
                crate::ipc::DaemonResponse::Error(err) => eprintln!("{err}"),
                _ => println!("Updated"),
            }
            Ok(())
        }
        "dash" => {
            if tokens.len() < 2 {
                println!("Usage: dash due_timeline [--mermaid]");
                return Ok(());
            }
            match tokens[1].as_str() {
                "due_timeline" => {
                    let mermaid = tokens.iter().any(|t| t == "--mermaid");
                    render_due_timeline(paths, mermaid)?;
                    Ok(())
                }
                _ => {
                    println!("Unknown dash command: {}", tokens[1]);
                    Ok(())
                }
            }
        }
        "keystore" => {
            if tokens.len() < 2 {
                println!("Usage: keystore rebuild");
                return Ok(());
            }
            match tokens[1].as_str() {
                "rebuild" => {
                    if !client::daemon_running(paths) {
                        eprintln!("Daemon not running. Start it first to rebuild keystore.");
                        return Ok(());
                    }
                    let mut new_password = prompt::prompt_password_confirm()?;
                    let response = send_request(
                        paths,
                        &DaemonRequest::RebuildKeystore {
                            new_password: new_password.clone(),
                        },
                    )?;
                    new_password.zeroize();
                    match response {
                        crate::ipc::DaemonResponse::OkRecoveryCode(code) => {
                            println!("✅ Keystore rebuilt.");
                            println!("🧩 New Recovery Code (store this safely):\n{code}");
                        }
                        crate::ipc::DaemonResponse::Error(err) => eprintln!("{err}"),
                        _ => println!("Unexpected response"),
                    }
                    Ok(())
                }
                _ => {
                    println!("Unknown keystore command: {}", tokens[1]);
                    Ok(())
                }
            }
        }
        "delete" => {
            if tokens.len() < 2 {
                println!("Usage: delete <id> | delete all");
                return Ok(());
            }
            if tokens[1].eq_ignore_ascii_case("all") {
                if !confirm("Type YES to archive all notes: ")? {
                    println!("Aborted.");
                    return Ok(());
                }
                let _ = prompt::prompt_password()?;
                let response = send_request(paths, &DaemonRequest::ArchiveAll)?;
                match response {
                    crate::ipc::DaemonResponse::OkMessage(msg) => println!("{msg}"),
                    crate::ipc::DaemonResponse::Error(err) => eprintln!("{err}"),
                    _ => println!("Archived"),
                }
                return Ok(());
            }
            let id: i64 = tokens[1].parse().unwrap_or(0);
            if id == 0 {
                println!("Invalid id");
                return Ok(());
            }
            let response = send_request(
                paths,
                &DaemonRequest::UpdateStatus {
                    id,
                    new_status: crate::models::Status::Deleted,
                },
            )?;
            match response {
                crate::ipc::DaemonResponse::OkMessage(msg) => println!("{msg}"),
                crate::ipc::DaemonResponse::Error(err) => eprintln!("{err}"),
                _ => println!("Archived"),
            }
            Ok(())
        }
        "undo" => {
            let id = if tokens.len() > 1 {
                tokens[1].parse().ok()
            } else {
                None
            };
            let response = send_request(paths, &DaemonRequest::Undo { id })?;
            match response {
                crate::ipc::DaemonResponse::OkMessage(msg) => println!("{msg}"),
                crate::ipc::DaemonResponse::Error(err) => eprintln!("{err}"),
                _ => println!("Undo complete"),
            }
            Ok(())
        }
        "archive" => {
            let response = send_request(
                paths,
                &DaemonRequest::GetItems {
                    bucket_filter: None,
                    priority_filter: None,
                    status_filter: Some(crate::models::Status::Deleted),
                    date_cutoff: None,
                    include_notes: true,
                    notes_only: false,
                },
            )?;
            match response {
                crate::ipc::DaemonResponse::OkItems(items) => {
                    let table = crate::formatting::format_items_table(items);
                    println!("{table}");
                }
                crate::ipc::DaemonResponse::Error(err) => eprintln!("{err}"),
                _ => println!("No archived items"),
            }
            Ok(())
        }
        other => {
            println!("Unknown command: {other}");
            Ok(())
        }
    }
}

fn tokenize_input(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes: Option<char> = None;

    while let Some(ch) = chars.next() {
        match in_quotes {
            Some(quote) => {
                if ch == quote {
                    in_quotes = None;
                } else if ch == '\\' {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                } else {
                    current.push(ch);
                }
            }
            None => {
                if ch.is_whitespace() {
                    if !current.is_empty() {
                        tokens.push(current.clone());
                        current.clear();
                    }
                } else if ch == '\"' || ch == '\'' {
                    in_quotes = Some(ch);
                } else if ch == '\\' {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                } else {
                    current.push(ch);
                }
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn load_buckets(paths: &KeeperPaths) -> Vec<String> {
    let response = send_request(
        paths,
        &DaemonRequest::GetItems {
            bucket_filter: None,
            priority_filter: None,
            status_filter: None,
            date_cutoff: None,
            include_notes: true,
            notes_only: false,
        },
    );

    let mut buckets: BTreeSet<String> = BTreeSet::new();
    if let Ok(crate::ipc::DaemonResponse::OkItems(items)) = response {
        for item in items {
            buckets.insert(item.bucket);
        }
    }
    if buckets.is_empty() {
        buckets.insert("@inbox".to_string());
    }
    buckets.into_iter().collect()
}

fn clear_screen() {
    print!("\u{001b}[2J\u{001b}[H");
    let _ = std::io::stdout().flush();
}

fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim() == "YES")
}

struct CommandHinter {
    commands: Vec<String>,
    help_topics: Vec<String>,
    current_hint: String,
}

impl CommandHinter {
    fn new(commands: Vec<String>, help_topics: Vec<String>) -> Self {
        Self {
            commands,
            help_topics,
            current_hint: String::new(),
        }
    }
}

impl Hinter for CommandHinter {
    fn handle(
        &mut self,
        line: &str,
        pos: usize,
        _history: &dyn History,
        use_ansi_coloring: bool,
    ) -> String {
        self.current_hint.clear();
        if pos != line.len() {
            return String::new();
        }

        let trimmed = line.trim_end();
        if trimmed.is_empty() || is_in_quotes(trimmed) {
            return String::new();
        }

        let tokens = tokenize_input(trimmed);
        if tokens.is_empty() {
            return String::new();
        }

        let first = tokens[0].as_str();
        let is_first_complete = self.commands.iter().any(|c| c == first);
        let has_space = trimmed.contains(' ') || trimmed.contains('\t');

        if !has_space && !is_first_complete {
            if let Some(cmd) = self
                .commands
                .iter()
                .filter(|c| c.starts_with(first))
                .min()
            {
                if cmd.len() > first.len() {
                    self.current_hint = cmd[first.len()..].to_string();
                }
            }
        } else if is_first_complete {
            if first == "help" && tokens.len() == 2 && !line.ends_with(' ') {
                let partial = tokens[1].as_str();
                if let Some(topic) = self
                    .help_topics
                    .iter()
                    .filter(|t| t.starts_with(partial))
                    .min()
                {
                    if topic.len() > partial.len() {
                        self.current_hint = topic[partial.len()..].to_string();
                    }
                }
            } else {
                self.current_hint = template_for_command(first, &tokens, line);
            }
        }

        if self.current_hint.is_empty() {
            return String::new();
        }
        if use_ansi_coloring {
            format!("\u{001b}[90m{}\u{001b}[0m", self.current_hint)
        } else {
            self.current_hint.clone()
        }
    }

    fn complete_hint(&self) -> String {
        self.current_hint.clone()
    }

    fn next_hint_token(&self) -> String {
        self.current_hint.clone()
    }
}

fn template_for_command(cmd: &str, tokens: &[String], line: &str) -> String {
    let ends_with_space = line.ends_with(' ');
    let mut hint = String::new();

    match cmd {
        "note" => {
            let mut has_bucket = false;
            let mut has_priority = false;
            let mut has_date = false;
            for token in tokens.iter().skip(1) {
                if token.starts_with('@') {
                    has_bucket = true;
                }
                let lower = token.to_lowercase();
                if lower == "!p1"
                    || lower == "!p2"
                    || lower == "!p3"
                    || lower == "p1"
                    || lower == "p2"
                    || lower == "p3"
                {
                    has_priority = true;
                }
                if token.starts_with('^') {
                    has_date = true;
                }
            }

            if tokens.len() == 1 && ends_with_space {
                hint.push_str("\"mynote\"");
            }
            if !has_bucket {
                hint.push_str(" @bucket");
            }
            if !has_priority {
                hint.push_str(" p1");
            }
            if !has_date {
                hint.push_str(" ^today");
            }
        }
        "get" => {
            if tokens.len() == 1 {
                hint.push_str(" @bucket|--notes|--all");
            }
        }
        "mark" => {
            if tokens.len() == 1 {
                hint.push_str(" <id> done");
            }
        }
        "dash" => {
            if tokens.len() == 1 {
                hint.push_str(" due_timeline");
            }
        }
        "keystore" => {
            if tokens.len() == 1 {
                hint.push_str(" rebuild");
            }
        }
        "delete" => {
            if tokens.len() == 1 {
                hint.push_str(" <id>|all");
            }
        }
        "undo" => {
            if tokens.len() == 1 {
                hint.push_str(" [id]");
            }
        }
        "archive" => {}
        "help" => {
            if tokens.len() == 1 {
                hint.push_str(" note");
            }
        }
        _ => {}
    }

    if hint.is_empty() {
        return String::new();
    }

    if !ends_with_space && !hint.starts_with(' ') {
        format!(" {}", hint)
    } else {
        hint
    }
}

fn is_in_quotes(line: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
        } else if ch == '"' && !in_single {
            in_double = !in_double;
        }
    }
    in_single || in_double
}

struct KeeperCompleter {
    commands: Vec<String>,
    buckets: Arc<Mutex<Vec<String>>>,
    help_topics: Vec<String>,
}

impl KeeperCompleter {
    fn new(commands: Vec<String>, buckets: Arc<Mutex<Vec<String>>>, help_topics: Vec<String>) -> Self {
        Self {
            commands,
            buckets,
            help_topics,
        }
    }
}

impl Completer for KeeperCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let prefix = &line[..pos];
        if is_in_quotes(prefix) {
            return Vec::new();
        }

        let ends_with_space = prefix.ends_with(' ') || prefix.ends_with('\t');
        let tokens = tokenize_with_spans(prefix);
        if tokens.is_empty() {
            return suggest_from_candidates(&self.commands, "", 0, pos);
        }

        let first = &tokens[0];
        let cmd = first.text.as_str();

        if tokens.len() == 1 && !ends_with_space {
            return suggest_from_candidates(&self.commands, &first.text, first.start, pos);
        }

        if cmd == "help" {
            let topics = self.help_topics.clone();
            if tokens.len() == 1 && ends_with_space {
                return suggest_from_candidates(&topics, "", pos, pos);
            }
            if tokens.len() >= 2 && !ends_with_space {
                let current = tokens.last().unwrap();
                return suggest_from_candidates(&topics, &current.text, current.start, pos);
            }
        }

        match cmd {
            "note" => self.complete_note(&tokens, ends_with_space, pos),
            "get" => self.complete_get(&tokens, ends_with_space, pos),
            "mark" => self.complete_mark(&tokens, ends_with_space, pos),
            "delete" => self.complete_delete(&tokens, ends_with_space, pos),
            "dash" => self.complete_dash(&tokens, ends_with_space, pos),
            "keystore" => self.complete_keystore(&tokens, ends_with_space, pos),
            _ => Vec::new(),
        }
    }
}

impl KeeperCompleter {
    fn complete_note(
        &self,
        tokens: &[Token],
        ends_with_space: bool,
        pos: usize,
    ) -> Vec<Suggestion> {
        if tokens.len() == 1 {
            if ends_with_space {
                return suggest_from_candidates(&["<text>"], "", pos, pos);
            }
            return Vec::new();
        }

        let mut has_bucket = false;
        let mut has_priority = false;
        let mut has_date = false;
        for token in tokens.iter().skip(1) {
            if token.text.starts_with('@') {
                has_bucket = true;
            }
            let lower = token.text.to_lowercase();
            if lower == "!p1"
                || lower == "!p2"
                || lower == "!p3"
                || lower == "p1"
                || lower == "p2"
                || lower == "p3"
            {
                has_priority = true;
            }
            if token.text.starts_with('^') {
                has_date = true;
            }
        }

        let mut suggestions = Vec::new();
        let current = if ends_with_space {
            None
        } else {
            tokens.last()
        };
        let current_text = current.map(|t| t.text.as_str()).unwrap_or("");
        let span_start = current.map(|t| t.start).unwrap_or(pos);

        if current_text.starts_with('@') || (!has_bucket && (ends_with_space || current_text.is_empty())) {
            let buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
            suggestions.extend(suggest_from_candidates(&buckets, current_text, span_start, pos));
        }

        if current_text.starts_with('p')
            || current_text.starts_with("!p")
            || (!has_priority && (ends_with_space || current_text.is_empty()))
        {
            let priorities = vec!["p1", "p2", "p3"];
            suggestions.extend(suggest_from_candidates(&priorities, current_text, span_start, pos));
        }

        if current_text.starts_with('^') || (!has_date && (ends_with_space || current_text.is_empty())) {
            let dates = build_date_candidates();
            suggestions.extend(suggest_from_candidates(&dates, current_text, span_start, pos));
        }

        suggestions
    }

    fn complete_get(&self, tokens: &[Token], ends_with_space: bool, pos: usize) -> Vec<Suggestion> {
        let current = if ends_with_space { None } else { tokens.last() };
        let current_text = current.map(|t| t.text.as_str()).unwrap_or("");
        let span_start = current.map(|t| t.start).unwrap_or(pos);
        let mut candidates: Vec<String> = vec!["--all".into(), "--notes".into()];
        let buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        candidates.extend(buckets.iter().cloned());
        suggest_from_candidates(&candidates, current_text, span_start, pos)
    }

    fn complete_mark(
        &self,
        tokens: &[Token],
        ends_with_space: bool,
        pos: usize,
    ) -> Vec<Suggestion> {
        if tokens.len() >= 2 && (ends_with_space || tokens.len() >= 3) {
            let current = if ends_with_space { None } else { tokens.last() };
            let current_text = current.map(|t| t.text.as_str()).unwrap_or("");
            let span_start = current.map(|t| t.start).unwrap_or(pos);
            let statuses = vec!["open", "done", "deleted"];
            return suggest_from_candidates(&statuses, current_text, span_start, pos);
        }
        Vec::new()
    }

    fn complete_delete(
        &self,
        tokens: &[Token],
        ends_with_space: bool,
        pos: usize,
    ) -> Vec<Suggestion> {
        let current = if ends_with_space { None } else { tokens.last() };
        let current_text = current.map(|t| t.text.as_str()).unwrap_or("");
        let span_start = current.map(|t| t.start).unwrap_or(pos);
        suggest_from_candidates(&["all"], current_text, span_start, pos)
    }

    fn complete_dash(
        &self,
        tokens: &[Token],
        ends_with_space: bool,
        pos: usize,
    ) -> Vec<Suggestion> {
        let current = if ends_with_space { None } else { tokens.last() };
        let current_text = current.map(|t| t.text.as_str()).unwrap_or("");
        let span_start = current.map(|t| t.start).unwrap_or(pos);
        let subcommands = ["due_timeline"];

        if tokens.len() == 1 {
            if ends_with_space {
                return suggest_from_candidates(&subcommands, "", pos, pos);
            }
            return Vec::new();
        }

        if tokens.len() == 2 {
            if current_text.starts_with('-') {
                return suggest_from_candidates(&["--mermaid"], current_text, span_start, pos);
            }
            return suggest_from_candidates(&subcommands, current_text, span_start, pos);
        }

        if tokens.get(1).map(|t| t.text.as_str()) == Some("due_timeline") {
            return suggest_from_candidates(&["--mermaid"], current_text, span_start, pos);
        }

        Vec::new()
    }

    fn complete_keystore(
        &self,
        tokens: &[Token],
        ends_with_space: bool,
        pos: usize,
    ) -> Vec<Suggestion> {
        let current = if ends_with_space { None } else { tokens.last() };
        let current_text = current.map(|t| t.text.as_str()).unwrap_or("");
        let span_start = current.map(|t| t.start).unwrap_or(pos);
        let subcommands = ["rebuild"];

        if tokens.len() == 1 {
            if ends_with_space {
                return suggest_from_candidates(&subcommands, "", pos, pos);
            }
            return Vec::new();
        }
        if tokens.len() == 2 {
            return suggest_from_candidates(&subcommands, current_text, span_start, pos);
        }
        Vec::new()
    }
}

fn suggest_from_candidates(
    candidates: &[impl AsRef<str>],
    prefix: &str,
    start: usize,
    end: usize,
) -> Vec<Suggestion> {
    let mut suggestions = Vec::new();
    for cand in candidates {
        let value = cand.as_ref();
        if value.starts_with(prefix) {
            suggestions.push(Suggestion {
                value: value.to_string(),
                description: None,
                extra: None,
                span: Span { start, end },
                append_whitespace: true,
            });
        }
    }
    suggestions
}

#[derive(Clone)]
struct Token {
    text: String,
    start: usize,
    end: usize,
}

fn tokenize_with_spans(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut start = 0usize;
    let mut in_quotes: Option<char> = None;
    let mut escaped = false;
    let mut last_index = 0usize;

    for (idx, ch) in input.char_indices() {
        last_index = idx + ch.len_utf8();
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        match in_quotes {
            Some(quote) => {
                if ch == quote {
                    in_quotes = None;
                } else {
                    current.push(ch);
                }
            }
            None => {
                if ch.is_whitespace() {
                    if !current.is_empty() {
                        tokens.push(Token {
                            text: current.clone(),
                            start,
                            end: idx,
                        });
                        current.clear();
                    }
                    start = idx + ch.len_utf8();
                } else if ch == '"' || ch == '\'' {
                    if current.is_empty() {
                        start = idx + ch.len_utf8();
                    }
                    in_quotes = Some(ch);
                } else {
                    if current.is_empty() {
                        start = idx;
                    }
                    current.push(ch);
                }
            }
        }
    }

    if !current.is_empty() {
        tokens.push(Token {
            text: current,
            start,
            end: last_index,
        });
    }
    tokens
}

fn build_repl_commands() -> Vec<String> {
    let mut cmds = Vec::new();
    let mut root = crate::cli::Cli::command();
    for sub in root.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        cmds.push(sub.get_name().to_string());
    }
    cmds.extend(["clear", "exit", "quit", "help"].iter().map(|s| s.to_string()));
    cmds
}

fn build_help_topics() -> Vec<String> {
    let mut topics = build_repl_commands();
    let mut root = crate::cli::Cli::command();
    for sub in root.get_subcommands_mut() {
        if sub.is_hide_set() {
            continue;
        }
        let name = sub.get_name().to_string();
        for sub2 in sub.get_subcommands() {
            if sub2.is_hide_set() {
                continue;
            }
            topics.push(format!("{name} {}", sub2.get_name()));
        }
    }
    topics.sort();
    topics.dedup();
    topics
}

fn repl_help_for(topic: &str) -> Option<String> {
    match topic {
        "clear" => return Some("clear: clear the screen and re-render dashboard".to_string()),
        "exit" | "quit" => return Some("exit: leave the REPL".to_string()),
        "help" => return Some("help [command]: show help".to_string()),
        _ => {}
    }

    if let Some(help) = clap_help_for(topic) {
        return Some(help.trim().to_string());
    }

    None
}

fn clap_help_for(topic: &str) -> Option<String> {
    let mut root = crate::cli::Cli::command();
    let mut parts = topic.split_whitespace();
    let first = parts.next()?;
    let mut cmd = root.find_subcommand_mut(first)?;
    for part in parts {
        cmd = cmd.find_subcommand_mut(part)?;
    }
    let mut buf = Vec::new();
    cmd.write_long_help(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).to_string())
}

fn build_date_candidates() -> Vec<String> {
    let today = Local::now().date_naive();
    let mut candidates = Vec::new();
    candidates.push("^today".to_string());
    candidates.push("^tomorrow".to_string());
    for offset in 0..14 {
        let date = today + Duration::days(offset);
        candidates.push(format!("^{}", date.format("%Y-%m-%d")));
    }
    candidates
}

fn render_dashboard(paths: &KeeperPaths) -> Result<()> {
    let ascii = r#"  _  __                             
 | |/ /___ ___ _ __   ___ _ __  
 |   // _ \ _ \ '_ \ / _ \ '__|     v0.1.0
 |_|\_\___|\___| .__/ \___|_|    ⚡ Daemon Connected
               |_|
"#;
    println!("{ascii}");

    let urgent = fetch_urgent(paths)?;
    let approaching = fetch_approaching(paths)?;
    let stats = fetch_stats(paths)?;
    let overdue = fetch_overdue_counts(paths)?;

    println!(" 🚨 URGENT FOCUS (Top P1s) __________________________________");
    if urgent.is_empty() {
        println!(" (none)");
    } else {
        println!("{}", Table::new(urgent));
    }
    println!();

    println!(" 📅 APPROACHING (Due Tomorrow) ______________________________");
    if approaching.is_empty() {
        println!(" * (none)");
    } else {
        for item in approaching {
            println!(
                " * [{}] {} ({})",
                item.priority, item.content, item.bucket
            );
        }
    }
    println!();

    println!(" 📊 QUICK STATS _____________________________________________");
    println!(
        " Open: {} | Done Today: {} | P1: {}",
        stats.0, stats.1, stats.2
    );
    println!(
        " Overdue by Priority: P1 {} | P2 {} | P3 {} | None {}",
        overdue.0, overdue.1, overdue.2, overdue.3
    );
    println!();

    Ok(())
}

fn fetch_urgent(paths: &KeeperPaths) -> Result<Vec<UrgentRow>> {
    let resp = send_request(
        paths,
        &DaemonRequest::GetItems {
            bucket_filter: None,
            priority_filter: Some(Priority::P1_Urgent),
            status_filter: Some(Status::Open),
            date_cutoff: None,
            include_notes: false,
            notes_only: false,
        },
    )?;

    let items = match resp {
        crate::ipc::DaemonResponse::OkItems(items) => items,
        _ => Vec::new(),
    };

    let mut rows: Vec<UrgentRow> = items
        .into_iter()
        .take(3)
        .map(|item| UrgentRow {
            id: item.id,
            task: item.content,
            context: item.bucket,
            due: crate::formatting::display_due_date(item.due_date),
        })
        .collect();

    if rows.is_empty() {
        return Ok(rows);
    }

    rows.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(rows)
}

fn fetch_approaching(paths: &KeeperPaths) -> Result<Vec<Item>> {
    let tomorrow = Local::now().date_naive() + Duration::days(1);
    let resp = send_request(
        paths,
        &DaemonRequest::GetItems {
            bucket_filter: None,
            priority_filter: None,
            status_filter: Some(Status::Open),
            date_cutoff: Some(tomorrow),
            include_notes: false,
            notes_only: false,
        },
    )?;

    let items = match resp {
        crate::ipc::DaemonResponse::OkItems(items) => items,
        _ => Vec::new(),
    };

    let approaching: Vec<Item> = items
        .into_iter()
        .filter(|item| item.due_date == Some(tomorrow))
        .collect();

    Ok(approaching)
}

fn fetch_stats(paths: &KeeperPaths) -> Result<(i64, i64, i64)> {
    let resp = send_request(paths, &DaemonRequest::GetDashboardStats)?;
    match resp {
        crate::ipc::DaemonResponse::OkStats { open, done_today, p1 } => Ok((open, done_today, p1)),
        _ => Ok((0, 0, 0)),
    }
}

fn fetch_overdue_counts(paths: &KeeperPaths) -> Result<(usize, usize, usize, usize)> {
    let today = Local::now().date_naive();
    let resp = send_request(
        paths,
        &DaemonRequest::GetItems {
            bucket_filter: None,
            priority_filter: None,
            status_filter: Some(Status::Open),
            date_cutoff: Some(today),
            include_notes: false,
            notes_only: false,
        },
    )?;

    let items = match resp {
        crate::ipc::DaemonResponse::OkItems(items) => items,
        _ => Vec::new(),
    };

    let mut p1 = 0usize;
    let mut p2 = 0usize;
    let mut p3 = 0usize;
    let mut none = 0usize;

    for item in items {
        if let Some(due) = item.due_date {
            if due < today {
                match item.priority {
                    Priority::P1_Urgent => p1 += 1,
                    Priority::P2_Important => p2 += 1,
                    Priority::P3_Task => p3 += 1,
                    Priority::None => none += 1,
                }
            }
        }
    }

    Ok((p1, p2, p3, none))
}

fn render_due_timeline(paths: &KeeperPaths, mermaid: bool) -> Result<()> {
    let today = Local::now().date_naive();
    let cutoff = today + Duration::days(15);
    let response = send_request(
        paths,
        &DaemonRequest::GetItems {
            bucket_filter: None,
            priority_filter: None,
            status_filter: Some(Status::Open),
            date_cutoff: Some(cutoff),
            include_notes: false,
            notes_only: false,
        },
    )?;

    let items = match response {
        crate::ipc::DaemonResponse::OkItems(items) => items,
        _ => Vec::new(),
    };

    let mut overdue = Vec::new();
    let mut upcoming = Vec::new();

    for item in items {
        if let Some(due) = item.due_date {
            if due < today {
                overdue.push(item);
            } else if due <= cutoff {
                upcoming.push(item);
            }
        }
    }

    let mermaid_code = timeline::build_mermaid_due_timeline(&upcoming, cutoff)?;
    if mermaid {
        println!("{mermaid_code}");
        return Ok(());
    }
    let link = timeline::mermaid_live_edit_url(&mermaid_code)?;
    let link_label = if std::io::stdout().is_terminal() {
        timeline::format_terminal_hyperlink("timeline", &link)
    } else {
        "timeline".to_string()
    };

    println!("🧭 DUE TIMELINE (Next 15 Days)");
    if overdue.is_empty() {
        println!("Overdue: (none)");
    } else {
        println!("Overdue:");
        overdue.sort_by(|a, b| a.due_date.cmp(&b.due_date).then(a.id.cmp(&b.id)));
        for item in overdue {
            let due = timeline::format_date(item.due_date);
            println!(
                " - [{}] {} ({}) due {}",
                item.priority, item.content, item.bucket, due
            );
        }
    }
    println!();
    let ascii = timeline::mermaid_timeline_to_ascii(&mermaid_code);
    println!("{ascii}");
    println!("Timeline: {link_label}");
    println!("Timeline URL: {link}");
    Ok(())
}
