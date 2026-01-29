use crate::models::{Item, Priority};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Local, NaiveDate};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use serde::Serialize;
use std::io::Write;

pub fn build_mermaid_due_timeline(items: &[Item], cutoff: NaiveDate) -> Result<String> {
    let today = Local::now().date_naive();
    let mut lines = Vec::new();
    lines.push("timeline".to_string());
    lines.push(format!("    title Due Timeline ({today} to {cutoff})"));

    let mut sorted: Vec<&Item> = items.iter().collect();
    sorted.sort_by(|a, b| a.due_date.cmp(&b.due_date).then(a.id.cmp(&b.id)));

    for item in sorted {
        let due = match item.due_date {
            Some(d) => d,
            None => continue,
        };
        let label = format_label(item);
        lines.push(format!("    {} : {}", due.format("%Y-%m-%d"), label));
    }

    Ok(lines.join("\n"))
}

pub fn mermaid_timeline_to_ascii(code: &str) -> String {
    let mut title = None;
    let mut entries: Vec<(String, String)> = Vec::new();

    for line in code.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "timeline" {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("title ") {
            title = Some(rest.trim().to_string());
            continue;
        }
        if let Some((date, text)) = trimmed.split_once(" : ") {
            entries.push((date.trim().to_string(), text.trim().to_string()));
        }
    }

    if entries.is_empty() {
        return "(no upcoming tasks)".to_string();
    }

    let mut output = String::new();
    if let Some(title) = title {
        output.push_str(&title);
        output.push('\n');
    }
    for (date, text) in entries {
        output.push_str(&format!("{date} | {text}\n"));
    }
    output.trim_end().to_string()
}

pub fn format_date(date: Option<NaiveDate>) -> String {
    match date {
        Some(d) => d.format("%Y-%m-%d").to_string(),
        None => "n/a".to_string(),
    }
}

#[derive(Serialize)]
struct MermaidLiveState<'a> {
    code: &'a str,
    mermaid: MermaidConfig,
    auto_sync: bool,
    update_diagram: bool,
    editor_mode: &'a str,
    pan_zoom: bool,
}

#[derive(Serialize)]
struct MermaidConfig {
    theme: &'static str,
}

pub fn mermaid_live_edit_url(code: &str) -> Result<String> {
    let state = MermaidLiveState {
        code,
        mermaid: MermaidConfig { theme: "default" },
        auto_sync: true,
        update_diagram: true,
        editor_mode: "code",
        pan_zoom: false,
    };
    let json = serde_json::to_string(&state)?;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(json.as_bytes())?;
    let compressed = encoder.finish()?;
    let encoded = URL_SAFE_NO_PAD.encode(compressed);
    Ok(format!("https://mermaid.live/edit#pako:{encoded}"))
}

pub fn format_terminal_hyperlink(label: &str, url: &str) -> String {
    format!("\u{001b}]8;;{url}\u{001b}\\{label}\u{001b}]8;;\u{001b}\\")
}

fn format_label(item: &Item) -> String {
    let mut label = String::new();
    label.push('[');
    label.push_str(&format_priority(&item.priority));
    label.push_str("] ");
    label.push_str(&sanitize_label(&item.content));
    label.push_str(" (");
    label.push_str(&item.bucket);
    label.push(')');
    label
}

fn format_priority(priority: &Priority) -> &'static str {
    match priority {
        Priority::P1_Urgent => "P1",
        Priority::P2_Important => "P2",
        Priority::P3_Task => "P3",
        Priority::None => "None",
    }
}

fn sanitize_label(input: &str) -> String {
    input.replace(':', " - ").trim().to_string()
}
