use crate::models::{Item, Priority};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::NaiveDate;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use serde::Serialize;
use std::io::Write;

pub struct OverdueCounts {
    pub p1: usize,
    pub p2: usize,
    pub p3: usize,
    pub notes: usize,
}

pub fn build_mermaid_due_timeline(
    items: &[Item],
    overdue: &OverdueCounts,
    today: NaiveDate,
    cutoff: NaiveDate,
) -> Result<String> {
    let mut lines = Vec::new();
    lines.push(
        "%%{init: {'theme':'base','themeVariables':{'timelineTextColor':'#1f2937','timelineBorderColor':'#e5e7eb','timelineSectionColor':'#ffffff','fontFamily':'Inter, ui-sans-serif'}}}%%"
            .to_string(),
    );
    lines.push("timeline".to_string());
    lines.push("    title 🗓️ Tasks Timeline".to_string());
    lines.push("    section ⚠️ Overdue".to_string());
    lines.push(format!("    P1: {}", overdue.p1));
    lines.push(format!("    P2: {}", overdue.p2));
    lines.push(format!("    P3: {}", overdue.p3));
    lines.push(format!("    notes: {}", overdue.notes));

    lines.push(format!("    section 📍 TODAY( {today})"));
    append_section_items(&mut lines, items, Some(today));

    let mut dates: Vec<NaiveDate> = items
        .iter()
        .filter_map(|item| item.due_date)
        .filter(|d| *d > today && *d <= cutoff)
        .collect();
    dates.sort();
    dates.dedup();
    for date in dates {
        lines.push(format!("    section 📅 {date}"));
        append_section_items(&mut lines, items, Some(date));
    }

    Ok(lines.join("\n"))
}

pub fn mermaid_timeline_to_ascii(code: &str) -> String {
    let mut title = None;
    let mut entries: Vec<(String, String)> = Vec::new();

    for line in code.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed == "timeline"
            || trimmed.starts_with("%%{")
            || trimmed.starts_with("classDef ")
            || trimmed.starts_with("class ")
        {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("title ") {
            title = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("section ") {
            entries.push(("".to_string(), rest.trim().to_string()));
            continue;
        }
        if let Some((date, text)) = trimmed.split_once(" : ") {
            entries.push((date.trim().to_string(), text.trim().to_string()));
        }
        if let Some((label, text)) = trimmed.split_once(':') {
            entries.push((label.trim().to_string(), text.trim().to_string()));
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
    for (label, text) in entries {
        if label.is_empty() {
            output.push_str(&format!("{text}\n"));
        } else if text.is_empty() {
            output.push_str(&format!("{label}\n"));
        } else {
            output.push_str(&format!("{label} | {text}\n"));
        }
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

fn append_section_items(lines: &mut Vec<String>, items: &[Item], date: Option<NaiveDate>) {
    let mut buckets: Vec<&Item> = items.iter().filter(|item| item.due_date == date).collect();
    buckets.sort_by_key(|item| (priority_rank(item.priority), item.id));

    append_priority_group(lines, &buckets, Priority::P1_Urgent, "P1");
    append_priority_group(lines, &buckets, Priority::P2_Important, "P2");
    append_priority_group(lines, &buckets, Priority::P3_Task, "P3");
    append_priority_group(lines, &buckets, Priority::None, "notes");
}

fn append_priority_group(
    lines: &mut Vec<String>,
    items: &[&Item],
    priority: Priority,
    label: &str,
) {
    let mut first = true;
    for item in items.iter().filter(|item| item.priority == priority) {
        let entry = format_entry(item);
        if first {
            lines.push(format!("    {label} : {entry}"));
            first = false;
        } else {
            lines.push(format!("          : {entry}"));
        }
    }
}

fn format_entry(item: &Item) -> String {
    let (workspace, bucket) = split_bucket(&item.bucket);
    format!(
        "[📁{workspace}>📦 {bucket}] {}",
        sanitize_label(&item.content)
    )
}

fn split_bucket(bucket: &str) -> (String, String) {
    let trimmed = bucket.trim().trim_start_matches('@');
    if let Some((workspace, bucket_name)) = trimmed.split_once('/') {
        return (workspace.to_string(), bucket_name.to_string());
    }
    ("default".to_string(), trimmed.to_string())
}

fn priority_rank(priority: Priority) -> u8 {
    match priority {
        Priority::P1_Urgent => 0,
        Priority::P2_Important => 1,
        Priority::P3_Task => 2,
        Priority::None => 3,
    }
}

fn sanitize_label(input: &str) -> String {
    input.replace(':', " - ").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Item, Priority, Status};
    use chrono::{NaiveDate, Utc};

    #[test]
    fn mermaid_includes_classes_and_today() {
        let item = Item {
            id: 1,
            bucket: "@default/work".to_string(),
            content: "Test".to_string(),
            priority: Priority::P1_Urgent,
            status: Status::Open,
            due_date: Some(NaiveDate::from_ymd_opt(2026, 2, 1).unwrap()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let cutoff = NaiveDate::from_ymd_opt(2026, 2, 15).unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 1, 30).unwrap();
        let code = build_mermaid_due_timeline(
            &[item],
            &OverdueCounts {
                p1: 0,
                p2: 0,
                p3: 0,
                notes: 0,
            },
            today,
            cutoff,
        )
        .unwrap();
        assert!(code.contains("section ⚠️ Overdue"));
        assert!(code.contains("section 📍 TODAY"));
        assert!(code.contains("P1: 0"));
    }
}
