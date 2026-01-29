use crate::client::send_request;
use crate::ipc::DaemonRequest;
use crate::models::{Item, Priority, Status};
use crate::paths::KeeperPaths;
use anyhow::Result;
use chrono::{Duration, Local, NaiveDate};
use reedline::{DefaultPrompt, DefaultPromptSegment, Reedline, Signal};
use tabled::{Table, Tabled};

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

pub fn run_repl(paths: &KeeperPaths) -> Result<()> {
    render_dashboard(paths)?;

    let mut line_editor = Reedline::create();
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
                    println!("Unknown command: {trimmed}");
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
            due: display_due_date(item.due_date),
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

fn display_due_date(date: Option<NaiveDate>) -> String {
    let today = Local::now().date_naive();
    let tomorrow = today + Duration::days(1);
    match date {
        Some(d) if d == today => "Today".to_string(),
        Some(d) if d == tomorrow => "Tomorrow".to_string(),
        Some(d) => d.format("%Y-%m-%d").to_string(),
        None => "".to_string(),
    }
}
