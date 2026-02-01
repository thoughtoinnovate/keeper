use crate::cli::{NoteArgs, UpdateArgs};
use crate::models::Priority;
use anyhow::{Result, anyhow};
use chrono::{Duration, Local, NaiveDate};

pub fn parse_note_args(
    args: &NoteArgs,
    default_workspace: &str,
) -> Result<(String, String, Priority, Option<NaiveDate>)> {
    let mut bucket = format!("{default_workspace}/inbox");
    let mut priority = Priority::None;
    let mut due_date: Option<NaiveDate> = None;
    let mut content_parts: Vec<String> = Vec::new();

    for token in &args.content {
        if let Some(new_bucket) = parse_bucket(token, default_workspace)? {
            bucket = new_bucket;
            continue;
        }

        if let Some(new_priority) = parse_priority(token) {
            priority = new_priority;
            continue;
        }

        if token.starts_with('^') {
            if let Some(date) = parse_due_date_token_strict(token)? {
                due_date = Some(date);
            }
            continue;
        }

        content_parts.push(token.clone());
    }

    let content = content_parts.join(" ").trim().to_string();
    Ok((content, bucket, priority, due_date))
}

pub struct UpdateSpec {
    pub content: Option<String>,
    pub bucket: Option<String>,
    pub priority: Option<Priority>,
    pub due_date: Option<Option<NaiveDate>>,
}

pub fn parse_update_args(args: &UpdateArgs, default_workspace: &str) -> Result<UpdateSpec> {
    parse_update_tokens(&args.content, default_workspace)
}

pub fn parse_update_tokens(tokens: &[String], default_workspace: &str) -> Result<UpdateSpec> {
    let mut bucket: Option<String> = None;
    let mut priority: Option<Priority> = None;
    let mut due_date: Option<Option<NaiveDate>> = None;
    let mut content_parts: Vec<String> = Vec::new();

    for token in tokens {
        if let Some(new_bucket) = parse_bucket(token, default_workspace)? {
            bucket = Some(new_bucket);
            continue;
        }

        if let Some(new_priority) = parse_update_priority(token) {
            priority = Some(new_priority);
            continue;
        }

        if token.starts_with('^') {
            if let Some(date_result) = parse_update_due_date_token_strict(token)? {
                due_date = Some(date_result);
            }
            continue;
        }

        content_parts.push(token.clone());
    }

    let content = if content_parts.is_empty() {
        None
    } else {
        Some(content_parts.join(" ").trim().to_string())
    };

    Ok(UpdateSpec {
        content,
        bucket,
        priority,
        due_date,
    })
}

pub fn normalize_bucket_filter(input: &str) -> Result<String> {
    let trimmed = input.trim().trim_end_matches('/');
    if !trimmed.starts_with('@') {
        return Err(anyhow!("Bucket/workspace must start with @"));
    }
    if trimmed == "@" {
        return Err(anyhow!("Workspace is required"));
    }

    // Check for null bytes (VALID-001)
    if trimmed.contains('\0') {
        return Err(anyhow!("Workspace cannot contain null bytes"));
    }

    // Check for path traversal sequences (VALID-002)
    if trimmed.contains("..") || trimmed.contains("../") || trimmed.contains("..\\") {
        return Err(anyhow!("Workspace cannot contain path traversal sequences"));
    }

    // Validate characters (alphanumeric, @, /, -, _ only)
    if !trimmed
        .chars()
        .all(|c| c.is_alphanumeric() || c == '@' || c == '/' || c == '_' || c == '-')
    {
        return Err(anyhow!("Workspace contains invalid characters"));
    }

    if let Some((workspace, bucket)) = trimmed.split_once('/')
        && (workspace.len() <= 1 || bucket.is_empty())
    {
        return Err(anyhow!(
            "Bucket must include workspace and bucket (e.g. @default/inbox)"
        ));
    }
    Ok(trimmed.to_string())
}

fn parse_bucket(token: &str, default_workspace: &str) -> Result<Option<String>> {
    if !token.starts_with('@') {
        return Ok(None);
    }
    if token == "@" {
        return Ok(None);
    }

    // Check for null bytes (VALID-001)
    if token.contains('\0') {
        return Err(anyhow!("Bucket cannot contain null bytes"));
    }

    // Check for path traversal sequences (VALID-002)
    if token.contains("..") || token.contains("../") || token.contains("..\\") {
        return Err(anyhow!("Bucket cannot contain path traversal sequences"));
    }

    // Validate characters (alphanumeric, @, /, -, _ only)
    if !token
        .chars()
        .all(|c| c.is_alphanumeric() || c == '@' || c == '/' || c == '_' || c == '-')
    {
        return Err(anyhow!("Bucket contains invalid characters"));
    }

    if token.contains('/') {
        return Ok(Some(token.to_string()));
    }
    Err(anyhow!(
        "Bucket must include workspace (e.g. {default_workspace}/inbox)"
    ))
}

fn parse_priority(token: &str) -> Option<Priority> {
    match token.to_lowercase().as_str() {
        "!p1" | "p1" => Some(Priority::P1_Urgent),
        "!p2" | "p2" => Some(Priority::P2_Important),
        "!p3" | "p3" => Some(Priority::P3_Task),
        _ => None,
    }
}

fn parse_due_date_token_strict(token: &str) -> Result<Option<NaiveDate>> {
    if !token.starts_with('^') || token.len() <= 1 {
        return Ok(None);
    }

    let raw = &token[1..];
    let normalized = raw.to_lowercase();
    let today = Local::now().date_naive();
    let parsed = match normalized.as_str() {
        "today" => Some(today),
        "tomorrow" => Some(today + Duration::days(1)),
        _ => NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok(),
    };

    parsed
        .ok_or_else(|| anyhow!("Invalid due date: {raw}"))
        .map(Some)
}

fn parse_update_priority(token: &str) -> Option<Priority> {
    match token.to_lowercase().as_str() {
        "!p1" | "p1" => Some(Priority::P1_Urgent),
        "!p2" | "p2" => Some(Priority::P2_Important),
        "!p3" | "p3" => Some(Priority::P3_Task),
        "!none" | "none" => Some(Priority::None),
        _ => None,
    }
}

fn parse_update_due_date_token_strict(token: &str) -> Result<Option<Option<NaiveDate>>> {
    if !token.starts_with('^') || token.len() <= 1 {
        return Ok(None);
    }
    let raw = &token[1..];
    let normalized = raw.to_lowercase();
    if normalized == "none" || normalized == "clear" {
        return Ok(Some(None));
    }
    let date = parse_due_date_token_strict(token)?;
    Ok(date.map(Some))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::NoteArgs;
    use crate::models::Priority;
    use chrono::{Duration, Local, NaiveDate};

    #[test]
    fn parse_defaults_without_sigils() {
        let args = NoteArgs {
            content: vec!["just".into(), "a".into(), "note".into()],
        };
        let (content, bucket, priority, due_date) = parse_note_args(&args, "@default").unwrap();
        assert_eq!(content, "just a note");
        assert_eq!(bucket, "@default/inbox");
        assert_eq!(priority, Priority::None);
        assert_eq!(due_date, None);
    }

    #[test]
    fn parse_bucket_priority_and_due_date() {
        let args = NoteArgs {
            content: vec![
                "Fix".into(),
                "auth".into(),
                "bug".into(),
                "@work/bugs".into(),
                "!p1".into(),
                "^2025-12-31".into(),
            ],
        };
        let (content, bucket, priority, due_date) = parse_note_args(&args, "@default").unwrap();
        assert_eq!(content, "Fix auth bug");
        assert_eq!(bucket, "@work/bugs");
        assert_eq!(priority, Priority::P1_Urgent);
        assert_eq!(
            due_date,
            Some(NaiveDate::from_ymd_opt(2025, 12, 31).unwrap())
        );
    }

    #[test]
    fn parse_today_and_tomorrow() {
        let today = Local::now().date_naive();
        let args_today = NoteArgs {
            content: vec!["Task".into(), "^today".into()],
        };
        let (_, _, _, due_today) = parse_note_args(&args_today, "@default").unwrap();
        assert_eq!(due_today, Some(today));

        let args_tomorrow = NoteArgs {
            content: vec!["Task".into(), "^tomorrow".into()],
        };
        let (_, _, _, due_tomorrow) = parse_note_args(&args_tomorrow, "@default").unwrap();
        assert_eq!(due_tomorrow, Some(today + Duration::days(1)));
    }

    #[test]
    fn invalid_due_date_errors() {
        let args = NoteArgs {
            content: vec!["Review".into(), "^notadate".into()],
        };
        let err = parse_note_args(&args, "@default").unwrap_err();
        assert!(err.to_string().contains("Invalid due date"));
    }

    #[test]
    fn last_bucket_and_priority_win() {
        let args = NoteArgs {
            content: vec![
                "Plan".into(),
                "@home/projects".into(),
                "@work/plan".into(),
                "!p2".into(),
                "!p3".into(),
            ],
        };
        let (content, bucket, priority, _) = parse_note_args(&args, "@default").unwrap();
        assert_eq!(content, "Plan");
        assert_eq!(bucket, "@work/plan");
        assert_eq!(priority, Priority::P3_Task);
    }

    #[test]
    fn bucket_requires_workspace() {
        let args = NoteArgs {
            content: vec!["Fix".into(), "@work".into()],
        };
        let err = parse_note_args(&args, "@default").unwrap_err();
        assert!(err.to_string().contains("Bucket must include workspace"));
    }

    #[test]
    fn parse_priority_without_bang() {
        let args = NoteArgs {
            content: vec!["Task".into(), "p1".into()],
        };
        let (_, _, priority, _) = parse_note_args(&args, "@default").unwrap();
        assert_eq!(priority, Priority::P1_Urgent);
    }
}
