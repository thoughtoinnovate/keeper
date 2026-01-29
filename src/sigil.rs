use crate::cli::NoteArgs;
use crate::models::Priority;
use chrono::{Duration, Local, NaiveDate};

pub fn parse_note_args(args: &NoteArgs) -> (String, String, Priority, Option<NaiveDate>) {
    let mut bucket = "@inbox".to_string();
    let mut priority = Priority::None;
    let mut due_date: Option<NaiveDate> = None;
    let mut content_parts: Vec<String> = Vec::new();

    for token in &args.content {
        if let Some(new_bucket) = parse_bucket(token) {
            bucket = new_bucket;
            continue;
        }

        if let Some(new_priority) = parse_priority(token) {
            priority = new_priority;
            continue;
        }

        if let Some(date_result) = parse_due_date_token(token) {
            if let Some(date) = date_result {
                due_date = Some(date);
                continue;
            }
        }

        content_parts.push(token.clone());
    }

    let content = content_parts.join(" ").trim().to_string();
    (content, bucket, priority, due_date)
}

fn parse_bucket(token: &str) -> Option<String> {
    if token.starts_with('@') && token.len() > 1 {
        return Some(token.to_string());
    }
    None
}

fn parse_priority(token: &str) -> Option<Priority> {
    match token.to_lowercase().as_str() {
        "!p1" | "p1" => Some(Priority::P1_Urgent),
        "!p2" | "p2" => Some(Priority::P2_Important),
        "!p3" | "p3" => Some(Priority::P3_Task),
        _ => None,
    }
}

fn parse_due_date_token(token: &str) -> Option<Option<NaiveDate>> {
    if !token.starts_with('^') || token.len() <= 1 {
        return None;
    }

    let raw = &token[1..];
    let normalized = raw.to_lowercase();
    let today = Local::now().date_naive();
    let parsed = match normalized.as_str() {
        "today" => Some(today),
        "tomorrow" => Some(today + Duration::days(1)),
        _ => NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok(),
    };

    Some(parsed)
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
        let (content, bucket, priority, due_date) = parse_note_args(&args);
        assert_eq!(content, "just a note");
        assert_eq!(bucket, "@inbox");
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
                "@work".into(),
                "!p1".into(),
                "^2025-12-31".into(),
            ],
        };
        let (content, bucket, priority, due_date) = parse_note_args(&args);
        assert_eq!(content, "Fix auth bug");
        assert_eq!(bucket, "@work");
        assert_eq!(priority, Priority::P1_Urgent);
        assert_eq!(due_date, Some(NaiveDate::from_ymd_opt(2025, 12, 31).unwrap()));
    }

    #[test]
    fn parse_today_and_tomorrow() {
        let today = Local::now().date_naive();
        let args_today = NoteArgs {
            content: vec!["Task".into(), "^today".into()],
        };
        let (_, _, _, due_today) = parse_note_args(&args_today);
        assert_eq!(due_today, Some(today));

        let args_tomorrow = NoteArgs {
            content: vec!["Task".into(), "^tomorrow".into()],
        };
        let (_, _, _, due_tomorrow) = parse_note_args(&args_tomorrow);
        assert_eq!(due_tomorrow, Some(today + Duration::days(1)));
    }

    #[test]
    fn invalid_due_date_stays_in_content() {
        let args = NoteArgs {
            content: vec!["Review".into(), "^notadate".into()],
        };
        let (content, _, _, due_date) = parse_note_args(&args);
        assert_eq!(content, "Review ^notadate");
        assert_eq!(due_date, None);
    }

    #[test]
    fn last_bucket_and_priority_win() {
        let args = NoteArgs {
            content: vec!["Plan".into(), "@home".into(), "@work".into(), "!p2".into(), "!p3".into()],
        };
        let (content, bucket, priority, _) = parse_note_args(&args);
        assert_eq!(content, "Plan");
        assert_eq!(bucket, "@work");
        assert_eq!(priority, Priority::P3_Task);
    }

    #[test]
    fn parse_priority_without_bang() {
        let args = NoteArgs {
            content: vec!["Task".into(), "p1".into()],
        };
        let (_, _, priority, _) = parse_note_args(&args);
        assert_eq!(priority, Priority::P1_Urgent);
    }
}
