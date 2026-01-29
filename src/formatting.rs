use crate::models::{Item, Priority};
use chrono::{Duration, Local, NaiveDate};
use tabled::Tabled;

pub fn format_items_table(items: Vec<Item>) -> String {
    let mut items = items;
    items.sort_by(|a, b| {
        let rank_a = priority_rank(a.priority);
        let rank_b = priority_rank(b.priority);
        rank_a
            .cmp(&rank_b)
            .then_with(|| due_key(a.due_date).cmp(&due_key(b.due_date)))
            .then_with(|| a.id.cmp(&b.id))
    });

    #[derive(Tabled)]
    struct Row {
        #[tabled(rename = "ID")]
        id: i64,
        #[tabled(rename = "Bucket")]
        bucket: String,
        #[tabled(rename = "Content")]
        content: String,
        #[tabled(rename = "Priority")]
        priority: String,
        #[tabled(rename = "Due")]
        due: String,
    }

    let rows: Vec<Row> = items
        .into_iter()
        .map(|item| Row {
            id: item.id,
            bucket: item.bucket,
            content: item.content,
            priority: item.priority.to_string(),
            due: display_due_date(item.due_date),
        })
        .collect();

    if rows.is_empty() {
        return "(no items)".to_string();
    }

    tabled::Table::new(rows).to_string()
}

fn priority_rank(priority: Priority) -> u8 {
    match priority {
        Priority::P1_Urgent => 0,
        Priority::P2_Important => 1,
        Priority::P3_Task => 2,
        Priority::None => 3,
    }
}

fn due_key(date: Option<NaiveDate>) -> NaiveDate {
    date.unwrap_or_else(|| NaiveDate::from_ymd_opt(9999, 12, 31).unwrap())
}

pub fn display_due_date(date: Option<NaiveDate>) -> String {
    let today = Local::now().date_naive();
    let tomorrow = today + Duration::days(1);
    match date {
        Some(d) if d == today => "Today".to_string(),
        Some(d) if d == tomorrow => "Tomorrow".to_string(),
        Some(d) => d.format("%Y-%m-%d").to_string(),
        None => "".to_string(),
    }
}
