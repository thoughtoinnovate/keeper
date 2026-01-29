use crate::models::{Item, Priority, Status};
use anyhow::Result;
use chrono::{DateTime, NaiveDate, Utc};
use rusqlite::{params_from_iter, Connection};
use rusqlite::types::Value;
use std::path::Path;

const MIGRATION_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket TEXT NOT NULL,
    content TEXT NOT NULL,
    priority TEXT NOT NULL,
    status TEXT NOT NULL,
    due_date TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bucket ON items(bucket);
CREATE INDEX IF NOT EXISTS idx_status_priority ON items(status, priority);
CREATE INDEX IF NOT EXISTS idx_due_date ON items(due_date);
"#;

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &Path, key: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "key", &key)?;
        conn.execute_batch(MIGRATION_SQL)?;
        Ok(Self { conn })
    }

    pub fn insert_item(
        &self,
        bucket: &str,
        content: &str,
        priority: Priority,
        due_date: Option<NaiveDate>,
    ) -> Result<i64> {
        let now = Utc::now();
        let due_date_str = due_date.map(|d| d.format("%Y-%m-%d").to_string());
        self.conn.execute(
            "INSERT INTO items (bucket, content, priority, status, due_date, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                bucket,
                content,
                priority.as_str(),
                Status::Open.as_str(),
                due_date_str,
                now.to_rfc3339(),
                now.to_rfc3339(),
            ),
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn update_status(&self, id: i64, new_status: Status) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE items SET status = ?1, updated_at = ?2 WHERE id = ?3",
            (new_status.as_str(), now, id),
        )?;
        Ok(())
    }

    pub fn get_items(
        &self,
        bucket_filter: Option<String>,
        priority_filter: Option<Priority>,
        status_filter: Option<Status>,
        date_cutoff: Option<NaiveDate>,
    ) -> Result<Vec<Item>> {
        let mut sql = String::from(
            "SELECT id, bucket, content, priority, status, due_date, created_at, updated_at FROM items",
        );
        let mut conditions: Vec<String> = Vec::new();
        let mut params: Vec<Value> = Vec::new();

        if let Some(bucket) = bucket_filter {
            conditions.push("bucket = ?".to_string());
            params.push(Value::from(bucket));
        }
        if let Some(priority) = priority_filter {
            conditions.push("priority = ?".to_string());
            params.push(Value::from(priority.as_str().to_string()));
        }
        if let Some(status) = status_filter {
            conditions.push("status = ?".to_string());
            params.push(Value::from(status.as_str().to_string()));
        }
        if let Some(cutoff) = date_cutoff {
            conditions.push("due_date IS NOT NULL AND due_date <= ?".to_string());
            params.push(Value::from(cutoff.format("%Y-%m-%d").to_string()));
        }

        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }
        sql.push_str(" ORDER BY id DESC");

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(params), |row| {
            let priority_str: String = row.get(3)?;
            let status_str: String = row.get(4)?;
            let due_date_str: Option<String> = row.get(5)?;
            let created_at_str: String = row.get(6)?;
            let updated_at_str: String = row.get(7)?;

            let priority = Priority::from_str(&priority_str).unwrap_or(Priority::None);
            let status = Status::from_str(&status_str).unwrap_or(Status::Open);
            let due_date = due_date_str
                .and_then(|s| NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok());
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Ok(Item {
                id: row.get(0)?,
                bucket: row.get(1)?,
                content: row.get(2)?,
                priority,
                status,
                due_date,
                created_at,
                updated_at,
            })
        })?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn stats(&self) -> Result<(i64, i64, i64)> {
        let open: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM items WHERE status = ?1",
            [Status::Open.as_str()],
            |row| row.get(0),
        )?;

        let done_today: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM items WHERE status = ?1 AND date(updated_at) = date('now', 'localtime')",
            [Status::Done.as_str()],
            |row| row.get(0),
        )?;

        let p1: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM items WHERE status = ?1 AND priority = ?2",
            (Status::Open.as_str(), Priority::P1_Urgent.as_str()),
            |row| row.get(0),
        )?;

        Ok((open, done_today, p1))
    }
}

impl Priority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Priority::P1_Urgent => "P1_Urgent",
            Priority::P2_Important => "P2_Important",
            Priority::P3_Task => "P3_Task",
            Priority::None => "None",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "P1_Urgent" => Some(Priority::P1_Urgent),
            "P2_Important" => Some(Priority::P2_Important),
            "P3_Task" => Some(Priority::P3_Task),
            "None" => Some(Priority::None),
            _ => None,
        }
    }
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Open => "Open",
            Status::Done => "Done",
            Status::Deleted => "Deleted",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "Open" => Some(Status::Open),
            "Done" => Some(Status::Done),
            "Deleted" => Some(Status::Deleted),
            _ => None,
        }
    }
}
