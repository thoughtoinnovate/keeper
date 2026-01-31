use crate::models::{Item, Priority, Status};
use anyhow::Result;
use chrono::{DateTime, NaiveDate, Utc};
use rusqlite::types::Value;
use rusqlite::{params_from_iter, Connection, OptionalExtension};
use std::fs;
use std::path::Path;

const MIGRATION_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket TEXT NOT NULL,
    workspace TEXT NOT NULL,
    content TEXT NOT NULL,
    priority TEXT NOT NULL,
    status TEXT NOT NULL,
    due_date TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bucket ON items(bucket);
CREATE INDEX IF NOT EXISTS idx_workspace ON items(workspace);
CREATE INDEX IF NOT EXISTS idx_status_priority ON items(status, priority);
CREATE INDEX IF NOT EXISTS idx_due_date ON items(due_date);
"#;

const ALLOWED_UPDATE_COLUMNS: &[&str] = &[
    "bucket",
    "workspace",
    "content",
    "priority",
    "status",
    "due_date",
];

fn validate_column_name(name: &str) -> Result<()> {
    if !ALLOWED_UPDATE_COLUMNS.contains(&name) {
        return Err(anyhow::anyhow!("Invalid column name: {}", name));
    }
    Ok(())
}

pub struct Db {
    conn: Connection,
}

pub enum InsertOutcome {
    Inserted(i64),
    Duplicate(i64),
}

impl Db {
    pub fn open(path: &Path, key: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "key", key)?;
        conn.execute_batch(MIGRATION_SQL)?;
        migrate_workspaces(&conn)?;
        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let perms = Permissions::from_mode(0o600);
            fs::set_permissions(path, perms)?;
        }
        Ok(Self { conn })
    }

    pub fn insert_item(
        &self,
        bucket: &str,
        content: &str,
        priority: Priority,
        due_date: Option<NaiveDate>,
    ) -> Result<InsertOutcome> {
        let now = Utc::now();
        let content = content.trim();
        if content.is_empty() {
            return Err(anyhow::anyhow!("Note content cannot be empty"));
        }
        let workspace = workspace_from_bucket(bucket)?;
        let due_date_str = due_date.map(|d| d.format("%Y-%m-%d").to_string());

        let mut dup_sql = String::from(
            "SELECT id FROM items WHERE bucket = ?1 AND content = ?2 AND priority = ?3 AND status = ?4",
        );
        if due_date_str.is_some() {
            dup_sql.push_str(" AND due_date = ?5");
        } else {
            dup_sql.push_str(" AND due_date IS NULL");
        }
        dup_sql.push_str(" ORDER BY id DESC LIMIT 1");
        let dup_id: Option<i64> = if let Some(ref due) = due_date_str {
            self.conn
                .query_row(
                    &dup_sql,
                    (
                        bucket,
                        content,
                        priority.as_str(),
                        Status::Open.as_str(),
                        due,
                    ),
                    |row| row.get(0),
                )
                .optional()?
        } else {
            self.conn
                .query_row(
                    &dup_sql,
                    (bucket, content, priority.as_str(), Status::Open.as_str()),
                    |row| row.get(0),
                )
                .optional()?
        };

        if let Some(id) = dup_id {
            return Ok(InsertOutcome::Duplicate(id));
        }

        self.conn.execute(
            "INSERT INTO items (bucket, workspace, content, priority, status, due_date, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                bucket,
                workspace,
                content,
                priority.as_str(),
                Status::Open.as_str(),
                due_date_str,
                now.to_rfc3339(),
                now.to_rfc3339(),
            ),
        )?;
        Ok(InsertOutcome::Inserted(self.conn.last_insert_rowid()))
    }

    pub fn upsert_item(&self, item: &Item) -> Result<()> {
        let content = item.content.trim();
        if content.is_empty() {
            return Err(anyhow::anyhow!("Note content cannot be empty"));
        }
        let workspace = workspace_from_bucket(&item.bucket)?;
        let due_date_str = item.due_date.map(|d| d.format("%Y-%m-%d").to_string());
        self.conn.execute(
            "INSERT INTO items (id, bucket, workspace, content, priority, status, due_date, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
               bucket = excluded.bucket,
               workspace = excluded.workspace,
               content = excluded.content,
               priority = excluded.priority,
               status = excluded.status,
               due_date = excluded.due_date,
               created_at = excluded.created_at,
               updated_at = excluded.updated_at",
            (
                item.id,
                item.bucket.trim(),
                workspace,
                content,
                item.priority.as_str(),
                item.status.as_str(),
                due_date_str,
                item.created_at.to_rfc3339(),
                item.updated_at.to_rfc3339(),
            ),
        )?;
        Ok(())
    }

    pub fn update_status(&self, id: i64, new_status: Status) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        let updated = self.conn.execute(
            "UPDATE items SET status = ?1, updated_at = ?2 WHERE id = ?3",
            (new_status.as_str(), now, id),
        )?;
        Ok(updated > 0)
    }

    pub fn update_item(
        &self,
        id: i64,
        bucket: Option<String>,
        content: Option<String>,
        priority: Option<Priority>,
        due_date: Option<Option<NaiveDate>>,
    ) -> Result<bool> {
        let mut sets: Vec<String> = Vec::new();
        let mut params: Vec<Value> = Vec::new();

        if let Some(bucket) = bucket {
            validate_column_name("bucket")?;
            let workspace = workspace_from_bucket(&bucket)?;
            validate_column_name("workspace")?;
            sets.push("bucket = ?".to_string());
            params.push(Value::from(bucket));
            sets.push("workspace = ?".to_string());
            params.push(Value::from(workspace));
        }
        if let Some(content) = content {
            validate_column_name("content")?;
            let trimmed = content.trim();
            if trimmed.is_empty() {
                return Err(anyhow::anyhow!("Note content cannot be empty"));
            }
            sets.push("content = ?".to_string());
            params.push(Value::from(trimmed.to_string()));
        }
        if let Some(priority) = priority {
            validate_column_name("priority")?;
            sets.push("priority = ?".to_string());
            params.push(Value::from(priority.as_str().to_string()));
        }
        if let Some(due_date) = due_date {
            validate_column_name("due_date")?;
            sets.push("due_date = ?".to_string());
            match due_date {
                Some(date) => params.push(Value::from(date.format("%Y-%m-%d").to_string())),
                None => params.push(Value::Null),
            }
        }

        if sets.is_empty() {
            return Ok(false);
        }

        let now = Utc::now().to_rfc3339();
        validate_column_name("updated_at")?;
        sets.push("updated_at = ?".to_string());
        params.push(Value::from(now));
        params.push(Value::from(id));

        let sql = format!("UPDATE items SET {} WHERE id = ?", sets.join(", "));
        let updated = self.conn.execute(&sql, params_from_iter(params))?;
        Ok(updated > 0)
    }

    pub fn get_items(
        &self,
        bucket_filter: Option<String>,
        priority_filter: Option<Priority>,
        status_filter: Option<Status>,
        date_cutoff: Option<NaiveDate>,
        include_notes: bool,
        notes_only: bool,
    ) -> Result<Vec<Item>> {
        let mut sql = String::from(
            "SELECT id, bucket, content, priority, status, due_date, created_at, updated_at FROM items",
        );
        let mut conditions: Vec<String> = Vec::new();
        let mut params: Vec<Value> = Vec::new();

        if let Some(bucket) = bucket_filter {
            let prefix = bucket_prefix(&bucket)?;
            conditions.push("(bucket = ? OR bucket LIKE ?)".to_string());
            params.push(Value::from(prefix.clone()));
            params.push(Value::from(format!("{prefix}/%")));
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
            conditions.push(
                "due_date IS NOT NULL AND trim(due_date) != '' AND length(due_date) = 10 AND due_date <= ?"
                    .to_string(),
            );
            params.push(Value::from(cutoff.format("%Y-%m-%d").to_string()));
        }
        if notes_only {
            conditions.push(
                "(due_date IS NULL OR trim(due_date) = '' OR length(due_date) != 10)".to_string(),
            );
        } else if !include_notes {
            conditions.push(
                "due_date IS NOT NULL AND trim(due_date) != '' AND length(due_date) = 10"
                    .to_string(),
            );
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
            let due_date =
                due_date_str.and_then(|s| NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok());
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

    pub fn archive_all(&self) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let updated = self.conn.execute(
            "UPDATE items SET status = ?1, updated_at = ?2 WHERE status != ?1",
            (Status::Deleted.as_str(), now),
        )?;
        Ok(updated as i64)
    }

    pub fn undo_last(&self) -> Result<Option<i64>> {
        let id: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM items WHERE status = ?1 ORDER BY updated_at DESC LIMIT 1",
                [Status::Deleted.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(id) = id {
            let _ = self.update_status(id, Status::Open)?;
            Ok(Some(id))
        } else {
            Ok(None)
        }
    }

    pub fn purge_archived_before(&self, cutoff: DateTime<Utc>) -> Result<i64> {
        let cutoff = cutoff.to_rfc3339();
        let deleted = self.conn.execute(
            "DELETE FROM items WHERE status = ?1 AND updated_at < ?2",
            (Status::Deleted.as_str(), cutoff),
        )?;
        Ok(deleted as i64)
    }

    pub fn list_buckets(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT bucket FROM items ORDER BY bucket")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut buckets = Vec::new();
        for row in rows {
            buckets.push(row?);
        }
        Ok(buckets)
    }

    pub fn list_workspaces(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT workspace FROM items ORDER BY workspace")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut workspaces = Vec::new();
        for row in rows {
            workspaces.push(row?);
        }
        Ok(workspaces)
    }

    pub fn move_bucket_prefix(&mut self, from: &str, to: &str) -> Result<i64> {
        let from_prefix = bucket_prefix(from)?;
        let to_prefix = bucket_prefix(to)?;

        let mut stmt = self
            .conn
            .prepare("SELECT id, bucket FROM items WHERE bucket = ?1 OR bucket LIKE ?2")?;
        let rows = stmt.query_map((from_prefix.clone(), format!("{from_prefix}/%")), |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        drop(stmt);

        let mut count = 0i64;
        let tx = self.conn.transaction()?;
        for (id, bucket) in items {
            let new_bucket = if bucket == from_prefix {
                to_prefix.clone()
            } else {
                let suffix = bucket.strip_prefix(&from_prefix).unwrap_or("");
                format!("{to_prefix}{suffix}")
            };
            let workspace = workspace_from_bucket(&new_bucket)?;
            tx.execute(
                "UPDATE items SET bucket = ?1, workspace = ?2 WHERE id = ?3",
                (new_bucket, workspace, id),
            )?;
            count += 1;
        }
        tx.commit()?;
        Ok(count)
    }
}

fn bucket_prefix(input: &str) -> Result<String> {
    let trimmed = input.trim().trim_end_matches('/');
    if !trimmed.starts_with('@') {
        return Err(anyhow::anyhow!("Bucket must start with @"));
    }
    if trimmed == "@" {
        return Err(anyhow::anyhow!("Workspace is required"));
    }
    Ok(trimmed.to_string())
}

fn workspace_from_bucket(bucket: &str) -> Result<String> {
    let bucket = bucket.trim();
    if !bucket.starts_with('@') {
        return Err(anyhow::anyhow!("Bucket must start with @"));
    }
    let (workspace, bucket_name) = bucket
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("Bucket must include workspace and bucket"))?;
    if workspace.len() <= 1 || bucket_name.is_empty() {
        return Err(anyhow::anyhow!("Bucket must include workspace and bucket"));
    }
    Ok(workspace.to_string())
}

fn migrate_workspaces(conn: &Connection) -> Result<()> {
    let mut has_workspace = false;
    let mut stmt = conn.prepare("PRAGMA table_info(items)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == "workspace" {
            has_workspace = true;
            break;
        }
    }
    if has_workspace {
        return Ok(());
    }

    conn.execute("ALTER TABLE items ADD COLUMN workspace TEXT", [])?;
    conn.execute(
        "UPDATE items
         SET bucket = '@default/' || ltrim(bucket, '@'),
             workspace = '@default'
         WHERE instr(bucket, '/') = 0",
        [],
    )?;
    conn.execute(
        "UPDATE items
         SET workspace = substr(bucket, 1, instr(bucket, '/') - 1)
         WHERE instr(bucket, '/') > 0",
        [],
    )?;
    Ok(())
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
