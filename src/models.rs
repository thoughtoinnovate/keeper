use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Serialize, Deserialize, PartialEq, PartialOrd, Clone, Copy)]
pub enum Priority {
    P1_Urgent,    // !p1
    P2_Important, // !p2
    P3_Task,      // !p3
    None,         // No sigil provided (Reference Note)
}

// Needed for displaying in tables
impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Priority::P1_Urgent => write!(f, "🚨 P1"),
            Priority::P2_Important => write!(f, "⭐ P2"),
            Priority::P3_Task => write!(f, "✅ P3"),
            Priority::None => write!(f, "📝 Note"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
pub enum Status {
    Open,
    Done,
    Deleted,
}

// The main entity. Note: dates are typically stored as strings in SQLite.
// Ensure your DB layer handles conversion between Option<NaiveDate> and String.
#[derive(Debug, Serialize, Deserialize)]
pub struct Item {
    pub id: i64,
    pub bucket: String,
    pub content: String,
    pub priority: Priority,
    pub status: Status,
    pub due_date: Option<NaiveDate>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
