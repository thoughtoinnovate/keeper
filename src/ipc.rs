use crate::models::{Item, Priority, Status};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonRequest {
    CreateNote {
        bucket: String,
        content: String,
        priority: Priority,
        due_date: Option<NaiveDate>,
    },
    GetItems {
        bucket_filter: Option<String>,
        priority_filter: Option<Priority>,
        status_filter: Option<Status>,
        date_cutoff: Option<NaiveDate>,
    },
    UpdateStatus { id: i64, new_status: Status },
    GetDashboardStats,
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonResponse {
    OkMessage(String),
    OkItems(Vec<Item>),
    // Create a specific struct for dash stats if needed
    OkStats { open: i64, done_today: i64, p1: i64 },
    Error(String),
}
