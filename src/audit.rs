//! Append-only audit log (JSONL): every decision gets a record.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AuditRecord {
    pub at: chrono::DateTime<chrono::Utc>,
    pub subject: String,
    pub role: String,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub rate_limited: bool,
    pub request_id: String,
}

#[derive(Clone)]
pub struct AuditLog {
    path: Option<PathBuf>,
    lock: Arc<Mutex<()>>,
}

impl AuditLog {
    /// File-backed in production; in-memory (tests) when path is None.
    pub fn to_file(path: impl AsRef<Path>) -> Self {
        Self {
            path: Some(path.as_ref().to_path_buf()),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn in_memory() -> Self {
        Self {
            path: None,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn append(&self, record: &AuditRecord) {
        let Ok(line) = serde_json::to_string(record) else {
            return;
        };
        let _guard = self.lock.lock().expect("audit lock");
        if let Some(path) = &self.path {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(file, "{line}");
            }
        } else {
            tracing::info!(audit = %line, "decision");
        }
    }
}
