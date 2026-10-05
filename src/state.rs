//! Shared state: demo secret, rate limiter, audit log, demo records.

use std::collections::BTreeMap;

use crate::audit::AuditLog;
use crate::rate_limit::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub secret: Vec<u8>,
    pub limiter: RateLimiter,
    pub audit: AuditLog,
    pub records: std::sync::Arc<std::sync::RwLock<BTreeMap<String, String>>>,
}

impl AppState {
    pub fn demo() -> Self {
        let mut records = BTreeMap::new();
        records.insert(
            "cardio-patient-1".to_string(),
            "Cardiology record: synthetic".to_string(),
        );
        records.insert(
            "onco-patient-1".to_string(),
            "Oncology record: synthetic".to_string(),
        );
        Self {
            secret: b"zero-trust-demo-secret".to_vec(),
            limiter: RateLimiter::new(10, 2.0),
            audit: AuditLog::in_memory(),
            records: std::sync::Arc::new(std::sync::RwLock::new(records)),
        }
    }

    pub fn record_department(record_id: &str) -> Option<&'static str> {
        match record_id.split('-').next() {
            Some("cardio") => Some("cardiology"),
            Some("onco") => Some("oncology"),
            _ => None,
        }
    }
}
