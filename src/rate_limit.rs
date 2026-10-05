//! Per-client token-bucket rate limiting (in-memory; Redis in Phase 1).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_second: f64,
    buckets: std::sync::Arc<Mutex<HashMap<String, (f64, Instant)>>>,
}

impl RateLimiter {
    pub fn new(capacity: usize, refill_per_second: f64) -> Self {
        Self {
            capacity: capacity as f64,
            refill_per_second,
            buckets: std::sync::Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Consume one token for the client; false = rate-limited.
    pub fn allow(&self, client: &str) -> bool {
        let mut buckets = self.buckets.lock().expect("buckets lock");
        let now = Instant::now();
        let (tokens, last) = buckets.get(client).copied().unwrap_or((self.capacity, now));
        let elapsed = now.duration_since(last).as_secs_f64();
        let tokens = (tokens + elapsed * self.refill_per_second).min(self.capacity);
        if tokens >= 1.0 {
            buckets.insert(client.to_string(), (tokens - 1.0, now));
            true
        } else {
            buckets.insert(client.to_string(), (tokens, now));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bursts_are_limited() {
        let limiter = RateLimiter::new(3, 0.0); // zero refill for a tight test
        assert!(limiter.allow("client"));
        assert!(limiter.allow("client"));
        assert!(limiter.allow("client"));
        assert!(!limiter.allow("client"), "4th call must be limited");
    }

    #[test]
    fn clients_are_isolated() {
        let limiter = RateLimiter::new(1, 0.0);
        assert!(limiter.allow("a"));
        assert!(!limiter.allow("a"));
        assert!(limiter.allow("b"), "client b unaffected");
    }

    #[test]
    fn refill_restores_capacity() {
        let limiter = RateLimiter::new(1, 1000.0); // refills instantly
        assert!(limiter.allow("a"));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(limiter.allow("a"), "refill must restore the token");
    }
}
