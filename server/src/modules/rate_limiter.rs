use std::net::IpAddr;
use chrono::{Utc, Duration};
use dashmap::DashMap;
use std::sync::Arc;

pub struct SimpleRateLimiter {
    limits: Arc<DashMap<IpAddr, Vec<chrono::DateTime<Utc>>>>,
    max_per_minute: usize,
}

impl SimpleRateLimiter {
    pub fn new(max_per_minute: usize) -> Self {
        Self {
            limits: Arc::new(DashMap::new()),
            max_per_minute,
        }
    }

    pub async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let now = Utc::now();
        let one_minute_ago = now - Duration::seconds(60);
        
        let mut entry = self.limits.entry(ip).or_insert_with(Vec::new);
        // Remove old entries
        entry.retain(|&time| time > one_minute_ago);
        
        if entry.len() >= self.max_per_minute {
            return false;
        }
        
        entry.push(now);
        true
    }

    pub async fn cleanup_old_entries(&self) {
        let one_minute_ago = Utc::now() - Duration::seconds(60);
        self.limits.retain(|_, timestamps| {
            timestamps.retain(|&time| time > one_minute_ago);
            !timestamps.is_empty()
        });
    }
}
