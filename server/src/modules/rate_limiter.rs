use dashmap::DashMap;
use std::net::IpAddr;
use chrono::{Utc, DateTime, Duration};
use sqlx::SqlitePool;
use tracing::error;

pub struct SimpleRateLimiter {
    pool: SqlitePool,
    max_per_minute: usize,
    cache: DashMap<IpAddr, Vec<DateTime<Utc>>>,
}

impl SimpleRateLimiter {
    pub fn new(max_per_minute: usize, pool: SqlitePool) -> Self {
        Self {
            pool,
            max_per_minute,
            cache: DashMap::new(),
        }
    }

    pub async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let now = Utc::now();
        let one_minute_ago = now - Duration::seconds(60);
        
        let mut allowed = true;
        
        {
            let mut entry = self.cache.entry(ip).or_insert(Vec::new());
            entry.retain(|&t| t > one_minute_ago);
            
            if entry.len() >= self.max_per_minute {
                allowed = false;
            } else {
                entry.push(now);
            }
        }

        let pool = self.pool.clone();
        let ip_str = ip.to_string();
        tokio::spawn(async move {
             if let Err(e) = sqlx::query("INSERT INTO rate_limits (ip, attempt_time) VALUES (?, ?)")
                .bind(ip_str)
                .bind(now)
                .execute(&pool)
                .await 
            {
                 error!("Failed to record rate limit attempt: {}", e);
            }
        });

        allowed
    }

    pub async fn cleanup_old_entries(&self) {
        let one_minute_ago = Utc::now() - Duration::seconds(60);
        
        // Cleanup DB
        if let Err(e) = sqlx::query("DELETE FROM rate_limits WHERE attempt_time < ?")
            .bind(one_minute_ago)
            .execute(&self.pool)
            .await
        {
            error!("Failed to cleanup rate limits: {}", e);
        }
        
        // Cleanup memory cache
        self.cache.retain(|_, timestamps| {
            timestamps.retain(|&t| t > one_minute_ago);
            !timestamps.is_empty()
        });
    }
}
