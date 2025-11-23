use std::net::IpAddr;
use chrono::{Utc, Duration};
use sqlx::SqlitePool;

/// Persistent rate limiter using SQLite
pub struct SimpleRateLimiter {
    pool: SqlitePool,
    max_per_minute: usize,
}

impl SimpleRateLimiter {
    pub fn new(pool: SqlitePool, max_per_minute: usize) -> Self {
        Self {
            pool,
            max_per_minute,
        }
    }
    
    /// Check if the IP is within rate limit
    /// Returns true if allowed, false if rate limited
    pub async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let ip_str = ip.to_string();
        let now = Utc::now();
        let one_minute_ago = now - Duration::seconds(60);
        
        // Count attempts in the last minute
        let count: i64 = match sqlx::query_scalar(
            "SELECT COUNT(*) FROM rate_limits WHERE ip = ? AND attempt_time > ?"
        )
        .bind(&ip_str)
        .bind(one_minute_ago)
        .fetch_one(&self.pool)
        .await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Rate limiter DB error: {}", e);
                return true; // Fail open if DB error
            }
        };
        
        if count >= self.max_per_minute as i64 {
            return false;
        }
        
        // Record this attempt
        let _ = sqlx::query("INSERT INTO rate_limits (ip, attempt_time) VALUES (?, ?)")
            .bind(&ip_str)
            .bind(now)
            .execute(&self.pool)
            .await;
            
        true
    }
    
    /// Cleanup old entries (should be called periodically)
    pub async fn cleanup_old_entries(&self) {
        let one_hour_ago = Utc::now() - Duration::hours(1);
        let _ = sqlx::query("DELETE FROM rate_limits WHERE attempt_time < ?")
            .bind(one_hour_ago)
            .execute(&self.pool)
            .await;
    }
}
