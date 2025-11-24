use std::net::IpAddr;
use chrono::{Utc, Duration};
use sqlx::SqlitePool;
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
    pub async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let ip_str = ip.to_string();
        let now = Utc::now();
        let one_minute_ago = now - Duration::seconds(60);
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
                return true; 
            }
        };
        if count >= self.max_per_minute as i64 {
            return false;
        }
        let _ = sqlx::query("INSERT INTO rate_limits (ip, attempt_time) VALUES (?, ?)")
            .bind(&ip_str)
            .bind(now)
            .execute(&self.pool)
            .await;
        true
    }
    pub async fn cleanup_old_entries(&self) {
        let one_hour_ago = Utc::now() - Duration::hours(1);
        let _ = sqlx::query("DELETE FROM rate_limits WHERE attempt_time < ?")
            .bind(one_hour_ago)
            .execute(&self.pool)
            .await;
    }
}
