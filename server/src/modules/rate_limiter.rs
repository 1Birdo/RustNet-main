use std::collections::HashMap;
use std::net::IpAddr;
use tokio::time::Instant;
use tokio::sync::Mutex;
use std::sync::Arc;

/// Simple rate limiter for IP-based connection limiting
pub struct SimpleRateLimiter {
    attempts: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    max_per_minute: usize,
}

impl SimpleRateLimiter {
    pub fn new(max_per_minute: usize) -> Self {
        Self {
            attempts: Arc::new(Mutex::new(HashMap::new())),
            max_per_minute,
        }
    }
    
    /// Check if the IP is within rate limit
    /// Returns true if allowed, false if rate limited
    pub async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let mut attempts = self.attempts.lock().await;
        let now = Instant::now();
        
        // Get attempts for this IP
        let ip_attempts = attempts.entry(ip).or_insert_with(Vec::new);
        
        // Remove attempts older than 1 minute
        ip_attempts.retain(|&time| now.duration_since(time).as_secs() < 60);
        
        // Check if under limit
        if ip_attempts.len() >= self.max_per_minute {
            return false;  // Rate limited
        }
        
        // Record this attempt
        ip_attempts.push(now);
        true
    }
    
    /// Cleanup old entries (should be called periodically)
    pub async fn cleanup_old_entries(&self) {
        let mut attempts = self.attempts.lock().await;
        let now = Instant::now();
        
        // Remove IPs with no recent attempts (> 5 minutes)
        attempts.retain(|_, times| {
            times.iter().any(|&t| now.duration_since(t).as_secs() < 300)
        });
    }
}
