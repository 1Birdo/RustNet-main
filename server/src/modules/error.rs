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
}

pub type Result<T> = std::result::Result<T, CncError>;

// Audit logging structures
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

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

pub async fn log_audit_event(event: AuditLog, audit_file: &str) -> Result<()> {
    use tokio::fs::OpenOptions;
    use tokio::io::AsyncWriteExt;
    
    let log_line = format!(
        "[{}] {} by {} - {} {}\n",
        event.timestamp.format("%Y-%m-%d %H:%M:%S"),
        event.action,
        event.username,
        event.result,
        event.target.map(|t| format!("(target: {})", t)).unwrap_or_default()
    );
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_file)
        .await?;
    
    file.write_all(log_line.as_bytes()).await?;
    Ok(())
}
