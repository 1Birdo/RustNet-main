use std::sync::Arc;
use crate::modules::client_manager::Client;
use crate::modules::state::AppState;
use crate::modules::error::{Result, AuditLog, log_audit_event};
use crate::modules::auth::{User, Level};
use super::ui::*;
use super::general::show_prompt;

pub async fn handle_admin_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("Admin Menu");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    let commands = [
        ("users", "Manage users"),
        ("bots", "Manage bots"),
        ("broadcast", "Send message to all users"),
        ("kick", "Kick a user"),
        ("ban", "Ban a user"),
        ("unban", "Unban a user"),
        ("banlist", "List banned users"),
        ("logs", "View system logs"),
        ("sessions", "View active sessions"),
        ("userinfo", "View user information"),
        ("listusers", "List all users"),
        ("lock", "Lock a user account"),
        ("botcount", "View bot statistics"),
        ("blacklist", "Manage IP blacklist"),
        ("whitelist", "Manage IP whitelist")
    ];
    
    for (cmd, desc) in commands.iter() {
        let cmd_gradient = apply_gradient(cmd, 39, 51);
        client.write(format!("  \x1b[38;5;245m{:<12} : \x1b[0m{}\n\r", cmd_gradient, desc).as_bytes()).await?;
    }
    
    client.write(b"\n\r").await?;
    
    client.set_breadcrumb("Home > Admin Menu").await;
    show_prompt(client, state).await?;
    Ok(())
}

pub async fn handle_listbots_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let tokens = state.bot_manager.list_tokens().await;
    let bots = state.bot_manager.get_all_bots().await;
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("Registered Bots");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    let stats_msg = format!("  \x1b[38;5;245mTotal: \x1b[38;5;39m{}\x1b[38;5;245m | Connected: \x1b[38;5;51m{}\x1b[0m\n\r", tokens.len(), bots.len());
    client.write(stats_msg.as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    if tokens.is_empty() {
        client.write(b"  \x1b[38;5;245mNo bots registered\x1b[0m\n\r").await?;
    } else {
        for token_info in tokens {
            let connected_bot = bots.iter().find(|b| {
                let info = b.info.try_lock();
                if let Ok(info) = info {
                    info.id == token_info.bot_id
                } else {
                    false
                }
            });
            
            let is_connected = connected_bot.is_some();
            let mut error_msg = String::new();
            if let Some(bot) = connected_bot {
                 let info = bot.info.lock().await;
                 if let Some(err) = &info.last_error {
                     error_msg = format!(" \x1b[38;5;196m[ERR: {}]\x1b[0m", err);
                 }
            }
            
            let status = if is_connected { "\x1b[38;5;51mONLINE\x1b[0m" } else { "\x1b[38;5;245mOFFLINE\x1b[0m" };
            let last_used = token_info.last_used
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Never".to_string());
                
            let id_gradient = apply_gradient(&token_info.bot_id.to_string(), 39, 45);
            let arch_gradient = apply_gradient(&token_info.arch, 45, 51);
            let last_gradient = apply_gradient(&last_used, 51, 87);
            
            client.write(format!("  [{}] {} | {} | Last: {}{}\n\r", 
                status, id_gradient, arch_gradient, last_gradient, error_msg).as_bytes()).await?;
        }
    }
    
    client.write(b"\n\r").await?;
    client.set_breadcrumb("Home > Bot List").await;
    Ok(())
}

pub async fn handle_kick_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    client.write(b"\n\rEnter username to kick: ").await?;
    let username = client.read_line().await?.trim().to_string();
    
    if username.is_empty() {
        client.write(b"\x1b[38;5;196m[X] Username cannot be empty\n\r").await?;
        return Ok(());
    }
    
    if username == client.user.username {
        client.write(b"\x1b[38;5;196m[X] You cannot kick yourself\n\r").await?;
        return Ok(());
    }
    
    let clients = state.client_manager.get_all_clients().await;
    let target = clients.iter().find(|c| c.user.username == username);
    
    if let Some(target) = target {
        // Check if admin trying to kick owner
        if target.user.get_level() == Level::Owner && client.user.get_level() != Level::Owner {
            client.write(b"\x1b[38;5;196m[X] You cannot kick the owner\n\r").await?;
            return Ok(());
        }
        
        target.write(b"\n\r\x1b[38;5;196m[!] You have been kicked by an administrator\n\r").await?;
        state.client_manager.remove_client(&target.id).await;
        
        client.write(format!("\x1b[38;5;82m[✓] User '{}' has been kicked\n\r", username).as_bytes()).await?;
        let audit_event = AuditLog::new(client.user.username.clone(), "KICK_USER".to_string(), "SUCCESS".to_string())
            .with_target(username.clone());
        let _ = log_audit_event(audit_event, &state.pool).await;
    } else {
        client.write(format!("\x1b[38;5;196m[X] User '{}' not found or not online\n\r", username).as_bytes()).await?;
    }
    
    Ok(())
}

pub async fn handle_ban_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    client.write(b"\n\rEnter username to ban: ").await?;
    let username = client.read_line().await?.trim().to_string();
    
    if username.is_empty() {
        client.write(b"\x1b[38;5;196m[X] Username cannot be empty\n\r").await?;
        return Ok(());
    }
    
    if username == client.user.username {
        client.write(b"\x1b[38;5;196m[X] You cannot ban yourself\n\r").await?;
        return Ok(());
    }
    
    if let Ok(Some(user)) = state.user_manager.get_user(&username).await {
        if user.get_level() == Level::Owner {
            client.write(b"\x1b[38;5;196m[X] You cannot ban the owner\n\r").await?;
            return Ok(());
        }
        
        // Set expiry to past date to ban
        let expire = chrono::Utc::now() - chrono::Duration::days(1);
        state.user_manager.update_user(&username, None, Some(expire)).await?;
        
        // Kick if online
        let clients = state.client_manager.get_all_clients().await;
        if let Some(target) = clients.iter().find(|c| c.user.username == username) {
            target.write(b"\n\r\x1b[38;5;196m[!] You have been banned\n\r").await?;
            state.client_manager.remove_client(&target.id).await;
        }
        
        client.write(format!("\x1b[38;5;82m[✓] User '{}' has been banned\n\r", username).as_bytes()).await?;
        let audit_event = AuditLog::new(client.user.username.clone(), "BAN_USER".to_string(), "SUCCESS".to_string())
            .with_target(username.clone());
        let _ = log_audit_event(audit_event, &state.pool).await;
    } else {
        client.write(format!("\x1b[38;5;196m[X] User '{}' not found\n\r", username).as_bytes()).await?;
    }
    
    Ok(())
}

pub async fn handle_unban_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    client.write(b"\n\rEnter username to unban: ").await?;
    let username = client.read_line().await?.trim().to_string();
    
    if username.is_empty() {
        client.write(b"\x1b[38;5;196m[X] Username cannot be empty\n\r").await?;
        return Ok(());
    }
    
    if let Ok(Some(_)) = state.user_manager.get_user(&username).await {
        // Set expiry to 30 days from now
        let expire = chrono::Utc::now() + chrono::Duration::days(30);
        state.user_manager.update_user(&username, None, Some(expire)).await?;
        
        client.write(format!("\x1b[38;5;82m[✓] User '{}' has been unbanned (30 days access)\n\r", username).as_bytes()).await?;
        let audit_event = AuditLog::new(client.user.username.clone(), "UNBAN_USER".to_string(), "SUCCESS".to_string())
            .with_target(username.clone());
        let _ = log_audit_event(audit_event, &state.pool).await;
    } else {
        client.write(format!("\x1b[38;5;196m[X] User '{}' not found\n\r", username).as_bytes()).await?;
    }
    
    Ok(())
}

pub async fn handle_banlist_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let users = state.user_manager.get_all_users().await.unwrap_or_default();
    
    let now = chrono::Utc::now();
    let banned: Vec<&User> = users.iter().filter(|u| u.expire < now).collect();
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("Banned Users");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    if banned.is_empty() {
        client.write(b"  \x1b[38;5;245mNo banned users found.\x1b[0m\n\r").await?;
    } else {
        for (i, user) in banned.iter().enumerate() {
            let user_str = format!("{} ({})", user.username, user.level.to_str());
            let expire_str = format!("Expired: {}", user.expire.format("%Y-%m-%d"));
            
            let user_gradient = apply_gradient(&user_str, 39 + (i as u8 % 50), 45 + (i as u8 % 50));
            let expire_gradient = apply_gradient(&expire_str, 245, 250);
            
            client.write(format!("  \x1b[38;5;196m[BANNED] \x1b[0m{} - {}\n\r", user_gradient, expire_gradient).as_bytes()).await?;
        }
    }
    
    client.write(b"\n\r").await?;
    client.set_breadcrumb("Home > Ban List").await;
    Ok(())
}

pub async fn handle_broadcast_command(client: &Arc<Client>, state: &Arc<AppState>, message: &str) -> Result<()> {
    if message.is_empty() {
        client.write(b"\x1b[38;5;196m[X] Usage: broadcast <message>\n\r").await?;
        return Ok(());
    }
    
    let clients = state.client_manager.get_all_clients().await;
    let from_gradient = apply_gradient(&format!("[BROADCAST from {}]", client.user.username), 45, 51);
    let msg_gradient = apply_gradient(message, 255, 250);
    let broadcast_msg = format!("\n\r{} {}\x1b[0m\n\r", from_gradient, msg_gradient);
    
    let mut sent_count = 0;
    for c in clients.iter() {
        if let Ok(true) = c.try_write(broadcast_msg.as_bytes()).await {
            sent_count += 1;
        }
    }
    
    client.write(format!("\x1b[38;5;51m[✓] Message broadcast to {}/{} users\n\r", sent_count, clients.len()).as_bytes()).await?;
    
    let audit_event = AuditLog::new(client.user.username.clone(), "BROADCAST".to_string(), "SUCCESS".to_string())
        .with_target(message.to_string());
    let _ = log_audit_event(audit_event, &state.pool).await;
    
    Ok(())
}

pub async fn handle_logs_command(client: &Arc<Client>, state: &Arc<AppState>, lines: usize) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("System Logs");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    // Query logs from database
    let logs = sqlx::query_as::<_, AuditLog>(
        "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?"
    )
    .bind(lines as i64)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| crate::modules::error::CncError::DatabaseError(e))?;

    // Reverse to show oldest first (chronological order)
    let logs: Vec<AuditLog> = logs.into_iter().rev().collect();
    
    if logs.is_empty() {
        client.write(b"  \x1b[38;5;245mNo logs found\x1b[0m\n\r").await?;
    } else {
        for log in logs.iter() {
            let timestamp = log.timestamp.format("%Y-%m-%d %H:%M:%S");
            let target_str = if let Some(t) = &log.target { format!(" -> {}", t) } else { "".to_string() };
            let ip_str = if let Some(ip) = &log.ip_address { format!(" [{}]", ip) } else { "".to_string() };
            
            let line = format!("{} [{}] {}{}: {}{}", 
                timestamp, 
                log.action, 
                log.username, 
                target_str,
                log.result,
                ip_str
            );
            
            let log_gradient = apply_gradient(&line, 245, 250);
            client.write(format!("  {}\n\r", log_gradient).as_bytes()).await?;
        }
    }
    
    client.write(b"\n\r").await?;
    client.set_breadcrumb("Home > Logs").await;
    Ok(())
}

pub async fn handle_sessions_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let clients = state.client_manager.get_all_clients().await;
    
    let title = apply_ice_gradient("Active Sessions");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    if clients.is_empty() {
        client.write(b"  \x1b[38;5;245mNo active sessions\x1b[0m\n\r").await?;
    } else {
        for c in clients.iter() {
            let elapsed = chrono::Utc::now().signed_duration_since(c.connected_at);
            let elapsed_secs = elapsed.num_seconds();
            let time_str = if elapsed_secs < 60 {
                format!("{}s", elapsed_secs)
            } else if elapsed_secs < 3600 {
                format!("{}m", elapsed_secs / 60)
            } else {
                format!("{}h", elapsed_secs / 3600)
            };
            
            let username_gradient = apply_gradient(&c.user.username, 39, 45);
            let addr_str = c.address.to_string();
            let addr_gradient = apply_gradient(&addr_str, 45, 51);
            let id_str = &c.id.to_string()[..8];
            let id_gradient = apply_gradient(id_str, 51, 57);
            let time_gradient = apply_gradient(&time_str, 57, 87);
            
            client.write(format!("  {} | {} | {} | {}\n\r", 
                username_gradient, addr_gradient, id_gradient, time_gradient).as_bytes()).await?;
        }
    }
    
    client.write(b"\n\r").await?;
    client.set_breadcrumb("Home > Sessions").await;
    Ok(())
}

pub async fn handle_userinfo_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let username = match parts.get(1) {
        Some(u) => u.to_string(),
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: userinfo <username>\n\r").await?;
            return Ok(());
        }
    };
    
    if let Ok(Some(user)) = state.user_manager.get_user(&username).await {
        client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
        
        let title = apply_ice_gradient("User Information");
        client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
        client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
        
        // User info lines
        let username_gradient = apply_gradient(&user.username, 39, 45);
        let level_gradient = apply_gradient(&format!("{:?}", user.level), 45, 51);
        let expire_gradient = apply_gradient(&user.expire.format("%Y-%m-%d").to_string(), 51, 57);
        let status_str = if user.expire > chrono::Utc::now() { "Active" } else { "Expired" };
        let status_gradient = apply_gradient(status_str, 57, 87);

        client.write(format!("  \x1b[38;5;245mUsername: \x1b[0m{}\n\r", username_gradient).as_bytes()).await?;
        client.write(format!("  \x1b[38;5;245mLevel:    \x1b[0m{}\n\r", level_gradient).as_bytes()).await?;
        client.write(format!("  \x1b[38;5;245mExpires:  \x1b[0m{}\n\r", expire_gradient).as_bytes()).await?;
        client.write(format!("  \x1b[38;5;245mStatus:   \x1b[0m{}\n\r", status_gradient).as_bytes()).await?;
        
        client.write(b"\n\r").await?;
    } else {
        client.write(format!("\x1b[38;5;196m[X] User '{}' not found\n\r", username).as_bytes()).await?;
    }
    
    client.set_breadcrumb("Home > User Info").await;
    Ok(())
}

pub async fn handle_lock_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let username = match parts.get(1) {
        Some(u) => u.to_string(),
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: lock <username>\n\r").await?;
            return Ok(());
        }
    };
    
    if let Ok(Some(_)) = state.user_manager.get_user(&username).await {
        let expire = chrono::Utc::now() - chrono::Duration::days(1);
        state.user_manager.update_user(&username, None, Some(expire)).await?;
        
        client.write(format!("\x1b[38;5;51m[✓] Account '{}' locked\n\r", username).as_bytes()).await?;
        
        let audit_event = AuditLog::new(client.user.username.clone(), "LOCK_USER".to_string(), "SUCCESS".to_string())
            .with_target(username);
        let _ = log_audit_event(audit_event, &state.pool).await;
    } else {
        client.write(format!("\x1b[38;5;196m[X] User '{}' not found\n\r", username).as_bytes()).await?;
    }
    
    Ok(())
}

pub async fn handle_botcount_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let bot_count = state.bot_manager.get_bot_count().await;
    
    let title = apply_ice_gradient("Bot Statistics");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    // Stats lines
    let count_gradient = apply_gradient(&bot_count.to_string(), 39, 51);
    let status_gradient = apply_gradient("Online", 82, 118);
    let server_gradient = apply_gradient(&format!("{}:{}", state.config.read().await.bot_server_ip, state.config.read().await.bot_server_port), 39, 51);

    client.write(format!("  \x1b[38;5;245mTotal Bots: \x1b[0m{}\n\r", count_gradient).as_bytes()).await?;
    client.write(format!("  \x1b[38;5;245mStatus:     \x1b[0m{}\n\r", status_gradient).as_bytes()).await?;
    client.write(format!("  \x1b[38;5;245mServer:     \x1b[0m{}\n\r", server_gradient).as_bytes()).await?;
    
    client.write(b"\n\r").await?;
    client.set_breadcrumb("Home > Bot Count").await;
    Ok(())
}

pub async fn handle_listusers_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let users = state.user_manager.get_all_users().await.unwrap_or_default();
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("User List");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    let total_msg = format!("  \x1b[38;5;245mTotal Users: \x1b[38;5;39m{}\x1b[0m\n\r", users.len());
    client.write(total_msg.as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    for user in users {
        let expired = if user.expire < chrono::Utc::now() { " [EXPIRED]" } else { "" };
        let level_color = match user.level.to_str() {
            "Owner" => 51,
            "Admin" => 45,
            "Pro" => 39,
            _ => 255
        };
        
        let user_str = format!("{} ({})", user.username, user.level.to_str());
        let expire_str = format!("Expires: {}{}", user.expire.format("%Y-%m-%d"), expired);
        
        let user_gradient = apply_gradient(&user_str, level_color, level_color + 6);
        let expire_gradient = apply_gradient(&expire_str, 245, 252);
        
        client.write(format!("  {} - {}\n\r", user_gradient, expire_gradient).as_bytes()).await?;
    }
    
    client.write(b"\n\r").await?;
    client.set_breadcrumb("Home > User List").await;
    Ok(())
}

pub async fn handle_blacklist_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 3 {
        client.write(b"\x1b[38;5;196m[X] Usage: blacklist <add/remove> <ip> [reason]\n\r").await?;
        return Ok(());
    }
    
    let action = parts[1].to_lowercase();
    let ip_str = parts[2];
    let reason = if parts.len() > 3 { parts[3..].join(" ") } else { "No reason provided".to_string() };
    
    let ip = match ip_str.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            client.write(format!("\x1b[38;5;196m[X] Invalid IP address: {}\n\r", ip_str).as_bytes()).await?;
            return Ok(());
        }
    };
    
    match action.as_str() {
        "add" => {
            state.blacklist.insert(ip);
            let _ = sqlx::query("INSERT OR REPLACE INTO blacklist (ip, reason) VALUES (?, ?)
")
                .bind(ip_str)
                .bind(&reason)
                .execute(&state.pool)
                .await;
            client.write(format!("\x1b[38;5;82m[✓] Added {} to blacklist\n\r", ip_str).as_bytes()).await?;
            
            let audit_event = AuditLog::new(client.user.username.clone(), "BLACKLIST_ADD".to_string(), "SUCCESS".to_string())
                .with_target(ip_str.to_string());
            let _ = log_audit_event(audit_event, &state.pool).await;
        },
        "remove" => {
            state.blacklist.remove(&ip);
            let _ = sqlx::query("DELETE FROM blacklist WHERE ip = ?")
                .bind(ip_str)
                .execute(&state.pool)
                .await;
            client.write(format!("\x1b[38;5;82m[✓] Removed {} from blacklist\n\r", ip_str).as_bytes()).await?;
            
            let audit_event = AuditLog::new(client.user.username.clone(), "BLACKLIST_REMOVE".to_string(), "SUCCESS".to_string())
                .with_target(ip_str.to_string());
            let _ = log_audit_event(audit_event, &state.pool).await;
        },
        _ => {
            client.write(b"\x1b[38;5;196m[X] Unknown action. Use 'add' or 'remove'\n\r").await?;
        }
    }
    Ok(())
}

pub async fn handle_whitelist_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 3 {
        client.write(b"\x1b[38;5;196m[X] Usage: whitelist <add/remove> <ip> [description]\n\r").await?;
        return Ok(());
    }
    
    let action = parts[1].to_lowercase();
    let ip_str = parts[2];
    let description = if parts.len() > 3 { parts[3..].join(" ") } else { "No description".to_string() };
    
    let ip = match ip_str.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            client.write(format!("\x1b[38;5;196m[X] Invalid IP address: {}\n\r", ip_str).as_bytes()).await?;
            return Ok(());
        }
    };
    
    match action.as_str() {
        "add" => {
            state.whitelist.insert(ip);
            let _ = sqlx::query("INSERT OR REPLACE INTO whitelist (ip, description) VALUES (?, ?)
")
                .bind(ip_str)
                .bind(&description)
                .execute(&state.pool)
                .await;
            client.write(format!("\x1b[38;5;82m[✓] Added {} to whitelist\n\r", ip_str).as_bytes()).await?;
            
            let audit_event = AuditLog::new(client.user.username.clone(), "WHITELIST_ADD".to_string(), "SUCCESS".to_string())
                .with_target(ip_str.to_string());
            let _ = log_audit_event(audit_event, &state.pool).await;
        },
        "remove" => {
            state.whitelist.remove(&ip);
            let _ = sqlx::query("DELETE FROM whitelist WHERE ip = ?")
                .bind(ip_str)
                .execute(&state.pool)
                .await;
            client.write(format!("\x1b[38;5;82m[✓] Removed {} from whitelist\n\r", ip_str).as_bytes()).await?;
            
            let audit_event = AuditLog::new(client.user.username.clone(), "WHITELIST_REMOVE".to_string(), "SUCCESS".to_string())
                .with_target(ip_str.to_string());
            let _ = log_audit_event(audit_event, &state.pool).await;
        },
        _ => {
            client.write(b"\x1b[38;5;196m[X] Unknown action. Use 'add' or 'remove'\n\r").await?;
        }
    }
    Ok(())
}
